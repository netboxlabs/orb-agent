package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/redact"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
	"github.com/netboxlabs/orb-agent/agent/telemetry"
	"github.com/netboxlabs/orb-agent/agent/version"
)

const (
	routineKey             config.ContextKey = "routine"
	otlpShutdownTimeout    time.Duration     = 5 * time.Second
	restartBackendChanSize int               = 5
)

// Agent is the interface that all agents must implement
type Agent interface {
	Start(ctx context.Context, cancelFunc context.CancelFunc) error
	Stop(ctx context.Context)
	RestartAll(ctx context.Context, reason string) error
	RestartBackend(ctx context.Context, backend string, reason string) error
}

type orbAgent struct {
	logger         *slog.Logger
	config         config.Config
	backends       map[string]backend.Backend
	backendsCommon config.BackendCommons
	debug          bool
	ctx            context.Context
	cancelFunction context.CancelFunc
	otlpShutdown   func(context.Context) error

	policyManager       policymgr.PolicyManager
	configManager       configmgr.Manager
	secretsManager      secretsmgr.Manager
	backendStateManager backend.StateManager
	restartBackendChan  chan string
}

var _ Agent = (*orbAgent)(nil)

// New creates a new agent
func New(logger *slog.Logger, c config.Config, debug bool) (Agent, error) {
	sm := secretsmgr.New(logger, c.OrbAgent.SecretsManager)
	pm, err := policymgr.New(logger, sm, c)
	if err != nil {
		logger.Error("error during create policy manager, exiting", "error", err)
		return nil, err
	}
	if pm.GetRepo() == nil {
		logger.Error("policy manager failed to get repository", "error", err)
		return nil, err
	}

	restartBackendChan := make(chan string, restartBackendChanSize)

	backendStateManager := backend.NewStateManager(c.OrbAgent.ConfigManager.Active, logger, restartBackendChan, pm.GetRepo())
	// Pass a background context to the config manager at construction time. The
	// manager keeps its own copy and later derives child contexts from the
	// runtime context supplied in Agent.Start.
	cm := configmgr.New(logger, pm, c.OrbAgent.ConfigManager.Active, backendStateManager)

	return &orbAgent{
		logger:              logger,
		config:              c,
		debug:               debug,
		policyManager:       pm,
		configManager:       cm,
		secretsManager:      sm,
		backendStateManager: backendStateManager,
		restartBackendChan:  restartBackendChan,
	}, nil
}

func (a *orbAgent) startBackends(agentCtx context.Context, cfgBackends map[string]any, labels map[string]string) (err error) {
	a.logger.Info("registered backends", "values", backend.GetList())
	if len(cfgBackends) == 0 {
		return errors.New("no backends specified")
	}
	a.ctx = agentCtx
	a.backends = make(map[string]backend.Backend, len(cfgBackends))
	var commonConfig config.BackendCommons
	if v, prs := cfgBackends["common"]; prs {
		bytes, err := yaml.Marshal(v)
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(bytes, &commonConfig)
		if err != nil {
			a.logger.Info("failed to marshal common backend config", "error", err)
			return err
		}
	} else {
		commonConfig = config.BackendCommons{}
	}
	commonConfig.Otlp.AgentLabels = labels
	commonConfig.Debug = a.debug
	a.backendsCommon = commonConfig
	delete(cfgBackends, "common")

	var otlpShutdown func(context.Context) error
	if a.backendsCommon.Otlp.Grpc != "" {
		a.logger, otlpShutdown, err = telemetry.BuildOTLPLogExporter(agentCtx, a.logger, a.backendsCommon)
		if err != nil {
			a.logger.Error("failed to create OTLP log exporter", "error", err)
			return err
		}
		if otlpShutdown != nil {
			a.otlpShutdown = otlpShutdown
			defer func() {
				if err != nil {
					a.shutdownOTLP(agentCtx)
				}
			}()
		}
	}

	for name, configurationEntry := range cfgBackends {
		var cEntity map[string]any
		if configurationEntry != nil {
			var ok bool
			cEntity, ok = configurationEntry.(map[string]any)
			if !ok {
				return errors.New("invalid backend configuration format for backend: " + name)
			}
		}
		if !backend.HaveBackend(name) {
			return errors.New("specified backend does not exist: " + name)
		}
		be := backend.GetBackend(name)

		if err := be.Configure(a.logger, a.policyManager.GetRepo(), cEntity, a.backendsCommon); err != nil {
			a.logger.Info("failed to configure backend", "backend", name, "error", err)
			return err
		}
		backendCtx := context.WithValue(agentCtx, routineKey, name)
		backendCtx = a.configManager.GetContext(backendCtx)
		a.backends[name] = be
		// Create a cancellable context for the backend and ensure we pass both
		// the context and its cancel function to Start, matching the Backend
		// interface.
		runCtx, cancel := context.WithCancel(backendCtx)
		if err := be.Start(runCtx, cancel); err != nil {
			var errMessage string
			if be.GetInitialState() == backend.BackendError {
				errMessage = err.Error()
			}
			a.backendStateManager.RegisterError(name, errMessage)
			return err
		}
		a.backendStateManager.StartBackendMonitor(name, be)

		go a.waitForRestartRequests()
	}
	return nil
}

func (a *orbAgent) waitForRestartRequests() {
	for name := range a.restartBackendChan {
		a.logger.Info("restarting backend", "backend", name)
		err := a.RestartBackend(a.ctx, name, "restart requested by fleet")
		if err != nil {
			a.logger.Error("failed to restart backend", "backend", name, "error", err)
		}
	}
}

func (a *orbAgent) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	startTime := time.Now()
	defer func(t time.Time) {
		a.logger.Debug("Startup of agent execution duration", "Start() execution duration", time.Since(t).String())
	}(startTime)
	agentCtx := context.WithValue(ctx, routineKey, "agentRoutine")
	a.cancelFunction = cancelFunc
	a.logger.Info("agent started", "version", version.GetBuildVersion(), "routine", agentCtx.Value(routineKey))
	a.logger.Info("requested backends", "values", redact.SensitiveData(a.config.OrbAgent.Backends))

	if err := a.secretsManager.Start(ctx); err != nil {
		a.logger.Error("error during start secrets manager", "error", err)
		return err
	}

	// Bind fleet secrets manager to fleet config manager if both are fleet-based
	// This needs to happen before SolveConfigSecrets so secrets can be resolved
	if a.config.OrbAgent.ConfigManager.Active == "fleet" && a.config.OrbAgent.SecretsManager.Active == "fleet" {
		if fleetCM, ok := a.configManager.(*configmgr.FleetConfigManager); ok {
			if err := fleetCM.BindSecretsManager(a.secretsManager); err != nil {
				a.logger.Error("error binding fleet secrets manager", "error", err)
				return err
			}
		}
	}

	var err error
	if a.config.OrbAgent.Backends,
		a.config.OrbAgent.ConfigManager,
		err = a.secretsManager.SolveConfigSecrets(a.config.OrbAgent.Backends, a.config.OrbAgent.ConfigManager); err != nil {
		return err
	}

	if a.config.OrbAgent.ConfigManager.Active == "fleet" {
		// Get gRPC port from config, defaulting to 4317 if not specified
		grpcPort := 4317
		if a.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort != nil {
			grpcPort = *a.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort
		}
		otlpBridgeEndpoint := fmt.Sprintf("grpc://localhost:%d", grpcPort)
		if commonBackend, exists := a.config.OrbAgent.Backends["common"]; exists {
			if commonMap, ok := commonBackend.(map[string]any); ok {
				if otlpSection, ok := commonMap["otlp"].(map[string]any); ok {
					grpcURL, _ := otlpSection["grpc"].(string)
					if grpcURL != "" {
						a.logger.Warn("Overriding OTLP gRPC URL for fleet config manager", "url", grpcURL)
					}
					otlpSection["grpc"] = otlpBridgeEndpoint
					a.logger.Info("auto-configured OTLP gRPC URL for fleet config manager", "url", otlpBridgeEndpoint)

				} else {
					// otlp section doesn't exist, create it
					commonMap["otlp"] = map[string]any{
						"grpc": otlpBridgeEndpoint,
					}
					a.logger.Info("auto-configured OTLP gRPC URL for fleet config manager", "url", otlpBridgeEndpoint)
				}
			}
		} else {
			// common backend doesn't exist, create it with otlp config
			a.config.OrbAgent.Backends["common"] = map[string]any{
				"otlp": map[string]any{
					"grpc": otlpBridgeEndpoint,
				},
			}
			a.logger.Info("auto-configured OTLP gRPC URL for fleet config manager", "url", otlpBridgeEndpoint)
		}
	}

	if err = a.startBackends(agentCtx, a.config.OrbAgent.Backends, a.config.OrbAgent.Labels); err != nil {
		return err
	}

	if err = a.configManager.Start(a.config, a.backends); err != nil {
		return err
	}

	return nil
}

func (a *orbAgent) Stop(ctx context.Context) {
	a.logger.Info("routine call for stop agent", "routine", ctx.Value(routineKey))
	for name, b := range a.backends {
		if state, _, _ := b.GetRunningStatus(); state == backend.Running {
			a.logger.Debug("stopping backend", "backend", name)
			if err := b.Stop(ctx); err != nil {
				a.logger.Error("error while stopping the backend", "backend", name)
			}
		}
	}
	if err := a.configManager.Stop(ctx); err != nil {
		a.logger.Error("error while stopping config manager", slog.Any("error", err))
	}
	a.logger.Debug("stopping agent with number of go routines and go calls", slog.Int("goroutines", runtime.NumGoroutine()), slog.Int64("gocalls", runtime.NumCgoCall()))
	if a.cancelFunction != nil {
		a.cancelFunction()
	}
	a.shutdownOTLP(ctx)
	a.logger.Debug("stopping agent with number of go routines and go calls", "goroutines", runtime.NumGoroutine(), "gocalls", runtime.NumCgoCall())
	defer func() {
		if a.cancelFunction != nil {
			a.cancelFunction()
		}
	}()
}

func (a *orbAgent) shutdownOTLP(ctx context.Context) {
	shutdown := a.otlpShutdown
	if shutdown == nil {
		return
	}
	a.otlpShutdown = nil

	if ctx == nil {
		ctx = context.Background()
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, otlpShutdownTimeout)
	defer cancel()

	if err := shutdown(shutdownCtx); err != nil {
		a.logger.Error("error while shutting down OTLP log exporter", "error", err)
		return
	}
	a.logger.Debug("shut down OTLP log exporter")
}

func (a *orbAgent) RestartBackend(ctx context.Context, name string, reason string) error {
	if !backend.HaveBackend(name) {
		return errors.New("specified backend does not exist: " + name)
	}

	be := a.backends[name]
	a.logger.Info("restarting backend", "backend", name, "reason", reason)
	a.backendStateManager.RegisterRestart(name, reason)
	a.logger.Info("removing policies", "backend", name)
	if err := a.policyManager.RemoveBackendPolicies(be, true); err != nil {
		a.logger.Error("failed to remove policies", "backend", name, "error", err)
	}
	var beConfig map[string]any
	if a.config.OrbAgent.Backends[name] != nil {
		var ok bool
		beConfig, ok = a.config.OrbAgent.Backends[name].(map[string]any)
		if !ok {
			return errors.New("backend not found: " + name)
		}
	}
	if err := be.Configure(a.logger, a.policyManager.GetRepo(), beConfig, a.backendsCommon); err != nil {
		return err
	}
	a.logger.Info("resetting backend", "backend", name)

	if err := be.FullReset(ctx); err != nil {
		a.backendStateManager.RegisterError(name, fmt.Sprintf("failed to reset backend: %v", err))
	}

	return nil
}

func (a *orbAgent) RestartAll(ctx context.Context, reason string) error {
	ctx = a.configManager.GetContext(ctx)
	a.logger.Info("restarting comms", "reason", reason)
	for name := range a.backends {
		a.logger.Info("restarting backend", "backend", name, "reason", reason)
		err := a.RestartBackend(ctx, name, reason)
		if err != nil {
			a.logger.Error("failed to restart backend", "error", err)
		}
	}
	a.logger.Info("all backends and comms were restarted")

	return nil
}
