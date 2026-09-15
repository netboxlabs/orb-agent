package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/redact"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
	"github.com/netboxlabs/orb-agent/agent/supervisor"
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
	// Start starts the managers and every declared backend. It returns nil
	// when startup completed, and also when a Stop that began meanwhile won
	// against a backend still starting: that stop finishes the shutdown, so
	// the caller waits for it as it would after a completed startup.
	Start(ctx context.Context, cancelFunc context.CancelFunc) error
	Stop(ctx context.Context)
}

type orbAgent struct {
	logger *slog.Logger
	config config.Config

	backendsCommon   config.BackendCommons
	debug            bool
	cancelFunction   context.CancelFunc
	otlpShutdown     func(context.Context) error
	otlpShutdownOnce sync.Once

	policyManager       policymgr.PolicyManager
	configManager       configmgr.Manager
	secretsManager      secretsmgr.Manager
	backendStateManager backend.StateManager
	filesManager        filesmgr.Manager
	filesmgrUnsubscribe func()

	// supervisor owns every declared backend's lifecycle: configuring and
	// starting them, restarting them on request, replaying their policies
	// after a restart, and stopping them at shutdown. The agent delegates to
	// it instead of tracking backends, restarts and replays itself.
	supervisor *supervisor.Supervisor
}

var _ Agent = (*orbAgent)(nil)

// New creates a new agent
func New(logger *slog.Logger, c config.Config, debug bool) (Agent, error) {
	sm, err := secretsmgr.New(logger, c.OrbAgent.SecretsManager)
	if err != nil {
		logger.Error("error during create secrets manager, exiting", "error", err)
		return nil, err
	}
	fm := filesmgr.New(logger, c.OrbAgent.FilesManager)
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
	cm := configmgr.New(logger, pm, c.OrbAgent.ConfigManager.Active, backendStateManager, fm)

	sup := supervisor.New(logger, backendStateManager, fm, pm, restartBackendChan, supervisor.Options{NotRunning: policymgr.ErrBackendNotRunning})
	// The fleet connection is built inside newFleetConfigManager, so it
	// already exists here: a full agent reset restarts through the
	// supervisor from the moment the fleet config manager can dispatch one.
	if fleetCM, ok := cm.(*configmgr.FleetConfigManager); ok {
		fleetCM.SetResetter(sup)
	}

	a := &orbAgent{
		logger:              logger,
		config:              c,
		debug:               debug,
		policyManager:       pm,
		configManager:       cm,
		secretsManager:      sm,
		backendStateManager: backendStateManager,
		filesManager:        fm,
		supervisor:          sup,
	}
	return a, nil
}

func (a *orbAgent) startBackends(agentCtx context.Context, cfgBackends map[string]any, labels map[string]string) (err error) {
	a.logger.Info("registered backends", "values", backend.GetList())
	if len(cfgBackends) == 0 {
		return errors.New("no backends specified")
	}
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
					a.shutdownOTLP()
				}
			}()
		}
	}

	return a.supervisor.ConfigureAll(cfgBackends, a.backendsCommon, func(name string) context.Context {
		return a.configManager.GetContext(context.WithValue(agentCtx, routineKey, name))
	})
}

// subscribeFilesmgr wires FilesManager upgrade events to the supervisor's
// upgrade queue. When a file's logical name matches the ManagedBinaryName of
// a declared backend, the backend (identified by its backend name, NOT the
// file name) is queued for restart. This decouples backend identity from
// binary identity. The unsubscribe function stored in a.filesmgrUnsubscribe
// must be called on Stop().
//
// Must be called after startBackends has declared every backend with the
// supervisor; the subscriber callback reads the supervisor's declared
// backends from the FileEvent goroutine.
func (a *orbAgent) subscribeFilesmgr() {
	if a.filesManager == nil {
		return
	}
	a.filesmgrUnsubscribe = a.filesManager.Subscribe(func(ev filesmgr.FileEvent) {
		switch ev.Type {
		case filesmgr.EventInstalled, filesmgr.EventUpgraded:
			// continue — both signal that a new binary is on disk and the backend
			// should be restarted to pick up the FilesManager-managed path.
		default:
			// Do NOT act on EventRolledBack or EventRemoved — those originate from
			// the auto-rollback flow which handles its own restart, and restarting
			// on them would create duplicate restart cycles.
			return
		}
		for name, be := range a.supervisor.Declared() {
			mb, ok := be.(backend.ManagedBinary)
			if !ok {
				continue
			}
			if mb.ManagedBinaryName() == ev.Entry.Name {
				a.supervisor.QueueUpgrade(name)
				a.logger.Info("filesmgr: queued restart", "backend", name, "file", ev.Entry.Name, "version", ev.Entry.Version)
			}
		}
	})
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

	// Bind the fleet files manager so it sends the bundle_list_req catch-up on
	// connect. Gated on the config manager being fleet; BindFilesManager handles
	// the non-fleet files-manager case itself (warns and does nothing).
	if a.config.OrbAgent.ConfigManager.Active == "fleet" {
		if fleetCM, ok := a.configManager.(*configmgr.FleetConfigManager); ok {
			if err := fleetCM.BindFilesManager(a.filesManager); err != nil {
				a.logger.Error("error binding fleet files manager", "error", err)
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
		// The bridge ports are handed to backends as fixed localhost URLs, so
		// they must be real ports: 0 would bind an ephemeral listener whose
		// number never reaches the backends (pktvisor then silently starts
		// without --otel), and anything out of range cannot be bound at all.
		grpcPort, err := fleetBridgePort(a.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort, 4317, "otlp_bridge_grpc_port")
		if err != nil {
			return err
		}
		// Same for the HTTP listener, which pktvisor (OTLP/HTTP only) uses.
		httpPort, err := fleetBridgePort(a.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeHTTPPort, 4318, "otlp_bridge_http_port")
		if err != nil {
			return err
		}
		otlpBridgeEndpoint := fmt.Sprintf("grpc://localhost:%d", grpcPort)
		otlpBridgeHTTPEndpoint := fmt.Sprintf("http://localhost:%d", httpPort)

		// A missing "common" block, an empty one (`common:` with no value, which
		// yaml.v3 stores as nil) or a non-map value are all treated the same:
		// replaced by a map that carries the bridge endpoints. The same applies
		// to the nested "otlp" section.
		if a.config.OrbAgent.Backends == nil {
			a.config.OrbAgent.Backends = map[string]any{}
		}
		commonMap, ok := a.config.OrbAgent.Backends["common"].(map[string]any)
		if !ok || commonMap == nil {
			commonMap = map[string]any{}
			a.config.OrbAgent.Backends["common"] = commonMap
		}
		otlpSection, ok := commonMap["otlp"].(map[string]any)
		if !ok || otlpSection == nil {
			otlpSection = map[string]any{}
			commonMap["otlp"] = otlpSection
		}
		if grpcURL, _ := otlpSection["grpc"].(string); grpcURL != "" && grpcURL != otlpBridgeEndpoint {
			a.logger.Warn("Overriding OTLP gRPC URL for fleet config manager", "url", grpcURL)
		}
		if httpURL, _ := otlpSection["http"].(string); httpURL != "" && httpURL != otlpBridgeHTTPEndpoint {
			a.logger.Warn("Overriding OTLP HTTP URL for fleet config manager", "url", httpURL)
		}
		otlpSection["grpc"] = otlpBridgeEndpoint
		otlpSection["http"] = otlpBridgeHTTPEndpoint
		a.logger.Info("auto-configured OTLP URLs for fleet config manager", "grpc", otlpBridgeEndpoint, "http", otlpBridgeHTTPEndpoint)
	}

	if a.filesManager != nil {
		if err := a.filesManager.Start(ctx); err != nil {
			return fmt.Errorf("filesmgr start: %w", err)
		}
	}

	var fleetCM *configmgr.FleetConfigManager
	if a.config.OrbAgent.ConfigManager.Active == "fleet" {
		var ok bool
		fleetCM, ok = a.configManager.(*configmgr.FleetConfigManager)
		if ok {
			if err = fleetCM.StartOTLPBridge(ctx, a.config); err != nil {
				return err
			}
			defer func() {
				if err != nil {
					_ = fleetCM.StopOTLPBridge(context.Background())
				}
			}()
		}
	}

	if err = a.startBackends(agentCtx, a.config.OrbAgent.Backends, a.config.OrbAgent.Labels); err != nil {
		// A stop that began while the backends were still starting is a
		// shutdown in progress, not a startup failure: Stop has already
		// been called and finishes the shutdown (StopAll stops whatever
		// came up, then the managers stop), so Start returns nil and main
		// waits for that stop to complete instead of exiting with an error
		// while backends are still being stopped gracefully.
		if errors.Is(err, supervisor.ErrStopped) {
			a.logger.Info("startup interrupted by a stop; the stop completes the shutdown", "error", err)
			// The stop path owns the teardown of everything Start brought
			// up, the OTLP bridge included (the config manager's Stop), so
			// the failure cleanup deferred above must not run alongside it.
			err = nil
			return nil
		}
		return err
	}

	// Subscribe after startBackends has declared every backend with the
	// supervisor so the subscriber callback reads a fully-populated set.
	// Must be called after startBackends returns; reads the supervisor's
	// declared backends from the FileEvent goroutine.
	a.subscribeFilesmgr()

	if err = a.configManager.Start(agentCtx, a.config, a.supervisor.Declared()); err != nil {
		return err
	}

	return nil
}

func (a *orbAgent) Stop(ctx context.Context) {
	a.logger.Info("routine call for stop agent", "routine", ctx.Value(routineKey))
	// Guarded against nil for tests that build an orbAgent literal without
	// going through New. StopAll cancels the supervisor's own stop context as
	// its first statement, so an in-flight restart's replay observes
	// shutdown as soon as it checks it, then stops every running backend and
	// waits for every rescheduled replay to exit.
	if a.supervisor != nil {
		a.supervisor.StopAll(ctx)
	}
	a.shutdownOTLP()
	if a.policyManager != nil {
		if repo := a.policyManager.GetRepo(); repo != nil {
			if err := repo.FailNonTerminalRuns(policies.RunFailureReasonAgentStopped); err != nil {
				a.logger.Error("error while finalizing policy runs on shutdown", slog.Any("error", err))
			}
		}
	}
	if a.filesmgrUnsubscribe != nil {
		a.filesmgrUnsubscribe()
	}
	if a.filesManager != nil {
		if err := a.filesManager.Stop(ctx); err != nil {
			a.logger.Warn("filesmgr stop returned error", "error", err)
		}
	}
	if err := a.configManager.Stop(ctx); err != nil {
		a.logger.Error("error while stopping config manager", slog.Any("error", err))
	}
	a.logger.Debug("stopping agent with number of go routines and go calls", slog.Int("goroutines", runtime.NumGoroutine()), slog.Int64("gocalls", runtime.NumCgoCall()))
	if a.cancelFunction != nil {
		a.cancelFunction()
	}
	a.logger.Debug("stopping agent with number of go routines and go calls", "goroutines", runtime.NumGoroutine(), "gocalls", runtime.NumCgoCall())
	defer func() {
		if a.cancelFunction != nil {
			a.cancelFunction()
		}
	}()
}

// fleetBridgePort resolves a configured bridge port (nil means the default)
// and rejects values outside 1-65535, since backends dial the port verbatim.
func fleetBridgePort(configured *int, def int, setting string) (int, error) {
	if configured == nil {
		return def, nil
	}
	if *configured < 1 || *configured > 65535 {
		return 0, fmt.Errorf("%s must be between 1 and 65535, got %d (backends dial this port on localhost, so an ephemeral port cannot be used)", setting, *configured)
	}
	return *configured, nil
}

func (a *orbAgent) shutdownOTLP() {
	a.otlpShutdownOnce.Do(func() {
		shutdown := a.otlpShutdown
		if shutdown == nil {
			return
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), otlpShutdownTimeout)
		defer cancel()

		if err := shutdown(shutdownCtx); err != nil {
			a.logger.Error("error while shutting down OTLP log exporter", "error", err)
			return
		}
		a.logger.Debug("shut down OTLP log exporter")
	})
}
