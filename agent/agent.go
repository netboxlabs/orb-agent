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
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
	"github.com/netboxlabs/orb-agent/agent/version"
)

const routineKey config.ContextKey = "routine"

const restartBackendChanSize = 5

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
	ctx            context.Context
	cancelFunction context.CancelFunc

	policyManager       policymgr.PolicyManager
	configManager       configmgr.Manager
	secretsManager      secretsmgr.Manager
	backendStateManager *backend.BackendStateManager
	restartBackendChan  chan string
}

var _ Agent = (*orbAgent)(nil)

// New creates a new agent
func New(logger *slog.Logger, c config.Config) (Agent, error) {
	sm := secretsmgr.New(logger, c.OrbAgent.SecretsManger)
	pm, err := policymgr.New(logger, sm, c)
	if err != nil {
		logger.Error("error during create policy manager, exiting", slog.Any("error", err))
		return nil, err
	}
	if pm.GetRepo() == nil {
		logger.Error("policy manager failed to get repository", slog.Any("error", err))
		return nil, err
	}

	restartBackendChan := make(chan string, restartBackendChanSize)

	backendStateManager := backend.NewBackendStateManager(logger, restartBackendChan)
	// Pass a background context to the config manager at construction time. The
	// manager keeps its own copy and later derives child contexts from the
	// runtime context supplied in Agent.Start.
	cm := configmgr.New(logger, pm, c.OrbAgent.ConfigManager.Active, backendStateManager)

	return &orbAgent{
		logger:              logger,
		config:              c,
		policyManager:       pm,
		configManager:       cm,
		secretsManager:      sm,
		backendStateManager: backendStateManager,
		restartBackendChan:  restartBackendChan,
	}, nil
}

func (a *orbAgent) startBackends(agentCtx context.Context, cfgBackends map[string]any, labels map[string]string) error {
	a.logger.Info("registered backends", slog.Any("values", backend.GetList()))
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
			a.logger.Info("failed to marshal common backend config", slog.Any("error", err))
			return err
		}
	} else {
		commonConfig = config.BackendCommons{}
	}
	commonConfig.Otlp.AgentLabels = labels
	a.backendsCommon = commonConfig
	delete(cfgBackends, "common")

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
			a.logger.Info("failed to configure backend", slog.String("backend", name), slog.Any("error", err))
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
		a.logger.Info("restarting backend", slog.String("backend", name))
		err := a.RestartBackend(a.ctx, name, "restart requested by fleet")
		if err != nil {
			a.logger.Error("failed to restart backend", slog.String("backend", name), slog.Any("error", err))
		}
	}
}

func (a *orbAgent) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	startTime := time.Now()
	defer func(t time.Time) {
		a.logger.Debug("Startup of agent execution duration", slog.String("Start() execution duration", time.Since(t).String()))
	}(startTime)
	agentCtx := context.WithValue(ctx, routineKey, "agentRoutine")
	a.cancelFunction = cancelFunc
	a.logger.Info("agent started", slog.String("version", version.GetBuildVersion()), slog.Any("routine", agentCtx.Value(routineKey)))
	a.logger.Info("requested backends", slog.Any("values", a.config.OrbAgent.Backends))

	if err := a.secretsManager.Start(ctx); err != nil {
		a.logger.Error("error during start secrets manager", slog.Any("error", err))
		return err
	}

	var err error
	if a.config.OrbAgent.Backends,
		a.config.OrbAgent.ConfigManager,
		err = a.secretsManager.SolveConfigSecrets(a.config.OrbAgent.Backends, a.config.OrbAgent.ConfigManager); err != nil {
		return err
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
	a.logger.Info("routine call for stop agent", slog.Any("routine", ctx.Value(routineKey)))
	for name, b := range a.backends {
		if state, _, _ := b.GetRunningStatus(); state == backend.Running {
			a.logger.Debug("stopping backend", slog.String("backend", name))
			if err := b.Stop(ctx); err != nil {
				a.logger.Error("error while stopping the backend", slog.String("backend", name))
			}
		}
	}
	a.logger.Debug("stopping agent with number of go routines and go calls", slog.Int("goroutines", runtime.NumGoroutine()), slog.Int64("gocalls", runtime.NumCgoCall()))
	defer a.cancelFunction()
}

func (a *orbAgent) RestartBackend(ctx context.Context, name string, reason string) error {
	if !backend.HaveBackend(name) {
		return errors.New("specified backend does not exist: " + name)
	}

	be := a.backends[name]
	a.logger.Info("restarting backend", slog.String("backend", name), slog.String("reason", reason))
	a.backendStateManager.RegisterRestart(name, reason)
	a.logger.Info("removing policies", slog.String("backend", name))
	if err := a.policyManager.RemoveBackendPolicies(be, true); err != nil {
		a.logger.Error("failed to remove policies", slog.String("backend", name), slog.Any("error", err))
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
	a.logger.Info("resetting backend", slog.String("backend", name))

	if err := be.FullReset(ctx); err != nil {
		a.backendStateManager.RegisterError(name, fmt.Sprintf("failed to reset backend: %v", err))
	}

	return nil
}

func (a *orbAgent) RestartAll(ctx context.Context, reason string) error {
	ctx = a.configManager.GetContext(ctx)
	a.logger.Info("restarting comms", slog.String("reason", reason))
	for name := range a.backends {
		a.logger.Info("restarting backend", slog.String("backend", name), slog.String("reason", reason))
		err := a.RestartBackend(ctx, name, reason)
		if err != nil {
			a.logger.Error("failed to restart backend", slog.Any("error", err))
		}
	}
	a.logger.Info("all backends and comms were restarted")

	return nil
}
