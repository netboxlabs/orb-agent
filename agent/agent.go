package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
	"github.com/netboxlabs/orb-agent/agent/version"
)

const routineKey config.ContextKey = "routine"

// Agent is the interface that all agents must implement
type Agent interface {
	Start(ctx context.Context, cancelFunc context.CancelFunc) error
	Stop(ctx context.Context)
	RestartAll(ctx context.Context, reason string) error
	RestartBackend(ctx context.Context, backend string, reason string) error
}

type orbAgent struct {
	logger            *slog.Logger
	config            config.Config
	backends          map[string]backend.Backend
	backendState      map[string]*backend.State
	backendsCommon    config.BackendCommons
	cancelFunction    context.CancelFunc
	rpcFromCancelFunc context.CancelFunc

	asyncContext context.Context

	heartbeatCtx    context.Context
	heartbeatCancel context.CancelFunc

	// Retry Mechanism to ensure the Request is received
	groupRequestSucceeded  context.CancelFunc
	policyRequestSucceeded context.CancelFunc

	// AgentGroup channels sent from core
	groupsInfos map[string]groupInfo

	policyManager  policymgr.PolicyManager
	configManager  configmgr.Manager
	secretsManager secretsmgr.Manager
}

type groupInfo struct {
	Name      string
	ChannelID string
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

	cm := configmgr.New(logger, pm, c.OrbAgent.ConfigManager)

	return &orbAgent{
		logger: logger, config: c, policyManager: pm, configManager: cm,
		secretsManager: sm, groupsInfos: make(map[string]groupInfo),
	}, nil
}

func (a *orbAgent) startBackends(agentCtx context.Context) error {
	a.logger.Info("registered backends", slog.Any("values", backend.GetList()))
	a.logger.Info("requested backends", slog.Any("values", a.config.OrbAgent.Backends))
	if len(a.config.OrbAgent.Backends) == 0 {
		return errors.New("no backends specified")
	}
	a.backends = make(map[string]backend.Backend, len(a.config.OrbAgent.Backends))
	a.backendState = make(map[string]*backend.State)

	var commonConfig config.BackendCommons
	if v, prs := a.config.OrbAgent.Backends["common"]; prs {
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
	commonConfig.Otel.AgentLabels = a.config.OrbAgent.Labels
	a.backendsCommon = commonConfig
	delete(a.config.OrbAgent.Backends, "common")

	for name, configurationEntry := range a.config.OrbAgent.Backends {
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
		initialState := be.GetInitialState()
		a.backendState[name] = &backend.State{
			Status:        initialState,
			LastRestartTS: time.Now(),
		}
		if err := be.Start(context.WithCancel(backendCtx)); err != nil {
			a.logger.Info("failed to start backend", slog.String("backend", name), slog.Any("error", err))
			var errMessage string
			if initialState == backend.BackendError {
				errMessage = err.Error()
			}
			a.backendState[name] = &backend.State{
				Status:        initialState,
				LastError:     errMessage,
				LastRestartTS: time.Now(),
			}
			return err
		}
	}
	return nil
}

func (a *orbAgent) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	startTime := time.Now()
	defer func(t time.Time) {
		a.logger.Debug("Startup of agent execution duration", slog.String("Start() execution duration", time.Since(t).String()))
	}(startTime)
	agentCtx := context.WithValue(ctx, routineKey, "agentRoutine")
	asyncCtx, cancelAllAsync := context.WithCancel(context.WithValue(ctx, routineKey, "asyncParent"))
	a.asyncContext = asyncCtx
	a.rpcFromCancelFunc = cancelAllAsync
	a.cancelFunction = cancelFunc
	a.logger.Info("agent started", slog.String("version", version.GetBuildVersion()), slog.Any("routine", agentCtx.Value(routineKey)))

	if err := a.secretsManager.Start(ctx); err != nil {
		a.logger.Error("error during start secrets manager", slog.Any("error", err))
		return err
	}

	if err := a.startBackends(ctx); err != nil {
		return err
	}

	if err := a.configManager.Start(a.config, a.backends); err != nil {
		return err
	}

	a.logonWithHeartbeat()

	return nil
}

func (a *orbAgent) logonWithHeartbeat() {
	a.heartbeatCtx, a.heartbeatCancel = a.extendContext("heartbeat")
	a.logger.Info("heartbeat routine started")
}

func (a *orbAgent) logoffWithHeartbeat(ctx context.Context) {
	a.logger.Debug("stopping heartbeat, going offline status", slog.Any("routine", ctx.Value(routineKey)))
	if a.heartbeatCtx != nil {
		a.heartbeatCancel()
	}
}

func (a *orbAgent) Stop(ctx context.Context) {
	a.logger.Info("routine call for stop agent", slog.Any("routine", ctx.Value(routineKey)))
	if a.rpcFromCancelFunc != nil {
		a.rpcFromCancelFunc()
	}
	for name, b := range a.backends {
		if state, _, _ := b.GetRunningStatus(); state == backend.Running {
			a.logger.Debug("stopping backend", slog.String("backend", name))
			if err := b.Stop(ctx); err != nil {
				a.logger.Error("error while stopping the backend", slog.String("backend", name))
			}
		}
	}
	a.logoffWithHeartbeat(ctx)
	a.logger.Debug("stopping agent with number of go routines and go calls", slog.Int("goroutines", runtime.NumGoroutine()), slog.Int64("gocalls", runtime.NumCgoCall()))
	if a.policyRequestSucceeded != nil {
		a.policyRequestSucceeded()
	}
	if a.groupRequestSucceeded != nil {
		a.groupRequestSucceeded()
	}
	defer a.cancelFunction()
}

func (a *orbAgent) RestartBackend(ctx context.Context, name string, reason string) error {
	if !backend.HaveBackend(name) {
		return errors.New("specified backend does not exist: " + name)
	}

	be := a.backends[name]
	a.logger.Info("restarting backend", slog.String("backend", name), slog.String("reason", reason))
	a.backendState[name].RestartCount++
	a.backendState[name].LastRestartTS = time.Now()
	a.backendState[name].LastRestartReason = reason
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
		a.backendState[name].LastError = fmt.Sprintf("failed to reset backend: %v", err)
		a.logger.Error("failed to reset backend", slog.String("backend", name), slog.Any("error", err))
	}

	return nil
}

func (a *orbAgent) RestartAll(ctx context.Context, reason string) error {
	ctx = a.configManager.GetContext(ctx)
	a.logoffWithHeartbeat(ctx)
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

func (a *orbAgent) extendContext(routine string) (context.Context, context.CancelFunc) {
	uuidTraceID := uuid.NewString()
	a.logger.Debug("creating context for receiving message", slog.String("routine", routine), slog.String("trace-id", uuidTraceID))
	return context.WithCancel(context.WithValue(context.WithValue(a.asyncContext, routineKey, routine), config.ContextKey("trace-id"), uuidTraceID))
}
