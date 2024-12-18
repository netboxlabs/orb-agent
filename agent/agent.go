package agent

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/orb-community/orb/fleet"
	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	manager "github.com/netboxlabs/orb-agent/agent/policyMgr"
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
	logger            *zap.Logger
	config            config.Config
	client            mqtt.Client
	agentID           string
	backends          map[string]backend.Backend
	backendState      map[string]*backend.State
	backendsCommon    config.BackendCommons
	cancelFunction    context.CancelFunc
	rpcFromCancelFunc context.CancelFunc

	asyncContext context.Context

	hbTicker        *time.Ticker
	heartbeatCtx    context.Context
	heartbeatCancel context.CancelFunc

	// Agent RPC channel, configured from command line
	baseTopic        string
	rpcFromCoreTopic string
	heartbeatsTopic  string

	// Retry Mechanism to ensure the Request is received
	groupRequestSucceeded  context.CancelFunc
	policyRequestSucceeded context.CancelFunc

	// AgentGroup channels sent from core
	groupsInfos map[string]groupInfo

	policyManager manager.PolicyManager
	configManager config.Manager
}

type groupInfo struct {
	Name      string
	ChannelID string
}

var _ Agent = (*orbAgent)(nil)

// New creates a new agent
func New(logger *zap.Logger, c config.Config) (Agent, error) {
	pm, err := manager.New(logger, c)
	if err != nil {
		logger.Error("error during create policy manager, exiting", zap.Error(err))
		return nil, err
	}
	if pm.GetRepo() == nil {
		logger.Error("policy manager failed to get repository", zap.Error(err))
		return nil, err
	}
	cm := config.New(logger, c.OrbAgent.ConfigManager)

	return &orbAgent{logger: logger, config: c, policyManager: pm, configManager: cm, groupsInfos: make(map[string]groupInfo)}, nil
}

func (a *orbAgent) managePolicies() error {
	if a.config.OrbAgent.Policies == nil {
		return errors.New("no policies specified")
	}

	for beName, policy := range a.config.OrbAgent.Policies {
		_, ok := a.backends[beName]
		if !ok {
			return errors.New("backend not found: " + beName)
		}
		for pName, data := range policy {
			id := uuid.NewString()
			payload := fleet.AgentPolicyRPCPayload{Action: "manage", Name: pName, DatasetID: id, Backend: beName, Version: 1, Data: data}
			a.policyManager.ManagePolicy(payload)
		}

	}
	return nil
}

func (a *orbAgent) startBackends(agentCtx context.Context) error {
	a.logger.Info("registered backends", zap.Strings("values", backend.GetList()))
	a.logger.Info("requested backends", zap.Any("values", a.config.OrbAgent.Backends))
	if len(a.config.OrbAgent.Backends) == 0 {
		return errors.New("no backends specified")
	}
	a.backends = make(map[string]backend.Backend, len(a.config.OrbAgent.Backends))
	a.backendState = make(map[string]*backend.State)

	var commonConfig config.BackendCommons
	if v, prs := a.config.OrbAgent.Backends["common"]; prs {
		if err := mapstructure.Decode(v, &commonConfig); err != nil {
			return fmt.Errorf("failed to decode common backend config: %w", err)
		}
	}
	commonConfig.Otel.AgentTags = a.config.OrbAgent.Tags
	a.backendsCommon = commonConfig
	delete(a.config.OrbAgent.Backends, "common")

	for name, configurationEntry := range a.config.OrbAgent.Backends {

		if !backend.HaveBackend(name) {
			return errors.New("specified backend does not exist: " + name)
		}
		be := backend.GetBackend(name)

		if err := be.Configure(a.logger, a.policyManager.GetRepo(), configurationEntry, a.backendsCommon); err != nil {
			a.logger.Info("failed to configure backend", zap.String("backend", name), zap.Error(err))
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
			a.logger.Info("failed to start backend", zap.String("backend", name), zap.Error(err))
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
		a.logger.Debug("Startup of agent execution duration", zap.String("Start() execution duration", time.Since(t).String()))
	}(startTime)
	agentCtx := context.WithValue(ctx, routineKey, "agentRoutine")
	asyncCtx, cancelAllAsync := context.WithCancel(context.WithValue(ctx, routineKey, "asyncParent"))
	a.asyncContext = asyncCtx
	a.rpcFromCancelFunc = cancelAllAsync
	a.cancelFunction = cancelFunc
	a.logger.Info("agent started", zap.String("version", version.GetBuildVersion()), zap.Any("routine", agentCtx.Value(routineKey)))
	mqtt.CRITICAL = &agentLoggerCritical{a: a}
	mqtt.ERROR = &agentLoggerError{a: a}

	if a.config.OrbAgent.Debug.Enable {
		a.logger.Info("debug logging enabled")
		mqtt.DEBUG = &agentLoggerDebug{a: a}
	}

	if err := a.startBackends(ctx); err != nil {
		return err
	}

	if err := a.managePolicies(); err != nil {
		return err
	}

	a.logonWithHeartbeat()

	return nil
}

func (a *orbAgent) logonWithHeartbeat() {
	a.hbTicker = time.NewTicker(HeartbeatFreq)
	a.heartbeatCtx, a.heartbeatCancel = a.extendContext("heartbeat")
	go a.sendHeartbeats(a.heartbeatCtx, a.heartbeatCancel)
	a.logger.Info("heartbeat routine started")
}

func (a *orbAgent) logoffWithHeartbeat(ctx context.Context) {
	a.logger.Debug("stopping heartbeat, going offline status", zap.Any("routine", ctx.Value(routineKey)))
	if a.heartbeatCtx != nil {
		a.heartbeatCancel()
	}
	if a.client != nil && a.client.IsConnected() {
		if token := a.client.Unsubscribe(a.rpcFromCoreTopic); token.Wait() && token.Error() != nil {
			a.logger.Warn("failed to unsubscribe to RPC channel", zap.Error(token.Error()))
		}
	}
}

func (a *orbAgent) Stop(ctx context.Context) {
	a.logger.Info("routine call for stop agent", zap.Any("routine", ctx.Value(routineKey)))
	if a.rpcFromCancelFunc != nil {
		a.rpcFromCancelFunc()
	}
	for name, b := range a.backends {
		if state, _, _ := b.GetRunningStatus(); state == backend.Running {
			a.logger.Debug("stopping backend", zap.String("backend", name))
			if err := b.Stop(ctx); err != nil {
				a.logger.Error("error while stopping the backend", zap.String("backend", name))
			}
		}
	}
	a.logoffWithHeartbeat(ctx)
	if a.client != nil && a.client.IsConnected() {
		a.client.Disconnect(0)
	}
	a.logger.Debug("stopping agent with number of go routines and go calls", zap.Int("goroutines", runtime.NumGoroutine()), zap.Int64("gocalls", runtime.NumCgoCall()))
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
	a.logger.Info("restarting backend", zap.String("backend", name), zap.String("reason", reason))
	a.backendState[name].RestartCount++
	a.backendState[name].LastRestartTS = time.Now()
	a.backendState[name].LastRestartReason = reason
	a.logger.Info("removing policies", zap.String("backend", name))
	if err := a.policyManager.RemoveBackendPolicies(be, true); err != nil {
		a.logger.Error("failed to remove policies", zap.String("backend", name), zap.Error(err))
	}
	if err := be.Configure(a.logger, a.policyManager.GetRepo(), a.config.OrbAgent.Backends[name], a.backendsCommon); err != nil {
		return err
	}
	a.logger.Info("resetting backend", zap.String("backend", name))

	if err := be.FullReset(ctx); err != nil {
		a.backendState[name].LastError = fmt.Sprintf("failed to reset backend: %v", err)
		a.logger.Error("failed to reset backend", zap.String("backend", name), zap.Error(err))
	}
	be.SetCommsClient(a.agentID, &a.client, fmt.Sprintf("%s/?/%s", a.baseTopic, name))

	return nil
}

func (a *orbAgent) RestartAll(ctx context.Context, reason string) error {
	ctx = a.configManager.GetContext(ctx)
	a.logoffWithHeartbeat(ctx)
	a.logger.Info("restarting comms", zap.String("reason", reason))
	for name := range a.backends {
		a.logger.Info("restarting backend", zap.String("backend", name), zap.String("reason", reason))
		err := a.RestartBackend(ctx, name, reason)
		if err != nil {
			a.logger.Error("failed to restart backend", zap.Error(err))
		}
	}
	a.logger.Info("all backends and comms were restarted")

	return nil
}

func (a *orbAgent) extendContext(routine string) (context.Context, context.CancelFunc) {
	uuidTraceID := uuid.NewString()
	a.logger.Debug("creating context for receiving message", zap.String("routine", routine), zap.String("trace-id", uuidTraceID))
	return context.WithCancel(context.WithValue(context.WithValue(a.asyncContext, routineKey, routine), config.ContextKey("trace-id"), uuidTraceID))
}
