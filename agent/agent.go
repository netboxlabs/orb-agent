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
	logger *slog.Logger
	config config.Config

	// backends maps backend names to their Backend implementations.
	//
	// Invariant: this map is populated exactly once during startBackends and is
	// read-only after Start returns. Multiple goroutines (subscribeFilesmgr's
	// callback, restartBackendWithFilesmgrRollback) read it concurrently
	// without synchronization, which is safe ONLY because of this invariant.
	// Any future code path that mutates a.backends after Start MUST add a
	// mutex to protect concurrent access.
	backends         map[string]backend.Backend
	backendsCommon   config.BackendCommons
	debug            bool
	ctx              context.Context
	cancelFunction   context.CancelFunc
	otlpShutdown     func(context.Context) error
	otlpShutdownOnce sync.Once

	policyManager       policymgr.PolicyManager
	configManager       configmgr.Manager
	secretsManager      secretsmgr.Manager
	backendStateManager backend.StateManager
	filesManager        filesmgr.Manager
	filesmgrUnsubscribe func()
	restartBackendChan  chan string

	// pendingRestarts holds backend names that need to be restarted.
	// The restartDispatcher goroutine drains this map and sends to
	// restartBackendChan, coalescing rapid successive upgrade events
	// into a single restart.
	pendingRestarts   map[string]struct{}
	pendingRestartsMu sync.Mutex

	// restartCancels stores the cancel functions for backend contexts created
	// by restartBackendWithFilesmgrRollback. The prior cancel is called before
	// each new restart to avoid leaking contexts across multiple upgrade cycles.
	// Note: startBackends does not store its cancel functions (pre-existing
	// pattern); only the new restartBackendWithFilesmgrRollback code paths are
	// guarded here.
	restartCancels   map[string]context.CancelFunc
	restartCancelsMu sync.Mutex

	// dispatcherCancel stops the restartDispatcher goroutine independently of
	// the root agent context. Cancelled in Stop() before iterating backends so
	// the dispatcher cannot fire a restart after backends have been stopped.
	dispatcherCancel context.CancelFunc

	// backendRestartMu serializes Stop+Start sequences per backend across
	// both restart paths (file-driven via restartDispatcher and health/fleet-
	// driven via waitForRestartRequests). Without this, a file event and a
	// health-driven restart for the same backend can interleave Stop/Start
	// operations.
	backendRestartMu sync.Map // name -> *sync.Mutex
}

var _ Agent = (*orbAgent)(nil)

// New creates a new agent
func New(logger *slog.Logger, c config.Config, debug bool) (Agent, error) {
	sm := secretsmgr.New(logger, c.OrbAgent.SecretsManager)
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

	return &orbAgent{
		logger:              logger,
		config:              c,
		debug:               debug,
		policyManager:       pm,
		configManager:       cm,
		secretsManager:      sm,
		backendStateManager: backendStateManager,
		filesManager:        fm,
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
					a.shutdownOTLP()
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

		if err := be.Configure(a.logger, a.policyManager.GetRepo(), cEntity, a.backendsCommon, a.filesManager); err != nil {
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
	}

	// Start the restart workers once, after all backends are registered.
	// Use a dedicated context for the dispatcher so Stop() can cancel it before
	// iterating backends, preventing a restart from firing after shutdown begins.
	//
	// waitForRestartRequests is started exactly once per agent lifetime.
	// If startBackends is ever invoked again for the same agent (e.g., a
	// future reload path), a second listener would be started, leading to
	// duplicate consumption and panics on channel close. This mirrors the
	// write-once invariant on a.backends.
	go a.waitForRestartRequests()
	dispatcherCtx, dispatcherCancel := context.WithCancel(agentCtx)
	a.dispatcherCancel = dispatcherCancel
	go a.restartDispatcher(dispatcherCtx)

	return nil
}

// subscribeFilesmgr wires FilesManager upgrade events to the backend
// restart channel. When a file's logical name matches the ManagedBinaryName
// of a registered backend, the backend (identified by its backend name, NOT
// the file name) is enqueued for restart. This decouples backend identity
// from binary identity. The unsubscribe function stored in
// a.filesmgrUnsubscribe must be called on Stop().
//
// Must be called after startBackends has populated a.backends; the subscriber
// callback reads a.backends from the FileEvent goroutine.
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
		for name, be := range a.backends {
			mb, ok := be.(backend.ManagedBinary)
			if !ok {
				continue
			}
			if mb.ManagedBinaryName() == ev.Entry.Name {
				a.pendingRestartsMu.Lock()
				if a.pendingRestarts == nil {
					a.pendingRestarts = make(map[string]struct{})
				}
				a.pendingRestarts[name] = struct{}{}
				a.pendingRestartsMu.Unlock()
				a.logger.Info("filesmgr: queued restart", "backend", name, "file", ev.Entry.Name, "version", ev.Entry.Version)
			}
		}
	})
}

// backendRestartLock returns a per-backend mutex that serializes concurrent
// Stop+Start sequences. Both restartBackendWithFilesmgrRollback (file-driven)
// and RestartBackend (health/fleet-driven) acquire this mutex before touching
// a backend, ensuring only one restart sequence runs at a time per backend.
// Entries are never deleted — same race rationale as filesmgr.perNameMu.
func (a *orbAgent) backendRestartLock(name string) *sync.Mutex {
	v, _ := a.backendRestartMu.LoadOrStore(name, &sync.Mutex{})
	mu, _ := v.(*sync.Mutex) // LoadOrStore stored a *sync.Mutex; assertion cannot fail.
	return mu
}

// restartBackendWithFilesmgrRollback performs a Stop + Start sequence for a
// backend after a FilesManager event upgraded its managed binary. If Start
// fails, asks FilesManager to roll back the binary to its previous version,
// then retries Start once. On second failure, gives up and logs the error —
// no infinite loop.
func (a *orbAgent) restartBackendWithFilesmgrRollback(ctx context.Context, backendName string) {
	// Serialize concurrent Stop+Start sequences for the same backend across
	// both restart paths (file-driven and health/fleet-driven).
	restartMu := a.backendRestartLock(backendName)
	restartMu.Lock()
	defer restartMu.Unlock()

	be, ok := a.backends[backendName]
	if !ok {
		a.logger.Warn("filesmgr: backend not registered for restart", "backend", backendName)
		return
	}
	binaryName := ""
	if mb, ok := be.(backend.ManagedBinary); ok {
		binaryName = mb.ManagedBinaryName()
	}

	if err := be.Stop(ctx); err != nil {
		a.logger.Warn("filesmgr: backend Stop returned error", "backend", backendName, "error", err)
	}

	// Cancel any prior per-backend context from a previous restart cycle to
	// avoid leaking contexts across multiple upgrade events for the same backend.
	a.restartCancelsMu.Lock()
	if a.restartCancels == nil {
		a.restartCancels = make(map[string]context.CancelFunc)
	}
	if prior, ok := a.restartCancels[backendName]; ok {
		prior()
	}
	a.restartCancelsMu.Unlock()

	// Derive a fresh per-backend context from the same ctx parameter so that
	// if the backend calls its own cancel (self-termination pattern), it does NOT
	// tear down the whole agent. Both the initial attempt and the rollback retry
	// use ctx as the parent for consistency.
	runCtx, runCancel := context.WithCancel(ctx)
	a.restartCancelsMu.Lock()
	a.restartCancels[backendName] = runCancel
	a.restartCancelsMu.Unlock()

	startErr := be.Start(runCtx, runCancel)
	if startErr == nil {
		a.logger.Info("filesmgr: backend restarted with upgraded binary", "backend", backendName, "binary", binaryName)
		return
	}
	a.logger.Warn("filesmgr: backend Start failed after upgrade, rolling back", "backend", backendName, "error", startErr)

	if binaryName == "" {
		a.logger.Error("filesmgr: cannot roll back, backend declares no managed binary", "backend", backendName)
		return
	}
	if err := a.filesManager.Rollback(ctx, binaryName); err != nil {
		a.logger.Error("filesmgr: rollback failed", "backend", backendName, "binary", binaryName, "error", err)
		return
	}

	// Retry Start with the rolled-back binary — fresh context derived from ctx again.
	// Cancel the prior runCancel before storing runCancel2 to avoid leaking the
	// context created for the first (failed) Start attempt.
	runCtx2, runCancel2 := context.WithCancel(ctx)
	a.restartCancelsMu.Lock()
	if prior, ok := a.restartCancels[backendName]; ok {
		prior()
	}
	a.restartCancels[backendName] = runCancel2
	a.restartCancelsMu.Unlock()

	if err := be.Start(runCtx2, runCancel2); err != nil {
		a.logger.Error("filesmgr: backend Start failed even after rollback", "backend", backendName, "error", err)
		return
	}
	a.logger.Info("filesmgr: backend restarted with rolled-back binary", "backend", backendName, "binary", binaryName)
}

// restartDispatcher runs as a background goroutine and drains pendingRestarts
// every 500 ms, spawning a dedicated goroutine per backend that handles
// upgrade-driven restart with automatic rollback on Start failure.
// Coalescing semantics: multiple upgrade events for the same backend within
// a 500 ms window result in exactly one restart.
func (a *orbAgent) restartDispatcher(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pendingRestartsMu.Lock()
			pending := a.pendingRestarts
			a.pendingRestarts = nil
			a.pendingRestartsMu.Unlock()
			for name := range pending {
				select {
				case <-ctx.Done():
					return
				default:
				}
				a.logger.Info("filesmgr: dispatched restart", "backend", name)
				// Run synchronously so concurrent Stop+Start sequences for the
				// same backend cannot overlap across ticks. The dispatcher
				// is on its own goroutine; the rest of the agent is unaffected.
				a.restartBackendWithFilesmgrRollback(ctx, name)
			}
		}
	}
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
		return err
	}

	// Subscribe after startBackends has populated a.backends so the subscriber
	// callback reads a fully-initialized map. Must be called after startBackends
	// returns; reads a.backends from the FileEvent goroutine.
	a.subscribeFilesmgr()

	if err = a.configManager.Start(agentCtx, a.config, a.backends); err != nil {
		return err
	}

	return nil
}

func (a *orbAgent) Stop(ctx context.Context) {
	a.logger.Info("routine call for stop agent", "routine", ctx.Value(routineKey))
	// Cancel the restart dispatcher first so it cannot fire a restart after we
	// begin stopping backends. The dispatcher's select loop respects cancellation
	// and will exit on the next tick.
	if a.dispatcherCancel != nil {
		a.dispatcherCancel()
	}
	// Explicitly cancel all in-flight file-driven restart contexts. While ctx
	// propagation from a.ctx → dispatcherCtx → runCtx would also cancel these,
	// making teardown explicit ensures correctness even if the context chain is
	// ever refactored.
	a.restartCancelsMu.Lock()
	for name, cancel := range a.restartCancels {
		cancel()
		a.logger.Debug("filesmgr restart context canceled", "backend", name)
	}
	clear(a.restartCancels)
	a.restartCancelsMu.Unlock()
	for name, b := range a.backends {
		// Acquire the per-backend restart lock before calling Stop so that any
		// in-flight file-driven restart (restartBackendWithFilesmgrRollback) that
		// has already passed its ctx-done check is allowed to finish before we
		// attempt to stop the backend. Without this, Stop could race with a
		// concurrent Start from the dispatcher goroutine.
		mu := a.backendRestartLock(name)
		mu.Lock()
		if state, _, _ := b.GetRunningStatus(); state == backend.Running {
			a.logger.Debug("stopping backend", "backend", name)
			if err := b.Stop(ctx); err != nil {
				a.logger.Error("error while stopping the backend", "backend", name)
			}
		}
		mu.Unlock()
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

func (a *orbAgent) RestartBackend(ctx context.Context, name string, reason string) error {
	if !backend.HaveBackend(name) {
		return errors.New("specified backend does not exist: " + name)
	}

	// Serialize concurrent Stop+Start sequences for the same backend across
	// both restart paths (file-driven and health/fleet-driven).
	restartMu := a.backendRestartLock(name)
	restartMu.Lock()
	defer restartMu.Unlock()

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
	if err := be.Configure(a.logger, a.policyManager.GetRepo(), beConfig, a.backendsCommon, a.filesManager); err != nil {
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
