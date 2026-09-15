// Package supervisor owns the lifecycle of the backends an agent declares:
// it configures and starts them, restarts them on request, replays their
// policies after a restart, and stops them at shutdown. The agent delegates
// to it and the policy manager reaches it only through the interfaces
// declared here, so neither package imports the other.
//
// Lock order: an entry's restart mutex is taken before the policy manager's
// apply mutex (through the applier), never after; an entry's field mutex is
// innermost, guards the phase and the run cancel only, and the only call
// made under it is the run cancel function, which never calls back; the
// state manager's mutex is never held across a call out. The entries map
// is guarded by entriesMu: written once by ConfigureAll after every entry
// is declared, and snapshotted by every reader before it calls out.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// ErrStopped is the sentinel a start reports when the supervisor was, or
// became, stopped instead of the backend's own error; always wrapped with
// the entry's name, so a caller tells a stop-induced abort from a real
// start failure with errors.Is instead of string matching.
// ErrStopped is returned, wrapped, when a stop won against the operation:
// ConfigureAll returns it when StopAll began before every backend came up,
// Restart and RestartUpgraded when the entry was stopped first. The caller
// treats it as a stop in progress, not as a failure: StopAll stops whatever
// process came up and the stop path completes the shutdown.
var ErrStopped = errors.New("backend is stopped")

// PolicyApplier is what the supervisor needs from the policy manager: mark a
// backend's policies for a restart, hand them back after it, and the repo
// each backend is configured with.
type PolicyApplier interface {
	RemoveBackendPolicies(name string, be backend.Backend, permanently bool) error
	ApplyBackendPolicies(ctx context.Context, name string, be backend.Backend) error
	GetRepo() policies.PolicyRepo
}

// Options tunes the supervisor. New fills every zero field with the
// production value, except NotRunning, which is required.
type Options struct {
	// NotRunning is the error the applier returns when the backend cannot
	// take a replay yet; the replay retries it and nothing else. Required:
	// New panics if it is nil, since a replay could otherwise never tell a
	// transient not-running answer from a permanent failure and would give
	// up without ever rescheduling.
	NotRunning error
	// ReapplyAttempts bounds the replay attempts one restart makes while the
	// backend keeps answering NotRunning; ReapplyRetryDelay separates them.
	ReapplyAttempts   int
	ReapplyRetryDelay time.Duration
	// ReplayRetryInterval separates the attempts a rescheduled replay makes
	// after a restart's own replay gave up.
	ReplayRetryInterval time.Duration
	// DispatchInterval is how often queued binary-upgrade restarts are drained.
	DispatchInterval time.Duration
}

func (o Options) withDefaults() Options {
	if o.ReapplyAttempts == 0 {
		o.ReapplyAttempts = 3
	}
	if o.ReapplyRetryDelay == 0 {
		o.ReapplyRetryDelay = 10 * time.Second
	}
	if o.ReplayRetryInterval == 0 {
		o.ReplayRetryInterval = time.Minute
	}
	if o.DispatchInterval == 0 {
		o.DispatchInterval = 500 * time.Millisecond
	}
	return o
}

// Phase is where a declared backend is in its lifecycle.
type Phase int

const (
	// Declared means configured, never started.
	Declared Phase = iota
	// Starting means a start or a restart is in flight.
	Starting
	// Running means the last start succeeded.
	Running
	// Failed means the last start failed; a restart retries it now (a timer
	// that retries on its own comes with on-demand start).
	Failed
	// Stopped means StopAll ran; nothing starts afterwards.
	Stopped
)

// String names the phase for logs and tests.
func (p Phase) String() string {
	return [...]string{"declared", "starting", "running", "failed", "stopped"}[p]
}

// entry is one declared backend.
type entry struct {
	name   string
	be     backend.Backend
	config map[string]any // the entry's own settings as declared; nil when it had none

	// mu guards phase and runCancel; the only call made under it is
	// runCancel, which never calls back.
	mu        sync.Mutex
	phase     Phase
	runCancel context.CancelFunc

	// restartMu is held across the initial configure and start and across a
	// whole restart, including its replay and the replay's retries, so no
	// two of those interleave for one backend and no stop runs mid-flight.
	restartMu sync.Mutex

	// replayScheduled tracks whether a scheduleReplay goroutine is currently
	// waiting or attempting a replay for this entry, so a second give-up
	// while one is already scheduled is a no-op (restart.go).
	replayScheduled atomic.Bool
}

// beginStart cancels the entry's previous run context, if any, stores the
// new cancel and stamps Starting, in one critical section, so a StopAll
// landing in between cannot miss the cancel (it cancels every entry that
// is not running) and cannot be overwritten. It reports the phase it
// found; a caller refuses to start a stopped entry.
func (e *entry) beginStart(cancel context.CancelFunc) Phase {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase == Stopped {
		return Stopped
	}
	if e.runCancel != nil {
		e.runCancel()
	}
	e.runCancel = cancel
	prior := e.phase
	e.phase = Starting
	return prior
}

// beginReset installs a new run cancel and stamps Starting in one critical
// section, without calling the previous cancel, which it hands back for
// the caller to release once the process running under it has been
// stopped; it refuses, reporting stopped, once the entry is Stopped, so a
// StopAll that already ran its first loop cannot miss the new context.
// restartHealth uses it right before FullReset, which stops the previous
// process and starts the replacement in one call; the phase must not be
// Starting before this point, since StopAll's first loop cancels the run
// context of every entry that is not Running, and until here that context
// is the live process's.
func (e *entry) beginReset(cancel context.CancelFunc) (prev context.CancelFunc, stopped bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase == Stopped {
		return nil, true
	}
	prev = e.runCancel
	e.runCancel = cancel
	e.phase = Starting
	return prev, false
}

// restoreRun puts the previous run cancel back, for a reset that failed and
// may have left the previous process up. Only the holder of the entry's
// restart mutex replaces the run cancel (StopAll only calls it), so there is
// nothing else to have installed meanwhile; the caller releases the cancel
// it swapped in itself. A StopAll that stopped the entry meanwhile cancels
// whatever is installed in its second loop, so the restored one too.
func (e *entry) restoreRun(prev context.CancelFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runCancel = prev
}

// setPhase stores the phase unless the entry was stopped meanwhile, and
// reports whether it was.
func (e *entry) setPhase(p Phase) (stopped bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.phase == Stopped {
		return true
	}
	e.phase = p
	return false
}

// Supervisor owns the entries and the goroutines that drive them.
type Supervisor struct {
	logger  *slog.Logger
	state   backend.StateManager
	files   filesmgr.Manager
	applier PolicyApplier
	opts    Options

	// entries is published once by ConfigureAll under the write lock and
	// snapshotted under the read lock by every reader; commons and runCtxFor
	// are set alongside it.
	entriesMu  sync.RWMutex
	entries    map[string]*entry
	configured bool
	commons    config.BackendCommons
	runCtxFor  func(name string) context.Context

	// onServe and onDispatch, when set, run at the top of the request loop
	// and the upgrade dispatcher; tests count goroutine starts through them.
	onServe    func()
	onDispatch func()

	// restartRequests carries health-driven restart requests from the state
	// manager; serveRestartRequests drains it until stop begins.
	restartRequests <-chan string

	// dispatcherCtx and dispatcherCancel drive the upgrade dispatcher.
	// Both are built once in New, from stopCtx, and never written again,
	// so ConfigureAll and StopAll only ever read them: no lock needed and
	// no race between the goroutine that launches the dispatcher and the
	// one that stops it.
	dispatcherCtx    context.Context
	dispatcherCancel context.CancelFunc

	// stopCtx is cancelled as the first statement of StopAll; the request
	// loop, replays and waits observe it.
	stopCtx    context.Context
	stopCancel context.CancelFunc

	// pending holds backend names queued by QueueUpgrade; dispatchUpgrades
	// drains it every DispatchInterval, coalescing repeated upgrade events
	// for the same backend into a single restart.
	pending   map[string]struct{}
	pendingMu sync.Mutex

	// replayers tracks every goroutine scheduleReplay starts, so StopAll can
	// wait for all of them to exit before returning; replayAdmitMu orders
	// replay admission against that wait: scheduleReplay checks stopCtx and
	// adds to replayers under it, and waitReplays takes it once after
	// stopCtx is cancelled, so no replayer is added after the wait began.
	replayers     sync.WaitGroup
	replayAdmitMu sync.Mutex

	// replayStarts counts how many scheduleReplay calls actually started a
	// goroutine, for tests to assert a second call for an entry that already
	// has one scheduled is a no-op.
	replayStarts atomic.Int32
}

// New builds a supervisor over the state manager, the files manager (nil
// when the agent has none), the policy applier and the channel the state
// manager sends restart requests on. It panics if opts.NotRunning is nil.
func New(logger *slog.Logger, state backend.StateManager, files filesmgr.Manager, applier PolicyApplier, restartRequests <-chan string, opts Options) *Supervisor {
	if opts.NotRunning == nil {
		panic("supervisor: Options.NotRunning is required and must not be nil")
	}
	stopCtx, stopCancel := context.WithCancel(context.Background())
	dispatcherCtx, dispatcherCancel := context.WithCancel(stopCtx)
	return &Supervisor{
		logger:           logger,
		state:            state,
		files:            files,
		applier:          applier,
		opts:             opts.withDefaults(),
		entries:          map[string]*entry{},
		restartRequests:  restartRequests,
		dispatcherCtx:    dispatcherCtx,
		dispatcherCancel: dispatcherCancel,
		stopCtx:          stopCtx,
		stopCancel:       stopCancel,
	}
}

// ConfigureAll declares every backend in cfgBackends (the agent's backends
// map without its "common" entry; an empty map is accepted and starts
// nothing), then configures and starts each in map order, registering its
// monitor: the first failure is returned and later entries are not started.
// On success it starts the restart request loop and the upgrade dispatcher,
// once. runCtxFor returns the context a backend's process runs under.
func (s *Supervisor) ConfigureAll(cfgBackends map[string]any, commons config.BackendCommons, runCtxFor func(name string) context.Context) error {
	declared := make(map[string]*entry, len(cfgBackends))
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
		declared[name] = &entry{name: name, be: backend.GetBackend(name), config: cEntity, phase: Declared}
	}
	s.entriesMu.Lock()
	if s.configured {
		s.entriesMu.Unlock()
		return errors.New("backends already configured")
	}
	if s.stopCtx.Err() != nil {
		s.entriesMu.Unlock()
		// A stop that precedes the configure is the stop, not a configuration
		// failure: the agent treats ErrStopped as a shutdown in progress.
		return fmt.Errorf("supervisor is stopped: %w", ErrStopped)
	}
	s.configured = true
	s.entries = declared
	s.commons = commons
	s.runCtxFor = runCtxFor
	s.entriesMu.Unlock()
	for _, e := range s.snapshot() {
		if err := s.configureAndStart(e); err != nil {
			return err
		}
	}
	go s.serveRestartRequests()
	go s.dispatchUpgrades(s.dispatcherCtx)
	return nil
}

// snapshot returns the entries under the read lock, so callers never hold
// it while calling out.
func (s *Supervisor) snapshot() []*entry {
	s.entriesMu.RLock()
	defer s.entriesMu.RUnlock()
	out := make([]*entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	return out
}

func (s *Supervisor) entryFor(name string) (*entry, bool) {
	s.entriesMu.RLock()
	defer s.entriesMu.RUnlock()
	e, ok := s.entries[name]
	return e, ok
}

func (s *Supervisor) backendCommons() config.BackendCommons {
	s.entriesMu.RLock()
	defer s.entriesMu.RUnlock()
	return s.commons
}

// runContext calls the agent's context factory outside the entries lock:
// the factory is a call out (the config manager's GetContext).
func (s *Supervisor) runContext(name string) context.Context {
	s.entriesMu.RLock()
	f := s.runCtxFor
	s.entriesMu.RUnlock()
	if f == nil {
		return context.Background()
	}
	return f(name)
}

// configureAndStart configures one backend and starts it under a fresh run
// context, holding the entry's restart mutex across both so StopAll's
// second loop cannot read or stop the backend mid-configure, and records
// the outcome: Running and the monitor on success; Failed and the state
// manager's error on failure (with the message only when the backend
// reports BackendError as its initial state). A stop that began meanwhile
// wins: the phase stays Stopped, this returns ErrStopped, and StopAll's
// second loop stops the process that came up once it gets the mutex.
func (s *Supervisor) configureAndStart(e *entry) error {
	e.restartMu.Lock()
	defer e.restartMu.Unlock()
	if err := e.be.Configure(s.logger, s.applier.GetRepo(), e.config, s.backendCommons(), s.files); err != nil {
		s.logger.Info("failed to configure backend", "backend", e.name, "error", err)
		return err
	}
	runCtx, cancel := context.WithCancel(s.runContext(e.name))
	if e.beginStart(cancel) == Stopped {
		cancel()
		return fmt.Errorf("%w: %s", ErrStopped, e.name)
	}
	if err := e.be.Start(runCtx, cancel); err != nil {
		// A stop that began meanwhile cancelled this start: that is the
		// stop, not a start failure, so nothing is registered and the
		// caller learns which through ErrStopped, with the backend's own
		// error kept in the chain.
		if e.setPhase(Failed) {
			return fmt.Errorf("%w: %s: %w", ErrStopped, e.name, err)
		}
		var errMessage string
		if e.be.GetInitialState() == backend.BackendError {
			errMessage = err.Error()
		}
		s.state.RegisterError(e.name, errMessage)
		return err
	}
	if err := s.stoppedDuringStart(e); err != nil {
		return err
	}
	s.state.StartBackendMonitor(e.name, e.be)
	return nil
}

// stoppedDuringStart reports whether a stop won the race with a Start that
// just reported success: it returns ErrStopped and leaves the entry's phase
// at Stopped. The process that came up is stopped by StopAll's own second
// loop, which is waiting for this caller's restart mutex and runs the gated
// stop once the caller returns; nothing else sets Stopped, so no other
// stop is needed here. It returns nil when no stop won the race, leaving the
// phase at Running. configureAndStart and restartUpgraded both call it after
// their own Start succeeds; what each does next differs (starting the health
// monitor versus re-applying policies), so only this shared race check is
// factored out.
func (s *Supervisor) stoppedDuringStart(e *entry) error {
	if !e.setPhase(Running) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrStopped, e.name)
}

// Declared returns the backends this supervisor declared, by name (every
// entry, started or not); the map is the one the config managers and the
// fleet connection receive.
func (s *Supervisor) Declared() map[string]backend.Backend {
	s.entriesMu.RLock()
	defer s.entriesMu.RUnlock()
	out := make(map[string]backend.Backend, len(s.entries))
	for name, e := range s.entries {
		out[name] = e.be
	}
	return out
}

// Phase reports an entry's phase and whether the name is declared.
func (s *Supervisor) Phase(name string) (Phase, bool) {
	e, ok := s.entryFor(name)
	if !ok {
		return Declared, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.phase, true
}

// gatedStop is the one place a backend is stopped: only when a process
// exists. Running means it is up and answering; BackendError means a process
// handle exists but it is not answering its API (or its state could not be
// read), and it must be stopped too, or it outlives the agent and an upgrade
// restart starts a second process beside it. Unknown (never started) and
// Offline (the process ended) mean there is nothing to stop, and most
// backends panic on a Stop then. Callers hold the entry's restart mutex.
func (s *Supervisor) gatedStop(ctx context.Context, e *entry) {
	if state, _, _ := e.be.GetRunningStatus(); state != backend.Running && state != backend.BackendError {
		return
	}
	s.logger.Debug("stopping backend", "backend", e.name)
	if err := e.be.Stop(ctx); err != nil {
		s.logger.Error("error while stopping the backend", "backend", e.name, "error", err)
	}
}

// StopAll stops everything, in this order: the stop context (the request
// loop, replays and waits observe it), the upgrade dispatcher, then every
// entry is moved to Stopped and one not running has its run context
// cancelled at once so a blocked Start returns; then each entry that
// reports Running is stopped through the gated stop under its restart
// mutex and its run context is cancelled after the stop, for both the
// health-driven start and the binary-upgrade restart; finally every
// rescheduled replay goroutine is waited for (restart.go).
func (s *Supervisor) StopAll(ctx context.Context) {
	s.stopCancel()
	s.dispatcherCancel()
	entries := s.snapshot()
	for _, e := range entries {
		e.mu.Lock()
		// An entry that is not running has no process to stop gracefully:
		// cancel its context now so a start blocked in Start returns and
		// releases the restart mutex the next loop needs.
		if e.phase != Running && e.runCancel != nil {
			e.runCancel()
		}
		e.phase = Stopped
		e.mu.Unlock()
	}
	for _, e := range entries {
		e.restartMu.Lock()
		s.gatedStop(ctx, e)
		e.mu.Lock()
		if e.runCancel != nil {
			e.runCancel()
		}
		e.mu.Unlock()
		e.restartMu.Unlock()
	}
	s.waitReplays()
}
