package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// recorder is the shared event log every stub appends to, so one test can
// assert the order of calls across the supervisor, the backends, the state
// manager, the files manager and the applier. Goroutines the supervisor
// starts append concurrently, hence the mutex and the snapshot accessor.
type recorder struct {
	mu     sync.Mutex
	events []string
	// serveStarts and dispatchStarts count the supervisor's goroutine starts
	// separately from events, so no exact-equality assertion on events can
	// see them (the goroutines start concurrently with the test's next
	// statement); per recorder, so an earlier test's goroutine cannot
	// inflate a later test's count.
	serveStarts    atomic.Int32
	dispatchStarts atomic.Int32
}

func (r *recorder) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

func (r *recorder) count(prefix string) int {
	n := 0
	for _, e := range r.snapshot() {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			n++
		}
	}
	return n
}

// stubBackend is a backend whose lifecycle calls append to the recorder.
// Fields select the failure a test wants; zero values mean success. Its
// status is what the supervisor's gated stop reads: Running while it
// simulates a live process.
type stubBackend struct {
	backend.Backend
	rec          *recorder
	name         string
	status       atomic.Int32 // backend.RunningStatus
	startErrs    []error      // popped per Start; nil when exhausted
	startCalls   atomic.Int32
	startBlocks  chan struct{} // when set, Start waits on it or on its context
	ignoreCancel bool          // when set, Start ignores ctx and only waits on startBlocks
	resetErr     error
	configureErr error
	binary       string
	onStart      func(ctx context.Context, cancel context.CancelFunc)
	onConfigure  func()
	onReset      func(ctx context.Context)
	onResetCtx   func(ctx context.Context) error // when set, FullReset returns its result after recording
	onStop       func()
	mu           sync.Mutex
}

func newStub(rec *recorder, name string) *stubBackend {
	s := &stubBackend{rec: rec, name: name}
	s.status.Store(int32(backend.Unknown))
	return s
}

func (s *stubBackend) Configure(*slog.Logger, policies.PolicyRepo, map[string]any, config.BackendCommons, filesmgr.Manager) error {
	s.rec.add("configure:" + s.name)
	if s.onConfigure != nil {
		s.onConfigure()
	}
	return s.configureErr
}

func (s *stubBackend) Start(ctx context.Context, cancel context.CancelFunc) error {
	s.startCalls.Add(1)
	s.rec.add("start:" + s.name)
	if s.onStart != nil {
		s.onStart(ctx, cancel)
	}
	if s.startBlocks != nil {
		if s.ignoreCancel {
			// A real Start whose underlying call is not interruptible: it
			// only returns when the caller releases startBlocks, even if
			// the run context was already cancelled meanwhile.
			<-s.startBlocks
		} else {
			select {
			case <-s.startBlocks:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	s.mu.Lock()
	var err error
	if len(s.startErrs) > 0 {
		err = s.startErrs[0]
		s.startErrs = s.startErrs[1:]
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.status.Store(int32(backend.Running))
	return nil
}

func (s *stubBackend) Stop(context.Context) error {
	s.rec.add("stop:" + s.name)
	if s.onStop != nil {
		s.onStop()
	}
	s.status.Store(int32(backend.Offline))
	return nil
}

func (s *stubBackend) FullReset(ctx context.Context) error {
	s.rec.add("reset:" + s.name)
	if s.onResetCtx != nil {
		return s.onResetCtx(ctx)
	}
	if s.onReset != nil {
		s.onReset(ctx)
	}
	return s.resetErr
}

func (s *stubBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	return backend.RunningStatus(s.status.Load()), "", nil
}

func (s *stubBackend) GetInitialState() backend.RunningStatus { return backend.BackendError }

func (s *stubBackend) ApplyPolicy(pd policies.PolicyData, _ bool) error {
	s.rec.add("apply-policy:" + s.name + ":" + pd.ID)
	return nil
}

func (s *stubBackend) RemovePolicy(pd policies.PolicyData) error {
	s.rec.add("remove-policy:" + s.name + ":" + pd.ID)
	return nil
}

func (s *stubBackend) ManagedBinaryName() string { return s.binary }

// stubState records the state manager calls the supervisor makes.
type stubState struct {
	backend.StateManager
	rec *recorder
}

func (s *stubState) StartBackendMonitor(name string, _ backend.Backend) {
	s.rec.add("monitor:" + name)
}

func (s *stubState) RegisterError(name string, msg string) {
	s.rec.add("error:" + name + ":" + msg)
}

func (s *stubState) RegisterRestart(name string, reason string) {
	s.rec.add("restart-registered:" + name + ":" + reason)
}

// stubFiles records rollbacks and answers them from rollbackErr.
type stubFiles struct {
	filesmgr.Manager
	rec         *recorder
	rollbackErr error
}

func (f *stubFiles) Rollback(_ context.Context, name string) error {
	f.rec.add("rollback:" + name)
	return f.rollbackErr
}

// stubApplier records the applier calls and answers ApplyBackendPolicies
// from a queue, repeating the last answer when the queue runs dry and
// repeatLast is set, nil otherwise. onApply runs at the start of every
// apply, so a test can observe or block from inside the critical section.
type stubApplier struct {
	rec        *recorder
	repo       policies.PolicyRepo
	mu         sync.Mutex
	answers    []error
	repeatLast bool
	last       error
	onApply    func()
}

func (a *stubApplier) RemoveBackendPolicies(name string, _ backend.Backend, permanently bool) error {
	a.rec.add("remove:" + name + ":permanently=" + boolString(permanently))
	return nil
}

func (a *stubApplier) ApplyBackendPolicies(_ context.Context, name string, _ backend.Backend) error {
	a.rec.add("apply:" + name)
	if a.onApply != nil {
		a.onApply()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.answers) > 0 {
		a.last = a.answers[0]
		a.answers = a.answers[1:]
		return a.last
	}
	if a.repeatLast {
		return a.last
	}
	return nil
}

func (a *stubApplier) GetRepo() policies.PolicyRepo { return a.repo }

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

var errNotRunning = errors.New("backend is not running")

// newTestSupervisor builds a supervisor over the stubs with every delay
// shortened; tests that need a long interval override the option. files is
// a filesmgr.Manager so a test can pass a *stubFiles or, for an end-to-end
// rollback test, a real filesmgr.Manager; nil (the common case) starts the
// supervisor with none, as an agent without a files manager does.
func newTestSupervisor(t *testing.T, rec *recorder, applier *stubApplier, files filesmgr.Manager) *Supervisor {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if applier == nil {
		applier = &stubApplier{rec: rec}
	}
	s := New(logger, &stubState{rec: rec}, files, applier, make(chan string, 1), Options{
		NotRunning:          errNotRunning,
		ReapplyAttempts:     3,
		ReapplyRetryDelay:   time.Millisecond,
		ReplayRetryInterval: time.Hour,
		DispatchInterval:    time.Hour,
	})
	s.onServe = func() { rec.serveStarts.Add(1) }
	s.onDispatch = func() { rec.dispatchStarts.Add(1) }
	return s
}

func background(_ string) context.Context { return context.Background() }

// Options.NotRunning is required: without it, errors.Is(err, nil) is false
// for every non-nil error, so a replay could never tell the applier's
// transient not-running answer from a permanent failure and would never
// reschedule, leaving the restarting marker set forever. New panics rather
// than build a supervisor with that trap.
func TestNewPanicsWhenNotRunningIsNil(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	require.Panics(t, func() {
		New(logger, &stubState{rec: rec}, nil, applier, make(chan string, 1), Options{})
	})
}

// The eager start ordering is unchanged from the agent's startBackends:
// for each declared backend, Configure, Start, then the monitor; the
// restart request loop and the upgrade dispatcher start once, after every
// backend; the declared map holds exactly the started backends and every
// entry is Running.
func TestConfigureAllStartsEveryDeclaredBackendInOrder(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	one := newStub(rec, "one")
	two := newStub(rec, "two")
	backend.Register("sup_one", one)
	backend.Register("sup_two", two)

	err := s.ConfigureAll(map[string]any{"sup_one": map[string]any{"k": "v"}, "sup_two": nil}, config.BackendCommons{}, background)

	require.NoError(t, err)
	require.Eventually(t, func() bool { return rec.serveStarts.Load() == 1 && rec.dispatchStarts.Load() == 1 }, 5*time.Second, time.Millisecond)
	events := rec.snapshot()
	// The two goroutines start after the per-backend loop and record into
	// the counters, not into events, so the first six events are the loop's.
	require.GreaterOrEqual(t, len(events), 6, "the per-backend loop must have recorded six events")
	perBackend := events[:6]
	assert.ElementsMatch(t, []string{"configure:one", "start:one", "monitor:sup_one", "configure:two", "start:two", "monitor:sup_two"}, perBackend)
	for _, name := range []string{"one", "two"} {
		assert.Less(t, indexOf(perBackend, "configure:"+name), indexOf(perBackend, "start:"+name))
		assert.Less(t, indexOf(perBackend, "start:"+name), indexOf(perBackend, "monitor:sup_"+name))
	}
	assert.Equal(t, int32(1), rec.serveStarts.Load(), "the restart request loop starts once, after every backend")
	assert.Equal(t, int32(1), rec.dispatchStarts.Load(), "the upgrade dispatcher starts once, after every backend")
	assert.Equal(t, map[string]backend.Backend{"sup_one": one, "sup_two": two}, s.Declared())
	p, ok := s.Phase("sup_one")
	assert.True(t, ok)
	assert.Equal(t, Running, p)
	s.StopAll(context.Background())
}

func indexOf(events []string, e string) int {
	for i, x := range events {
		if x == e {
			return i
		}
	}
	return -1
}

// A backend that fails to start aborts ConfigureAll with its error, after
// registering the error with the state manager the way startBackends did
// (the message only when the backend reports BackendError as its initial
// state); backends declared after it are not started, and the entry is
// Failed. Both stubs are set to fail, so whichever ConfigureAll reaches
// first (map iteration order is random) is the one that aborts the loop;
// the assertions below key off which one actually started instead of
// fixing an order, so the test is deterministic either way.
func TestConfigureAllAbortsOnTheFirstStartFailure(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	bad := newStub(rec, "bad")
	bad.startErrs = []error{errors.New("boom")}
	other := newStub(rec, "other")
	other.startErrs = []error{errors.New("boom")}
	backend.Register("sup_bad", bad)
	backend.Register("sup_other", other)

	err := s.ConfigureAll(map[string]any{"sup_bad": nil, "sup_other": nil}, config.BackendCommons{}, background)

	require.EqualError(t, err, "boom")
	startedBad := bad.startCalls.Load() == 1
	startedOther := other.startCalls.Load() == 1
	require.True(t, startedBad != startedOther, "exactly one backend is started before the abort")
	if startedBad {
		assert.Equal(t, []string{"configure:bad", "start:bad", "error:sup_bad:boom"}, rec.snapshot())
		p, _ := s.Phase("sup_bad")
		assert.Equal(t, Failed, p)
		p, _ = s.Phase("sup_other")
		assert.Equal(t, Declared, p, "an entry declared after the failure is never started")
	} else {
		assert.Equal(t, []string{"configure:other", "start:other", "error:sup_other:boom"}, rec.snapshot())
		p, _ := s.Phase("sup_other")
		assert.Equal(t, Failed, p)
		p, _ = s.Phase("sup_bad")
		assert.Equal(t, Declared, p, "an entry declared after the failure is never started")
	}
	s.StopAll(context.Background())
}

// A name that is not registered, or an entry whose value is not a map, is
// refused with the same errors startBackends produced, before anything is
// configured; an empty map is accepted (the agent checks emptiness before
// removing its "common" entry, and a map holding only "common" starts).
func TestConfigureAllRefusesUnknownOrMalformedEntries(t *testing.T) {
	rec := &recorder{}
	backend.Register("sup_known", newStub(rec, "known"))

	// A call refused during declaration leaves the supervisor unconfigured
	// (the once-only flag is set after the declaration loop), so one
	// supervisor serves all three calls.
	s := newTestSupervisor(t, rec, nil, nil)
	err := s.ConfigureAll(map[string]any{"sup_missing": nil, "sup_known": nil}, config.BackendCommons{}, background)
	require.EqualError(t, err, "specified backend does not exist: sup_missing")
	err = s.ConfigureAll(map[string]any{"sup_known": "not a map"}, config.BackendCommons{}, background)
	require.EqualError(t, err, "invalid backend configuration format for backend: sup_known")
	assert.Empty(t, rec.snapshot(), "nothing is configured when the declaration is refused")

	require.NoError(t, s.ConfigureAll(map[string]any{}, config.BackendCommons{}, background))
	assert.Empty(t, s.Declared())
	s.StopAll(context.Background())
}

// ConfigureAll runs once per supervisor: a second call is refused, so no
// second request loop or dispatcher can ever be started.
func TestConfigureAllRunsOnce(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	backend.Register("sup_once", newStub(rec, "once"))
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_once": nil}, config.BackendCommons{}, background))

	err := s.ConfigureAll(map[string]any{"sup_once": nil}, config.BackendCommons{}, background)

	require.EqualError(t, err, "backends already configured")
	assert.Equal(t, 1, rec.count("start:"), "the second call started nothing")
	s.StopAll(context.Background())
}

// StopAll stops only backends that report Running, through the one gated
// stop, and moves every entry to Stopped; a backend that never came up is
// not stopped (seven of nine backends panic on a Stop without a process).
func TestStopAllStopsOnlyRunningBackends(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	up := newStub(rec, "up")
	backend.Register("sup_up", up)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_up": nil}, config.BackendCommons{}, background))
	down := newStub(rec, "down")
	down.status.Store(int32(backend.Offline))
	s.entriesMu.Lock()
	s.entries["sup_down"] = &entry{name: "sup_down", be: down, phase: Running}
	s.entriesMu.Unlock()
	rec.reset()

	s.StopAll(context.Background())

	assert.Equal(t, []string{"stop:up"}, rec.snapshot())
	p, _ := s.Phase("sup_up")
	assert.Equal(t, Stopped, p)
	p, _ = s.Phase("sup_down")
	assert.Equal(t, Stopped, p)
}

// A process that is alive but not answering its API reports BackendError,
// not Running; it still has to be stopped, or it outlives the agent (and an
// upgrade restart would start a second process beside it). Only the two
// no-process states, Unknown and Offline, skip the stop.
func TestGatedStopStopsALiveProcessWhoseAPIIsDown(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	sick := newStub(rec, "sick")
	backend.Register("sup_sick", sick)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_sick": nil}, config.BackendCommons{}, background))
	sick.status.Store(int32(backend.BackendError))
	ended := newStub(rec, "ended")
	ended.status.Store(int32(backend.Offline))
	s.entriesMu.Lock()
	s.entries["sup_ended"] = &entry{name: "sup_ended", be: ended, phase: Running}
	s.entriesMu.Unlock()
	rec.reset()

	s.StopAll(context.Background())

	assert.Equal(t, []string{"stop:sick"}, rec.snapshot(), "a live process with its API down is stopped; an ended one is not")
}

// StopAll cancels a start still blocked in Start, which returns with the
// context error; the entry ends Stopped, not Failed, and a backend that
// never reported Running is not stopped.
func TestStopAllCancelsABlockedStart(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	slow := newStub(rec, "slow")
	slow.startBlocks = make(chan struct{})
	backend.Register("sup_slow", slow)
	done := make(chan error, 1)
	go func() {
		done <- s.ConfigureAll(map[string]any{"sup_slow": nil}, config.BackendCommons{}, background)
	}()
	require.Eventually(t, func() bool { return slow.startCalls.Load() == 1 }, 5*time.Second, time.Millisecond)
	p, ok := s.Phase("sup_slow")
	require.True(t, ok)
	assert.Equal(t, Starting, p, "a start still inside Start is Starting")
	_, ok = s.Phase("sup_absent")
	assert.False(t, ok, "an undeclared name is not a phase")

	stopped := make(chan struct{})
	go func() { s.StopAll(context.Background()); close(stopped) }()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll did not return: the blocked start was not cancelled")
	}
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("ConfigureAll did not return after StopAll cancelled the start")
	}
	assert.NotContains(t, rec.snapshot(), "stop:slow")
	p, _ = s.Phase("sup_slow")
	assert.Equal(t, Stopped, p, "a start cancelled by StopAll does not overwrite Stopped")
}

// A running backend's context is cancelled only after it was stopped, as
// the agent did (the eager contexts were children of the agent context,
// cancelled at the end of Stop).
func TestStopAllCancelsARunningBackendsContextAfterStoppingIt(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "ctx")
	var runCtx context.Context
	be.onStart = func(ctx context.Context, _ context.CancelFunc) { runCtx = ctx }
	be.onStop = func() {
		if runCtx.Err() != nil {
			rec.add("context-cancelled-before-stop")
		}
	}
	backend.Register("sup_ctx", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_ctx": nil}, config.BackendCommons{}, background))

	s.StopAll(context.Background())

	assert.NotContains(t, rec.snapshot(), "context-cancelled-before-stop")
	assert.Error(t, runCtx.Err(), "the context is cancelled by the end of StopAll")
}

// StopAll landing just before beginStart must not deadlock: beginStart
// sees Stopped and the start bails, releasing the restart mutex StopAll
// needs. The seam is runCtxFor, which start calls right before beginStart
// while already holding the restart mutex. The swap and the Starting stamp
// are one critical section, so a stop cannot land between them; that fold
// is not reachable from a stub and is guarded by construction.
func TestStopAllJustBeforeBeginStartDoesNotDeadlock(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "seam")
	be.startBlocks = make(chan struct{})
	backend.Register("sup_seam", be)
	stopped := make(chan struct{})
	seam := func(string) context.Context {
		go func() { s.StopAll(context.Background()); close(stopped) }()
		// Wait on the observable state instead of the clock: this seam runs
		// on the ConfigureAll goroutine, so it must not use require/t.Fatal.
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			if p, _ := s.Phase("sup_seam"); p == Stopped {
				break
			}
			time.Sleep(time.Millisecond)
		}
		return context.Background()
	}
	done := make(chan error, 1)
	go func() {
		done <- s.ConfigureAll(map[string]any{"sup_seam": nil}, config.BackendCommons{}, seam)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll deadlocked against a start entering beginStart")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ConfigureAll never returned")
	}
	assert.NotContains(t, rec.snapshot(), "start:seam", "a start that finds the entry stopped never calls Start")
}

// TestConfigureAllAndStopAllRunConcurrentlyWithoutARace is the regression
// for the data race between ConfigureAll and StopAll on the dispatcher
// context: before the fix, ConfigureAll wrote s.dispatcherCancel with no
// lock held while StopAll read it with no lock held, racing whenever a stop
// landed while a start was still in flight. Both fields are now built once
// in New and never written again, so this loop, run under -race, is the
// kill: both goroutines are released off the same starting gate so they
// actually overlap; with the old code that reports a DATA RACE within a
// handful of the 200 iterations, and with the fix it runs clean for all of
// them.
func TestConfigureAllAndStopAllRunConcurrentlyWithoutARace(t *testing.T) {
	for i := 0; i < 200; i++ {
		rec := &recorder{}
		s := newTestSupervisor(t, rec, nil, nil)
		name := fmt.Sprintf("sup_race_%d", i)
		backend.Register(name, newStub(rec, name))

		start := make(chan struct{})
		var wg sync.WaitGroup
		var configureErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			configureErr = s.ConfigureAll(map[string]any{name: nil}, config.BackendCommons{}, background)
		}()
		go func() {
			defer wg.Done()
			<-start
			s.StopAll(context.Background())
		}()
		close(start)
		wg.Wait()

		if configureErr != nil {
			assert.True(t,
				errors.Is(configureErr, ErrStopped),
				"iteration %d: unexpected ConfigureAll error racing StopAll: %v", i, configureErr)
		}
	}
}

// StopAll leaves the supervisor stopped for good: a ConfigureAll called
// afterwards is refused before it configures or starts anything.
func TestConfigureAllRefusesAfterStopAll(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	backend.Register("sup_after_stop", newStub(rec, "after_stop"))
	s.StopAll(context.Background())

	err := s.ConfigureAll(map[string]any{"sup_after_stop": nil}, config.BackendCommons{}, background)

	require.ErrorIs(t, err, ErrStopped, "a stop that precedes the configure is the stop, not a configuration failure")
	require.EqualError(t, err, "supervisor is stopped: backend is stopped")
	assert.Empty(t, rec.snapshot(), "nothing is configured or started once the supervisor is stopped")
	assert.Empty(t, s.Declared())
}

// A start that already returned successfully, but loses the race to claim
// Running because StopAll stamped the entry Stopped first, must not report
// success: ConfigureAll aborts with ErrStopped, the backend that came up is
// gated-stopped once, and it is never handed to the state manager's
// monitor. The stub's Start ignores the run context (as a blocking,
// uninterruptible external call might), and only returns once this test has
// polled Phase into observing Stopped, which happens-before the run
// context's cancellation (both are set under the entry's own lock in
// StopAll's first loop) and so isolates this branch (setPhase losing the
// race) from beginStart's own Stopped guard, covered elsewhere.
func TestStartReportsErrStoppedWhenAStopWinsAfterStartSucceeds(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "raced")
	be.startBlocks = make(chan struct{})
	be.ignoreCancel = true
	stopDone := make(chan struct{})
	be.onStart = func(context.Context, context.CancelFunc) {
		go func() {
			s.StopAll(context.Background())
			close(stopDone)
		}()
	}
	backend.Register("sup_raced", be)

	done := make(chan error, 1)
	go func() {
		done <- s.ConfigureAll(map[string]any{"sup_raced": nil}, config.BackendCommons{}, background)
	}()

	require.Eventually(t, func() bool {
		p, ok := s.Phase("sup_raced")
		return ok && p == Stopped
	}, 5*time.Second, time.Millisecond, "StopAll's first loop must stamp the entry Stopped before the start is released")
	close(be.startBlocks)

	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrStopped)
	case <-time.After(5 * time.Second):
		t.Fatal("ConfigureAll never returned")
	}
	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll never completed")
	}
	assert.Equal(t, []string{"configure:raced", "start:raced", "stop:raced"}, rec.snapshot(),
		"the backend that raced is gated-stopped once and never monitored")
}

// A start that StopAll cancels while it is blocked reports ErrStopped, not
// the backend's own cancellation error, so the agent can tell a stop that
// won against startup apart from a backend that failed to start: the first
// is a shutdown in progress and exits cleanly once StopAll finishes; the
// second is a startup failure. Nothing is registered as a backend error.
func TestStartCancelledByStopAllReportsErrStopped(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "cancelled_start")
	be.startBlocks = make(chan struct{})
	entered := make(chan struct{})
	be.onStart = func(context.Context, context.CancelFunc) { close(entered) }
	backend.Register("sup_cancelled_start", be)

	done := make(chan error, 1)
	go func() {
		done <- s.ConfigureAll(map[string]any{"sup_cancelled_start": nil}, config.BackendCommons{}, background)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Start was never entered")
	}
	s.StopAll(context.Background())

	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrStopped, "a start cancelled by the stop is reported as the stop, not as a start failure")
		require.ErrorIs(t, err, context.Canceled, "the backend's own cancellation error stays in the chain")
	case <-time.After(5 * time.Second):
		t.Fatal("ConfigureAll did not return after StopAll cancelled the start")
	}
	assert.Equal(t, 0, rec.count("error:cancelled_start:"), "a cancelled start is not registered as a backend error")
	p, _ := s.Phase("sup_cancelled_start")
	assert.Equal(t, Stopped, p)
}
