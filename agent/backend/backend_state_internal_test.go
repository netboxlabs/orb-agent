package backend

import (
	"errors"
	"log/slog"
	"maps"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// countingBackend reports a fixed status and counts how often it is asked.
// status and started are guarded by mu so a test can flip them between
// ticks without racing the monitor goroutine's reads.
type countingBackend struct {
	Backend
	mu      sync.Mutex
	status  RunningStatus
	detail  string
	err     error
	started time.Time
	polls   atomic.Int32
}

func (c *countingBackend) GetInitialState() RunningStatus { return Running }

func (c *countingBackend) GetStartTime() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

func (c *countingBackend) GetRunningStatus() (RunningStatus, string, error) {
	c.polls.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, c.detail, c.err
}

func (c *countingBackend) setStatus(status RunningStatus) {
	c.set(status, "", nil)
}

// set changes the whole answer GetRunningStatus gives.
func (c *countingBackend) set(status RunningStatus, detail string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.detail, c.err = status, detail, err
}

func (c *countingBackend) setStarted(started time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started = started
}

// mutableClock is a manually advanced clock for tests that need to age a
// queued restart request deterministically instead of sleeping.
type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func newMutableClock(start time.Time) *mutableClock {
	return &mutableClock{now: start}
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestManager builds a stateManager whose tick source hands each call its
// own unbuffered channel, recorded in order, so a test can drive ticks by
// hand instead of waiting on a real ticker. Injected through WithTickSource,
// so there is no package variable to restore. Extra options, such as
// WithClock, are applied after it.
func newTestManager(t *testing.T, restartChan chan string, extraOpts ...StateManagerOption) (*stateManager, *[]chan time.Time) {
	t.Helper()
	channels := make([]chan time.Time, 0)
	tick := func(_ time.Duration) (<-chan time.Time, func()) {
		ch := make(chan time.Time)
		channels = append(channels, ch)
		return ch, func() {}
	}
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	opts := append([]StateManagerOption{WithTickSource(tick)}, extraOpts...)
	manager := NewStateManager("fleet", logger, restartChan, repo, opts...).(*stateManager)
	return manager, &channels
}

// sendTick delivers one tick on ch, failing the test if the monitor is not
// ready to receive it.
func sendTick(t *testing.T, ch chan time.Time) {
	t.Helper()
	select {
	case ch <- time.Now():
	case <-time.After(time.Second):
		t.Fatal("monitor did not receive the tick in time")
	}
}

// A monitor whose restart request cannot be delivered must not hold the
// state lock while it waits: heartbeats read that lock, and a full channel
// would freeze them. The request is dropped and logged instead.
func TestMonitorDoesNotHoldTheLockOnAFullRestartChannel(t *testing.T) {
	restartChan := make(chan string, 1)
	restartChan <- "already-queued"
	manager, channels := newTestManager(t, restartChan)
	be := &countingBackend{status: BackendError, started: time.Now().Add(-2 * MinRestartTime)}
	manager.StartBackendMonitor("unhealthy", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	sendTick(t, tick)
	// The second tick only arrives once the monitor has looped back to wait
	// for it, which requires the first iteration's restart attempt to have
	// returned; a monitor stuck holding the lock on the full channel would
	// never get here.
	sendTick(t, tick)

	done := make(chan struct{})
	go func() { manager.Get(); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Get() blocked behind a monitor waiting on the restart channel")
	}
}

// A backend holds at most one slot in the restart queue: repeated ticks
// while a request is still pending, or still in flight after RegisterRestart
// took it, must not enqueue it again, since a name with no dedup would let a
// handful of unhealthy backends fill every slot and starve one whose request
// never fits. A restart in flight keeps its slot until it finishes, even
// while the backend is seen running (a restart stops the process it
// replaces, and a tick meanwhile would ask for a second one); once it has
// finished, the slot is free for another request.
func TestMonitorQueuesOneRestartPerBackendUntilItIsTaken(t *testing.T) {
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan)
	be := &countingBackend{status: BackendError, started: time.Now().Add(-2 * MinRestartTime)}
	manager.StartBackendMonitor("unhealthy", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	sendTick(t, tick)
	require.Eventually(t, func() bool { return len(restartChan) == 1 }, time.Second, time.Millisecond)

	manager.RegisterRestart("unhealthy", "taken")
	sendTick(t, tick)
	// The next tick only arrives once the previous one's iteration is fully
	// done, which is what proves it really did skip instead of just not
	// having gotten to the send yet.
	sendTick(t, tick)
	require.Len(t, restartChan, 1, "a request already taken and in flight must not be queued again")

	slotHeld := func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		_, ok := manager.queued["unhealthy"]
		return ok
	}
	be.setStatus(Running)
	sendTick(t, tick)
	sendTick(t, tick)
	require.True(t, slotHeld(), "a restart in flight keeps its slot while the backend is seen running")

	manager.RestartFinished("unhealthy")
	require.False(t, slotHeld(), "a finished restart releases its slot")

	be.setStatus(BackendError)
	be.setStarted(time.Now().Add(-2 * MinRestartTime))
	sendTick(t, tick)
	require.Eventually(t, func() bool { return len(restartChan) == 2 }, time.Second, time.Millisecond,
		"a later failure after the slot was released must be able to queue again")
}

// A restart in flight for longer than MinRestartTime never brought the
// backend back, so its slot is released and the next tick may queue another
// one, keeping today's retry cadence for a permanently failing backend.
func TestMonitorReleasesAnInFlightRestartOlderThanMinRestartTime(t *testing.T) {
	clock := newMutableClock(time.Now())
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan, WithClock(clock.Now))
	be := &countingBackend{status: BackendError, started: time.Now().Add(-2 * MinRestartTime)}
	manager.StartBackendMonitor("unhealthy", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	sendTick(t, tick)
	require.Eventually(t, func() bool { return len(restartChan) == 1 }, time.Second, time.Millisecond)

	manager.RegisterRestart("unhealthy", "taken")
	clock.Advance(MinRestartTime)
	sendTick(t, tick)
	require.Eventually(t, func() bool { return len(restartChan) == 2 }, time.Second, time.Millisecond,
		"an in-flight restart older than MinRestartTime must release its slot")
}

// A restart request that did not fit in a full queue must not be considered
// queued: the monitor has to retry it on a later tick instead of dropping it
// for good.
func TestMonitorKeepsARequestThatDidNotFit(t *testing.T) {
	restartChan := make(chan string, 1)
	restartChan <- "other"
	manager, channels := newTestManager(t, restartChan)
	be := &countingBackend{status: BackendError, started: time.Now().Add(-2 * MinRestartTime)}
	manager.StartBackendMonitor("unhealthy", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	sendTick(t, tick)
	require.Eventually(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		_, ok := manager.queued["unhealthy"]
		return !ok
	}, time.Second, time.Millisecond, "a request that did not fit must be released so the next tick retries it")
	require.Len(t, restartChan, 1)
	require.Equal(t, "other", <-restartChan)

	sendTick(t, tick)
	require.Eventually(t, func() bool { return len(restartChan) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, "unhealthy", <-restartChan)
}

// Each monitor gets its own tick source, so adding a backend does not slow
// the polling of the others.
func TestEachMonitorHasItsOwnTickSource(t *testing.T) {
	manager, channels := newTestManager(t, make(chan string, 10))
	first := &countingBackend{status: Running, started: time.Now()}
	second := &countingBackend{status: Running, started: time.Now()}
	manager.StartBackendMonitor("first", first)
	manager.StartBackendMonitor("second", second)

	require.Len(t, *channels, 2, "each monitor must call the tick source for its own channel")
	firstTicks, secondTicks := (*channels)[0], (*channels)[1]

	for i := 0; i < 3; i++ {
		sendTick(t, firstTicks)
	}
	sendTick(t, secondTicks)

	require.Eventually(t, func() bool { return first.polls.Load() == 3 }, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return second.polls.Load() == 1 }, time.Second, time.Millisecond)
}

// A backend that failed and then recovers stops reporting the failure: the
// monitor clears the error when it sees the backend running, so a heartbeat
// carries no stale error for a backend that is up. An on-demand backend
// whose retry succeeds makes this routine, where it used to need a restart
// that registered the monitor again.
func TestMonitorClearsTheErrorWhenABackendRecovers(t *testing.T) {
	manager, channels := newTestManager(t, make(chan string, 5))
	be := &countingBackend{status: BackendError, started: time.Now()}
	manager.StartBackendMonitor("recovering", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]
	manager.RegisterError("recovering", "no binary")

	sendTick(t, tick)
	be.setStatus(Running)
	sendTick(t, tick)
	// The next tick is only accepted once the previous iteration finished.
	sendTick(t, tick)

	state := manager.Get()["recovering"]
	require.NotNil(t, state)
	require.Equal(t, Running, state.Status)
	require.Empty(t, state.LastError, "a backend that is up carries no error")
}

// erroringBackend is a running telemetry backend that reports, for each
// policy it runs, the error of the policy's last collection.
type erroringBackend struct {
	countingBackend
	errMu sync.Mutex
	errs  map[string]PolicyError
}

var _ PolicyErrorProvider = (*erroringBackend)(nil)

func (e *erroringBackend) GetPolicyErrors() (map[string]PolicyError, error) {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	errs := make(map[string]PolicyError, len(e.errs))
	maps.Copy(errs, e.errs)
	return errs, nil
}

func (e *erroringBackend) report(errs map[string]PolicyError) {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	e.errs = errs
}

// The monitor stores, on each tick, the error a telemetry backend reports
// for each policy's last collection as the policy's collection error, and
// clears it once the backend reports the policy collecting again. A name no
// policy has is skipped.
func TestMonitorStoresTheCollectionErrorOfEachPolicy(t *testing.T) {
	manager, channels := newTestManager(t, make(chan string, 1))
	require.NoError(t, manager.policyRepo.Update(policies.PolicyData{ID: "policy-1", Name: "core", Backend: "snmp_telemetry", State: policies.Running}))
	be := &erroringBackend{countingBackend: countingBackend{status: Running, started: time.Now()}}
	be.report(map[string]PolicyError{
		"core": {Message: "metrics collection failed: 10.0.0.1:161: request timeout", At: time.Now()},
		"gone": {Message: "timeout"},
	})
	manager.StartBackendMonitor("snmp_telemetry", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]
	collectionErr := func() string {
		t.Helper()
		pd, err := manager.policyRepo.Get("policy-1")
		require.NoError(t, err)
		return pd.CollectionErr
	}

	// The second tick arrives once the first one's poll has been stored.
	sendTick(t, tick)
	sendTick(t, tick)
	require.Equal(t, "metrics collection failed: 10.0.0.1:161: request timeout", collectionErr())

	be.report(map[string]PolicyError{"core": {}})
	sendTick(t, tick)
	sendTick(t, tick)
	require.Empty(t, collectionErr(), "cleared once the policy collects again")
}

// steppedBackend tells a test when a tick of its monitor is over: the monitor
// asks for the policies' errors last.
type steppedBackend struct {
	countingBackend
	ticks atomic.Int32
}

func (s *steppedBackend) GetPolicyErrors() (map[string]PolicyError, error) {
	s.ticks.Add(1)
	return nil, nil
}

// step delivers one tick and waits until the monitor is done with it.
func step(t *testing.T, ch chan time.Time, be *steppedBackend) {
	t.Helper()
	done := be.ticks.Load() + 1
	sendTick(t, ch)
	require.Eventually(t, func() bool { return be.ticks.Load() == done }, time.Second, time.Millisecond)
}

// pktvisord killed two minutes after it started: the monitor asks for a
// restart at the first tick that finds the process gone, rather than wait
// until MinRestartTime has passed since that start, and the error it records
// is the process's, not a failure to read the status.
func TestMonitorRestartsABackendWhoseProcessEndedAtOnce(t *testing.T) {
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan)
	be := &steppedBackend{countingBackend: countingBackend{status: Running, started: time.Now().Add(-2 * time.Minute)}}
	manager.StartBackendMonitor("pktvisor", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	be.set(BackendError, "process error: signal: killed", processEndedError{errors.New("signal: killed")})
	step(t, tick, be)

	require.Len(t, restartChan, 1, "the first tick that finds the process gone asks for its restart")
	require.Equal(t, "pktvisor", <-restartChan)
	state := manager.Get()["pktvisor"]
	require.Equal(t, "process error: signal: killed", state.LastError)
	require.True(t, state.Ended)

	manager.RegisterRestart("pktvisor", "test")
	manager.RestartFinished("pktvisor")
	require.False(t, manager.Get()["pktvisor"].Ended, "a restart replaced the process that ended")
}

// A process that runs but does not answer its API may still be starting up
// or busy, so the monitor keeps waiting until MinRestartTime has passed since
// its start before it restarts it, as before.
func TestMonitorWaitsBeforeRestartingAProcessThatDoesNotAnswer(t *testing.T) {
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan)
	be := &steppedBackend{countingBackend: countingBackend{status: Running, started: time.Now().Add(-2 * time.Minute)}}
	manager.StartBackendMonitor("pktvisor", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	be.set(BackendError, "process running, REST API unavailable", errors.New("connection refused"))
	for range 5 {
		step(t, tick, be)
	}
	require.Empty(t, restartChan)
	require.False(t, manager.Get()["pktvisor"].Ended)
}

// A process that ends after it has run MinRestartTime since its start is
// restarted at once, however many restarts came before it: the wait never
// exceeds what the rule before the backoff gave.
func TestMonitorRestartsAProcessThatRanMinRestartTimeAtOnce(t *testing.T) {
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan)
	be := &steppedBackend{countingBackend: countingBackend{status: Running, started: time.Now().Add(-MinRestartTime - time.Second)}}
	manager.StartBackendMonitor("pktvisor", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]
	manager.mu.Lock()
	manager.restarts["pktvisor"] = 7
	manager.mu.Unlock()

	be.set(Offline, "backend process ended", nil)
	step(t, tick, be)

	require.Len(t, restartChan, 1)
}

// A process that ends again right after its restart, before any tick found
// it running (it crashed on a replayed policy, or was killed again), waits
// only what its restarts earned, counted from the end of the restart, not
// until the restart is MinRestartTime old.
func TestMonitorRestartsAProcessThatEndsBeforeATickFindsItRunning(t *testing.T) {
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan)
	be := &steppedBackend{countingBackend: countingBackend{status: Running, started: time.Now().Add(-2 * time.Minute)}}
	manager.StartBackendMonitor("pktvisor", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	be.set(BackendError, "process error: signal: killed", processEndedError{errors.New("signal: killed")})
	step(t, tick, be)
	require.Len(t, restartChan, 1)
	<-restartChan
	manager.RegisterRestart("pktvisor", "test")
	be.setStarted(time.Now())
	manager.RestartFinished("pktvisor")

	step(t, tick, be)
	require.Empty(t, restartChan, "the second restart in a row waits one tick")
	step(t, tick, be)
	require.Len(t, restartChan, 1)
}

// A process that keeps ending soon after each restart is restarted later
// each time: at once, then after one tick, two, four and so on, up to
// MinRestartTime. Once a restarted process has run for MinRestartTime, the
// next end is restarted at once again.
func TestMonitorBacksOffABackendWhoseProcessKeepsEnding(t *testing.T) {
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan)
	be := &steppedBackend{countingBackend: countingBackend{status: Running, started: time.Now()}}
	manager.StartBackendMonitor("pktvisor", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]
	maxTicks := int(MinRestartTime / BackendMonitorInterval)

	// ticksUntilRestart ends the process and counts the ticks until the
	// monitor asks for a restart, the tick that asks included; then it plays
	// the restart through: taken, a new process started at started, finished,
	// and one tick that finds it running.
	ticksUntilRestart := func(started time.Time) int {
		t.Helper()
		be.set(Offline, "backend process ended", nil)
		for n := 1; n <= maxTicks+2; n++ {
			step(t, tick, be)
			if len(restartChan) == 1 {
				<-restartChan
				manager.RegisterRestart("pktvisor", "test")
				be.setStarted(started)
				be.setStatus(Running)
				manager.RestartFinished("pktvisor")
				step(t, tick, be)
				return n
			}
		}
		t.Fatal("the monitor never asked for a restart")
		return 0
	}

	var got []int
	for range 8 {
		got = append(got, ticksUntilRestart(time.Now()))
	}
	require.Equal(t, []int{1, 2, 3, 5, 9, 17, maxTicks + 1, maxTicks + 1}, got)

	ticksUntilRestart(time.Now().Add(-MinRestartTime))
	require.Equal(t, 1, ticksUntilRestart(time.Now()), "a run of MinRestartTime starts the count again")
}
