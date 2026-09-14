package backend

import (
	"log/slog"
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
	return c.status, "", nil
}

func (c *countingBackend) setStatus(status RunningStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
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
// never fits. Once the backend is seen running again, or fails again after a
// fresh restart, the slot is free for another request.
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

	be.setStatus(Running)
	sendTick(t, tick)
	// Wait for the Running tick's iteration to actually clear the slot
	// before flipping the backend again, so that iteration's own read of
	// status and start time cannot race the mutation below.
	require.Eventually(t, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		_, ok := manager.queued["unhealthy"]
		return !ok
	}, time.Second, time.Millisecond, "seeing the backend running again must release the slot")

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
