package backend

import (
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// countingBackend reports a fixed status and counts how often it is asked.
type countingBackend struct {
	Backend
	status  RunningStatus
	started time.Time
	polls   atomic.Int32
}

func (c *countingBackend) GetInitialState() RunningStatus { return Running }
func (c *countingBackend) GetStartTime() time.Time        { return c.started }
func (c *countingBackend) GetRunningStatus() (RunningStatus, string, error) {
	c.polls.Add(1)
	return c.status, "", nil
}

// newTestManager builds a stateManager whose tick source hands each call its
// own unbuffered channel, recorded in order, so a test can drive ticks by
// hand instead of waiting on a real ticker. Injected through WithTickSource,
// so there is no package variable to restore.
func newTestManager(t *testing.T, restartChan chan string) (*stateManager, *[]chan time.Time) {
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
	manager := NewStateManager("fleet", logger, restartChan, repo, WithTickSource(tick)).(*stateManager)
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
// while a request is still pending must not enqueue it again, since a name
// with no dedup would let a handful of unhealthy backends fill every slot
// and starve one whose request never fits.
func TestMonitorQueuesOneRestartPerBackendUntilItIsTaken(t *testing.T) {
	restartChan := make(chan string, 5)
	manager, channels := newTestManager(t, restartChan)
	be := &countingBackend{status: BackendError, started: time.Now().Add(-2 * MinRestartTime)}
	manager.StartBackendMonitor("unhealthy", be)
	require.Len(t, *channels, 1)
	tick := (*channels)[0]

	sendTick(t, tick)
	sendTick(t, tick)
	sendTick(t, tick)
	require.Len(t, restartChan, 1)

	manager.RegisterRestart("unhealthy", "taken")
	sendTick(t, tick)
	require.Eventually(t, func() bool { return len(restartChan) == 2 }, time.Second, time.Millisecond,
		"RegisterRestart must release the slot so the next tick can queue again")
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
		return !manager.queued["unhealthy"]
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
