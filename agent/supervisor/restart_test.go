package supervisor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
)

// --- health/fleet restart (restartHealth) ---

// A restart keeps the backend's policies and re-applies them once the
// backend is back: they are marked unknown for the restart, not deleted,
// and applied once, after the reset, while the restart mutex is still held.
func TestRestartReappliesItsOwnPolicies(t *testing.T) {
	// source: TestRestartBackendReappliesItsOwnPolicies (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "discovery")
	backend.Register("sup_restart_reapply", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_restart_reapply": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_restart_reapply", "test"))

	assert.Equal(t, []string{
		"restart-registered:sup_restart_reapply:test",
		"remove:sup_restart_reapply:permanently=false",
		"configure:discovery",
		"reset:discovery",
		"apply:sup_restart_reapply",
	}, rec.snapshot(), "policies kept, removed before the reset, applied once after")
}

// A reset that fails leaves the policies marked for the next restart and
// does not apply them to a backend that is not back.
func TestRestartDoesNotReapplyWhenTheResetFails(t *testing.T) {
	// source: TestRestartBackendDoesNotReapplyWhenTheResetFails (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "reset-fails")
	be.resetErr = errors.New("reset failed")
	backend.Register("sup_reset_fails", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_reset_fails": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_reset_fails", "test"))

	assert.Equal(t, []string{
		"restart-registered:sup_reset_fails:test",
		"remove:sup_reset_fails:permanently=false",
		"configure:reset-fails",
		"reset:reset-fails",
		"error:sup_reset_fails:failed to reset backend: reset failed",
	}, rec.snapshot(), "the removal still runs and nothing past the failed reset does, until the scheduled replay")

	s.stopCancel()
	s.waitReplays()
}

// A reset that fails can leave the process running (a stop that failed), in
// which case the health monitor never asks for another restart and nothing
// else would clear the restart marker: the replay is scheduled, keeps
// trying under the restart mutex, and completes once the backend answers.
func TestRestartSchedulesAReplayWhenTheResetFails(t *testing.T) {
	// source: TestRestartBackendSchedulesAReplayWhenTheResetFails (agent_test.go)
	rec := &recorder{}
	var lockedApplies atomic.Int32
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.ReplayRetryInterval = time.Millisecond
	be := newStub(rec, "reset-fail-replay")
	be.resetErr = errors.New("reset failed")
	backend.Register("sup_replay_scheduled", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_scheduled": nil}, config.BackendCommons{}, background))
	e, ok := s.entryFor("sup_replay_scheduled")
	require.True(t, ok)
	applier.onApply = func() {
		if !e.restartMu.TryLock() {
			lockedApplies.Add(1)
			return
		}
		e.restartMu.Unlock()
	}
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_scheduled", "test"))

	assert.Equal(t, int32(1), s.replayStarts.Load(), "a failed reset schedules a replay")
	require.Eventually(t, func() bool { return lockedApplies.Load() >= 1 }, 5*time.Second, time.Millisecond,
		"the scheduled replay must run under the restart mutex and complete")
	s.waitReplays()
}

// The backend never stopped when Configure fails, so the policies removed
// for the restart are handed back immediately rather than left marked
// unknown for a restart that may not come again soon.
func TestRestartReappliesPoliciesWhenConfigureFails(t *testing.T) {
	// source: TestRestartBackendReappliesPoliciesWhenConfigureFails (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "configure-fails")
	backend.Register("sup_configure_fails", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_configure_fails": nil}, config.BackendCommons{}, background))
	be.configureErr = errors.New("configure failed")
	rec.reset()

	err := s.Restart(context.Background(), "sup_configure_fails", "test")

	require.Error(t, err)
	assert.Equal(t, []string{
		"restart-registered:sup_configure_fails:test",
		"remove:sup_configure_fails:permanently=false",
		"configure:configure-fails",
		"apply:sup_configure_fails",
	}, rec.snapshot(), "the backend never stopped, so the removed policies are reapplied immediately")
}

// Every bundled backend is registered; only the ones this supervisor
// declared are in its entries map. A restart asked for a name never
// declared is refused rather than reached for.
func TestRestartRefusesAnUndeclaredBackend(t *testing.T) {
	// source: TestRestartBackendRefusesABackendTheAgentDidNotStart (agent_test.go)
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	require.NoError(t, s.ConfigureAll(map[string]any{}, config.BackendCommons{}, background))

	var err error
	require.NotPanics(t, func() { err = s.Restart(context.Background(), "sup_never_declared", "test") })

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not started by this agent")
}

// A start that succeeds after the caller's context was already cancelled
// before the call must not hand the policies back: the caller is shutting
// down.
func TestRestartDoesNotReapplyAfterShutdownBegan(t *testing.T) {
	// source: TestRestartBackendDoesNotReapplyAfterShutdownBegan (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "shutdown-began")
	backend.Register("sup_health_shutdown_began", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_health_shutdown_began": nil}, config.BackendCommons{}, background))
	rec.reset()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, s.Restart(ctx, "sup_health_shutdown_began", "test"))

	assert.Equal(t, []string{
		"restart-registered:sup_health_shutdown_began:test",
		"remove:sup_health_shutdown_began:permanently=false",
		"configure:shutdown-began",
		"reset:shutdown-began",
	}, rec.snapshot(), "shutdown already began, so the policies must stay unknown rather than be reapplied")
}

// StopAll cancels the stop context first; a restart that already holds the
// entry's restart mutex when a stop begins still sees a live ctx argument,
// so the stop context, not ctx.Err() alone, catches it.
func TestRestartDoesNotReapplyOnceStopBegan(t *testing.T) {
	// source: TestRestartBackendDoesNotReapplyOnceStopBegan (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "stop-began")
	backend.Register("sup_health_stop_began", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_health_stop_began": nil}, config.BackendCommons{}, background))
	rec.reset()
	s.stopCancel()

	require.NoError(t, s.Restart(context.Background(), "sup_health_stop_began", "test"))

	assert.Equal(t, []string{
		"restart-registered:sup_health_stop_began:test",
		"remove:sup_health_stop_began:permanently=false",
		"configure:stop-began",
		"reset:stop-began",
	}, rec.snapshot(), "stop already began, so the policies must stay unknown rather than be reapplied")
}

// --- replay retry ---

// Right after a reset, a backend's status probe can transiently fail, so
// the applier answers its not-running error even though the backend is on
// its way up. The replay must retry rather than leave the policies unknown
// until some later restart that may not come.
func TestRestartRetriesTheReplayWhileTheBackendIsNotAnsweringYet(t *testing.T) {
	// source: TestRestartBackendRetriesTheReplayWhileTheBackendIsNotAnsweringYet (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{errNotRunning, errNotRunning, nil}}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "retries")
	backend.Register("sup_replay_retries", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_retries": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_retries", "test"))

	assert.Equal(t, []string{
		"restart-registered:sup_replay_retries:test",
		"remove:sup_replay_retries:permanently=false",
		"configure:retries",
		"reset:retries",
		"apply:sup_replay_retries",
		"apply:sup_replay_retries",
		"apply:sup_replay_retries",
	}, rec.snapshot(), "the replay retries while the backend answers not-running, then succeeds on the third attempt")
}

// The replay is retried a bounded number of times: a backend that keeps
// answering not-running must not be retried forever, since nothing else
// would ever install its policies.
func TestRestartGivesUpTheReplayAfterThreeAttempts(t *testing.T) {
	// source: TestRestartBackendGivesUpTheReplayAfterThreeAttempts (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{errNotRunning, errNotRunning, errNotRunning}}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "gives-up")
	backend.Register("sup_replay_gives_up", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_gives_up": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_gives_up", "test"))

	assert.Equal(t, []string{
		"restart-registered:sup_replay_gives_up:test",
		"remove:sup_replay_gives_up:permanently=false",
		"configure:gives-up",
		"reset:gives-up",
		"apply:sup_replay_gives_up",
		"apply:sup_replay_gives_up",
		"apply:sup_replay_gives_up",
	}, rec.snapshot(), "the replay gives up after three attempts and leaves the policies unknown")

	s.stopCancel()
	waitDone := make(chan struct{})
	go func() { s.waitReplays(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("replayers did not finish within 5s of shutdown")
	}
}

// A failure that is not the applier's not-running error is not transient in
// the same way, so the replay must not retry it.
func TestRestartDoesNotRetryAReplayThatFailedForAnotherReason(t *testing.T) {
	// source: TestRestartBackendDoesNotRetryAReplayThatFailedForAnotherReason (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{errors.New("repo failure")}}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "non-transient")
	backend.Register("sup_replay_non_transient", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_non_transient": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_non_transient", "test"))

	assert.Equal(t, []string{
		"restart-registered:sup_replay_non_transient:test",
		"remove:sup_replay_non_transient:permanently=false",
		"configure:non-transient",
		"reset:non-transient",
		"apply:sup_replay_non_transient",
	}, rec.snapshot(), "a non-transient failure must not be retried")
}

// A retry waits on the apply context, not a plain sleep, so a shutdown that
// begins mid-wait ends the wait immediately instead of the replay sleeping
// out a long retry delay.
func TestRestartStopsRetryingWhenStopBegins(t *testing.T) {
	// source: TestRestartBackendStopsRetryingWhenStopBegins (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{errNotRunning, errNotRunning, errNotRunning}}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.ReapplyRetryDelay = time.Hour
	be := newStub(rec, "stops-retrying")
	backend.Register("sup_replay_stops_retrying", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_stops_retrying": nil}, config.BackendCommons{}, background))
	applier.onApply = func() { s.stopCancel() }
	rec.reset()

	done := make(chan error, 1)
	go func() { done <- s.Restart(context.Background(), "sup_replay_stops_retrying", "test") }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Restart did not return promptly once stop began")
	}

	assert.Equal(t, []string{
		"restart-registered:sup_replay_stops_retrying:test",
		"remove:sup_replay_stops_retrying:permanently=false",
		"configure:stops-retrying",
		"reset:stops-retrying",
		"apply:sup_replay_stops_retrying",
	}, rec.snapshot(), "the retry wait is cancelled the instant stop begins, not slept out")
}

// A replay that gives up because the backend is still not answering must
// not leave the restart marker set forever: nothing else asks for another
// restart once the health monitor sees the backend running. The give-up is
// rescheduled and keeps trying, at ReplayRetryInterval, until it completes.
func TestRestartReschedulesAReplayThatGaveUp(t *testing.T) {
	// source: TestRestartBackendReschedulesAReplayThatGaveUp (agent_test.go)
	rec := &recorder{}
	var lockedApplies atomic.Int32
	applier := &stubApplier{rec: rec, answers: []error{errNotRunning, errNotRunning, errNotRunning}}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.ReplayRetryInterval = time.Millisecond
	be := newStub(rec, "reschedule")
	backend.Register("sup_replay_reschedules", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_reschedules": nil}, config.BackendCommons{}, background))
	e, ok := s.entryFor("sup_replay_reschedules")
	require.True(t, ok)
	applier.onApply = func() {
		if !e.restartMu.TryLock() {
			lockedApplies.Add(1)
			return
		}
		e.restartMu.Unlock()
	}
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_reschedules", "test"))

	require.Eventually(t, func() bool { return lockedApplies.Load() >= 4 }, 5*time.Second, time.Millisecond,
		"the scheduled replay must make a fourth attempt, holding the restart mutex, and complete")
	s.waitReplays()
}

// Once stop began, no replay is admitted: a late restart from the health
// monitor must not add a goroutine while waitReplays waits for them.
func TestScheduleReplayIsRefusedOnceStopBegan(t *testing.T) {
	// source: TestScheduleReplayIsRefusedOnceStopBegan (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.ReplayRetryInterval = time.Millisecond
	be := newStub(rec, "refused")
	be.resetErr = errors.New("reset failed")
	backend.Register("sup_replay_refused", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_refused": nil}, config.BackendCommons{}, background))
	rec.reset()
	s.stopCancel()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_refused", "late restart"))

	assert.Equal(t, int32(0), s.replayStarts.Load(), "no replay may be scheduled after stop began")
	s.waitReplays()
}

// The scheduled replay clears its per-entry flag while it still holds the
// restart mutex, so a restart that takes the mutex right after it and gives
// up is not told a replay is already scheduled by a goroutine about to
// exit.
func TestScheduledReplayClearsItsFlagBeforeReleasingTheRestartMutex(t *testing.T) {
	// source: TestScheduledReplayClearsItsFlagBeforeReleasingTheRestartMutex (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{errNotRunning, errNotRunning, errNotRunning}}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.ReplayRetryInterval = time.Millisecond
	be := newStub(rec, "clears-flag")
	backend.Register("sup_replay_clears_flag", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_clears_flag": nil}, config.BackendCommons{}, background))
	e, ok := s.entryFor("sup_replay_clears_flag")
	require.True(t, ok)
	rec.reset()

	var applies atomic.Int32
	observed := make(chan bool, 1)
	applier.onApply = func() {
		if applies.Add(1) != 4 {
			return
		}
		// The fourth apply is the scheduled replay's, made under the restart
		// mutex. Race for the mutex from here; whoever gets it after the
		// scheduled replay releases it must see the flag already cleared.
		go func() {
			for !e.restartMu.TryLock() {
				runtime.Gosched()
			}
			observed <- e.replayScheduled.Load()
			e.restartMu.Unlock()
		}()
	}

	require.NoError(t, s.Restart(context.Background(), "sup_replay_clears_flag", "test"))

	select {
	case stillScheduled := <-observed:
		assert.False(t, stillScheduled, "the flag must be cleared before the restart mutex is released")
	case <-time.After(5 * time.Second):
		t.Fatal("the scheduled replay never made its fourth attempt")
	}
	s.waitReplays()
}

// The wait between scheduled replay attempts is cancelled the instant stop
// begins, not slept out, even when the interval is long: the loop selects
// on the stop context rather than sleeping.
func TestScheduledReplayStopsOnShutdown(t *testing.T) {
	// source: TestScheduledReplayStopsOnShutdown (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{errNotRunning, errNotRunning, errNotRunning}, repeatLast: true}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "stops-on-shutdown")
	backend.Register("sup_replay_stops_on_shutdown", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_stops_on_shutdown": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_stops_on_shutdown", "test"))

	s.stopCancel()

	waitDone := make(chan struct{})
	go func() { s.waitReplays(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("replayers did not finish within 5s of shutdown")
	}
}

// A second give-up for the same backend while a replay is already scheduled
// must not start a second goroutine: the one already running keeps
// retrying on its own.
func TestScheduledReplayIsNotDuplicated(t *testing.T) {
	// source: TestScheduledReplayIsNotDuplicated (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{
		errNotRunning, errNotRunning, errNotRunning, errNotRunning, errNotRunning, errNotRunning,
	}, repeatLast: true}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "not-duplicated")
	backend.Register("sup_replay_not_duplicated", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_not_duplicated": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_not_duplicated", "test"))
	require.NoError(t, s.Restart(context.Background(), "sup_replay_not_duplicated", "test"))

	assert.Equal(t, int32(1), s.replayStarts.Load(),
		"a second give-up while one replay is already scheduled must not start a second goroutine")

	s.stopCancel()
	waitDone := make(chan struct{})
	go func() { s.waitReplays(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("replayers did not finish within 5s of shutdown")
	}
}

// A failure that is not the applier's not-running error is not transient,
// so it must not be rescheduled either: nothing about it will change on its
// own.
func TestRestartDoesNotRescheduleANonRetryableFailure(t *testing.T) {
	// source: TestRestartBackendDoesNotRescheduleANonRetryableFailure (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec, answers: []error{errors.New("repo failure")}}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.ReplayRetryInterval = time.Millisecond
	be := newStub(rec, "non-retryable")
	backend.Register("sup_replay_non_retryable", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_replay_non_retryable": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.Restart(context.Background(), "sup_replay_non_retryable", "test"))

	assert.Equal(t, int32(0), s.replayStarts.Load(), "a non-retryable failure must not be rescheduled")
}

// --- upgrade restart (restartUpgraded) ---

// A filesmgr-driven restart brackets its stop/start sequence the same way
// restartHealth does: policies are marked unknown before the stop and
// handed back to the backend once, after Start succeeds, while the restart
// mutex is still held.
func TestRestartUpgradedReappliesPoliciesAfterSuccessfulStart(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollback_ReappliesPoliciesAfterSuccessfulStart (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_success", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_success": nil}, config.BackendCommons{}, background))
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_success"))

	assert.Equal(t, []string{
		"remove:sup_upgrade_success:permanently=false",
		"stop:worker",
		"start:worker",
		"apply:sup_upgrade_success",
	}, rec.snapshot())
}

// A Start that fails, then succeeds after a rollback, is re-applied exactly
// once, after the retry rather than the failed first attempt, with the
// restart mutex still held.
func TestRestartUpgradedReappliesPoliciesAfterRollbackRetry(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollback_ReappliesPoliciesAfterRollbackRetry (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_retry", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_retry": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("start failed")}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_retry"))

	assert.Equal(t, []string{
		"remove:sup_upgrade_retry:permanently=false",
		"stop:worker",
		"start:worker",
		"rollback:orb-worker",
		"start:worker",
		"apply:sup_upgrade_retry",
	}, rec.snapshot(), "apply runs exactly once, after the successful retry")
}

// A Start that fails on a backend with no managed binary name cannot roll
// back, so the restart gives up without ever reapplying the policies it
// removed, and the process may still be running, so a replay is scheduled.
func TestRestartUpgradedDoesNotReapplyWithoutAManagedBinary(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollback_DoesNotReapplyWithoutAManagedBinary (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	backend.Register("sup_upgrade_no_binary", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_no_binary": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("start failed")}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_no_binary"))

	assert.Equal(t, []string{
		"remove:sup_upgrade_no_binary:permanently=false",
		"stop:worker",
		"start:worker",
	}, rec.snapshot())
	assert.Equal(t, int32(1), s.replayStarts.Load(), "an upgrade restart that cannot roll back schedules the replay, since the old process may still be running")

	s.stopCancel()
	s.waitReplays()
}

// An upgrade restart whose retried Start fails too leaves the policies
// unknown and the marker set; a scheduled replay keeps trying, because a
// stop that failed can leave the old process running with nothing else to
// hand its policies back.
func TestRestartUpgradedSchedulesAReplayWhenTheRetryFails(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollbackSchedulesAReplayWhenTheRetryFails (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_retry_fails", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_retry_fails": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("start failed"), errors.New("start failed again")}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_retry_fails"))

	assert.Equal(t, []string{
		"remove:sup_upgrade_retry_fails:permanently=false",
		"stop:worker",
		"start:worker",
		"rollback:orb-worker",
		"start:worker",
	}, rec.snapshot())
	assert.Equal(t, int32(1), s.replayStarts.Load(), "the failed retry schedules the replay")

	s.stopCancel()
	s.waitReplays()
}

// A Start that succeeds after the caller's context was already cancelled
// before the call (stop ran while this restart was blocked on the restart
// mutex) must not hand the policies back: the supervisor is shutting down.
func TestRestartUpgradedDoesNotReapplyAfterShutdownBegan(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollbackDoesNotReapplyAfterShutdownBegan (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_shutdown", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_shutdown": nil}, config.BackendCommons{}, background))
	rec.reset()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, s.RestartUpgraded(ctx, "sup_upgrade_shutdown"))

	assert.Equal(t, []string{
		"remove:sup_upgrade_shutdown:permanently=false",
		"stop:worker",
		"start:worker",
	}, rec.snapshot(), "shutdown already began, so the policies must stay unknown rather than be reapplied")
}

// A start the caller itself gave up on (its context was already cancelled,
// typically by shutdown) is not evidence the managed binary is bad, so it
// must not trigger a rollback to the previous version.
func TestRestartUpgradedDoesNotRollBackACancelledStart(t *testing.T) {
	// source: TestFilesmgrRestartDoesNotRollBackACancelledStart (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "stub-binary"
	backend.Register("sup_upgrade_cancelled", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_cancelled": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{fmt.Errorf("stub start cancelled: %w", context.Canceled)}
	rec.reset()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, s.RestartUpgraded(ctx, "sup_upgrade_cancelled"))

	assert.Equal(t, 1, rec.count("start:worker"), "Start should be attempted exactly once")
	assert.Equal(t, 0, rec.count("rollback:"), "a cancelled start must not trigger a rollback")
}

// A backend that cancels its own run context on a fatal start is not the
// supervisor shutting down: the upgrade must be rolled back and Start
// retried, not left with the bad binary installed.
func TestRestartUpgradedRollsBackWhenTheBackendCancelsItself(t *testing.T) {
	// source: TestFilesmgrRestartRollsBackWhenTheBackendCancelsItself (agent_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-stub"
	backend.Register("sup_upgrade_self_cancel", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_self_cancel": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{fmt.Errorf("fatal startup error: %w", context.Canceled)}
	var cancelledFirstAttempt bool
	be.onStart = func(_ context.Context, cancel context.CancelFunc) {
		if !cancelledFirstAttempt {
			cancelledFirstAttempt = true
			cancel()
		}
	}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_self_cancel"))

	assert.Equal(t, 2, rec.count("start:worker"), "Start is retried with the rolled-back binary")
	assert.Equal(t, 1, rec.count("rollback:orb-stub"), "the binary must be rolled back")
}

// backendRestartLock returned the same mutex for the same backend name, so
// restartBackendWithFilesmgrRollback and a concurrent RestartBackend caller
// serialized on it; the entry's own restart mutex now plays that role.
func TestRestartMutexSerializesConcurrentRestarts(t *testing.T) {
	// source: TestBackendRestartLock_SerializesConcurrentRestarts (agent_filesmgr_test.go)
	var order []string
	var orderMu sync.Mutex
	record := func(s string) {
		orderMu.Lock()
		order = append(order, s)
		orderMu.Unlock()
	}

	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_restart_mutex", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_restart_mutex": nil}, config.BackendCommons{}, background))
	e, ok := s.entryFor("sup_restart_mutex")
	require.True(t, ok)
	rec.reset()

	e.restartMu.Lock()
	record("A-locked")

	startedB := make(chan struct{})
	doneB := make(chan struct{})
	go func() {
		defer close(doneB)
		close(startedB)
		assert.NoError(t, s.RestartUpgraded(context.Background(), "sup_restart_mutex"))
		record("B-done")
	}()

	<-startedB
	time.Sleep(20 * time.Millisecond)

	assert.Equal(t, 0, rec.count("start:worker"), "B must not have called Start while A holds the lock")

	record("A-unlocked")
	e.restartMu.Unlock()

	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine B did not complete after A released the lock")
	}

	assert.Equal(t, 1, rec.count("start:worker"), "B must call Start exactly once after A releases the lock")

	orderMu.Lock()
	got := order
	orderMu.Unlock()
	require.Len(t, got, 3)
	assert.Equal(t, []string{"A-locked", "A-unlocked", "B-done"}, got,
		"operations must be serialized: B must not run until A releases the lock")
}

// buildTestTarGz produces a minimal in-memory .tar.gz containing the given
// files.
//
// ported from agent_filesmgr_test.go
func buildTestTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// ported from agent_filesmgr_test.go
func testSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// End-to-end first-install self-heal path with a real filesmgr.Manager: a
// backend's Start fails on the first call (a broken binary); the rollback,
// since there is no previous version, removes the entry from the manager
// entirely; the retry Start succeeds against the baked binary.
func TestRestartUpgradedFirstInstallFailureFallsBackToBaked(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollback_FirstInstallFailureFallsBackToBaked (agent_filesmgr_test.go)
	archive := buildTestTarGz(t, map[string]string{"orb-worker": "#!/bin/sh\nexit 0\n"})
	sum := testSHA256Hex(archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	root := t.TempDir()
	fm := filesmgr.NewManager(slog.Default(), root)
	require.NoError(t, fm.Start(context.Background()))
	defer func() { _ = fm.Stop(context.Background()) }()

	_, err := fm.Ensure(context.Background(), filesmgr.FileSpec{
		Name:    "orb-worker",
		Version: "1.0.0",
		URL:     srv.URL + "/orb-worker.tar.gz",
		SHA256:  sum,
		Extract: true,
	})
	require.NoError(t, err)
	_, ok := fm.Get("orb-worker")
	require.True(t, ok, "entry must exist before rollback test")

	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, fm)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_baked_fallback", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_baked_fallback": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("simulated start failure")}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_baked_fallback"))

	assert.Equal(t, 2, rec.count("start:worker"), "Start must be called twice: initial failure + retry after rollback")

	_, stillPresent := fm.Get("orb-worker")
	assert.False(t, stillPresent, "filesmgr entry must be removed after rollback-to-default")
}

// When restartUpgraded goes through the rollback-retry path, the cancel
// function from the first Start attempt's run context must already have
// been invoked (through beginStart) by the time the sequence finishes:
// nothing keeps the first attempt's context alive across the retry.
func TestRestartUpgradedNoCancelLeakOnRollbackRetry(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollback_NoCancelLeakOnRollbackRetry (agent_filesmgr_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_no_cancel_leak", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_no_cancel_leak": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("simulated start failure for cancel-leak test")}
	var mu sync.Mutex
	var runCtxs []context.Context
	be.onStart = func(ctx context.Context, _ context.CancelFunc) {
		mu.Lock()
		runCtxs = append(runCtxs, ctx)
		mu.Unlock()
	}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_no_cancel_leak"))

	mu.Lock()
	got := runCtxs
	mu.Unlock()
	require.Len(t, got, 2, "Start must be called twice: initial failure + retry after rollback")
	assert.Error(t, got[0].Err(), "the first attempt's run context must be cancelled once the retry's is installed")

	assert.Equal(t, 1, rec.count("rollback:orb-worker"), "Rollback must be called exactly once")
}

// A Start that fails once, then succeeds after a rollback, is retried
// exactly once.
func TestRestartUpgradedRetriesAfterFailure(t *testing.T) {
	// source: TestRestartBackendWithFilesmgrRollback_RetriesAfterFailure (agent_filesmgr_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_retries_after_failure", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_retries_after_failure": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("simulated start failure")}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_retries_after_failure"))

	assert.Equal(t, 2, rec.count("start:worker"), "Start must be called twice: initial attempt + post-rollback retry")
	assert.Equal(t, 1, rec.count("rollback:orb-worker"), "Rollback must be called exactly once")
}

// --- upgrade dispatcher (dispatchUpgrades / QueueUpgrade) ---

// Cancelling the dispatcher's dedicated context (what StopAll does)
// prevents it from processing any further pending restarts, even when a
// backend is queued.
func TestDispatchUpgradesStopsOnDispatcherCancel(t *testing.T) {
	// source: TestRestartDispatcher_StopsOnDispatcherCancel (agent_filesmgr_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_dispatch_stops_on_cancel", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_dispatch_stops_on_cancel": nil}, config.BackendCommons{}, background))
	require.Eventually(t, func() bool { return rec.dispatchStarts.Load() == 1 }, 5*time.Second, time.Millisecond)

	// Cancel the dispatcher context immediately, well before its (default,
	// one-hour) tick could fire.
	s.dispatcherCancel()
	s.QueueUpgrade("sup_dispatch_stops_on_cancel")

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), be.startCalls.Load(), "dispatcher must not restart backends after its context is cancelled")

	// The source test's central assertion, that the dispatcher goroutine
	// itself exits on a cancelled context, cannot be made against the one
	// ConfigureAll owns (nothing in the supervisor's API signals when that
	// goroutine returns). Run a second one on a test-local context, already
	// cancelled, alongside it, and keep the source's done-channel assertion
	// on that one; the default DispatchInterval is an hour and pending is
	// empty, so the extra dispatcher does nothing else.
	dctx, dcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.dispatchUpgrades(dctx); close(done) }()
	dcancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatchUpgrades did not exit after context cancellation")
	}
}

// The dispatcher does not run concurrent restart sequences for different
// backends within the same tick: it uses a slow Start to track the peak
// number of concurrent in-flight Start calls.
func TestDispatchUpgradesProcessesRestartsSequentially(t *testing.T) {
	// source: TestRestartDispatcher_ProcessesRestartsSequentially (agent_filesmgr_test.go)
	const delay = 50 * time.Millisecond
	const nBackends = 3

	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	track := func() {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		time.Sleep(delay)
		mu.Lock()
		inFlight--
		mu.Unlock()
	}

	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.DispatchInterval = 10 * time.Millisecond
	names := make([]string, nBackends)
	backends := map[string]any{}
	for i := 0; i < nBackends; i++ {
		name := fmt.Sprintf("sup_dispatch_sequential_%d", i)
		names[i] = name
		be := newStub(rec, fmt.Sprintf("seq-%d", i))
		be.binary = name
		be.onStart = func(context.Context, context.CancelFunc) { track() }
		backend.Register(name, be)
		backends[name] = nil
	}
	require.NoError(t, s.ConfigureAll(backends, config.BackendCommons{}, background))

	for _, n := range names {
		s.QueueUpgrade(n)
	}

	time.Sleep(time.Duration(nBackends+2)*delay + 300*time.Millisecond)

	mu.Lock()
	maxIF := maxInFlight
	mu.Unlock()
	assert.LessOrEqual(t, maxIF, 1, "restarts must be sequential: peak concurrent Start calls must be <= 1")
}

// When the dispatcher context is cancelled while the inner loop is draining
// a pending set with several backends, the remaining ones are not
// restarted: the ctx-check at the top of the loop aborts the drain early.
func TestDispatchUpgradesCtxCancelMidDrain(t *testing.T) {
	// source: TestRestartDispatcher_CtxCancelMidDrain (agent_filesmgr_test.go)
	const delay = 150 * time.Millisecond
	const nBackends = 4

	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	track := func() {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		time.Sleep(delay)
		mu.Lock()
		inFlight--
		mu.Unlock()
	}

	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.DispatchInterval = 10 * time.Millisecond
	names := make([]string, nBackends)
	backends := map[string]any{}
	for i := 0; i < nBackends; i++ {
		name := fmt.Sprintf("sup_dispatch_midcancel_%d", i)
		names[i] = name
		be := newStub(rec, fmt.Sprintf("mid-%d", i))
		be.binary = name
		be.onStart = func(context.Context, context.CancelFunc) { track() }
		backend.Register(name, be)
		backends[name] = nil
	}
	require.NoError(t, s.ConfigureAll(backends, config.BackendCommons{}, background))

	for _, n := range names {
		s.QueueUpgrade(n)
	}

	go func() {
		time.Sleep(delay / 3)
		s.dispatcherCancel()
	}()

	time.Sleep(time.Duration(nBackends)*delay + 500*time.Millisecond)

	mu.Lock()
	maxIF := maxInFlight
	mu.Unlock()
	assert.Less(t, maxIF, nBackends,
		"dispatcher must abort mid-drain on ctx cancel: fewer than the full set should have restarted")

	// As in TestDispatchUpgradesStopsOnDispatcherCancel, the source test's
	// central assertion, that the dispatcher goroutine itself exits, cannot
	// be made against the one ConfigureAll owns; run a second one on a
	// test-local context and keep the source's done-channel assertion there.
	dctx, dcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.dispatchUpgrades(dctx); close(done) }()
	dcancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatchUpgrades did not exit after context cancellation")
	}
}

// TestDispatchUpgradesCoalescesAndDeliversReliably queues ten upgrade events
// for the same backend and asserts that exactly one restart (stop+start) is
// issued.
func TestDispatchUpgradesCoalescesAndDeliversReliably(t *testing.T) {
	// source: TestSubscribeToFilesmgr_CoalescesAndDeliversReliably (agent_filesmgr_test.go)
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	s.opts.DispatchInterval = 10 * time.Millisecond
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_dispatch_coalesces", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_dispatch_coalesces": nil}, config.BackendCommons{}, background))
	rec.reset()

	for i := 0; i < 10; i++ {
		s.QueueUpgrade("sup_dispatch_coalesces")
	}

	require.Eventually(t, func() bool { return rec.count("start:worker") >= 1 }, time.Second, 10*time.Millisecond,
		"the coalesced restart must complete")

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, rec.count("start:worker"), "coalescing: 10 upgrade events must produce exactly 1 restart")
	assert.Equal(t, 1, rec.count("stop:worker"), "coalescing: 10 upgrade events must produce exactly 1 stop")
}

// --- new tests (mutants below) ---

// restartAllCtxMarkerKey marks the context s.runContext(name) hands back
// from the runCtxFor a test installs through ConfigureAll, so a test can
// tell that context apart from the caller's own (an unmarked
// context.Background()).
type restartAllCtxMarkerKey struct{}

// RestartAll restarts only entries that have started (Running, Starting or
// Failed); a Declared entry and one a StopAll already stopped are skipped
// without ever touching them, which this test proves by locking both
// entries' restart mutex before calling RestartAll: without the phase
// filter, RestartAll would block on the locked mutex and the 2s deadline
// would fire. It also proves RestartAll restarts each entry under
// s.runContext(name), the per-backend context factory, and not the
// caller's own ctx: the factory installed below stamps a marker the
// caller's context.Background() does not carry, and the running entry's
// FullReset observes it.
// A caller whose context is already cancelled gets no restarts: the sweep
// checks the caller's context before each entry, so a cancelled fleet RPC
// ends it, the way the agent's own sweep derived from the caller's context.
func TestRestartAllStopsWhenTheCallersContextIsCancelled(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "cancelled-sweep")
	backend.Register("sup_cancelled_sweep", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_cancelled_sweep": nil}, config.BackendCommons{}, background))
	rec.reset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.RestartAll(ctx, "cancelled")

	require.ErrorIs(t, err, context.Canceled, "a sweep the caller cancelled reports the cancellation, so the fleet handler sends no reconnect signal for it")
	assert.Equal(t, 0, rec.count("restart-registered:"), "no entry is restarted once the caller's context is cancelled")
	assert.Equal(t, 0, rec.count("reset:"))
	s.StopAll(context.Background())
}

func TestRestartAllRestartsOnlyStartedEntries(t *testing.T) {
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)

	running := newStub(rec, "running")
	failed := newStub(rec, "failed")
	backend.Register("sup_restartall_running", running)
	backend.Register("sup_restartall_failed", failed)
	runCtxFor := func(string) context.Context {
		return context.WithValue(context.Background(), restartAllCtxMarkerKey{}, true)
	}
	require.NoError(t, s.ConfigureAll(map[string]any{
		"sup_restartall_running": nil,
		"sup_restartall_failed":  nil,
	}, config.BackendCommons{}, runCtxFor))

	// A stub whose first start failed during ConfigureAll is not possible
	// without aborting the whole call, so the Failed phase is stamped
	// directly afterwards.
	failedEntry, ok := s.entryFor("sup_restartall_failed")
	require.True(t, ok)
	failedEntry.setPhase(Failed)

	// A Declared entry that never started and a Stopped one, inserted
	// directly like Task 1's TestStopAllStopsOnlyRunningBackends does for
	// its unregistered "down" entry.
	s.entriesMu.Lock()
	s.entries["sup_restartall_declared"] = &entry{name: "sup_restartall_declared", be: newStub(rec, "declared"), phase: Declared}
	s.entries["sup_restartall_stopped"] = &entry{name: "sup_restartall_stopped", be: newStub(rec, "stopped"), phase: Stopped}
	s.entriesMu.Unlock()

	declaredEntry, _ := s.entryFor("sup_restartall_declared")
	stoppedEntry, _ := s.entryFor("sup_restartall_stopped")
	declaredEntry.restartMu.Lock()
	defer declaredEntry.restartMu.Unlock()
	stoppedEntry.restartMu.Lock()
	defer stoppedEntry.restartMu.Unlock()

	var runningPhaseDuringReset Phase
	var runningResetSawMarker bool
	running.onReset = func(ctx context.Context) {
		p, _ := s.Phase("sup_restartall_running")
		runningPhaseDuringReset = p
		runningResetSawMarker, _ = ctx.Value(restartAllCtxMarkerKey{}).(bool)
	}

	rec.reset()

	done := make(chan error, 1)
	go func() { done <- s.RestartAll(context.Background(), "fleet reset") }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("RestartAll did not return within 2s: it must skip the locked Declared and Stopped entries")
	}

	assert.Equal(t, Starting, runningPhaseDuringReset, "onReset must observe Starting")
	assert.True(t, runningResetSawMarker, "RestartAll must reset each entry under s.runContext(name), not the caller's own ctx")
	assert.Equal(t, 1, rec.count("restart-registered:sup_restartall_running:fleet reset"))
	assert.Equal(t, 1, rec.count("restart-registered:sup_restartall_failed:fleet reset"))
	assert.Equal(t, 0, rec.count("restart-registered:sup_restartall_declared:fleet reset"))
	assert.Equal(t, 0, rec.count("restart-registered:sup_restartall_stopped:fleet reset"))
}

// The gated stop only stops a backend reporting Running; an upgrade restart
// for a backend with no process (its own health check never came back
// after ConfigureAll) must not call Stop.
func TestRestartUpgradedDoesNotStopABackendWithoutAProcess(t *testing.T) {
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "no-process")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_no_process", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_no_process": nil}, config.BackendCommons{}, background))
	be.status.Store(int32(backend.Unknown))
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_no_process"))

	assert.Equal(t, 0, rec.count("stop:no-process"), "gatedStop must not stop a backend that reports no process")
	assert.Equal(t, 1, rec.count("start:no-process"))
}

// A restart for an entry a StopAll already stopped is refused, producing no
// events.
func TestRestartIsRefusedForAStoppedEntry(t *testing.T) {
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	s := newTestSupervisor(t, rec, applier, nil)
	be := newStub(rec, "stopped-entry")
	backend.Register("sup_restart_stopped_entry", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_restart_stopped_entry": nil}, config.BackendCommons{}, background))
	s.StopAll(context.Background())
	rec.reset()

	err := s.Restart(context.Background(), "sup_restart_stopped_entry", "test")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend is stopped")
	assert.Empty(t, rec.snapshot(), "a refused restart on a stopped entry produces no events")
}

// An upgrade that fails even after the rollback retry leaves the entry
// Failed, not stuck: a failed entry restarts as a retry, so a following
// health restart runs normally and brings it back Running.
func TestAFailedUpgradeStaysRestartable(t *testing.T) {
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "flaky")
	be.binary = "orb-worker"
	backend.Register("sup_failed_upgrade_restartable", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_failed_upgrade_restartable": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("start failed"), errors.New("start failed again")}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_failed_upgrade_restartable"))

	p, _ := s.Phase("sup_failed_upgrade_restartable")
	assert.Equal(t, Failed, p, "a failed upgrade leaves the entry failed")

	require.NoError(t, s.Restart(context.Background(), "sup_failed_upgrade_restartable", "health"))

	assert.Equal(t, 1, rec.count("restart-registered:sup_failed_upgrade_restartable:health"))
	assert.Equal(t, 1, rec.count("reset:flaky"))
	p, _ = s.Phase("sup_failed_upgrade_restartable")
	assert.Equal(t, Running, p, "a failed entry restarts as a retry and comes back Running")
}

// F-1: the health body's Configure-failure exit must preserve Failed the
// same way the FullReset-failure exit does, since an entry that entered the
// restart Failed has no process running either way; claiming Running would
// be a lie nothing then corrects.
func TestConfigureFailureKeepsFailedWhenEnteredFailed(t *testing.T) {
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "flaky")
	be.binary = "orb-worker"
	backend.Register("sup_configure_fails_while_failed", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_configure_fails_while_failed": nil}, config.BackendCommons{}, background))
	be.startErrs = []error{errors.New("start failed"), errors.New("start failed again")}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_configure_fails_while_failed"))

	p, _ := s.Phase("sup_configure_fails_while_failed")
	require.Equal(t, Failed, p, "a failed upgrade leaves the entry failed")

	be.configureErr = errors.New("configure failed")
	err := s.Restart(context.Background(), "sup_configure_fails_while_failed", "health")

	require.Error(t, err)
	p, _ = s.Phase("sup_configure_fails_while_failed")
	assert.Equal(t, Failed, p, "a Configure failure on an entry that entered the restart Failed must not claim Running")
}

// The upgrade restart's run context comes from s.runContext(e.name), the
// same per-backend factory the health-driven start and
// TestRestartAllRestartsOnlyStartedEntries prove RestartAll uses, not the
// caller's own ctx: the factory installed below stamps a marker
// context.Background() does not carry, and the backend's Start observes it.
// Without this, an upgrade-restarted backend's run context is rooted at the
// caller's ctx instead, so it carries none of the per-backend values (its
// routine name among them) and is cancelled only by StopAll, not by the
// agent's root context.
func TestRestartUpgradedRunsUnderTheRunContextFactory(t *testing.T) {
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "worker")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_runctx", be)
	runCtxFor := func(string) context.Context {
		return context.WithValue(context.Background(), restartAllCtxMarkerKey{}, true)
	}
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_runctx": nil}, config.BackendCommons{}, runCtxFor))

	var sawMarker bool
	be.onStart = func(ctx context.Context, _ context.CancelFunc) {
		if v, _ := ctx.Value(restartAllCtxMarkerKey{}).(bool); v {
			sawMarker = true
		}
	}
	rec.reset()

	require.NoError(t, s.RestartUpgraded(context.Background(), "sup_upgrade_runctx"))

	assert.True(t, sawMarker, "the upgrade restart must run under s.runContext(name), not the caller's own ctx")
}

// TestRestartUpgradedReportsErrStoppedWhenAStopWinsAfterStartSucceeds
// mirrors TestStartReportsErrStoppedWhenAStopWinsAfterStartSucceeds
// (supervisor_test.go) for the upgrade path: a StopAll that stamps the
// entry Stopped while the upgrade's own Start is still in flight must win
// the race even though that Start goes on to report success, stopping the
// process that came up through the gated stop rather than leaving it
// running unsupervised.
// A health-driven reset in flight observes the supervisor's stop: the
// context handed to FullReset is cancelled when StopAll begins, so a
// shutdown that overlaps a reset does not wait out the backend's readiness
// loop; Restart returns and StopAll gets the restart mutex.
func TestRestartResetObservesStopAll(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "reset_ctx")
	backend.Register("sup_reset_ctx", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_reset_ctx": nil}, config.BackendCommons{}, background))
	entered := make(chan struct{})
	observed := make(chan error, 1)
	be.onResetCtx = func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		observed <- ctx.Err()
		return ctx.Err()
	}

	done := make(chan error, 1)
	go func() { done <- s.Restart(context.Background(), "sup_reset_ctx", "health") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the reset was never entered")
	}
	stopped := make(chan struct{})
	go func() { s.StopAll(context.Background()); close(stopped) }()

	select {
	case err := <-observed:
		require.ErrorIs(t, err, context.Canceled, "the reset's context is cancelled when StopAll begins")
	case <-time.After(5 * time.Second):
		t.Fatal("the reset never observed the stop; shutdown would wait out the readiness loop")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Restart did not return after the stop")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll did not return")
	}
}

func TestRestartUpgradedReportsErrStoppedWhenAStopWinsAfterStartSucceeds(t *testing.T) {
	rec := &recorder{}
	applier := &stubApplier{rec: rec}
	files := &stubFiles{rec: rec}
	s := newTestSupervisor(t, rec, applier, files)
	be := newStub(rec, "raced")
	be.binary = "orb-worker"
	backend.Register("sup_upgrade_raced", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_upgrade_raced": nil}, config.BackendCommons{}, background))

	be.startBlocks = make(chan struct{})
	be.ignoreCancel = true
	started := make(chan struct{})
	be.onStart = func(context.Context, context.CancelFunc) {
		// The upgrade's own gated stop (of the pre-upgrade process) has
		// already run by the time Start is called; reset here so the
		// assertion below counts only the stop that follows this race.
		rec.reset()
		close(started)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.RestartUpgraded(context.Background(), "sup_upgrade_raced")
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the upgrade's Start was never called")
	}

	stopDone := make(chan struct{})
	go func() {
		s.StopAll(context.Background())
		close(stopDone)
	}()

	require.Eventually(t, func() bool {
		p, ok := s.Phase("sup_upgrade_raced")
		return ok && p == Stopped
	}, 5*time.Second, time.Millisecond, "StopAll's first loop must stamp the entry Stopped before the upgrade's start is released")
	close(be.startBlocks)

	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrStopped)
	case <-time.After(5 * time.Second):
		t.Fatal("RestartUpgraded never returned")
	}
	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll never completed")
	}

	assert.Equal(t, 1, rec.count("stop:raced"), "the process that came up from the raced Start must be gated-stopped exactly once")
}

// The context handed to FullReset is the replacement process's run context:
// bundled backends derive the replacement's start context from it, and a
// backend that follows the cancellation contract stops on Done. It therefore
// has to outlive the restart and be cancelled by shutdown, not the moment
// FullReset returns.
func TestRestartResetContextOutlivesTheRestartUntilStopAll(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "reset_lives")
	backend.Register("sup_reset_lives", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_reset_lives": nil}, config.BackendCommons{}, background))
	var resetCtx context.Context
	be.onReset = func(ctx context.Context) { resetCtx = ctx }

	require.NoError(t, s.Restart(context.Background(), "sup_reset_lives", "health"))

	require.NotNil(t, resetCtx)
	require.NoError(t, resetCtx.Err(), "the replacement process's context is alive after the restart")
	s.StopAll(context.Background())
	assert.ErrorIs(t, resetCtx.Err(), context.Canceled, "shutdown cancels the replacement process's context")
}

// The next restart releases the previous replacement's context, but only
// after its FullReset returns: the previous process is stopped by that
// FullReset, gracefully, not by a context cancellation racing it.
func TestRestartResetContextIsReleasedByTheNextRestart(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "reset_next")
	backend.Register("sup_reset_next", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_reset_next": nil}, config.BackendCommons{}, background))
	var first context.Context
	be.onReset = func(ctx context.Context) { first = ctx }
	require.NoError(t, s.Restart(context.Background(), "sup_reset_next", "health"))
	require.NotNil(t, first)

	var firstErrAtSecondReset error
	be.onReset = func(context.Context) { firstErrAtSecondReset = first.Err() }
	require.NoError(t, s.Restart(context.Background(), "sup_reset_next", "health"))

	assert.NoError(t, firstErrAtSecondReset, "the previous context is still alive while the next FullReset stops its process")
	assert.ErrorIs(t, first.Err(), context.Canceled, "the previous context is released once the next restart replaced it")
}

// A reset that fails may have left the previous process up (its Stop
// failed), so the previous context stays the entry's run context and the
// unused replacement context is released; shutdown then cancels the
// previous one.
func TestRestartFailedResetKeepsThePreviousRunContext(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "reset_keep")
	backend.Register("sup_reset_keep", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_reset_keep": nil}, config.BackendCommons{}, background))
	var first context.Context
	be.onReset = func(ctx context.Context) { first = ctx }
	require.NoError(t, s.Restart(context.Background(), "sup_reset_keep", "health"))
	require.NotNil(t, first)

	var second context.Context
	be.onReset = func(ctx context.Context) { second = ctx }
	be.resetErr = errors.New("stop failed")
	require.NoError(t, s.Restart(context.Background(), "sup_reset_keep", "health"))

	require.NotNil(t, second)
	assert.ErrorIs(t, second.Err(), context.Canceled, "the replacement context of a failed reset is released")
	require.NoError(t, first.Err(), "the previous process's context survives a failed reset")
	s.StopAll(context.Background())
	assert.ErrorIs(t, first.Err(), context.Canceled, "shutdown cancels the previous process's context")
}

// A StopAll that marks the entry Stopped after the restart began but before
// its reset wins: the reset is refused with ErrStopped, so no replacement
// process is started for StopAll's second loop to have to stop again.
func TestRestartRefusesTheResetOnceStopAllMarkedTheEntryStopped(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "reset_late_stop")
	backend.Register("sup_reset_late_stop", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_reset_late_stop": nil}, config.BackendCommons{}, background))
	rec.reset()
	stopped := make(chan struct{})
	be.onConfigure = func() {
		be.onConfigure = nil
		go func() { s.StopAll(context.Background()); close(stopped) }()
		require.Eventually(t, func() bool {
			phase, _ := s.Phase("sup_reset_late_stop")
			return phase == Stopped
		}, 5*time.Second, 5*time.Millisecond, "StopAll's first loop marks the entry Stopped")
	}

	err := s.Restart(context.Background(), "sup_reset_late_stop", "health")

	require.ErrorIs(t, err, ErrStopped)
	assert.Equal(t, 0, rec.count("reset:reset_late_stop"), "no reset once the entry is stopped")
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll did not return")
	}
}

// A StopAll landing while a health restart is still configuring the backend
// finds the entry's run context pointing at the live process: that context
// must survive StopAll's first loop, so the process is stopped gracefully by
// the gated stop in its second loop and not terminated by its own context.
// Only the swap into the reset's fresh context stamps Starting.
func TestStopAllDuringRestartConfigureKeepsTheLiveProcessContext(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "cfg_live")
	backend.Register("sup_cfg_live", be)
	var liveCtx context.Context
	be.onStart = func(ctx context.Context, _ context.CancelFunc) { liveCtx = ctx }
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_cfg_live": nil}, config.BackendCommons{}, background))
	require.NotNil(t, liveCtx)
	be.status.Store(int32(backend.Running))
	rec.reset()

	stopped := make(chan struct{})
	var liveErrAfterFirstLoop error
	be.onConfigure = func() {
		be.onConfigure = nil
		go func() { s.StopAll(context.Background()); close(stopped) }()
		require.Eventually(t, func() bool {
			phase, _ := s.Phase("sup_cfg_live")
			return phase == Stopped
		}, 5*time.Second, 5*time.Millisecond, "StopAll's first loop marks the entry Stopped")
		liveErrAfterFirstLoop = liveCtx.Err()
	}

	err := s.Restart(context.Background(), "sup_cfg_live", "health")

	require.ErrorIs(t, err, ErrStopped)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("StopAll did not return")
	}
	assert.NoError(t, liveErrAfterFirstLoop, "the live process's context survives StopAll's first loop while the restart configures")
	assert.Equal(t, 1, rec.count("stop:cfg_live"), "the live process is stopped gracefully by StopAll's second loop")
	assert.ErrorIs(t, liveCtx.Err(), context.Canceled, "its context is released once it is stopped")
}

// A sweep that shutdown aborts reports it as both the stop sentinel and a
// cancellation: the fleet reset handler, which cannot see the supervisor's
// sentinel, recognises the cancellation and sends no reconnect signal for a
// reset that never completed.
func TestRestartAllReportsCancellationWhenStopAbortsTheSweep(t *testing.T) {
	rec := &recorder{}
	s := newTestSupervisor(t, rec, nil, nil)
	be := newStub(rec, "aborted_sweep")
	backend.Register("sup_aborted_sweep", be)
	require.NoError(t, s.ConfigureAll(map[string]any{"sup_aborted_sweep": nil}, config.BackendCommons{}, background))
	entered := make(chan struct{})
	be.onResetCtx = func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}

	done := make(chan error, 1)
	go func() { done <- s.RestartAll(context.Background(), "fleet reset") }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the reset was never entered")
	}
	s.StopAll(context.Background())

	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrStopped)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("RestartAll did not return after StopAll")
	}
}
