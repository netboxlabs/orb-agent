package supervisor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

// ReasonRetryAfterFailedStart is the restart reason the retry timer uses.
const ReasonRetryAfterFailedStart = "retry after failed start"

// armRetry arms an on-demand entry's retry timer under its field mutex; a
// timer already armed is left alone. The timer restarts the entry through
// Restart, which disarms it first, so a restart from any other source that
// runs meanwhile is not doubled unless the timer already fired; a callback
// already dispatched runs its restart after the other one, on an entry that
// is Running again, which the plan accepts. An eager entry is never armed:
// its failures are the health monitor's business.
func (s *Supervisor) armRetry(e *entry) {
	e.mu.Lock()
	if e.mode != startOnDemand || e.phase != Failed || e.retryTimer != nil {
		e.mu.Unlock()
		return
	}
	e.retryTimer = time.AfterFunc(s.opts.RetryInterval, func() {
		err := s.Restart(s.runContext(e.name), e.name, ReasonRetryAfterFailedStart)
		switch {
		case err == nil:
		case errors.Is(err, ErrStopped):
			s.logger.Info("on-demand start retry skipped, supervisor stopped", "backend", e.name)
		default:
			s.logger.Error("on-demand start retry failed", "backend", e.name, "error", err)
		}
	})
	e.mu.Unlock()
	// Logged outside the field mutex: a log handler is a call out (under
	// fleet it exports over OTLP), and the field mutex makes none.
	s.logger.Info("scheduling on-demand start retry", "backend", e.name, "in", s.opts.RetryInterval)
}

// disarmRetry stops a pending retry timer, if any, under the field mutex.
func (e *entry) disarmRetry() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retryTimer != nil {
		e.retryTimer.Stop()
		e.retryTimer = nil
	}
}

// Restart restarts one declared backend by resetting it in place: see
// restartHealth for the full sequence. The sequence holds the entry's
// restart mutex across it, so no two restarts for the same backend
// interleave and no stop runs mid-flight. A name this supervisor never
// declared is refused; a declared entry that never started, or one a
// StopAll already stopped, is refused too, with the same message
// RestartUpgraded gives for the same conditions.
func (s *Supervisor) Restart(ctx context.Context, name string, reason string) error {
	e, ok := s.entryFor(name)
	if !ok {
		return errors.New("backend is not started by this agent: " + name)
	}
	return s.restartHealth(ctx, e, reason)
}

// RestartUpgraded restarts one declared backend after a binary upgrade: see
// restartUpgraded for the full sequence (a gated stop, then Start, with a
// rollback and one retry if Start fails). dispatchUpgrades calls this
// instead of Restart. A name this supervisor never declared is refused; a
// declared entry that never started, or one a StopAll already stopped, is
// refused too, with the same message Restart gives for the same conditions.
func (s *Supervisor) RestartUpgraded(ctx context.Context, name string) error {
	e, ok := s.entryFor(name)
	if !ok {
		return errors.New("backend is not started by this agent: " + name)
	}
	return s.restartUpgraded(ctx, e)
}

// RestartAll restarts every entry that has started: Running, Starting or
// Failed (a failed entry restarts as a retry). An entry that was only
// declared, or one a StopAll already stopped, is skipped, since neither has
// a process a restart could reach. Per-backend failures are logged, not
// returned, the same way the per-backend loop it replaces logged them. The
// caller's context is checked before each entry, so a cancelled request
// starts no further restarts; it does not interrupt one already in flight,
// which runs under s.runContext(e.name), the per-backend context factory
// serveRestartRequests uses too. A sweep that did not complete, because
// the caller's context was cancelled or because StopAll began, returns an
// error satisfying errors.Is(err, context.Canceled) (and ErrStopped for
// the stop), so the fleet reset handler sends no reconnect signal for it:
// there is no connection to refresh, and the handler that signal wakes is
// on its way down.
func (s *Supervisor) RestartAll(ctx context.Context, reason string) error {
	s.logger.Info("restarting comms", "reason", reason)
	for _, e := range s.snapshot() {
		if err := ctx.Err(); err != nil {
			s.logger.Info("restart sweep cancelled by the caller", "reason", reason, "error", err)
			return fmt.Errorf("restart sweep cancelled by the caller: %w", err)
		}
		e.mu.Lock()
		phase := e.phase
		e.mu.Unlock()
		switch phase {
		case Running, Starting, Failed:
			s.logger.Info("restarting backend", "backend", e.name, "reason", reason)
			if err := s.Restart(s.runContext(e.name), e.name, reason); err != nil {
				s.logger.Error("failed to restart backend", "backend", e.name, "error", err)
			}
		default:
			s.logger.Debug("skipping restart for a backend that never started", "backend", e.name, "phase", phase)
		}
	}
	if err := s.stopCtx.Err(); err != nil {
		s.logger.Info("restart sweep aborted by stop", "reason", reason)
		return fmt.Errorf("%w: restart sweep aborted by stop: %w", ErrStopped, err)
	}
	s.logger.Info("all backends and comms were restarted")
	return nil
}

// QueueUpgrade marks a backend for an upgrade restart; dispatchUpgrades
// drains the queue every DispatchInterval, coalescing repeated events for
// the same backend within one interval into a single restart.
func (s *Supervisor) QueueUpgrade(name string) {
	s.pendingMu.Lock()
	if s.pending == nil {
		s.pending = make(map[string]struct{})
	}
	s.pending[name] = struct{}{}
	s.pendingMu.Unlock()
}

// restartHealth is the health- or fleet-driven restart: it keeps the
// backend's policies and re-applies them once the reset succeeds. They are
// marked unknown for the restart, not deleted, and handed back to the
// backend after it is running again. Every stored policy for the backend is
// handed back, including one whose run already finished, so a one-shot
// policy runs again. Any return after the removal re-applies immediately if
// the backend never stopped (a bad backend config, a Configure failure), or
// leaves the policies marked unknown for the next successful restart if the
// reset itself failed.
//
// The whole sequence runs under the entry's restart mutex, taken before the
// applier's own apply mutex, never after. The applier's own restarting
// marker is set by the removal below, the first thing it does under its own
// mutex, and cleared by the re-apply's entry gate once it confirms the
// backend answers: a manage arriving before the clear is stored as starting
// for that re-apply to pick up, and one arriving after applies directly to
// the backend, which is up by then; the re-apply itself skips anything
// already Running, so neither path ever applies a policy twice. A re-apply
// that gives up because the backend still is not answering is rescheduled
// and keeps trying, at ReplayRetryInterval, until it completes, so deferred
// manages are not stuck behind a marker nothing else would ever clear.
func (s *Supervisor) restartHealth(ctx context.Context, e *entry, reason string) error {
	e.restartMu.Lock()
	defer e.restartMu.Unlock()

	e.mu.Lock()
	prior := e.phase
	e.mu.Unlock()
	if prior == Declared {
		return errors.New("backend is not started by this agent: " + e.name)
	}
	if prior == Stopped {
		return fmt.Errorf("%w: %s", ErrStopped, e.name)
	}
	e.disarmRetry()

	s.logger.Info("restarting backend", "backend", e.name, "reason", reason)
	s.state.RegisterRestart(e.name, reason)
	s.logger.Info("marking policies for re-apply", "backend", e.name)
	if err := s.applier.RemoveBackendPolicies(e.name, e.be, false); err != nil {
		s.logger.Error("failed to remove policies", "backend", e.name, "error", err)
	}

	// The phase stays as it was through the configure: the entry's run
	// context still belongs to the live process, and StopAll cancels the run
	// context of every entry that is not Running in its first loop, so a
	// Starting stamp here would have a stop landing meanwhile terminate the
	// live process through its context instead of stopping it gracefully in
	// the second loop. Starting is stamped together with the context swap
	// below, once the run context is the replacement's.
	if err := s.configure(e); err != nil {
		if prior == Failed {
			// The retry could not even configure: remember why, and arm the
			// next attempt before the replay below, which may take a while.
			if !e.failWith(err) {
				s.armRetry(e)
			}
		}
		// The backend never stopped, so it is still running its previous
		// configuration; hand its policies back rather than leave them
		// unknown for a restart that may not come again soon.
		if completed, retryable := s.reapply(ctx, e.name, e.be); !completed && retryable {
			s.scheduleReplay(e)
		}
		return err
	}
	s.logger.Info("resetting backend", "backend", e.name)

	// The apply mutex is deliberately not held across the reset: a manage
	// landing on this backend meanwhile may be stamped failed to apply, and
	// the re-apply below heals it by re-applying every stored policy.
	//
	// The reset runs under a fresh run context from the same per-backend
	// factory the start uses: backends derive their replacement process's
	// start context from it, so it is the replacement's run context and has
	// to outlive this restart, until the next one replaces it or StopAll
	// cancels it. It is installed as the entry's run context before the
	// reset, so a StopAll landing meanwhile cancels it (the entry is
	// Starting) and a Start blocked in its readiness loop returns; the
	// previous run context is released only after FullReset returns, so
	// the previous process is stopped by FullReset itself, gracefully, not
	// by a cancellation racing it. A stop that began first wins here the
	// way it does in configureAndStart.
	runCtx, cancel := context.WithCancel(backend.WithReadinessBudget(s.runContext(e.name), e.budget))
	prevCancel, stopped := e.beginReset(cancel)
	if stopped {
		cancel()
		return fmt.Errorf("%w: %s", ErrStopped, e.name)
	}
	err := e.be.FullReset(runCtx)
	if err != nil {
		// The previous process may still be up (a Stop that failed), so its
		// context stays the entry's run context and the unused replacement
		// context is released.
		e.restoreRun(prevCancel)
		cancel()
		s.state.RegisterError(e.name, fmt.Sprintf("failed to reset backend: %v", err))
		// The policies stay marked unknown and manages stay deferred until a
		// replay completes; the health monitor never asks for another restart
		// on its own, so the replay is scheduled here rather than left to a
		// restart that may never come.
		if prior == Running {
			// A Running entry keeps its previous process: the reset failed
			// before replacing it.
			e.setPhase(Running)
		} else if !e.failWith(err) {
			// Failed, or Starting for a launched on-demand start that a
			// restart got to first: no process came up either way, so the
			// entry stays failed and its retry repeats.
			s.armRetry(e)
		}
		s.scheduleReplay(e)
		return nil
	}
	if prevCancel != nil {
		prevCancel()
	}
	if stopped := e.setPhase(Running); !stopped {
		s.registerMonitorOnce(e)
	}
	s.replayAfterStart(ctx, e)
	return nil
}

// restartUpgraded performs a stop-then-start sequence for a backend after a
// binary upgrade. If Start fails, it asks the files manager to roll the
// binary back to its previous version, then retries Start once. On a second
// failure it gives up and leaves the entry failed and restartable.
//
// Like restartHealth, it marks the backend's policies unknown before the
// stop and re-applies them once, after whichever Start succeeds (the first
// attempt or the rollback retry), under the same restart mutex the
// applier's own apply mutex is taken after, never before. The applier owns
// the restarting marker itself: its non-permanent removal below sets it,
// and the re-apply's entry gate clears it once the backend answers, so a
// manage arriving before the clear is stored as starting for the re-apply
// to pick up, and one arriving after applies directly to the backend, which
// is up by then. A re-apply that gives up because the backend still is not
// answering is rescheduled the same way restartHealth reschedules one, and
// keeps retrying at ReplayRetryInterval until it completes, so a manage
// stored as starting is not deferred forever.
//
// Each run context comes from s.runContext(e.name), the same per-backend
// factory start uses, so an upgrade-restarted backend's context carries the
// same values (its routine name among them) and is cancelled by the agent's
// root context, not only by StopAll; ctx, the caller's own context, is used
// only for the gated stop, the files manager rollback, and to tell a
// caller-driven shutdown apart from the backend cancelling its own run
// context on a fatal start. Both the first Start and the rollback retry
// carry the entry's readiness budget too, the same as the initial start; it
// is zero for an eager entry, so wrapping the context there is a no-op.
func (s *Supervisor) restartUpgraded(ctx context.Context, e *entry) error {
	e.restartMu.Lock()
	defer e.restartMu.Unlock()

	e.mu.Lock()
	prior := e.phase
	e.mu.Unlock()
	if prior == Declared {
		return errors.New("backend is not started by this agent: " + e.name)
	}
	if prior == Stopped {
		return fmt.Errorf("%w: %s", ErrStopped, e.name)
	}
	e.disarmRetry()

	binaryName := ""
	if mb, ok := e.be.(backend.ManagedBinary); ok {
		binaryName = mb.ManagedBinaryName()
	}

	// The removal here is bookkeeping symmetry with restartHealth, not
	// because the process about to be stopped needs it.
	if err := s.applier.RemoveBackendPolicies(e.name, e.be, false); err != nil {
		s.logger.Error("filesmgr: failed to remove policies", "backend", e.name, "error", err)
	}

	// Only a backend reporting Running has a process to stop gracefully; one
	// that never came up is left alone.
	s.gatedStop(ctx, e)

	runCtx, cancel := context.WithCancel(backend.WithReadinessBudget(s.runContext(e.name), e.budget))
	if e.beginStart(cancel) == Stopped {
		cancel()
		return fmt.Errorf("%w: %s", ErrStopped, e.name)
	}

	startErr := e.be.Start(runCtx, cancel)
	if startErr == nil {
		s.logger.Info("filesmgr: backend restarted with upgraded binary", "backend", e.name, "binary", binaryName)
		// A stop that began meanwhile wins: stoppedDuringStart leaves the
		// phase at Stopped and returns ErrStopped; StopAll's second loop
		// stops the process that came up once it gets the mutex, the way
		// configureAndStart handles the same race.
		if err := s.stoppedDuringStart(e); err != nil {
			return err
		}
		if completed, retryable := s.reapply(ctx, e.name, e.be); !completed && retryable {
			s.scheduleReplay(e)
		}
		return nil
	}
	// Only the caller's own context tells shutdown apart from a backend that
	// cancelled its run context on a fatal start: the latter also returns an
	// error wrapping the cancellation, and it must be rolled back.
	if ctx.Err() != nil {
		s.logger.Info("filesmgr: backend start cancelled during restart, leaving the binary as it is", "backend", e.name, "error", startErr)
		e.setPhase(Failed)
		return nil
	}
	s.logger.Warn("filesmgr: backend Start failed after upgrade, rolling back", "backend", e.name, "error", startErr)

	// Every failure exit after the removal schedules the replay: a stop that
	// failed can leave the old process running, and then the health monitor
	// never asks for another restart and nothing else would hand the
	// policies back or clear the restart marker.
	if binaryName == "" {
		s.logger.Error("filesmgr: cannot roll back, backend declares no managed binary", "backend", e.name)
		e.setPhase(Failed)
		s.armRetry(e)
		s.scheduleReplay(e)
		return nil
	}
	if s.files == nil {
		s.logger.Error("filesmgr: cannot roll back, no files manager configured", "backend", e.name, "binary", binaryName)
		e.setPhase(Failed)
		s.armRetry(e)
		s.scheduleReplay(e)
		return nil
	}
	if err := s.files.Rollback(ctx, binaryName); err != nil {
		s.logger.Error("filesmgr: rollback failed", "backend", e.name, "binary", binaryName, "error", err)
		e.setPhase(Failed)
		s.armRetry(e)
		s.scheduleReplay(e)
		return nil
	}

	// Retry Start with the rolled-back binary: a fresh context and cancel,
	// again through beginStart, which cancels the failed first attempt's
	// context before installing this one.
	runCtx2, cancel2 := context.WithCancel(backend.WithReadinessBudget(s.runContext(e.name), e.budget))
	if e.beginStart(cancel2) == Stopped {
		cancel2()
		return fmt.Errorf("%w: %s", ErrStopped, e.name)
	}
	if err := e.be.Start(runCtx2, cancel2); err != nil {
		s.logger.Error("filesmgr: backend Start failed even after rollback", "backend", e.name, "error", err)
		e.setPhase(Failed)
		s.armRetry(e)
		s.scheduleReplay(e)
		return nil
	}
	s.logger.Info("filesmgr: backend restarted with rolled-back binary", "backend", e.name, "binary", binaryName)
	// Same race as the first attempt: a stop that began meanwhile wins.
	if err := s.stoppedDuringStart(e); err != nil {
		return err
	}
	if completed, retryable := s.reapply(ctx, e.name, e.be); !completed && retryable {
		s.scheduleReplay(e)
	}
	return nil
}

// reapply hands the backend its own policies again after a restart. A
// backend that has just come back from a reset or a start may not answer
// its first status probe or two, so ApplyBackendPolicies can return the
// applier's not-running error transiently even though the backend is on its
// way up. The replay retries that specific error, up to ReapplyAttempts
// times, ReapplyRetryDelay apart, because nothing else would install the
// policies: the health monitor sees a healthy backend and never asks for
// another restart. Any other failure is logged, not returned: the policies
// stay marked unknown for the next successful restart. Once the context is
// done the caller is shutting down and no new work is launched; the
// policies stay unknown.
//
// Giving up after ReapplyAttempts is different from every other failure:
// the caller is told, through the returned retryable flag, to reschedule
// the replay via scheduleReplay, which keeps attempting it, at
// ReplayRetryInterval, until it completes. Without that, the restarting
// marker set by the removal above would stay set forever and every later
// manage for the backend would stay deferred, since a healthy backend never
// asks for another restart on its own.
//
// The apply context is cancelled by whichever of the caller's context or
// the supervisor's stop context is cancelled first. The stop context is
// cancelled as the first statement of StopAll, so a restart that already
// holds the entry's restart mutex when a stop begins observes it here at
// once. The caller's context is folded in through context.AfterFunc, whose
// callback runs in its own goroutine, so it is checked directly up front
// rather than relied on to interrupt a loop already in flight.
//
// completed is true only when ApplyBackendPolicies returns nil. Otherwise
// completed is false, and retryable tells the caller whether to reschedule:
// true when every attempt answered the not-running error and ReapplyAttempts
// was reached, false for any other failure and for a replay that never ran
// because the context was already done.
func (s *Supervisor) reapply(ctx context.Context, name string, be backend.Backend) (completed, retryable bool) {
	applyCtx, cancel := context.WithCancel(s.stopCtx)
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()
	if err := ctx.Err(); err != nil {
		s.logger.Info("shutting down; backend policies left unknown", "backend", name, "error", err)
		return false, false
	}
	if err := applyCtx.Err(); err != nil {
		s.logger.Info("shutting down; backend policies left unknown", "backend", name, "error", err)
		return false, false
	}
	for attempt := 1; ; attempt++ {
		err := s.applier.ApplyBackendPolicies(applyCtx, name, be)
		if err == nil {
			return true, false
		}
		if !errors.Is(err, s.opts.NotRunning) {
			s.logger.Error("backend policies left unapplied after restart; they stay unknown until the next successful restart",
				"backend", name, "attempts", attempt, "error", err)
			return false, false
		}
		if attempt == s.opts.ReapplyAttempts {
			s.logger.Error("backend policies left unapplied after restart; the replay will be rescheduled until it completes",
				"backend", name, "attempts", attempt, "error", err)
			return false, true
		}
		s.logger.Warn("backend not answering yet after restart; retrying the policy replay",
			"backend", name, "attempt", attempt, "retry_in", s.opts.ReapplyRetryDelay)
		select {
		case <-applyCtx.Done():
			s.logger.Info("shutting down; backend policies left unknown", "backend", name, "error", applyCtx.Err())
			return false, false
		case <-time.After(s.opts.ReapplyRetryDelay):
		}
	}
}

// scheduleReplay ensures a replay that gave up because the backend was
// still not answering keeps being attempted until it completes. Nothing
// else would ask for another one: the health monitor sees the backend as
// healthy once it does answer and never requests another restart on its
// own, so a give-up would otherwise leave the restarting marker set and
// every later manage for the backend deferred indefinitely.
//
// One scheduled replay per entry runs at a time; a second call while one is
// already scheduled for that entry is a no-op, since the loop already
// running keeps retrying on its own.
//
// Each attempt takes the entry's restart mutex before calling reapply, so
// it cannot interleave with a restart of the same backend. The wait between
// attempts does not hold the mutex, so a restart can run in between; that
// restart performs its own replay and clears the restarting marker itself,
// and this loop's next attempt then completes at once, because a replay
// with nothing left deferred is a no-op that returns nil.
func (s *Supervisor) scheduleReplay(e *entry) {
	s.replayAdmitMu.Lock()
	defer s.replayAdmitMu.Unlock()
	if s.stopCtx.Err() != nil {
		s.logger.Info("shutting down; no policy replay scheduled", "backend", e.name)
		return
	}
	if !e.replayScheduled.CompareAndSwap(false, true) {
		return
	}
	s.replayStarts.Add(1)
	s.replayers.Add(1)
	go func() {
		defer s.replayers.Done()
		for attempt := 1; ; attempt++ {
			select {
			case <-s.stopCtx.Done():
				e.replayScheduled.Store(false)
				return
			case <-time.After(s.opts.ReplayRetryInterval):
			}
			e.restartMu.Lock()
			completed, retryable := s.reapply(s.stopCtx, e.name, e.be)
			done := completed || !retryable
			if done {
				// Cleared while the restart mutex is still held: a restart
				// that takes the mutex next and gives up must be able to
				// schedule its own replay rather than be told one is
				// pending by a goroutine about to exit.
				e.replayScheduled.Store(false)
			}
			e.restartMu.Unlock()
			if completed {
				return
			}
			if !retryable {
				s.logger.Error("scheduled policy replay failed and will not be retried",
					"backend", e.name, "attempt", attempt)
				return
			}
			s.logger.Warn("scheduled policy replay gave up again; retrying",
				"backend", e.name, "attempt", attempt, "retry_in", s.opts.ReplayRetryInterval)
		}
	}()
}

// serveRestartRequests drains the state manager's restart requests until
// stop begins, restarting the named backend for each one.
func (s *Supervisor) serveRestartRequests() {
	if s.onServe != nil {
		s.onServe()
	}
	for {
		select {
		case <-s.stopCtx.Done():
			return
		case name, ok := <-s.restartRequests:
			if !ok {
				return
			}
			s.logger.Info("restart requested", "backend", name)
			if err := s.Restart(s.runContext(name), name, "restart requested by fleet"); err != nil {
				s.logger.Error("failed to restart backend", "backend", name, "error", err)
			}
		}
	}
}

// dispatchUpgrades drains queued binary-upgrade restarts every
// DispatchInterval, restarting each pending backend in turn. Running
// synchronously means concurrent restart sequences for the same backend
// cannot overlap across ticks; dispatchUpgrades is on its own goroutine, so
// the rest of the supervisor is unaffected.
func (s *Supervisor) dispatchUpgrades(ctx context.Context) {
	if s.onDispatch != nil {
		s.onDispatch()
	}
	ticker := time.NewTicker(s.opts.DispatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pendingMu.Lock()
			pending := s.pending
			s.pending = nil
			s.pendingMu.Unlock()
			for name := range pending {
				select {
				case <-ctx.Done():
					return
				default:
				}
				s.logger.Info("filesmgr: dispatched restart", "backend", name)
				if err := s.RestartUpgraded(ctx, name); err != nil {
					s.logger.Error("filesmgr: dispatched restart failed", "backend", name, "error", err)
				}
			}
		}
	}
}

// waitReplays waits for every rescheduled replay goroutine to exit. Called
// once stopCtx is already cancelled, so every scheduled replay either
// already exited or is about to, on its next check. Taking the admission
// mutex once here lets any admission already in flight finish its Add, and
// every later one sees the cancelled context and refuses, so Wait cannot
// race an Add.
func (s *Supervisor) waitReplays() {
	s.replayAdmitMu.Lock()
	s.replayAdmitMu.Unlock() //nolint:staticcheck // the empty critical section is the barrier
	s.replayers.Wait()
}

// replayAfterStart is the tail a successful start and a successful reset
// share: the entry is Running, and the policies stored while it was not
// (unknown for a restart, "backend starting" for an on-demand start) are
// handed back to the backend, with the bounded retries and the
// rescheduling a replay that gives up gets. Callers hold the restart mutex.
func (s *Supervisor) replayAfterStart(ctx context.Context, e *entry) {
	if completed, retryable := s.reapply(ctx, e.name, e.be); !completed && retryable {
		s.scheduleReplay(e)
	}
}
