package supervisor

import "context"

// serveRestartRequests drains the state manager's restart requests until
// stop begins. Task 2 makes it restart the backend.
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
		}
	}
}

// dispatchUpgrades drains queued binary-upgrade restarts. Task 2 fills it.
func (s *Supervisor) dispatchUpgrades(ctx context.Context) {
	if s.onDispatch != nil {
		s.onDispatch()
	}
	<-ctx.Done()
}

// BeginStop cancels the stop context without stopping anything: the first
// step of StopAll on its own, for a caller that must signal shutdown to an
// in-flight replay before it can take the entry's restart mutex (the agent's
// signal handler could use it to make a long restart notice shutdown before
// StopAll can get the mutex). StopAll still has to run afterwards.
func (s *Supervisor) BeginStop() { s.stopCancel() }

// waitReplays waits for rescheduled replay goroutines. Task 2 fills it.
func (s *Supervisor) waitReplays() {}
