//go:build unix

package backend

import (
	"log/slog"
	"syscall"
	"time"
)

// DefaultStopGracePeriod is how long to wait for a process to exit after SIGTERM
// before sending SIGKILL to its process group.
const DefaultStopGracePeriod = 5 * time.Second

// postKillTimeout is how long to wait for a process to exit after SIGKILL.
// SIGKILL is handled by the kernel near-instantly; a short timeout here bounds
// the per-backend worst case to gracePeriod+postKillTimeout rather than 2×gracePeriod.
const postKillTimeout = 2 * time.Second

// StopProcess sends SIGTERM via proc.Stop(), waits up to gracePeriod for the
// process to exit, then escalates to SIGKILL if needed. Returns without draining
// statusChan if the pid is invalid or if the process does not exit after SIGKILL.
func StopProcess(logger *slog.Logger, proc Commander, statusChan <-chan CmdStatus, gracePeriod time.Duration, backendName string) {
	if gracePeriod <= 0 {
		gracePeriod = DefaultStopGracePeriod
	}
	if err := proc.Stop(); err != nil {
		logger.Error("SIGTERM error", "backend", backendName, "error", err)
	}
	select {
	case finalStatus := <-statusChan:
		logger.Info("process stopped gracefully", "backend", backendName, "pid", finalStatus.PID, "exit_code", finalStatus.Exit)
	case <-time.After(gracePeriod):
		pid := proc.Status().PID
		if pid <= 0 {
			logger.Error("skipping SIGKILL escalation: invalid pid", "backend", backendName, "pid", pid)
			return
		}
		logger.Warn("process did not stop within grace period, sending SIGKILL",
			"backend", backendName, "pid", pid, "grace_period", gracePeriod)
		// Kill the process group (handles subprocess trees where Setpgid was set)
		// and the process directly (reliable fallback when not in its own group).
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
			logger.Debug("process group kill failed (process may not be group leader)", "backend", backendName, "pid", pid, "error", err)
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			logger.Error("direct SIGKILL failed", "backend", backendName, "pid", pid, "error", err)
		}
		select {
		case finalStatus := <-statusChan:
			logger.Info("process force-stopped", "backend", backendName, "pid", finalStatus.PID, "exit_code", finalStatus.Exit)
		case <-time.After(postKillTimeout):
			logger.Error("process did not exit after SIGKILL, giving up", "backend", backendName, "pid", pid)
		}
	}
}
