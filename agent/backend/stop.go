package backend

import (
	"log/slog"
	"syscall"
	"time"
)

// DefaultStopGracePeriod is how long to wait for a process to exit after SIGTERM
// before sending SIGKILL to its process group.
const DefaultStopGracePeriod = 5 * time.Second

// StopProcess sends SIGTERM via proc.Stop(), waits up to gracePeriod for the
// process to exit, then escalates to SIGKILL on the process group if needed.
// It always drains statusChan before returning.
func StopProcess(logger *slog.Logger, proc Commander, statusChan <-chan CmdStatus, gracePeriod time.Duration, backendName string) {
	if err := proc.Stop(); err != nil {
		logger.Error("SIGTERM error", "backend", backendName, "error", err)
	}
	select {
	case finalStatus := <-statusChan:
		logger.Info("process stopped gracefully", "backend", backendName, "pid", finalStatus.PID, "exit_code", finalStatus.Exit)
	case <-time.After(gracePeriod):
		pid := proc.Status().PID
		logger.Warn("process did not stop within grace period, sending SIGKILL",
			"backend", backendName, "pid", pid, "grace_period", gracePeriod)
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
			logger.Error("SIGKILL failed", "backend", backendName, "pid", pid, "error", err)
		}
		finalStatus := <-statusChan
		logger.Info("process force-stopped", "backend", backendName, "pid", finalStatus.PID, "exit_code", finalStatus.Exit)
	}
}
