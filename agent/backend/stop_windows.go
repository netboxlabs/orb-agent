//go:build windows

package backend

import (
	"log/slog"
	"time"
)

// DefaultStopGracePeriod is how long to wait for a process to exit after SIGTERM
// before sending SIGKILL to its process group.
const DefaultStopGracePeriod = 5 * time.Second

// StopProcess on Windows only sends SIGTERM and waits for the process to exit;
// SIGKILL escalation via process-group kill is not supported on this platform.
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
		logger.Error("process did not stop within grace period (SIGKILL escalation not supported on Windows)", "backend", backendName)
	}
}
