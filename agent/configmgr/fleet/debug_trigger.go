//go:build debug

package fleet

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// StartDebugTrigger listens for OS signals to trigger debug actions.
// Only compiled when built with "-tags debug".
//
//	SIGUSR1 → force token rotation + reconnect
//	SIGUSR2 → log current token age/status
//
// The goroutine exits when ctx is cancelled; no explicit stop needed.
func StartDebugTrigger(ctx context.Context, logger *slog.Logger, dc DebugCredentials) {
	sigRotate := make(chan os.Signal, 1)
	sigPeek := make(chan os.Signal, 1)
	signal.Notify(sigRotate, syscall.SIGUSR1)
	signal.Notify(sigPeek, syscall.SIGUSR2)

	go func() {
		logger.Info("debug triggers active (SIGUSR1=rotate, SIGUSR2=peek)")
		for {
			select {
			case <-ctx.Done():
				signal.Stop(sigRotate)
				signal.Stop(sigPeek)
				return
			case <-sigRotate:
				logger.Warn("debug: SIGUSR1 received — forcing token rotation")
				if err := dc.RotateCredentials(ctx); err != nil {
					logger.Error("debug: token rotation failed", "error", err)
				}
			case <-sigPeek:
				dc.LogCredentials()
			}
		}
	}()
}
