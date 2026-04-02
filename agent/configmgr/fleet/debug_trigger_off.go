//go:build !debug

package fleet

import (
	"context"
	"log/slog"
)

// StartDebugTrigger is a no-op when built without "-tags debug".
func StartDebugTrigger(_ context.Context, _ *slog.Logger, _ DebugCredentials) {}
