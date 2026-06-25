package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccessorsNeverNilWithoutOTEL(t *testing.T) {
	// No SetupMetricsExport called -> generic GetCounter returns nil; the gNMI
	// accessors must still return usable (noop) instruments and never panic.
	require.NotPanics(t, func() {
		GetTargetsActive().Add(context.Background(), 1)
		GetSubscriptionsActive().Add(context.Background(), -1)
		GetReconnects().Add(context.Background(), 1)
		GetNotifications().Add(context.Background(), 1)
		GetNotificationsDropped().Add(context.Background(), 1)
		GetCapabilityErrors().Add(context.Background(), 1)
		GetFlushes().Add(context.Background(), 1)
		GetIngestErrors().Add(context.Background(), 1)
		GetModeFallbacks().Add(context.Background(), 1)
		GetProfileFallbacks().Add(context.Background(), 1)
		GetRemovalsBlocked().Add(context.Background(), 3)
		GetFlushSkippedNoIdentity().Add(context.Background(), 1)
	})
}
