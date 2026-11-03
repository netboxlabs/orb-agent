package policy

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// An early stream failure keeps the target's gRPC status readable, so the
// code that refused the stream is not lost behind the sentinel.
func TestEarlyStreamFailureKeepsTheStatusCode(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Runner{ctx: ctx, logger: slog.Default(), states: map[string]*targetState{}}

	errs := make(chan error, 1)
	errs <- status.Error(codes.InvalidArgument, "on_change not supported")
	deb := NewDebouncer(0)
	defer deb.Stop()
	got := r.streamLoop("h", base, 0, make(chan gnmi.Notification), errs, mapping.NewDeviceModel(), deb, func() {})

	require.ErrorIs(t, got, errEarlyStreamFailure)
	require.Equal(t, codes.InvalidArgument, status.Code(got))
}
