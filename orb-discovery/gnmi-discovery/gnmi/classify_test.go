package gnmi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTransient(t *testing.T) {
	for _, c := range []codes.Code{codes.Unauthenticated, codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded, codes.Aborted} {
		require.True(t, Transient(status.Error(c, "x")), c.String())
		require.True(t, Transient(fmt.Errorf("gnmi get: %w", status.Error(c, "x"))), "wrapped %s", c)
	}
	for _, c := range []codes.Code{codes.NotFound, codes.InvalidArgument, codes.Unimplemented, codes.FailedPrecondition, codes.PermissionDenied, codes.Unknown, codes.Internal, codes.Canceled} {
		require.False(t, Transient(status.Error(c, "x")), c.String())
	}
	require.True(t, Transient(fmt.Errorf("probe: %w", context.DeadlineExceeded)))
	require.False(t, Transient(errors.New("tls: handshake failure")))
	require.False(t, Transient(nil))
}
