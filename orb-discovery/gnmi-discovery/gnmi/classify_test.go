package gnmi

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A device with slow AAA gets 30 s to set up before it is treated as silent.
func TestSetupTimeoutDefault(t *testing.T) {
	require.Equal(t, 30*time.Second, SetupTimeout)
	require.Equal(t, SetupTimeout, (&gnmicSession{}).probeDeadline())
	require.Equal(t, time.Second, (&gnmicSession{setupTimeout: time.Second}).probeDeadline())
}

// The dial spec's setup timeout reaches the session.
func TestDialCarriesTheSetupTimeout(t *testing.T) {
	addr := startTestGNMIServer(t, &testGNMIServer{})
	sess, err := (&GnmicDialer{}).Dial(context.Background(), TargetSpec{Host: addr, Insecure: true, SetupTimeout: 2 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	require.Equal(t, 2*time.Second, sess.(*gnmicSession).probeDeadline())
}

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
