//go:build unix

package otlpbridge

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// newListenConfig returns a net.ListenConfig with SO_REUSEADDR enabled for faster port reuse.
// This is particularly important for docker restart scenarios where ports may be in TIME_WAIT.
func newListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockOptErr error
			if err := c.Control(func(fd uintptr) {
				// Enable SO_REUSEADDR to allow binding to TIME_WAIT sockets
				sockOptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return sockOptErr
		},
	}
}

// listen creates a TCP listener with platform-specific socket options.
func listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := newListenConfig()
	return lc.Listen(ctx, "tcp", addr)
}
