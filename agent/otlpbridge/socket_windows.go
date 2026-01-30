//go:build windows

package otlpbridge

import (
	"context"
	"net"
)

// listen creates a TCP listener using standard net.Listen.
// Windows doesn't need SO_REUSEADDR configuration like Unix systems do.
func listen(ctx context.Context, addr string) (net.Listener, error) {
	// On Windows, we use standard Listen without SO_REUSEADDR
	// Windows handles port reuse differently and doesn't have the same TIME_WAIT issues
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", addr)
}
