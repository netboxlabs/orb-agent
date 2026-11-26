package server

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
)

func newServerOn(t *testing.T, host string, port int) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	require.NoError(t, err)
	return NewServer(host, port, logger, manager, "1.0.0")
}

// An IPv6 literal carries the colons the port separator uses, so the address
// has to bracket the host; unbracketed, net.Listen refuses it.
func TestNewServer_ListenAddressBracketsIPv6(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"127.0.0.1", "127.0.0.1:8070"},
		{"localhost", "localhost:8070"},
		{"", ":8070"},
		{"::1", "[::1]:8070"},
		{"::", "[::]:8070"},
		{"2001:db8::1", "[2001:db8::1]:8070"},
		{"fe80::1%eth0", "[fe80::1%eth0]:8070"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, newServerOn(t, tt.host, 8070).httpServer.Addr, "host %q", tt.host)
	}
}

// The address has to be one the listener accepts. A loopback the platform
// cannot bind is skipped, established with an address known to parse.
func TestNewServer_ListenAddressIsBindable(t *testing.T) {
	for host, bracketed := range map[string]string{"127.0.0.1": "127.0.0.1:0", "::1": "[::1]:0"} {
		probe, err := net.Listen("tcp", bracketed)
		if err != nil {
			t.Logf("skipping %s, the platform will not bind it: %v", host, err)
			continue
		}
		require.NoError(t, probe.Close())

		srv := newServerOn(t, host, 0)
		ln, err := net.Listen("tcp", srv.httpServer.Addr)
		require.NoError(t, err, "host %q rendered as %q", host, srv.httpServer.Addr)
		require.NoError(t, ln.Close())
	}
}
