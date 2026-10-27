package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPickListenPort hands each start the next of ports, and records the
// hosts it was asked to pick on.
func stubPickListenPort(t *testing.T, ports ...string) *[]string {
	t.Helper()
	var hosts []string
	orig := PickListenPort
	PickListenPort = func(_ context.Context, host string) (string, error) {
		hosts = append(hosts, host)
		require.NotEmpty(t, ports, "more starts than ports to pick")
		port := ports[0]
		ports = ports[1:]
		return port, nil
	}
	t.Cleanup(func() { PickListenPort = orig })
	return &hosts
}

func TestAPIPort_ConfiguredPortIsKept(t *testing.T) {
	stubPickListenPort(t)
	var p APIPort
	p.Configure("9000", "localhost", "8072")
	assert.Equal(t, "9000", p.Get(), "the API calls use the configured port before any start")

	port, err := p.ForStart(context.Background(), "localhost")
	require.NoError(t, err)
	assert.Equal(t, "9000", port)
	assert.Equal(t, "9000", p.Get())
}

func TestAPIPort_HostBeyondLoopbackKeepsTheDefault(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::", "192.0.2.10", "agent.example.com"} {
		t.Run(host, func(t *testing.T) {
			stubPickListenPort(t)
			var p APIPort
			p.Configure("", host, "8072")
			assert.Equal(t, "8072", p.Get())

			port, err := p.ForStart(context.Background(), host)
			require.NoError(t, err)
			assert.Equal(t, "8072", port, "whatever reaches the backend beyond loopback has to know its port")
		})
	}
}

func TestAPIPort_LoopbackHostPicksAPortAtEachStart(t *testing.T) {
	for _, host := range []string{"localhost", "LocalHost", "127.0.0.1", "127.0.0.2", "::1"} {
		t.Run(host, func(t *testing.T) {
			hosts := stubPickListenPort(t, "40001", "40002")
			var p APIPort
			p.Configure("", host, "8072")
			assert.Empty(t, p.Get(), "no port before the first start picks one")

			port, err := p.ForStart(context.Background(), host)
			require.NoError(t, err)
			assert.Equal(t, "40001", port)
			assert.Equal(t, "40001", p.Get())

			port, err = p.ForStart(context.Background(), host)
			require.NoError(t, err)
			assert.Equal(t, "40002", port, "each start picks anew, the last port may have been taken since")
			assert.Equal(t, "40002", p.Get())
			assert.Equal(t, []string{host, host}, *hosts, "the port is picked on the host the backend listens on")
		})
	}
}

// A restart configures the backend again while its process still serves on
// the picked port; the API calls keep reaching it until the next start.
func TestAPIPort_ReconfigureKeepsThePickedPort(t *testing.T) {
	stubPickListenPort(t, "40001")
	var p APIPort
	p.Configure("", "localhost", "8072")
	_, err := p.ForStart(context.Background(), "localhost")
	require.NoError(t, err)

	p.Configure("", "localhost", "8072")
	assert.Equal(t, "40001", p.Get())
}

func TestAPIPort_StartBeforeConfigureIsRefused(t *testing.T) {
	stubPickListenPort(t)
	var p APIPort
	_, err := p.ForStart(context.Background(), "localhost")
	require.Error(t, err)
	assert.Empty(t, p.Get())
}

func TestAPIPort_PickFailureLeavesThePortAlone(t *testing.T) {
	stubPickListenPort(t, "40001")
	var p APIPort
	p.Configure("", "localhost", "8072")
	_, err := p.ForStart(context.Background(), "localhost")
	require.NoError(t, err)

	PickListenPort = func(context.Context, string) (string, error) {
		return "", fmt.Errorf("%w: nothing free", ErrListenAddrInUse)
	}
	_, err = p.ForStart(context.Background(), "localhost")
	assert.ErrorIs(t, err, ErrListenAddrInUse, "the environment refused the start, not the binary")
	assert.Equal(t, "40001", p.Get())
}

func TestPickListenPort_FreeOnEveryAddressOfTheHost(t *testing.T) {
	port, err := PickListenPort(context.Background(), "localhost")
	require.NoError(t, err)
	n, err := net.LookupPort("tcp", port)
	require.NoError(t, err)
	assert.NotZero(t, n)

	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), "localhost")
	require.NoError(t, err)
	for _, h := range resolvedListenHosts(ips) {
		l, err := net.Listen("tcp", net.JoinHostPort(h, port))
		require.NoError(t, err, "the picked port is free on %s", h)
		require.NoError(t, l.Close())
	}
}

func stubReserveFreePort(t *testing.T, fn func(context.Context, string) (string, error)) {
	t.Helper()
	orig := reserveFreePort
	reserveFreePort = fn
	t.Cleanup(func() { reserveFreePort = orig })
}

// A port free on the first address the host resolves to can be held on
// another; the pick tries again rather than fail the start.
func TestPickListenPort_RetriesAPortHeldOnAnotherAddress(t *testing.T) {
	var calls int
	stubReserveFreePort(t, func(_ context.Context, addr string) (string, error) {
		calls++
		host, port, err := net.SplitHostPort(addr)
		require.NoError(t, err)
		assert.Equal(t, "localhost", host)
		assert.Equal(t, "0", port)
		if calls < 3 {
			return "", fmt.Errorf("%w: held on another address", ErrListenAddrInUse)
		}
		return "localhost:40003", nil
	})

	port, err := PickListenPort(context.Background(), "localhost")
	require.NoError(t, err)
	assert.Equal(t, "40003", port)
	assert.Equal(t, 3, calls)
}

func TestPickListenPort_GivesUp(t *testing.T) {
	var calls int
	stubReserveFreePort(t, func(context.Context, string) (string, error) {
		calls++
		return "", fmt.Errorf("%w: held", ErrListenAddrInUse)
	})

	_, err := PickListenPort(context.Background(), "localhost")
	assert.ErrorIs(t, err, ErrListenAddrInUse)
	assert.Equal(t, freePortAttempts, calls)
}

func TestPickListenPort_CancelledStartPicksNothing(t *testing.T) {
	stubReserveFreePort(t, func(context.Context, string) (string, error) {
		t.Fatal("a cancelled start must not pick a port")
		return "", nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := PickListenPort(ctx, "localhost")
	assert.True(t, errors.Is(err, context.Canceled), "the cancellation is returned: %v", err)
}

func TestLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":         true,
		"LOCALHOST":         true,
		"127.0.0.1":         true,
		"127.1.2.3":         true,
		"::1":               true,
		"":                  false,
		"0.0.0.0":           false,
		"::":                false,
		"192.0.2.10":        false,
		"agent.example.com": false,
		"[::1]":             false,
	} {
		assert.Equal(t, want, LoopbackHost(host), host)
	}
}
