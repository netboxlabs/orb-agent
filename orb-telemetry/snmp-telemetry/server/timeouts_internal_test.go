package server

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
)

func newInternalTestServer(t *testing.T) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	manager := policy.NewManager(context.Background(), logger, policy.Options{})
	return NewServer("127.0.0.1", 0, logger, manager, "1.0.0")
}

// Without finite read timeouts a client holds a connection, and the goroutine
// behind it, for as long as it likes by trickling a header or a sub-limit body.
// The body-size bound caps how many bytes arrive, not how long they take.
func TestNewServer_SetsFiniteTimeouts(t *testing.T) {
	srv := newInternalTestServer(t)

	assert.Equal(t, readHeaderTimeout, srv.httpServer.ReadHeaderTimeout)
	assert.Equal(t, readTimeout, srv.httpServer.ReadTimeout)
	assert.Equal(t, writeTimeout, srv.httpServer.WriteTimeout)
	assert.Equal(t, idleTimeout, srv.httpServer.IdleTimeout)

	for name, value := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.httpServer.ReadHeaderTimeout,
		"ReadTimeout":       srv.httpServer.ReadTimeout,
		"WriteTimeout":      srv.httpServer.WriteTimeout,
		"IdleTimeout":       srv.httpServer.IdleTimeout,
	} {
		assert.Positive(t, value, "%s must be finite", name)
	}
}

// A header read has to finish before the whole request does, or the narrower
// bound is the wider one and a trickling header is held for the full body
// window.
func TestReadHeaderTimeout_IsTheTighterBound(t *testing.T) {
	srv := newInternalTestServer(t)
	assert.Less(t, srv.httpServer.ReadHeaderTimeout, srv.httpServer.ReadTimeout)
}

// The write deadline covers the handler, not just the response write, so it has
// to outlast the slowest handler or a working request comes back truncated.
// DELETE /policies/:policy blocks on the runner's scheduler shutdown, which
// gocron bounds by its stop timeout plus two seconds, once for StopJobs and
// again for Shutdown: 24 seconds with gocron's ten second default.
func TestWriteTimeout_OutlastsTheSlowestHandler(t *testing.T) {
	srv := newInternalTestServer(t)

	const schedulerShutdownCeiling = 24 * time.Second
	assert.Greater(t, srv.httpServer.WriteTimeout, schedulerShutdownCeiling)
	// The write deadline starts when the request headers are read, so it also
	// has to cover a body arriving over the whole read window.
	assert.GreaterOrEqual(t, srv.httpServer.WriteTimeout, srv.httpServer.ReadTimeout)
}

// serveShortened serves the constructed server on a real listener with its read
// timeouts scaled to milliseconds, so a test need not wait out the real ones,
// and returns the address. It requires each field to be set first, so removing
// a timeout from NewServer fails here rather than being papered over. The
// values themselves are pinned by TestNewServer_SetsFiniteTimeouts.
func serveShortened(t *testing.T, srv *Server, d time.Duration) string {
	t.Helper()
	require.Positive(t, srv.httpServer.ReadHeaderTimeout, "ReadHeaderTimeout is unset")
	require.Positive(t, srv.httpServer.ReadTimeout, "ReadTimeout is unset")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv.httpServer.ReadHeaderTimeout = d
	srv.httpServer.ReadTimeout = d
	go func() { _ = srv.httpServer.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.httpServer.Shutdown(ctx)
	})
	return ln.Addr().String()
}

var statusLine4xx = regexp.MustCompile(`^HTTP/1\.1 4\d\d `)

// requireServerGaveUp asserts the server ended the exchange itself, by a 4xx or
// by closing. A read that expires on the client's own deadline means the server
// was still holding the connection, which is the defect.
func requireServerGaveUp(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		var netErr net.Error
		require.False(t, errors.As(err, &netErr) && netErr.Timeout(),
			"the server held the connection until the test's own deadline")
		return
	}
	assert.Regexp(t, statusLine4xx, line)
}

// A client that opens a connection and never finishes its headers is dropped
// rather than held. A well-formed request over the same listener still
// succeeds, so the timeout is not simply refusing everything.
func TestReadHeaderTimeout_DropsATricklingClient(t *testing.T) {
	srv := newInternalTestServer(t)
	addr := serveShortened(t, srv, 300*time.Millisecond)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte("GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n"))
	require.NoError(t, err)
	requireServerGaveUp(t, conn)

	resp, err := http.Get("http://" + addr + "/api/v1/status")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// A client that trickles a body under the size limit is dropped too: the body
// bound counts bytes, the read timeout counts seconds.
func TestReadTimeout_DropsATricklingBody(t *testing.T) {
	srv := newInternalTestServer(t)
	addr := serveShortened(t, srv, 300*time.Millisecond)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte("POST /api/v1/policies HTTP/1.1\r\nHost: localhost\r\n" +
		"Content-Type: application/x-yaml\r\nContent-Length: 4096\r\n\r\npolicies:\n"))
	require.NoError(t, err)
	requireServerGaveUp(t, conn)
}
