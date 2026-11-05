package server_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/server"
)

// A policy edited while one of its crawls is still walking is replaced the way
// the agent replaces it, DELETE then POST: the DELETE stops the crawl and
// answers at once, and the POST starts the new version under the same name.
func TestServerReplacesABusyPolicy(t *testing.T) {
	port, requested := silentSNMPAgent(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	policyManager, err := policy.NewManager(context.Background(), logger, new(MockClient), nil)
	require.NoError(t, err)
	srv := server.NewServer("localhost", 0, logger, policyManager, "1.0.0")
	t.Cleanup(srv.Stop)

	body := []byte(fmt.Sprintf(`
policies:
  busy-policy:
    config:
      timeout: 120
      snmp_timeout: 60
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 127.0.0.1
          port: %d
`, port))
	require.Equal(t, http.StatusCreated, serve(srv, http.MethodPost, "/api/v1/policies", body).Code)
	select {
	case <-requested:
	case <-time.After(10 * time.Second):
		t.Fatal("the policy never started crawling its target")
	}

	start := time.Now()
	w := serve(srv, http.MethodDelete, "/api/v1/policies/busy-policy", nil)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Less(t, time.Since(start), 5*time.Second, "the DELETE waited for the crawl")

	w = serve(srv, http.MethodPost, "/api/v1/policies", body)
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}

func serve(srv *server.Server, method, path string, body []byte) *httptest.ResponseRecorder {
	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, request)
	return w
}

// silentSNMPAgent listens on a local port and answers nothing, so a walk of it
// lasts until the walk is cancelled or times out. It returns the port and a
// channel closed when the first request arrives.
func silentSNMPAgent(t *testing.T) (uint16, <-chan struct{}) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	requested := make(chan struct{})
	go func() {
		var once sync.Once
		buf := make([]byte, 4096)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				return
			}
			once.Do(func() { close(requested) })
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port), requested
}
