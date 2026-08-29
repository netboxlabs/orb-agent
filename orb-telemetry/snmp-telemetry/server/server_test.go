package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/server"
)

func newTestServer(t *testing.T) *server.Server {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	manager := policy.NewManager(ctx, logger, "")
	return server.NewServer("localhost", 8078, logger, manager, "1.0.0")
}

func TestGetPolicies_Empty(t *testing.T) {
	srv := newTestServer(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	srv.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `[]`, w.Body.String())
}

func TestGetPolicies_WithPolicy(t *testing.T) {
	srv := newTestServer(t)

	// A policy-supplied profiles_dir may not walk upward, so the sibling
	// directory this test overlays is named absolutely.
	profilesDir, err := filepath.Abs("../profiles/snmp-profiles")
	require.NoError(t, err)

	body := fmt.Appendf(nil, `
policies:
  my-policy:
    config:
      metrics_interval: 60
      profiles_dir: %s
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
      targets:
        - host: 192.168.1.1
`, profilesDir)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	srv.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"my-policy"`)
	assert.Contains(t, w.Body.String(), `"running"`)

	srv.Stop()
}

// The agent polls /status on a timer while the API is otherwise in use, so two
// handlers run at once. Computing the uptime on the shared status struct while
// copying that struct into the response is a data race, which this test trips
// under -race.
func TestGetStatus_ConcurrentRequests(t *testing.T) {
	srv := newTestServer(t)

	const requests = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/v1/status", nil)
			srv.Router().ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)

			var got map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, "1.0.0", got["version"])
			assert.NotNil(t, got["up_time_seconds"])
		}()
	}
	close(start)
	wg.Wait()
}

// A policy with no targets starts no jobs, so accepting one leaves the operator
// with a policy the API reports as running and that collects nothing.
func TestCreatePolicy_RejectsPolicyWithNoTargets(t *testing.T) {
	srv := newTestServer(t)

	body := []byte(`
policies:
  my-policy:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
`)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "no targets")

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	srv.Router().ServeHTTP(w, req)
	assert.JSONEq(t, `[]`, w.Body.String())
}

// The documented policy body limit. Hard-coded rather than read from the
// package so a change to the constant has to be a deliberate contract change.
const policyBodyLimit = 1 << 20

// padPolicyTo grows a policy document to exactly n bytes with YAML comment
// lines, which the parser ignores.
func padPolicyTo(t *testing.T, body []byte, n int) []byte {
	t.Helper()
	require.Less(t, len(body), n, "policy is already at or over the target size")

	pad := make([]byte, 0, n-len(body))
	for len(pad) < n-len(body) {
		pad = append(pad, '#')
	}
	// The final byte closes the trailing comment line.
	pad[len(pad)-1] = '\n'
	return append(body, pad...)
}

func validPolicy(t *testing.T) []byte {
	t.Helper()
	profilesDir, err := filepath.Abs("../profiles/snmp-profiles")
	require.NoError(t, err)
	return fmt.Appendf(nil, `
policies:
  my-policy:
    config:
      metrics_interval: 60
      profiles_dir: %s
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
      targets:
        - host: 192.168.1.1
`, profilesDir)
}

func postPolicy(t *testing.T, srv *server.Server, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	require.NoError(t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	srv.Router().ServeHTTP(w, req)
	return w
}

// io.ReadAll buffers the whole body before parsing, so an unbounded body lets a
// single request exhaust the process. The listener defaults to 0.0.0.0.
func TestCreatePolicy_RejectsBodyOverTheLimit(t *testing.T) {
	srv := newTestServer(t)

	w := postPolicy(t, srv, "application/x-yaml", padPolicyTo(t, validPolicy(t), policyBodyLimit+1))

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "1048576")

	// The oversized policy must not have started.
	w = httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	require.NoError(t, err)
	srv.Router().ServeHTTP(w, req)
	assert.JSONEq(t, `[]`, w.Body.String())
}

// The bound is off by one if it rejects a body of exactly the documented size.
func TestCreatePolicy_AcceptsBodyAtTheLimit(t *testing.T) {
	srv := newTestServer(t)
	t.Cleanup(srv.Stop)

	body := padPolicyTo(t, validPolicy(t), policyBodyLimit)
	require.Len(t, body, policyBodyLimit)

	w := postPolicy(t, srv, "application/x-yaml", body)

	require.Equal(t, http.StatusCreated, w.Code)
}

// An endless chunked body never reaches io.ReadAll's end, so the read has to be
// stopped by the bound rather than by the sender.
func TestCreatePolicy_StopsReadingAnEndlessBody(t *testing.T) {
	srv := newTestServer(t)

	// Far more than the bound, so an unbounded read buffers all of it.
	endless := io.LimitReader(zeroes{}, 8*policyBodyLimit)

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/api/v1/policies", endless)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// zeroes is an endless source of comment bytes.
type zeroes struct{}

func (zeroes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '#'
	}
	return len(p), nil
}
