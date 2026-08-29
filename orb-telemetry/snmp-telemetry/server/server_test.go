package server_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
