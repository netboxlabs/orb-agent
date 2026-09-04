package snmptelemetry_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/backend/snmptelemetry"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

type statusResponse struct {
	Version       string `json:"version"`
	StartTime     string `json:"start_time"`
	UpTimeSeconds int64  `json:"up_time_seconds"`
}

// apiRecorder answers the binary's API and records every policy request.
// Handlers run on the server's goroutines, so failures are reported with
// t.Error rather than require, which must not leave the test goroutine.
type apiRecorder struct {
	mu       sync.Mutex
	requests []recorded
}

type recorded struct {
	method      string
	path        string
	contentType string
	body        string
}

func (a *apiRecorder) handler(t *testing.T) http.HandlerFunc {
	encode := func(w http.ResponseWriter, v any) {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Error(err)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/status":
			encode(w, statusResponse{Version: "1.0.0", StartTime: "2026-09-04T12:00:00Z", UpTimeSeconds: 42})
		case r.URL.Path == "/api/v1/capabilities":
			// The binary's body: {"capabilities": ["targets"]}.
			encode(w, map[string]any{"capabilities": []string{"targets"}})
		case strings.HasPrefix(r.URL.Path, "/api/v1/policies"):
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			a.mu.Lock()
			a.requests = append(a.requests, recorded{
				method: r.Method, path: r.URL.EscapedPath(),
				contentType: r.Header.Get("Content-Type"), body: string(body),
			})
			a.mu.Unlock()
			encode(w, map[string]any{"message": "ok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (a *apiRecorder) policyRequests() []recorded {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recorded(nil), a.requests...)
}

func TestSnmpTelemetryBackendStart(t *testing.T) {
	rec := &apiRecorder{}
	server := httptest.NewServer(rec.handler(t))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	overrideNewCmdOptions(t, mockCmd, func(options backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "snmp-telemetry", name)
		assert.False(t, options.Buffered)
		assert.True(t, options.Streaming)
		assert.Equal(t, []string{
			"--host", serverURL.Hostname(),
			"--port", serverURL.Port(),
			"--otel-endpoint", "grpc://collector:4317",
			"--log-level", "INFO",
		}, args)
	})

	assert.True(t, snmptelemetry.Register())
	assert.True(t, backend.HaveBackend("snmp_telemetry"))

	be := backend.GetBackend("snmp_telemetry")
	assert.Equal(t, backend.Unknown, be.GetInitialState())

	var commons config.BackendCommons
	commons.Otlp.Grpc = "grpc://collector:4317"

	require.NoError(t, be.Configure(logger, repo, map[string]any{
		"host":      serverURL.Hostname(),
		"port":      serverURL.Port(),
		"log_level": "INFO",
	}, commons, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, be.Start(ctx, cancel))

	version, err := be.Version()
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", version)

	caps, err := be.GetCapabilities()
	require.NoError(t, err)
	assert.Equal(t, []any{"targets"}, caps["capabilities"])

	status, msg, err := be.GetRunningStatus()
	require.NoError(t, err)
	assert.Equal(t, backend.Running, status)
	assert.Empty(t, msg)

	// A name with a slash: PathEscape turns it into one path segment,
	// core%2Fmetrics, while the raw name would be a different route.
	policy := policies.PolicyData{
		ID:   "id-1",
		Name: "core/metrics",
		Data: map[string]any{
			"config": map[string]any{"metrics_interval": 60},
			"scope":  map[string]any{"targets": []any{map[string]any{"host": "10.0.0.1"}}},
		},
	}
	require.NoError(t, be.ApplyPolicy(policy, false))

	renamed := policies.PolicyData{ID: "id-1", Name: "core", Data: policy.Data, PreviousPolicyData: &policy}
	require.NoError(t, be.ApplyPolicy(renamed, true))

	require.NoError(t, be.RemovePolicy(policies.PolicyData{ID: "id-1", Name: "core"}))

	reqs := rec.policyRequests()
	require.Len(t, reqs, 4, "apply, then remove-and-apply for the update, then remove")

	assert.Equal(t, http.MethodPost, reqs[0].method)
	assert.Equal(t, "/api/v1/policies", reqs[0].path)
	assert.Equal(t, "application/x-yaml", reqs[0].contentType)
	assert.Contains(t, reqs[0].body, "policies:\n    core/metrics:\n")
	assert.Contains(t, reqs[0].body, "metrics_interval: 60")

	assert.Equal(t, http.MethodDelete, reqs[1].method)
	assert.Equal(t, "/api/v1/policies/core%2Fmetrics", reqs[1].path, "an update removes the previous name first, escaped as one segment")

	assert.Equal(t, http.MethodPost, reqs[2].method)
	assert.Contains(t, reqs[2].body, "policies:\n    core:\n")

	assert.Equal(t, http.MethodDelete, reqs[3].method)
	assert.Equal(t, "/api/v1/policies/core", reqs[3].path, "a remove without rename history uses the current name")

	require.NoError(t, be.FullReset(ctx))

	// With the API gone the process still runs, and the backend says so.
	server.Close()
	status, msg, err = be.GetRunningStatus()
	assert.Error(t, err)
	assert.Equal(t, backend.BackendError, status)
	assert.Equal(t, "process running, REST API unavailable", msg)

	// No trailing Stop: the mock delivers exactly one process status, which
	// FullReset's Stop consumed. A second Stop would wait out the whole grace
	// on an empty channel and then SIGKILL the mock's PID on this host.
	mockCmd.AssertExpectations(t)
}

func TestSnmpTelemetryBackendCompleted(t *testing.T) {
	mockCmd := &mocks.MockCmd{}
	mocks.SetupCompletedProcess(mockCmd, 0, nil)

	overrideNewCmdOptions(t, mockCmd, nil)

	assert.True(t, snmptelemetry.Register())
	be := backend.GetBackend("snmp_telemetry")

	var commons config.BackendCommons
	commons.Otlp.Grpc = "collector:4317"
	require.NoError(t, be.Configure(slog.Default(), nil, map[string]any{"host": "invalid-host"}, commons, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	assert.Error(t, be.Start(ctx, cancel))

	mockCmd.AssertExpectations(t)
}

func TestSnmpTelemetryBackendRefusesToConfigureWithoutOTLP(t *testing.T) {
	assert.True(t, snmptelemetry.Register())
	be := backend.GetBackend("snmp_telemetry")

	err := be.Configure(slog.Default(), nil, map[string]any{}, config.BackendCommons{}, nil)
	require.Error(t, err)
	assert.Equal(t, "snmp_telemetry: common.otlp.grpc is required, the backend exports its metrics over OTLP", err.Error())
}

func overrideNewCmdOptions(t *testing.T, cmd backend.Commander, assertFn func(options backend.CmdOptions, name string, args []string)) {
	t.Helper()

	original := backend.NewCmdOptions
	backend.NewCmdOptions = func(options backend.CmdOptions, name string, args ...string) backend.Commander {
		if assertFn != nil {
			assertFn(options, name, args)
		}
		return cmd
	}

	t.Cleanup(func() {
		backend.NewCmdOptions = original
	})
}
