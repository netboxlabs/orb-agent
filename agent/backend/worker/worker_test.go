package worker_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

func TestWorkerBackendStart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/status":
			response := map[string]any{
				"version":      "1.3.4",
				"start_time":   "2023-10-01T12:00:00Z",
				"up_time":      123.456,
				"up_time_min":  123.456,
				"up_time_secs": 123.456,
			}
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(response))
		case r.URL.Path == "/api/v1/capabilities":
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"capability": true}))
		case strings.Contains(r.URL.Path, "/api/v1/policies"):
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"status":  "success",
				"message": "Policy operation successful",
			}))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	createExecutable(t, "orb-worker")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	overrideNewCmdOptions(t, mockCmd, func(options backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "orb-worker", name, "Expected command name to be orb-worker")
		assert.False(t, options.Buffered, "Expected buffered to be false")
		assert.True(t, options.Streaming, "Expected streaming to be true")
		assert.Contains(t, args, "--host", "Expected args to contain host flag")
		assert.Contains(t, args, serverURL.Hostname(), "Expected args to contain host value")
		assert.Contains(t, args, "--port", "Expected args to contain port flag")
		assert.Contains(t, args, serverURL.Port(), "Expected args to contain port value")
		assert.Contains(t, args, "--diode-target", "Expected args to contain diode target flag")
		assert.Contains(t, args, "worker-target", "Expected args to contain diode target value")
		assert.Contains(t, args, "--diode-client-id", "Expected args to contain diode client id flag")
		assert.Contains(t, args, "worker-client", "Expected args to contain diode client id value")
		assert.Contains(t, args, "--diode-client-secret", "Expected args to contain diode client secret flag")
		assert.Contains(t, args, "worker-secret", "Expected args to contain diode client secret value")
		assert.Contains(t, args, "--diode-app-name-prefix", "Expected args to contain diode app name prefix flag")
		assert.Contains(t, args, "worker-agent", "Expected args to contain diode app name prefix value")
		assert.Contains(t, args, "--otel-endpoint", "Expected args to contain otel endpoint flag")
		assert.Contains(t, args, "collector:4317", "Expected args to contain otel endpoint value")
	})

	assert.True(t, worker.Register(), "Failed to register Worker backend")
	assert.True(t, backend.HaveBackend("worker"), "Failed to get Worker backend")

	be := backend.GetBackend("worker")

	assert.Equal(t, backend.Unknown, be.GetInitialState())

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "collector:4317"
	commons.Diode.Target = "default-target"
	commons.Diode.ClientID = "default-client"
	commons.Diode.ClientSecret = "default-secret"
	commons.Diode.AgentName = "default-agent"
	commons.Diode.DryRunOutputDir = "/tmp/default"

	err = be.Configure(logger, repo, map[string]any{
		"host":               serverURL.Hostname(),
		"port":               serverURL.Port(),
		"target":             "worker-target",
		"client_id":          "worker-client",
		"client_secret":      "worker-secret",
		"agent_name":         "worker-agent",
		"dry_run":            false,
		"dry_run_output_dir": "/tmp/worker",
	}, commons)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, be.Start(ctx, cancel))

	startTime := be.GetStartTime()
	assert.False(t, startTime.IsZero(), "Expected start time to be set")

	status, _, err := be.GetRunningStatus()
	require.NoError(t, err)
	assert.Equal(t, backend.Running, status, "Expected backend to be running")

	capabilities, err := be.GetCapabilities()
	require.NoError(t, err)
	assert.Equal(t, true, capabilities["capability"], "Expected capability to be true")

	version, err := be.Version()
	require.NoError(t, err)
	assert.Equal(t, "1.3.4", version, "Expected version to match response")

	data := policies.PolicyData{
		ID:   "dummy-policy-id",
		Name: "dummy-policy-name",
		Data: map[string]any{"key": "value"},
	}
	require.NoError(t, be.ApplyPolicy(data, false))

	updatedData := policies.PolicyData{
		ID:   data.ID,
		Name: "dummy-policy-updated",
		Data: map[string]any{"key": "value"},
		PreviousPolicyData: &policies.PolicyData{
			Name: data.Name,
		},
	}
	require.NoError(t, be.ApplyPolicy(updatedData, true))

	require.NoError(t, be.FullReset(ctx))

	mockCmd.AssertExpectations(t)
}

func TestWorkerUsesOtelTargetWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/status" {
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"version": "1.0.0"}))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	createExecutable(t, "orb-worker")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 4243)

	otelEndpoint := "collector:4317"
	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "orb-worker", name)
		assert.Contains(t, args, "--diode-target")
		assert.Contains(t, args, otelEndpoint)
		assert.NotContains(t, args, "--diode-client-id")
		assert.NotContains(t, args, "--diode-client-secret")
		assert.NotContains(t, args, "worker-client")
		assert.NotContains(t, args, "worker-secret")
		assert.NotContains(t, args, "********")
	})

	assert.True(t, worker.Register())
	assert.True(t, backend.HaveBackend("worker"))

	be := backend.GetBackend("worker")

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = otelEndpoint
	commons.Diode.ClientID = "default-client"
	commons.Diode.ClientSecret = "default-secret"
	commons.Diode.AgentName = "worker-agent"

	err = be.Configure(logger, repo, map[string]any{
		"host":          serverURL.Hostname(),
		"port":          serverURL.Port(),
		"client_id":     "worker-client",
		"client_secret": "worker-secret",
		"agent_name":    "worker-agent",
	}, commons)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, be.Start(ctx, cancel))
	require.NoError(t, be.Stop(ctx))

	mockCmd.AssertExpectations(t)
}

func TestWorkerGetRunningStatusAPIFailure(t *testing.T) {
	var statusCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/status":
			if statusCalls.Add(1) == 1 {
				response := map[string]any{
					"version":     "1.3.4",
					"start_time":  "2023-10-01T12:00:00Z",
					"up_time_min": 1.5,
				}
				w.WriteHeader(http.StatusOK)
				require.NoError(t, json.NewEncoder(w).Encode(response))
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, err := w.Write([]byte(`{"detail":"unavailable"}`))
			require.NoError(t, err)
		case strings.Contains(r.URL.Path, "/api/v1/policies"):
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"status":  "success",
				"message": "Policy operation successful",
			}))
		default:
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{}`))
			require.NoError(t, err)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	createExecutable(t, "orb-worker")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 54321)

	overrideNewCmdOptions(t, mockCmd, nil)

	assert.True(t, worker.Register(), "Failed to register Worker backend")

	be := backend.GetBackend("worker")

	err = be.Configure(logger, repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, config.BackendCommons{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, be.Start(ctx, cancel))

	status, message, err := be.GetRunningStatus()
	assert.Equal(t, backend.BackendError, status, "Expected backend to report API failure")
	assert.Equal(t, "process running, REST API unavailable", message)
	assert.Error(t, err)
	require.NoError(t, be.Stop(ctx))

	mockCmd.AssertExpectations(t)
}

func TestWorkerBackendCompleted(t *testing.T) {
	mockCmd := &mocks.MockCmd{}
	mocks.SetupCompletedProcess(mockCmd, 0, nil)

	overrideNewCmdOptions(t, mockCmd, nil)

	assert.True(t, worker.Register(), "Failed to register Worker backend")
	assert.True(t, backend.HaveBackend("worker"), "Failed to get Worker backend")

	be := backend.GetBackend("worker")

	require.NoError(t, be.Configure(slog.Default(), nil, map[string]any{
		"host": "invalid-host",
	}, config.BackendCommons{}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := be.Start(ctx, cancel)
	assert.Error(t, err)

	mockCmd.AssertExpectations(t)
}

func createExecutable(t *testing.T, name string) {
	t.Helper()

	tempDir := t.TempDir()
	binaryPath := path.Join(tempDir, name)

	file, err := os.Create(binaryPath)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	require.NoError(t, os.Chmod(binaryPath, 0o755))

	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+originalPath)
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
