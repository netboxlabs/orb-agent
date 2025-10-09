package pktvisor_test

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
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

type StatusResponse struct {
	StartTime string  `json:"start_time"`
	Version   string  `json:"version"`
	UpTime    float64 `json:"up_time"`
}

func TestPktvisorBackendStart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/metrics/app":
			var response pktvisor.AppInfo
			response.App.Version = "1.2.3"
			response.App.UpTimeMin = 42.5
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(response))
		case r.URL.Path == "/api/v1/taps":
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"iface": "eth0"}))
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

	createExecutable(t, "pktvisord")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	overrideNewCmdOptions(t, mockCmd, func(options backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "pktvisord", name, "Expected command name to be pktvisord")
		assert.False(t, options.Buffered, "Expected buffered to be false")
		assert.True(t, options.Streaming, "Expected streaming to be true")
		assert.Contains(t, args, "--admin-api", "Expected args to contain admin-api flag")
		assert.Contains(t, args, "--config", "Expected args to contain config flag")
		assert.Contains(t, args, "--otel", "Expected args to contain otel flag")
		assert.Contains(t, args, "--otel-host", "Expected args to contain otel host flag")
		assert.Contains(t, args, serverURL.Hostname(), "Expected args to contain otel host value")
		assert.Contains(t, args, "--otel-port", "Expected args to contain otel port flag")
		assert.Contains(t, args, serverURL.Port(), "Expected args to contain otel port value")
	})

	assert.True(t, pktvisor.Register(), "Failed to register Pktvisor backend")
	assert.True(t, backend.HaveBackend("pktvisor"), "Failed to get Pktvisor backend")

	be := backend.GetBackend("pktvisor")

	assert.Equal(t, backend.Unknown, be.GetInitialState())

	commons := config.BackendCommons{}
	commons.Otlp.HTTP = server.URL
	commons.Otlp.AgentLabels = map[string]string{"env": "test"}

	err = be.Configure(logger, repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, commons)
	require.NoError(t, err)

	baseCtx := context.WithValue(context.Background(), config.ContextKey("agent_id"), "test-agent")
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()

	err = be.Start(ctx, cancel)
	require.NoError(t, err)

	startTime := be.GetStartTime()
	assert.False(t, startTime.IsZero(), "Expected start time to be set")

	status, _, err := be.GetRunningStatus()
	require.NoError(t, err)
	assert.Equal(t, backend.Running, status, "Expected backend to be running")

	capabilities, err := be.GetCapabilities()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"iface": "eth0"}, capabilities["taps"], "Expected taps to match response")

	version, err := be.Version()
	require.NoError(t, err)
	assert.Equal(t, "1.2.3", version, "Expected version to match response")

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

func TestPktvisorGetRunningStatusAPIFailure(t *testing.T) {
	var metricsCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/metrics/app":
			if metricsCalls.Add(1) == 1 {
				var response pktvisor.AppInfo
				response.App.Version = "1.2.3"
				response.App.UpTimeMin = 1.5
				w.WriteHeader(http.StatusOK)
				require.NoError(t, json.NewEncoder(w).Encode(response))
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, err := w.Write([]byte(`{"error":"unavailable"}`))
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

	createExecutable(t, "pktvisord")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 54321)

	overrideNewCmdOptions(t, mockCmd, nil)

	assert.True(t, pktvisor.Register(), "Failed to register Pktvisor backend")

	be := backend.GetBackend("pktvisor")

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
