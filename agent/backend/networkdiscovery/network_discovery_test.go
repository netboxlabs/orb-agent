package networkdiscovery_test

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/backend/networkdiscovery"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

type StatusResponse struct {
	Version   string  `json:"version"`
	StartTime string  `json:"start_time"`
	UpTime    float64 `json:"up_time"`
}

func TestNetworkDiscoveryBackendStart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/status":
			response := StatusResponse{
				Version:   "1.3.4",
				StartTime: "2023-10-01T12:00:00Z",
				UpTime:    123.456,
			}
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(response))
		case r.URL.Path == "/api/v1/capabilities":
			capabilities := map[string]any{
				"capability": true,
			}
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(capabilities))
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

	createExecutable(t, "network-discovery")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	overrideNewCmdOptions(t, mockCmd, func(options backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "network-discovery", name, "Expected command name to be network-discovery")
		assert.False(t, options.Buffered, "Expected buffered to be false")
		assert.True(t, options.Streaming, "Expected streaming to be true")
		assert.Contains(t, args, "--host", "Expected args to contain host flag")
		assert.Contains(t, args, serverURL.Hostname(), "Expected args to contain host value")
		assert.Contains(t, args, "--port", "Expected args to contain port flag")
		assert.Contains(t, args, serverURL.Port(), "Expected args to contain port value")
		assert.Contains(t, args, "--diode-target", "Expected args to contain diode target flag")
		assert.Contains(t, args, "network-target", "Expected args to contain diode target")
		assert.Contains(t, args, "--diode-client-id", "Expected args to contain diode client id flag")
		assert.Contains(t, args, "network-client", "Expected args to contain diode client id")
		assert.Contains(t, args, "--diode-client-secret", "Expected args to contain diode client secret flag")
		assert.Contains(t, args, "network-secret", "Expected args to contain diode client secret")
		assert.Contains(t, args, "--diode-app-name-prefix", "Expected args to contain diode app name prefix flag")
		assert.Contains(t, args, "network-agent", "Expected args to contain diode app name prefix")
		assert.Contains(t, args, "--log-level", "Expected args to contain log level flag")
		assert.Contains(t, args, "debug", "Expected args to contain log level value")
		assert.Contains(t, args, "--otel-endpoint", "Expected args to contain otel endpoint flag")
		assert.Contains(t, args, "collector:4317", "Expected args to contain otel endpoint value")
	})

	assert.True(t, networkdiscovery.Register(), "Failed to register NetworkDiscovery backend")
	assert.True(t, backend.HaveBackend("network_discovery"), "Failed to get NetworkDiscovery backend")

	be := backend.GetBackend("network_discovery")

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
		"target":             "network-target",
		"client_id":          "network-client",
		"client_secret":      "network-secret",
		"agent_name":         "network-agent",
		"log_level":          "debug",
		"dry_run":            false,
		"dry_run_output_dir": "/tmp/network",
	}, commons, nil)
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

func TestNetworkDiscoveryUsesOtelTargetWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/status" {
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(StatusResponse{Version: "1.0.0"}))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	createExecutable(t, "network-discovery")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 4244)

	otelEndpoint := "collector:4317"
	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "network-discovery", name)
		assert.Contains(t, args, "--diode-target")
		assert.Contains(t, args, otelEndpoint)
		assert.NotContains(t, args, "--diode-client-id")
		assert.NotContains(t, args, "--diode-client-secret")
		assert.NotContains(t, args, "network-client")
		assert.NotContains(t, args, "network-secret")
		assert.NotContains(t, args, "********")
	})

	assert.True(t, networkdiscovery.Register())
	assert.True(t, backend.HaveBackend("network_discovery"))

	be := backend.GetBackend("network_discovery")

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = otelEndpoint
	commons.Diode.ClientID = "default-client"
	commons.Diode.ClientSecret = "default-secret"
	commons.Diode.AgentName = "network-agent"

	err = be.Configure(logger, repo, map[string]any{
		"host":          serverURL.Hostname(),
		"port":          serverURL.Port(),
		"client_id":     "network-client",
		"client_secret": "network-secret",
		"agent_name":    "network-agent",
	}, commons, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, be.Start(ctx, cancel))
	require.NoError(t, be.Stop(ctx))

	mockCmd.AssertExpectations(t)
}

func TestNetworkDiscoveryBackendCompleted(t *testing.T) {
	mockCmd := &mocks.MockCmd{}
	mocks.SetupCompletedProcess(mockCmd, 0, nil)

	overrideNewCmdOptions(t, mockCmd, nil)

	assert.True(t, networkdiscovery.Register(), "Failed to register NetworkDiscovery backend")
	assert.True(t, backend.HaveBackend("network_discovery"), "Failed to get NetworkDiscovery backend")

	be := backend.GetBackend("network_discovery")

	require.NoError(t, be.Configure(slog.Default(), nil, map[string]any{
		"host": "invalid-host",
	}, config.BackendCommons{}, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := be.Start(ctx, cancel)
	assert.Error(t, err)

	mockCmd.AssertExpectations(t)
}

func TestNetworkDiscoveryBackendStartWithDryRunIncludesHostAndPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/status" {
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(StatusResponse{Version: "1.0.0"}))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	createExecutable(t, "network-discovery")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12349)

	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "network-discovery", name, "Expected command name to be network-discovery")
		assert.Contains(t, args, "--dry-run", "Expected args to contain dry-run flag")
		assert.Contains(t, args, "--dry-run-output-dir", "Expected args to contain dry-run-output-dir flag")
		assert.Contains(t, args, "/tmp/network-dry-run", "Expected args to contain dry-run-output-dir value")
		assert.Contains(t, args, "--host", "Expected args to contain host flag even in dry-run mode")
		assert.Contains(t, args, serverURL.Hostname(), "Expected args to contain host value even in dry-run mode")
		assert.Contains(t, args, "--port", "Expected args to contain port flag even in dry-run mode")
		assert.Contains(t, args, serverURL.Port(), "Expected args to contain port value even in dry-run mode")
		assert.Contains(t, args, "--diode-app-name-prefix", "Expected args to contain diode app name prefix flag")
		assert.Contains(t, args, "network-agent", "Expected args to contain diode app name prefix value")
		assert.NotContains(t, args, "--diode-target", "Expected args to NOT contain diode target flag in dry-run mode")
		assert.NotContains(t, args, "--diode-client-id", "Expected args to NOT contain diode client id flag in dry-run mode")
		assert.NotContains(t, args, "--diode-client-secret", "Expected args to NOT contain diode client secret flag in dry-run mode")
	})

	assert.True(t, networkdiscovery.Register(), "Failed to register NetworkDiscovery backend")
	assert.True(t, backend.HaveBackend("network_discovery"), "Failed to get NetworkDiscovery backend")

	be := backend.GetBackend("network_discovery")

	commons := config.BackendCommons{}
	commons.Diode.AgentName = "network-agent"
	commons.Diode.DryRunOutputDir = "/tmp/network-dry-run"

	err = be.Configure(logger, repo, map[string]any{
		"host":               serverURL.Hostname(),
		"port":               serverURL.Port(),
		"agent_name":         "network-agent",
		"dry_run":            true,
		"dry_run_output_dir": "/tmp/network-dry-run",
	}, commons, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, be.Start(ctx, cancel))
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
