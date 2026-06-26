package gnmidiscovery_test

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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/gnmidiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

type StatusResponse struct {
	Version   string  `json:"version"`
	StartTime string  `json:"start_time"`
	UpTime    float64 `json:"up_time"`
}

func TestGnmiDiscoveryBackendStart(t *testing.T) {
	var mu sync.Mutex
	var deletedPaths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/api/v1/status":
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"version": "1.3.4",
				"policies": []map[string]any{
					{
						"name":   "gnmi-policy-1",
						"status": "running",
						"runs": []map[string]any{
							// gnmi emits a singular `target` per run, not a `targets` array.
							{"id": "run-1", "target": "10.0.0.11:6030", "status": "completed"},
						},
					},
				},
			}))
		case r.URL.Path == "/api/v1/capabilities":
			capabilities := map[string]any{
				"capability": true,
			}
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(capabilities))
		case strings.Contains(r.URL.Path, "/api/v1/policies"):
			if r.Method == http.MethodDelete {
				mu.Lock()
				deletedPaths = append(deletedPaths, r.URL.Path)
				mu.Unlock()
			}
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

	createExecutable(t, "gnmi-discovery")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	overrideNewCmdOptions(t, mockCmd, func(options backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "gnmi-discovery", name, "Expected command name to be gnmi-discovery")
		assert.False(t, options.Buffered, "Expected buffered to be false")
		assert.True(t, options.Streaming, "Expected streaming to be true")
		assert.Contains(t, args, "--host", "Expected args to contain host flag")
		assert.Contains(t, args, serverURL.Hostname(), "Expected args to contain host value")
		assert.Contains(t, args, "--port", "Expected args to contain port flag")
		assert.Contains(t, args, serverURL.Port(), "Expected args to contain port value")
		assert.Contains(t, args, "--diode-target", "Expected args to contain diode target flag")
		assert.Contains(t, args, "gnmi-target", "Expected args to contain diode target")
		assert.Contains(t, args, "--diode-client-id", "Expected args to contain diode client id flag")
		assert.Contains(t, args, "gnmi-client", "Expected args to contain diode client id")
		assert.Contains(t, args, "--diode-client-secret", "Expected args to contain diode client secret flag")
		assert.Contains(t, args, "gnmi-secret", "Expected args to contain diode client secret")
		assert.Contains(t, args, "--diode-app-name-prefix", "Expected args to contain diode app name prefix flag")
		assert.Contains(t, args, "gnmi-agent", "Expected args to contain diode app name prefix")
		assert.Contains(t, args, "--log-level", "Expected args to contain log level flag")
		assert.Contains(t, args, "debug", "Expected args to contain log level value")
		assert.Contains(t, args, "--otel-endpoint", "Expected args to contain otel endpoint flag")
		assert.Contains(t, args, "collector:4317", "Expected args to contain otel endpoint value")
		// gNMI-specific flags
		assert.Contains(t, args, "--profiles-dir", "Expected args to contain profiles-dir flag")
		assert.Contains(t, args, "/etc/gnmi/profiles", "Expected args to contain profiles-dir value")
		assert.Contains(t, args, "--otel-export-period", "Expected args to contain otel-export-period flag")
		assert.Contains(t, args, "30", "Expected args to contain otel-export-period value")
		assert.Contains(t, args, "--log-format", "Expected args to contain log-format flag")
		assert.Contains(t, args, "json", "Expected args to contain log-format value")
	})

	assert.True(t, gnmidiscovery.Register(), "Failed to register GnmiDiscovery backend")
	assert.True(t, backend.HaveBackend("gnmi_discovery"), "Failed to get GnmiDiscovery backend")

	be := backend.GetBackend("gnmi_discovery")

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
		"target":             "gnmi-target",
		"client_id":          "gnmi-client",
		"client_secret":      "gnmi-secret",
		"agent_name":         "gnmi-agent",
		"log_level":          "debug",
		"dry_run":            false,
		"dry_run_output_dir": "/tmp/gnmi",
		"profiles_dir":       "/etc/gnmi/profiles",
		"otel_export_period": 30,
		"log_format":         "json",
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

	statusProvider, ok := be.(backend.PolicyStatusProvider)
	require.True(t, ok, "gnmi backend should implement PolicyStatusProvider")
	policyStatus, err := statusProvider.GetPolicyStatus()
	require.NoError(t, err)
	require.Len(t, policyStatus, 1, "Expected one policy status from /api/v1/status")
	assert.Equal(t, "gnmi-policy-1", policyStatus[0].Name, "Expected policy status name to match response")
	require.Len(t, policyStatus[0].Runs, 1, "Expected one run in the policy status")
	assert.Equal(t, []string{"10.0.0.11:6030"}, policyStatus[0].Runs[0].Targets,
		"gnmi's singular run target must be normalized into Targets")

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

	// Updating a policy must remove the PREVIOUS name first, not the new one.
	mu.Lock()
	gotDeletes := append([]string(nil), deletedPaths...)
	mu.Unlock()
	require.NotEmpty(t, gotDeletes, "Expected a DELETE for the previous policy name on update")
	lastDelete := gotDeletes[len(gotDeletes)-1]
	assert.Contains(t, lastDelete, "/api/v1/policies/dummy-policy-name",
		"update must DELETE the previous policy name")
	assert.NotContains(t, lastDelete, "dummy-policy-updated",
		"update must not DELETE the new policy name")

	require.NoError(t, be.FullReset(ctx))

	mockCmd.AssertExpectations(t)
}

func TestGnmiDiscoveryUsesOtelTargetWithoutCredentials(t *testing.T) {
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

	createExecutable(t, "gnmi-discovery")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 4244)

	otelEndpoint := "collector:4317"
	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "gnmi-discovery", name)
		assert.Contains(t, args, "--diode-target")
		assert.Contains(t, args, otelEndpoint)
		assert.NotContains(t, args, "--diode-client-id")
		assert.NotContains(t, args, "--diode-client-secret")
		assert.NotContains(t, args, "gnmi-client")
		assert.NotContains(t, args, "gnmi-secret")
		assert.NotContains(t, args, "********")
	})

	assert.True(t, gnmidiscovery.Register())
	assert.True(t, backend.HaveBackend("gnmi_discovery"))

	be := backend.GetBackend("gnmi_discovery")

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = otelEndpoint
	commons.Diode.ClientID = "default-client"
	commons.Diode.ClientSecret = "default-secret"
	commons.Diode.AgentName = "gnmi-agent"

	err = be.Configure(logger, repo, map[string]any{
		"host":          serverURL.Hostname(),
		"port":          serverURL.Port(),
		"client_id":     "gnmi-client",
		"client_secret": "gnmi-secret",
		"agent_name":    "gnmi-agent",
	}, commons, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, be.Start(ctx, cancel))
	require.NoError(t, be.Stop(ctx))

	mockCmd.AssertExpectations(t)
}

func TestGnmiDiscoveryBackendCompleted(t *testing.T) {
	mockCmd := &mocks.MockCmd{}
	mocks.SetupCompletedProcess(mockCmd, 0, nil)

	overrideNewCmdOptions(t, mockCmd, nil)

	assert.True(t, gnmidiscovery.Register(), "Failed to register GnmiDiscovery backend")
	assert.True(t, backend.HaveBackend("gnmi_discovery"), "Failed to get GnmiDiscovery backend")

	be := backend.GetBackend("gnmi_discovery")

	require.NoError(t, be.Configure(slog.Default(), nil, map[string]any{
		"host": "invalid-host",
	}, config.BackendCommons{}, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := be.Start(ctx, cancel)
	assert.Error(t, err)

	mockCmd.AssertExpectations(t)
}

func TestGnmiDiscoveryBackendStartWithDryRunIncludesHostAndPort(t *testing.T) {
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

	createExecutable(t, "gnmi-discovery")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12349)

	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "gnmi-discovery", name, "Expected command name to be gnmi-discovery")
		assert.Contains(t, args, "--dry-run", "Expected args to contain dry-run flag")
		assert.Contains(t, args, "--dry-run-output-dir", "Expected args to contain dry-run-output-dir flag")
		assert.Contains(t, args, "/tmp/gnmi-dry-run", "Expected args to contain dry-run-output-dir value")
		assert.Contains(t, args, "--host", "Expected args to contain host flag even in dry-run mode")
		assert.Contains(t, args, serverURL.Hostname(), "Expected args to contain host value even in dry-run mode")
		assert.Contains(t, args, "--port", "Expected args to contain port flag even in dry-run mode")
		assert.Contains(t, args, serverURL.Port(), "Expected args to contain port value even in dry-run mode")
		assert.Contains(t, args, "--diode-app-name-prefix", "Expected args to contain diode app name prefix flag")
		assert.Contains(t, args, "gnmi-agent", "Expected args to contain diode app name prefix value")
		assert.NotContains(t, args, "--diode-target", "Expected args to NOT contain diode target flag in dry-run mode")
		assert.NotContains(t, args, "--diode-client-id", "Expected args to NOT contain diode client id flag in dry-run mode")
		assert.NotContains(t, args, "--diode-client-secret", "Expected args to NOT contain diode client secret flag in dry-run mode")
	})

	assert.True(t, gnmidiscovery.Register(), "Failed to register GnmiDiscovery backend")
	assert.True(t, backend.HaveBackend("gnmi_discovery"), "Failed to get GnmiDiscovery backend")

	be := backend.GetBackend("gnmi_discovery")

	commons := config.BackendCommons{}
	commons.Diode.AgentName = "gnmi-agent"
	commons.Diode.DryRunOutputDir = "/tmp/gnmi-dry-run"

	err = be.Configure(logger, repo, map[string]any{
		"host":               serverURL.Hostname(),
		"port":               serverURL.Port(),
		"agent_name":         "gnmi-agent",
		"dry_run":            true,
		"dry_run_output_dir": "/tmp/gnmi-dry-run",
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
