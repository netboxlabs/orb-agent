package worker_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

type StatusResponse struct {
	StartTime string  `json:"start_time"`
	Version   string  `json:"version"`
	UpTime    float64 `json:"up_time"`
}

func TestWorkerBackendStart(t *testing.T) {
	// Create server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/status" {
			response := StatusResponse{
				Version:   "1.3.4",
				StartTime: "2023-10-01T12:00:00Z",
				UpTime:    123.456,
			}
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(response)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if r.URL.Path == "/api/v1/capabilities" {
			capabilities := map[string]any{
				"capability": true,
			}
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(capabilities)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if strings.Contains(r.URL.Path, "/api/v1/policies") {
			switch r.Method {
			case http.MethodPost:
				w.WriteHeader(http.StatusOK)
				response := map[string]any{
					"status":  "success",
					"message": "Policy applied successfully",
				}
				err := json.NewEncoder(w).Encode(response)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			case http.MethodDelete:
				w.WriteHeader(http.StatusOK)
				response := map[string]any{
					"status":  "success",
					"message": "Policy removed successfully",
				}
				err := json.NewEncoder(w).Encode(response)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Parse server URL
	serverURL, err := url.Parse(server.URL)
	assert.NoError(t, err)

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a mock repository
	repo, err := policies.NewMemRepo()
	assert.NoError(t, err)

	// Create a mock command
	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	// Save original function and restore after test
	originalNewCmdOptions := backend.NewCmdOptions
	defer func() {
		backend.NewCmdOptions = originalNewCmdOptions
	}()

	// Override NewCmdOptions to return our mock
	backend.NewCmdOptions = func(options backend.CmdOptions, name string, args ...string) backend.Commander {
		// Assert that the correct parameters were passed
		assert.Equal(t, "orb-worker", name, "Expected command name to be orb-worker")
		assert.Contains(t, args, "--port", "Expected args to contain port")
		assert.Contains(t, args, "--host", "Expected args to contain host")
		assert.False(t, options.Buffered, "Expected buffered to be false")
		assert.True(t, options.Streaming, "Expected streaming to be true")
		return mockCmd
	}

	assert.True(t, worker.Register(), "Failed to register Worker backend")

	assert.True(t, backend.HaveBackend("worker"), "Failed to get Worker backend")

	be := backend.GetBackend("worker")

	// Configure backend
	err = be.Configure(logger, repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, config.BackendCommons{})
	assert.NoError(t, err)

	assert.Equal(t, backend.Unknown, be.GetInitialState())

	// Start the backend
	ctx, cancel := context.WithCancel(context.Background())
	err = be.Start(ctx, cancel)

	// Assert successful start
	assert.NoError(t, err)

	// Get Running status
	status, _, err := be.GetRunningStatus()
	assert.NoError(t, err)
	assert.Equal(t, backend.Running, status, "Expected backend to be running")

	// Get capabilities
	capabilities, err := be.GetCapabilities()
	assert.NoError(t, err)
	assert.Equal(t, capabilities["capability"], true, "Expected capability to be true")

	data := policies.PolicyData{
		ID:   "dummy-policy-id",
		Name: "dummy-policy-name",
		Data: map[string]any{"key": "value"},
	}
	// Apply policy
	err = be.ApplyPolicy(data, false)
	assert.NoError(t, err)

	// Update policy
	err = be.ApplyPolicy(data, true)
	assert.NoError(t, err)

	// Assert restart
	err = be.FullReset(ctx)
	assert.NoError(t, err)

	// Verify expectations
	mockCmd.AssertExpectations(t)
}

func TestWorkerBackendCompleted(t *testing.T) {
	// Create a mock command that simulates a failure
	mockCmd := &mocks.MockCmd{}
	mocks.SetupCompletedProcess(mockCmd, 0, nil)
	// Save original function and restore after test
	originalNewCmdOptions := backend.NewCmdOptions
	defer func() {
		backend.NewCmdOptions = originalNewCmdOptions
	}()

	// Override NewCmdOptions to return our mock
	backend.NewCmdOptions = func(_ backend.CmdOptions, _ string, _ ...string) backend.Commander {
		return mockCmd
	}

	assert.True(t, worker.Register(), "Failed to register Worker backend")

	assert.True(t, backend.HaveBackend("worker"), "Failed to get Worker backend")

	be := backend.GetBackend("worker")

	// Configure backend with invalid parameters
	err := be.Configure(slog.Default(), nil, map[string]any{
		"host": "invalid-host",
	}, config.BackendCommons{})
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	err = be.Start(ctx, cancel)

	assert.Error(t, err)
}

func TestWorkerBackendDryRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/status":
			response := StatusResponse{Version: "1.3.4", StartTime: "2023-10-01T12:00:00Z", UpTime: 123.456}
			_ = json.NewEncoder(w).Encode(response)
		case r.URL.Path == "/api/v1/capabilities":
			capabilities := map[string]any{"capability": true}
			_ = json.NewEncoder(w).Encode(capabilities)
		case strings.HasPrefix(r.URL.Path, "/api/v1/policies"):
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	assert.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	repo, err := policies.NewMemRepo()
	assert.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	originalNewCmdOptions := backend.NewCmdOptions
	var capturedArgs []string
	backend.NewCmdOptions = func(options backend.CmdOptions, name string, args ...string) backend.Commander {
		capturedArgs = args
		return mockCmd
	}
	defer func() { backend.NewCmdOptions = originalNewCmdOptions }()

	assert.True(t, worker.Register())
	be := backend.GetBackend("worker")

	beCommons := config.BackendCommons{
		Diode: struct {
			Target          string `yaml:"target"`
			ClientID        string `yaml:"client_id"`
			ClientSecret    string `yaml:"client_secret"`
			AgentName       string `yaml:"agent_name"`
			DryRun          bool   `yaml:"dry_run"`
			DryRunOutputDir string `yaml:"dry_run_output_dir"`
		}{
			DryRun:          true,
			DryRunOutputDir: "/tmp/dry-run-output",
		},
	}

	err = be.Configure(logger, repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, beCommons)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	err = be.Start(ctx, cancel)
	assert.NoError(t, err)

	assert.Contains(t, capturedArgs, "--dry-run")
	assert.Contains(t, capturedArgs, "--dry-run-output-dir")
	assert.NotContains(t, capturedArgs, "--host")
	assert.NotContains(t, capturedArgs, "--port")

	assert.False(t, be.GetStartTime().IsZero())

	err = be.RemovePolicy(policies.PolicyData{ID: "1", Name: "policy", Data: map[string]any{"k": "v"}})
	assert.NoError(t, err)

	err = be.Stop(context.WithValue(context.Background(), config.ContextKey("routine"), "test"))
	assert.NoError(t, err)

	mockCmd.AssertExpectations(t)
}
