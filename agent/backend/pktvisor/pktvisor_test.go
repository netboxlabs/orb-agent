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
	// Create server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/v1/metrics/app" {
			var response pktvisor.AppInfo
			response.App.Version = "1.2.3"
			response.App.UpTimeMin = 42.5
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(response)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if r.URL.Path == "/api/v1/taps" {
			capabilities := map[string]any{
				"iface": "eth0",
			}
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(capabilities)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if strings.Contains(r.URL.Path, "/api/v1/policies") {
			if r.Method == http.MethodPost {
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
			} else if r.Method == http.MethodDelete {
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

	// Create a temporary directory and file for the test
	tempDir := t.TempDir()
	binaryPath := path.Join(tempDir, "pktvisord")
	dummyBinary, err := os.Create(binaryPath)
	require.NoError(t, err)
	err = dummyBinary.Close()
	require.NoError(t, err)

	// Make the binary executable
	err = os.Chmod(binaryPath, 0o755)
	require.NoError(t, err)

	// Add our temp directory to the PATH
	err = os.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	require.NoError(t, err)

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
		assert.Equal(t, "pktvisord", name, "Expected command name to be pktvisord")
		assert.Contains(t, args, "--admin-api", "Expected args to contain admin-api")
		assert.False(t, options.Buffered, "Expected buffered to be false")
		assert.True(t, options.Streaming, "Expected streaming to be true")
		return mockCmd
	}

	assert.True(t, pktvisor.Register(), "Failed to register Pktvisor backend")

	assert.True(t, backend.HaveBackend("pktvisor"), "Failed to get Pktvisor backend")

	be := backend.GetBackend("pktvisor")

	assert.Equal(t, backend.Unknown, be.GetInitialState())

	// Configure backend
	err = be.Configure(logger, repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, config.BackendCommons{})
	assert.NoError(t, err)

	// Start the backend
	ctx, cancel := context.WithCancel(context.Background())
	err = be.Start(ctx, cancel)

	// Assert successful start
	assert.NoError(t, err)

	// Get capabilities
	capabilities, err := be.GetCapabilities()
	assert.NoError(t, err)
	assert.Equal(t, map[string]any{"iface": "eth0"}, capabilities["taps"], "Expected taps")

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

	// Assert that the command was started
	err = be.Stop(ctx)
	assert.NoError(t, err)

	// Verify expectations
	mockCmd.AssertExpectations(t)
}
