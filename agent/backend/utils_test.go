package backend

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockCommander implements Commander interface for testing
type mockCommander struct {
	status CmdStatus
}

func (m *mockCommander) Start() <-chan CmdStatus {
	ch := make(chan CmdStatus, 1)
	ch <- m.status
	return ch
}

func (m *mockCommander) Stop() error {
	return nil
}

func (m *mockCommander) Status() CmdStatus {
	return m.status
}

func (m *mockCommander) GetStdout() <-chan string {
	return make(chan string)
}

func (m *mockCommander) GetStderr() <-chan string {
	return make(chan string)
}

func newRunningCommander() *mockCommander {
	return &mockCommander{
		status: CmdStatus{
			PID:      1234,
			Complete: false,
			Exit:     0,
			Error:    nil,
			StopTs:   0,
		},
	}
}

func TestCommonRequest_Empty200Response(t *testing.T) {
	// Arrange - create a server that returns an empty 200 response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// No body written - empty response
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proc := newRunningCommander()

	var response StatusResponse

	// Act
	err := CommonRequest("test-backend", proc, logger, server.URL, &response, http.MethodGet,
		http.NoBody, "application/json", 5, "error")

	// Assert - should succeed with empty body
	assert.NoError(t, err)
	// Response should remain as zero value
	assert.Empty(t, response.Policies)
	assert.Empty(t, response.Version)
}

func TestCommonRequest_ValidJSONResponse(t *testing.T) {
	// Arrange - create a server that returns valid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":"1.0.0","policies":[{"name":"test-policy","status":"running"}]}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proc := newRunningCommander()

	var response StatusResponse

	// Act
	err := CommonRequest("test-backend", proc, logger, server.URL, &response, http.MethodGet,
		http.NoBody, "application/json", 5, "error")

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", response.Version)
	assert.Len(t, response.Policies, 1)
	assert.Equal(t, "test-policy", response.Policies[0].Name)
}

func TestCommonRequest_Non2xxEmptyBody(t *testing.T) {
	// Arrange - create a server that returns an empty 500 response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// No body written
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proc := newRunningCommander()

	var response StatusResponse

	// Act
	err := CommonRequest("test-backend", proc, logger, server.URL, &response, http.MethodGet,
		http.NoBody, "application/json", 5, "error")

	// Assert - should return error for non-2xx
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500 empty body")
}

func TestCommonRequest_Non2xxWithJSONError(t *testing.T) {
	// Arrange - create a server that returns a 400 with JSON error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request"}`))
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proc := newRunningCommander()

	var response StatusResponse

	// Act
	err := CommonRequest("test-backend", proc, logger, server.URL, &response, http.MethodGet,
		http.NoBody, "application/json", 5, "error")

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "invalid request")
}

func TestCommonRequest_ProcessNotRunning(t *testing.T) {
	// Arrange - process is not running (Complete = true)
	proc := &mockCommander{
		status: CmdStatus{
			Complete: true, // Process has completed
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	var response StatusResponse

	// Act - request to non-existent server, but should be skipped due to process state
	err := CommonRequest("test-backend", proc, logger, "http://localhost:9999", &response, http.MethodGet,
		http.NoBody, "application/json", 5, "error")

	// Assert - should skip the request (returns nil when process is not running)
	assert.NoError(t, err)
}

func TestCommonRequest_204NoContent(t *testing.T) {
	// Arrange - create a server that returns 204 No Content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		// 204 responses should not have a body
	}))
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proc := newRunningCommander()

	var response StatusResponse

	// Act
	err := CommonRequest("test-backend", proc, logger, server.URL, &response, http.MethodGet,
		http.NoBody, "application/json", 5, "error")

	// Assert - should succeed with 204 empty body
	assert.NoError(t, err)
	assert.Empty(t, response.Policies)
}
