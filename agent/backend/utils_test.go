package backend_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

type mockCommander struct {
	status backend.CmdStatus
	stopFn func() error
}

func (m *mockCommander) Status() backend.CmdStatus { return m.status }
func (m *mockCommander) Start() <-chan backend.CmdStatus {
	ch := make(chan backend.CmdStatus, 1)
	ch <- m.status
	return ch
}

func (m *mockCommander) Stop() error {
	if m.stopFn != nil {
		return m.stopFn()
	}
	return nil
}
func (m *mockCommander) GetStdout() <-chan string { return make(chan string) }
func (m *mockCommander) GetStderr() <-chan string { return make(chan string) }

func TestGetRunningStatus_NilProc(t *testing.T) {
	status, detail, err := backend.GetRunningStatus(nil)
	assert.Equal(t, backend.Unknown, status)
	assert.Equal(t, "backend not started yet", detail)
	assert.NoError(t, err)
}

func TestGetRunningStatus_Running(t *testing.T) {
	proc := &mockCommander{status: backend.CmdStatus{PID: 123}}
	status, detail, err := backend.GetRunningStatus(proc)
	assert.Equal(t, backend.Running, status)
	assert.Empty(t, detail)
	assert.NoError(t, err)
}

func TestGetRunningStatus_ProcessError(t *testing.T) {
	proc := &mockCommander{status: backend.CmdStatus{Error: errors.New("crash")}}
	status, _, err := backend.GetRunningStatus(proc)
	assert.Equal(t, backend.BackendError, status)
	assert.Error(t, err)
}

func TestGetRunningStatus_Complete(t *testing.T) {
	proc := &mockCommander{status: backend.CmdStatus{Complete: true}}
	status, detail, _ := backend.GetRunningStatus(proc)
	assert.Equal(t, backend.Offline, status)
	assert.Equal(t, "backend process ended", detail)
}

func TestGetRunningStatus_Stopped(t *testing.T) {
	proc := &mockCommander{status: backend.CmdStatus{StopTs: time.Now().Unix()}}
	status, detail, err := backend.GetRunningStatus(proc)
	assert.Equal(t, backend.Offline, status)
	assert.Equal(t, "backend process ended", detail)
	assert.NoError(t, err)
}

func TestCommonRequest_Non2xxReturnsHTTPError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := &mockCommander{status: backend.CmdStatus{PID: 123}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail": "policy 'test-job' not found"}`))
	}))
	defer srv.Close()

	var resp any
	err := backend.CommonRequest("testbackend", proc, logger, srv.URL, &resp,
		http.MethodDelete, http.NoBody, "application/json", 5, "detail")

	require.Error(t, err)
	var httpErr *backend.HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)
	assert.Contains(t, err.Error(), "404 policy 'test-job' not found")
}

func TestCommonRequest_Non2xxEmptyBodyReturnsHTTPError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proc := &mockCommander{status: backend.CmdStatus{PID: 123}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var resp any
	err := backend.CommonRequest("testbackend", proc, logger, srv.URL, &resp,
		http.MethodGet, http.NoBody, "application/json", 5, "detail")

	require.Error(t, err)
	var httpErr *backend.HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
}
