package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/policy"
	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/server"
)

// fakeBlockingNmap puts a script named nmap first on PATH that runs until it
// is killed, as a long scan does, without touching the network. The script
// creates the returned marker file when it starts.
func fakeBlockingNmap(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake nmap is a shell script")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	body := "#!/bin/sh\ntouch '" + marker + "'\nexec sleep 30\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nmap"), []byte(body), 0o700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

func serve(srv *server.Server, method, path string, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	request, _ := http.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, request)
	return w
}

// The agent updates a policy by deleting it and posting the new version. Done
// while the policy's scan runs, the delete returns at once and the post starts
// the new version.
func TestServerReplacesAPolicyWhileItsScanRuns(t *testing.T) {
	started := fakeBlockingNmap(t)
	logger := slog.New(slog.DiscardHandler)
	manager := policy.NewManager(context.Background(), logger, new(MockClient))
	t.Cleanup(manager.Stop)
	srv := server.NewServer("localhost", 8073, logger, manager, "1.0.0")
	body := []byte("policies:\n  p1:\n    scope:\n      targets: [192.0.2.0/24]\n")

	require.Equal(t, http.StatusCreated, serve(srv, http.MethodPost, "/api/v1/policies", body).Code)
	require.Eventually(t, func() bool {
		var status server.StatusResponse
		w := serve(srv, http.MethodGet, "/api/v1/status", nil)
		return json.Unmarshal(w.Body.Bytes(), &status) == nil &&
			len(status.Policies) == 1 && status.Policies[0].Status == "running"
	}, 10*time.Second, 10*time.Millisecond, "the scan did not start")
	require.Eventually(t, func() bool {
		_, err := os.Stat(started)
		return err == nil
	}, 10*time.Second, 10*time.Millisecond, "the fake nmap did not start")

	start := time.Now()
	w := serve(srv, http.MethodDelete, "/api/v1/policies/p1", nil)
	assert.Less(t, time.Since(start), 5*time.Second, "the delete waited for the scan")
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serve(srv, http.MethodPost, "/api/v1/policies", body)
	assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
}
