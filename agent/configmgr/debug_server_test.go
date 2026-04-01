package configmgr

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebugServer_Health(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)

	ds, err := startDebugServer(logger, 0, debugServerOpts{reconnectChan: reconnectChan})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Get(fmt.Sprintf("http://%s/debug/health", ds.addr()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDebugServer_ForceTokenRotation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)

	ds, err := startDebugServer(logger, 0, debugServerOpts{reconnectChan: reconnectChan})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Post(fmt.Sprintf("http://%s/debug/force-token-rotation", ds.addr()), "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "token_rotation_triggered", body["status"])

	// Verify the reconnect signal was sent
	select {
	case <-reconnectChan:
		// expected
	default:
		t.Fatal("expected signal on reconnectChan")
	}
}

func TestDebugServer_ForceTokenRotation_AlreadyInProgress(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)
	// Pre-fill the channel to simulate reconnect already in progress
	reconnectChan <- struct{}{}

	ds, err := startDebugServer(logger, 0, debugServerOpts{reconnectChan: reconnectChan})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Post(fmt.Sprintf("http://%s/debug/force-token-rotation", ds.addr()), "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestDebugServer_TokenStatus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)
	expiry := time.Now().Add(30 * time.Minute)

	ds, err := startDebugServer(logger, 0, debugServerOpts{
		reconnectChan: reconnectChan,
		tokenStatus: func() tokenStatusInfo {
			return tokenStatusInfo{
				ExpiresAt:       expiry,
				TimeUntilExpiry: "30m0s",
				Expired:         false,
				ExpiringSoon:    false,
			}
		},
	})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Get(fmt.Sprintf("http://%s/debug/token-status", ds.addr()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var info tokenStatusInfo
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&info))
	assert.False(t, info.Expired)
	assert.False(t, info.ExpiringSoon)
}

func TestDebugServer_TokenStatus_NotAvailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)

	ds, err := startDebugServer(logger, 0, debugServerOpts{
		reconnectChan: reconnectChan,
		tokenStatus:   nil,
	})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Get(fmt.Sprintf("http://%s/debug/token-status", ds.addr()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}

func TestDebugServer_ForceReconnect(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)

	ds, err := startDebugServer(logger, 0, debugServerOpts{reconnectChan: reconnectChan})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Post(fmt.Sprintf("http://%s/debug/force-reconnect", ds.addr()), "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case <-reconnectChan:
		// expected
	default:
		t.Fatal("expected signal on reconnectChan")
	}
}
