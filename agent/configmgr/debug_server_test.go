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

func TestDebugServer_ForceTokenRotation_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)
	oldExpiry := time.Now().Add(5 * time.Minute)
	newExpiry := time.Now().Add(60 * time.Minute)

	ds, err := startDebugServer(logger, 0, debugServerOpts{
		reconnectChan: reconnectChan,
		tokenRotate: func() (time.Time, time.Time, error) {
			return oldExpiry, newExpiry, nil
		},
	})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Post(fmt.Sprintf("http://%s/debug/force-token-rotation", ds.addr()), "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body tokenRotationResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "token_rotated", body.Status)
	assert.False(t, body.NewExpiry.IsZero(), "new_expiry should be set")

	// Verify NO reconnect signal was sent (non-destructive rotation)
	select {
	case <-reconnectChan:
		t.Fatal("force-token-rotation should NOT signal reconnectChan")
	default:
		// expected — no reconnect triggered
	}
}

func TestDebugServer_ForceTokenRotation_RefreshError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)

	ds, err := startDebugServer(logger, 0, debugServerOpts{
		reconnectChan: reconnectChan,
		tokenRotate: func() (time.Time, time.Time, error) {
			return time.Time{}, time.Time{}, fmt.Errorf("auth server unavailable")
		},
	})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Post(fmt.Sprintf("http://%s/debug/force-token-rotation", ds.addr()), "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "token_rotation_failed", body["status"])
	assert.Contains(t, body["error"], "auth server unavailable")
}

func TestDebugServer_ForceTokenRotation_NotAvailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reconnectChan := make(chan struct{}, 1)

	ds, err := startDebugServer(logger, 0, debugServerOpts{
		reconnectChan: reconnectChan,
		tokenRotate:   nil,
	})
	require.NoError(t, err)
	defer ds.stop()

	resp, err := http.Post(fmt.Sprintf("http://%s/debug/force-token-rotation", ds.addr()), "", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
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
