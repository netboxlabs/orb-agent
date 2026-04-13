package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findAvailablePort finds an available port by listening on port 0 and returning the assigned port
func findAvailablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err, "failed to find available port")
	defer func() {
		_ = listener.Close()
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port
}

func TestBridgeServer_Start_PortInUse(t *testing.T) {
	// Test that Start() returns a clear error when the port is already in use
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Pre-occupy a port with a test listener
	testPort := findAvailablePort(t)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", testPort))
	require.NoError(t, err, "failed to create test listener")
	defer func() {
		_ = listener.Close()
	}()

	// Create bridge server with the pre-occupied port
	bridgeConfig := BridgeConfig{
		ListenAddr: fmt.Sprintf(":%d", testPort),
		Encoding:   "json",
	}

	bridge, err := NewBridgeServer(bridgeConfig, nil, logger)
	require.NoError(t, err, "failed to create bridge server")

	// Act
	err = bridge.Start(context.Background())

	// Assert
	require.Error(t, err, "Start() should fail when port is in use")
	assert.Contains(t, err.Error(), "failed to listen", "error should mention listening failure")
	assert.Contains(t, err.Error(), fmt.Sprintf(":%d", testPort), "error should mention the port")
	assert.Contains(t, err.Error(), "port may be in use", "error should mention port may be in use")
}

func TestBridgeServer_Start_Success(t *testing.T) {
	// Test that Start() succeeds when port is available
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Use port 0 to let the OS assign an available port
	bridgeConfig := BridgeConfig{
		ListenAddr: ":0",
		Encoding:   "json",
	}

	bridge, err := NewBridgeServer(bridgeConfig, nil, logger)
	require.NoError(t, err, "failed to create bridge server")

	// Act
	err = bridge.Start(context.Background())

	// Assert
	require.NoError(t, err, "Start() should succeed when port is available")

	// Cleanup
	if bridge != nil {
		_ = bridge.Stop(context.Background())
	}
}

func TestBridgeServer_Start_ErrorMessageFormat(t *testing.T) {
	// Test that the error message format is helpful
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Pre-occupy a port
	testPort := findAvailablePort(t)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", testPort))
	require.NoError(t, err, "failed to create test listener")
	defer func() {
		_ = listener.Close()
	}()

	bridgeConfig := BridgeConfig{
		ListenAddr: fmt.Sprintf(":%d", testPort),
		Encoding:   "json",
	}

	bridge, err := NewBridgeServer(bridgeConfig, nil, logger)
	require.NoError(t, err)

	err = bridge.Start(context.Background())

	// Verify error message contains helpful information
	require.Error(t, err)
	errorMsg := strings.ToLower(err.Error())
	assert.True(t,
		strings.Contains(errorMsg, "port") || strings.Contains(errorMsg, "listen"),
		"error message should mention port or listen: %s", err.Error())
	assert.True(t,
		strings.Contains(errorMsg, "use") || strings.Contains(errorMsg, "bind"),
		"error message should mention port in use or bind failure: %s", err.Error())
}

func TestBridgeServer_Enqueue_BoundedQueue(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := BridgeConfig{
		ListenAddr:      ":0",
		Encoding:        "json",
		MaxPendingQueue: 5,
	}
	bridge, err := NewBridgeServer(cfg, nil, logger)
	require.NoError(t, err)
	//nolint:errcheck // err doesn't matter
	defer bridge.Stop(context.Background())

	ctx := context.Background()

	// Fill the channel buffer.
	for i := 0; i < 5; i++ {
		require.NoError(t, bridge.Enqueue(ctx, false, []byte(fmt.Sprintf("msg-%d", i))))
	}

	// Beyond the limit — should return ResourceExhausted.
	// The writer goroutine may have pulled at most 1 message from the channel,
	// so we verify that most attempts beyond the limit are rejected.
	var rejected int
	for i := 5; i < 10; i++ {
		if err := bridge.Enqueue(ctx, false, []byte(fmt.Sprintf("msg-%d", i))); err != nil {
			assert.Contains(t, err.Error(), "queue is full")
			rejected++
		}
	}
	assert.GreaterOrEqual(t, rejected, 4, "most messages beyond the limit should be rejected")
}

func TestBridgeServer_Enqueue_DefaultQueueLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := BridgeConfig{
		ListenAddr: ":0",
		Encoding:   "json",
		// MaxPendingQueue = 0 → should use default
	}
	bridge, err := NewBridgeServer(cfg, nil, logger)
	require.NoError(t, err)

	//nolint:errcheck // err doesn't matter
	defer bridge.Stop(context.Background())

	assert.Equal(t, defaultMaxPendingQueue, cap(bridge.msgCh), "should use default when MaxPendingQueue is 0")
}
