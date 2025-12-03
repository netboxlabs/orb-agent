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

func TestBridgeServer_Start_PortInUse(t *testing.T) {
	// Test that Start() returns a clear error when the port is already in use
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Pre-occupy a port with a test listener
	testPort := 54322
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
	testPort := 54323
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
