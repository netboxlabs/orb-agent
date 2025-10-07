package fleet

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

func TestFleetConfigManager_Connect_InvalidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	// Act with invalid URL
	backends := make(map[string]backend.Backend)
	trt := TokenResponseTopics{Inbox: "test/topic"}
	err := connection.Connect(context.Background(), "://invalid-url", "test_token", trt, backends, "test-agent-id", "test-zone", map[string]string{})

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing protocol scheme") // URL parsing error
}

func TestFleetConfigManager_Connect_ValidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	// Act with valid URL but don't expect successful connection
	// since we don't have a real MQTT server
	backends := make(map[string]backend.Backend)
	trt2 := TokenResponseTopics{Inbox: "test/topic"}
	// Timeout after 3 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := connection.Connect(ctx, "mqtt://localhost:1883", "test_token", trt2, backends, "test-agent-id", "test-zone", map[string]string{})

	// Assert - we expect connection to fail since no server is running,
	// but URL parsing should succeed
	assert.Error(t, err)
	// The actual error could be context deadline exceeded or connection refused
	assert.True(t,
		strings.Contains(err.Error(), "context deadline exceeded") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server denied connect"),
		"Expected connection-related error, got: %v", err)
}
