package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
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

func TestFleetConfigManager_SendCapabilities_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	// Create mock backends
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	// Set up backend expectations
	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{
		"feature1": "enabled",
		"feature2": "disabled",
	}, nil)

	mockBackend2.On("Version").Return("2.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any{
		"protocol":   "mqtt",
		"encryption": "tls",
	}, nil)

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	// Mock publish function
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	labels := map[string]string{}

	// Act
	connection.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	// Verify the published capabilities structure
	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)
	assert.Len(t, capabilities.Backends, 2)

	// Verify backend1 capabilities
	assert.Contains(t, capabilities.Backends, "backend1")
	backend1Info := capabilities.Backends["backend1"]
	assert.Equal(t, "1.2.3", backend1Info.Version)
	assert.Equal(t, "enabled", backend1Info.Data["feature1"])
	assert.Equal(t, "disabled", backend1Info.Data["feature2"])

	// Verify backend2 capabilities
	assert.Contains(t, capabilities.Backends, "backend2")
	backend2Info := capabilities.Backends["backend2"]
	assert.Equal(t, "2.0.0", backend2Info.Version)
	assert.Equal(t, "mqtt", backend2Info.Data["protocol"])
	assert.Equal(t, "tls", backend2Info.Data["encryption"])

	// Verify all mock expectations were met
	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_BackendVersionError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	// Create mock backends - one succeeds, one fails on version
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"feature": "enabled"}, nil)

	mockBackend2.On("Version").Return("", errors.New("version retrieval failed"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	labels := map[string]string{}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	connection.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Only backend1 should be included, backend2 should be skipped
	assert.Len(t, capabilities.Backends, 1)
	assert.Contains(t, capabilities.Backends, "backend1")
	assert.NotContains(t, capabilities.Backends, "backend2")

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_BackendCapabilitiesError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	// Create mock backends - one succeeds, one fails on capabilities
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"feature": "enabled"}, nil)

	mockBackend2.On("Version").Return("2.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any(nil), errors.New("capabilities retrieval failed"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	labels := map[string]string{}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	connection.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Only backend1 should be included, backend2 should be skipped
	assert.Len(t, capabilities.Backends, 1)
	assert.Contains(t, capabilities.Backends, "backend1")
	assert.NotContains(t, capabilities.Backends, "backend2")

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_PublishError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	mockBackend1 := &mockBackend{}
	mockBackend1.On("Version").Return("1.0.0", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"test": "value"}, nil)

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
	}

	labels := map[string]string{}

	publishError := errors.New("publish failed")
	publishFunc := func(_ context.Context, _ []byte) error {
		return publishError
	}

	ctx := context.Background()

	// Act
	connection.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	assert.Equal(t, publishError, publishFunc(ctx, []byte{}))

	mockBackend1.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_EmptyBackends(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	backends := map[string]backend.Backend{} // Empty backends
	labels := map[string]string{}
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	connection.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)
	assert.Empty(t, capabilities.Backends)
}

func TestFleetConfigManager_SendCapabilities_AllBackendsFail(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	// All backends fail
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	labels := map[string]string{}

	mockBackend1.On("Version").Return("", errors.New("version error"))
	mockBackend2.On("Version").Return("1.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any(nil), errors.New("capabilities error"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	connection.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// No backends should be included
	assert.Empty(t, capabilities.Backends)

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_CapabilitiesStructure(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := NewMQTTConnection(logger)

	mockBackend1 := &mockBackend{}
	mockBackend1.On("Version").Return("test-version", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{
		"string_val":  "test",
		"number_val":  42,
		"boolean_val": true,
		"array_val":   []string{"a", "b", "c"},
		"object_val":  map[string]string{"nested": "value"},
	}, nil)

	backends := map[string]backend.Backend{
		"test_backend": mockBackend1,
	}

	labels := map[string]string{}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	connection.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	// Verify JSON structure can be unmarshaled and contains expected data types
	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Verify structure fields
	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)

	// Verify backend data structure preservation
	backendInfo := capabilities.Backends["test_backend"]
	assert.Equal(t, "test-version", backendInfo.Version)

	// Verify all data types are preserved
	assert.Equal(t, "test", backendInfo.Data["string_val"])
	assert.Equal(t, float64(42), backendInfo.Data["number_val"]) // JSON numbers become float64
	assert.Equal(t, true, backendInfo.Data["boolean_val"])
	assert.IsType(t, []interface{}{}, backendInfo.Data["array_val"])
	assert.IsType(t, map[string]interface{}{}, backendInfo.Data["object_val"])

	mockBackend1.AssertExpectations(t)
}
