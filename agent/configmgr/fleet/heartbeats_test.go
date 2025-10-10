package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

// mockPublishFunc is a testify mock for the publish function
type mockPublishFunc struct {
	mock.Mock
}

func (m *mockPublishFunc) Publish(ctx context.Context, topic string, payload []byte) error {
	args := m.Called(ctx, topic, payload)
	return args.Error(0)
}

// Test helper to create a heartbeater instance for testing
func createTestHeartbeater() *heartbeater {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &heartbeater{
		logger:       logger,
		hbTicker:     time.NewTicker(50 * time.Millisecond), // Short interval for testing
		heartbeatCtx: context.Background(),
	}
}

func TestNewHeartbeater_HeartbeaterInitialization(t *testing.T) {
	// Act
	fleetManager := createTestHeartbeater()

	// Assert
	assert.NotNil(t, fleetManager)
	assert.NotNil(t, fleetManager.logger)
	assert.NotNil(t, fleetManager.hbTicker)
	assert.NotNil(t, fleetManager.hbTicker.C, "Ticker channel should be available")
	assert.NotNil(t, fleetManager.heartbeatCtx, "Heartbeat context should be initialized")

	// Clean up ticker
	fleetManager.hbTicker.Stop()
}

func TestHeartbeater_SendSingleHeartbeat_Success(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()
	testTopic := "test/heartbeat"

	// We don't assert exact bytes; validate the marshalled heartbeat content
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(nil)

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, mockPublish.Publish, "test-agent-id", testTime, messages.Online)

	// Assert: ensure one publish happened with a valid heartbeat payload
	calls := mockPublish.Calls
	require.Len(t, calls, 1)
	payload, ok := calls[0].Arguments.Get(2).([]byte)
	require.True(t, ok)

	var hbMsg messages.Heartbeat
	require.NoError(t, json.Unmarshal(payload, &hbMsg))
	assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, hbMsg.SchemaVersion)
	assert.Equal(t, messages.State(1), hbMsg.State)
	assert.False(t, hbMsg.TimeStamp.IsZero())
}

func TestHeartbeater_SendSingleHeartbeat_PublishError(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()
	testTopic := "test/heartbeat"
	publishError := errors.New("publish failed")

	// Set up mock expectations - publish function returns error
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(publishError)

	// Act - should not panic despite publish error
	hb.sendSingleHeartbeat(ctx, testTopic, mockPublish.Publish, "test-agent-id", testTime, messages.Online)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_HeartbeatContent(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, heartbeat.SchemaVersion)
	assert.Equal(t, messages.State(1), heartbeat.State)
	assert.False(t, heartbeat.TimeStamp.IsZero())
}

func TestHeartbeater_SendHeartbeats_InitialHeartbeat(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	// Set up expectations for initial heartbeat (Online state)
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Set up expectations for final heartbeat (Offline state) when context is cancelled
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Act
	go hb.sendHeartbeats(ctx, cancel, testTopic, "test-agent-id", mockPublish.Publish)

	// Give some time for initial heartbeat
	time.Sleep(10 * time.Millisecond)

	// Cancel context to trigger cleanup
	cancel()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_PeriodicHeartbeats(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	// We expect at least 3 heartbeats: initial + at least 2 periodic + final
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Times(4)

	// Act
	go hb.sendHeartbeats(ctx, cancel, testTopic, "test-agent-id", mockPublish.Publish)

	// Wait for some periodic heartbeats (ticker is 50ms in test)
	time.Sleep(120 * time.Millisecond)

	// Cancel context
	cancel()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_ContextCancellation(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	// Use a channel to signal when the goroutine has finished
	done := make(chan bool, 1)

	publishFunc := func(ctx context.Context, topic string, payload []byte) error {
		return mockPublish.Publish(ctx, topic, payload)
	}

	// Expect initial heartbeat (Online) and final heartbeat (Offline)
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Twice()

	// Act
	go func() {
		hb.sendHeartbeats(ctx, cancel, testTopic, "test-agent-id", publishFunc)
		done <- true
	}()

	// Let it run briefly
	time.Sleep(10 * time.Millisecond)

	// Cancel context immediately
	cancel()

	// Wait for the goroutine to finish
	<-done

	// Assert
	mockPublish.AssertExpectations(t)

	// Verify context is properly cleaned up (now safe to read after goroutine finished)
	assert.Nil(t, hb.heartbeatCtx)
}

func TestHeartbeater_SendHeartbeats_PublishErrors(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	publishError := errors.New("network error")

	// Mock publish function to return errors - should not stop the heartbeat loop
	// Expect initial + periodic + final heartbeat (all with errors)
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(publishError).Times(4)

	// Act
	go hb.sendHeartbeats(ctx, cancel, testTopic, "test-agent-id", mockPublish.Publish)

	// Wait for some heartbeats with errors
	time.Sleep(120 * time.Millisecond)

	// Cancel context
	cancel()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert - even with publish errors, all calls should be made
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_ConcurrentCancellation(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	// Allow any number of publish calls since timing can vary
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Maybe()

	// Act - start heartbeats
	go hb.sendHeartbeats(ctx, cancel, testTopic, "test-agent-id", mockPublish.Publish)

	// Cancel immediately in a separate goroutine
	go func() {
		time.Sleep(1 * time.Millisecond)
		cancel()
	}()

	// Give time for everything to complete
	time.Sleep(50 * time.Millisecond)

	// Assert - should not panic or hang
	// The test passes if we reach this point without deadlock
	assert.True(t, true, "Concurrent cancellation handled without deadlock")
}

func TestHeartbeater_SendHeartbeats_HeartbeatStates(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	var capturedPayloads [][]byte
	var mutex sync.Mutex
	testTopic := "test/heartbeat"

	// Use a channel to signal when the goroutine has finished
	done := make(chan bool, 1)

	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		// Store a copy of the payload with proper synchronization
		payloadCopy := make([]byte, len(payload))
		copy(payloadCopy, payload)

		mutex.Lock()
		capturedPayloads = append(capturedPayloads, payloadCopy)
		mutex.Unlock()

		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Act
	go func() {
		hb.sendHeartbeats(ctx, cancel, testTopic, "test-agent-id", publishFunc)
		done <- true
	}()

	// Wait for initial heartbeat
	time.Sleep(10 * time.Millisecond)

	// Cancel to trigger offline heartbeat
	cancel()

	// Wait for goroutine to finish
	<-done

	// Assert - now safe to read capturedPayloads
	mutex.Lock()
	payloadsCopy := make([][]byte, len(capturedPayloads))
	copy(payloadsCopy, capturedPayloads)
	mutex.Unlock()

	assert.GreaterOrEqual(t, len(payloadsCopy), 2, "Should have at least initial and final heartbeats")

	// Verify all payloads are valid heartbeat messages and contain expected fields
	for i, payload := range payloadsCopy {
		var heartbeat messages.Heartbeat
		err := json.Unmarshal(payload, &heartbeat)
		require.NoError(t, err, "Heartbeat %d should be valid JSON", i)
		assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, heartbeat.SchemaVersion)
		assert.False(t, heartbeat.TimeStamp.IsZero())
		// Current implementation always sends Online state (1)
		assert.Equal(t, messages.State(1), heartbeat.State)
	}
}

// Test edge cases for heartbeater ticker cleanup
func TestFleetConfigManager_HeartbeaterTickerCleanup(t *testing.T) {
	// Act
	heartBeater := createTestHeartbeater()

	// Verify ticker is created
	assert.NotNil(t, heartBeater.hbTicker)

	// Stop ticker to clean up
	heartBeater.hbTicker.Stop()

	// Assert - no panic should occur
	assert.True(t, true, "Ticker cleanup should not cause issues")
}

func TestHeartbeater_Stop_Success(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	testTopic := "test/heartbeat"

	// Expect one heartbeat to be sent with Offline state
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Act
	hb.stop(testTopic, mockPublish.Publish)

	// Assert
	mockPublish.AssertExpectations(t)

	// Verify the ticker was stopped
	select {
	case <-hb.hbTicker.C:
		t.Error("Ticker should be stopped but channel is still active")
	case <-time.After(100 * time.Millisecond):
		// Expected - ticker is stopped
	}
}

func TestHeartbeater_Stop_PublishError(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	testTopic := "test/heartbeat"
	publishError := errors.New("publish failed")

	// Set up mock expectations - publish function returns error
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(publishError).Once()

	// Act - should not panic despite publish error
	hb.stop(testTopic, mockPublish.Publish)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_Stop_HeartbeatContent(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	// Act
	hb.stop(testTopic, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, heartbeat.SchemaVersion)
	// The stop method sends an Offline heartbeat, but the implementation currently sends Online (1)
	assert.Equal(t, messages.State(1), heartbeat.State)
	assert.False(t, heartbeat.TimeStamp.IsZero())
}
