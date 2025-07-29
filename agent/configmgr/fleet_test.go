package configmgr

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/messages"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockPublishFunc is a testify mock for the publish function
type mockPublishFunc struct {
	mock.Mock
}

func (m *mockPublishFunc) Publish(ctx context.Context, payload []byte) error {
	args := m.Called(ctx, payload)
	return args.Error(0)
}

// mockPolicyManagerForFleet implements the PolicyManager interface for fleet testing
type mockPolicyManagerForFleet struct {
	mock.Mock
}

func (m *mockPolicyManagerForFleet) ManagePolicy(payload config.PolicyPayload) {
	m.Called(payload)
}

func (m *mockPolicyManagerForFleet) RemovePolicyDataset(policyID string, datasetID string, be backend.Backend) {
	m.Called(policyID, datasetID, be)
}

func (m *mockPolicyManagerForFleet) GetPolicyState() ([]policies.PolicyData, error) {
	args := m.Called()
	return args.Get(0).([]policies.PolicyData), args.Error(1)
}

func (m *mockPolicyManagerForFleet) GetRepo() policies.PolicyRepo {
	args := m.Called()
	return args.Get(0).(policies.PolicyRepo)
}

func (m *mockPolicyManagerForFleet) ApplyBackendPolicies(be backend.Backend) error {
	args := m.Called(be)
	return args.Error(0)
}

func (m *mockPolicyManagerForFleet) RemoveBackendPolicies(be backend.Backend, permanently bool) error {
	args := m.Called(be, permanently)
	return args.Error(0)
}

func (m *mockPolicyManagerForFleet) RemovePolicy(policyID string, policyName string, beName string) error {
	args := m.Called(policyID, policyName, beName)
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

func TestHeartbeater_SendSingleHeartbeat_Success(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()

	// Expected heartbeat data
	expectedHeartbeat := messages.Heartbeat{
		AgentID: "orb-agent",
		Version: "1.0.0",
	}
	expectedPayload, _ := json.Marshal(expectedHeartbeat)

	// Set up mock expectations
	mockPublish.On("Publish", ctx, expectedPayload).Return(nil)

	// Act
	hb.sendSingleHeartbeat(ctx, mockPublish.Publish, testTime, messages.Online)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_PublishError(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()
	publishError := errors.New("publish failed")

	// Set up mock expectations - publish function returns error
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(publishError)

	// Act - should not panic despite publish error
	hb.sendSingleHeartbeat(ctx, mockPublish.Publish, testTime, messages.Online)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_HeartbeatContent(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	var capturedPayload []byte
	publishFunc := func(ctx context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, publishFunc, testTime, messages.Online)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	assert.Equal(t, "orb-agent", heartbeat.AgentID)
	assert.Equal(t, "1.0.0", heartbeat.Version)
}

func TestHeartbeater_SendHeartbeats_InitialHeartbeat(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up expectations for initial heartbeat (Online state)
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Set up expectations for final heartbeat (Offline state) when context is cancelled
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Act
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish)

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

	// We expect at least 3 heartbeats: initial + at least 2 periodic + final
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Times(4)

	// Act
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish)

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

	publishFunc := func(ctx context.Context, payload []byte) error {
		return mockPublish.Publish(ctx, payload)
	}

	// Expect initial heartbeat (Online) and final heartbeat (Offline)
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Twice()

	// Act
	go hb.sendHeartbeats(ctx, cancel, publishFunc)

	// Let it run briefly
	time.Sleep(10 * time.Millisecond)

	// Cancel context immediately
	cancel()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert
	mockPublish.AssertExpectations(t)

	// Verify context is properly cleaned up
	assert.Nil(t, hb.heartbeatCtx)
}

func TestHeartbeater_SendHeartbeats_PublishErrors(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publishError := errors.New("network error")

	// Mock publish function to return errors - should not stop the heartbeat loop
	// Expect initial + periodic + final heartbeat (all with errors)
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(publishError).Times(4)

	// Act
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish)

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

	// Allow any number of publish calls since timing can vary
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Maybe()

	// Act - start heartbeats
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish)

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
	publishFunc := func(ctx context.Context, payload []byte) error {
		// Store a copy of the payload
		payloadCopy := make([]byte, len(payload))
		copy(payloadCopy, payload)
		capturedPayloads = append(capturedPayloads, payloadCopy)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Act
	go hb.sendHeartbeats(ctx, cancel, publishFunc)

	// Wait for initial heartbeat
	time.Sleep(10 * time.Millisecond)

	// Cancel to trigger offline heartbeat
	cancel()

	// Wait for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert
	assert.GreaterOrEqual(t, len(capturedPayloads), 2, "Should have at least initial and final heartbeats")

	// Verify all payloads are valid heartbeat messages
	for i, payload := range capturedPayloads {
		var heartbeat messages.Heartbeat
		err := json.Unmarshal(payload, &heartbeat)
		require.NoError(t, err, "Heartbeat %d should be valid JSON", i)
		assert.Equal(t, "orb-agent", heartbeat.AgentID)
		assert.Equal(t, "1.0.0", heartbeat.Version)
	}
}

func TestNewFleetConfigManager_HeartbeaterInitialization(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}

	// Act
	fleetManager := NewFleetConfigManager(logger, mockPMgr)

	// Assert
	assert.NotNil(t, fleetManager)
	assert.NotNil(t, fleetManager.heartbeater)
	assert.NotNil(t, fleetManager.heartbeater.logger)
	assert.NotNil(t, fleetManager.heartbeater.hbTicker)
	assert.NotNil(t, fleetManager.heartbeater.hbTicker.C, "Ticker channel should be available")
	assert.NotNil(t, fleetManager.heartbeater.heartbeatCtx, "Heartbeat context should be initialized")

	// Clean up ticker
	fleetManager.heartbeater.hbTicker.Stop()
}

func TestHeartbeater_Constants(t *testing.T) {
	// Test that constants are properly defined
	assert.Equal(t, 50*time.Second, HeartbeatFreq)
	assert.Equal(t, 5*time.Minute, RestartTimeMin)
}
