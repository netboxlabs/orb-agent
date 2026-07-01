package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

type stubBundleRetriever struct{ entries []filesmgr.FileEntry }

func (s stubBundleRetriever) List() []filesmgr.FileEntry { return s.entries }

func init() {
	heartbeatTickInterval = 50 * time.Millisecond
}

// testPolicyManagerWithRepo implements policymgr.PolicyManager by delegating
// GetPolicyState / GetRepo to an in-memory repo (for shutdown / heartbeat payload tests).
type testPolicyManagerWithRepo struct {
	repo policies.PolicyRepo
}

func (t *testPolicyManagerWithRepo) ManagePolicy(_ config.PolicyPayload) {}

func (t *testPolicyManagerWithRepo) RemovePolicyDataset(_ string, _ string, _ backend.Backend) {}

func (t *testPolicyManagerWithRepo) GetPolicyState() ([]policies.PolicyData, error) {
	return t.repo.GetAll()
}

func (t *testPolicyManagerWithRepo) GetRepo() policies.PolicyRepo { return t.repo }

func (t *testPolicyManagerWithRepo) ApplyBackendPolicies(_ backend.Backend) error { return nil }

func (t *testPolicyManagerWithRepo) RemoveBackendPolicies(_ backend.Backend, _ bool) error {
	return nil
}

func (t *testPolicyManagerWithRepo) RemovePolicy(_ string, _ string, _ string) error { return nil }

var _ policymgr.PolicyManager = (*testPolicyManagerWithRepo)(nil)

// mockPublishFunc is a testify mock for the publish function
type mockPublishFunc struct {
	mock.Mock
}

func (m *mockPublishFunc) Publish(ctx context.Context, topic string, payload []byte) error {
	args := m.Called(ctx, topic, payload)
	return args.Error(0)
}

// mockPolicyManagerForHeartbeat implements the PolicyManager interface for heartbeat testing
type mockPolicyManagerForHeartbeat struct {
	mock.Mock
}

func (m *mockPolicyManagerForHeartbeat) ManagePolicy(payload config.PolicyPayload) {
	m.Called(payload)
}

func (m *mockPolicyManagerForHeartbeat) RemovePolicyDataset(policyID string, datasetID string, be backend.Backend) {
	m.Called(policyID, datasetID, be)
}

func (m *mockPolicyManagerForHeartbeat) GetPolicyState() ([]policies.PolicyData, error) {
	args := m.Called()
	return args.Get(0).([]policies.PolicyData), args.Error(1)
}

func (m *mockPolicyManagerForHeartbeat) GetRepo() policies.PolicyRepo {
	args := m.Called()
	return args.Get(0).(policies.PolicyRepo)
}

func (m *mockPolicyManagerForHeartbeat) ApplyBackendPolicies(be backend.Backend) error {
	args := m.Called(be)
	return args.Error(0)
}

func (m *mockPolicyManagerForHeartbeat) RemoveBackendPolicies(be backend.Backend, permanently bool) error {
	args := m.Called(be, permanently)
	return args.Error(0)
}

func (m *mockPolicyManagerForHeartbeat) RemovePolicy(policyID string, policyName string, beName string) error {
	args := m.Called(policyID, policyName, beName)
	return args.Error(0)
}

// Test helper to create a heartbeater instance for testing
func createTestHeartbeater() *heartbeater {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil).Maybe()
	groupManager := newGroupManager()
	return &heartbeater{
		logger:         logger,
		backendState:   &mockBackendState{},
		policyManager:  mockPMgr,
		groupRetriever: &groupManager,
	}
}

func createTestHeartbeaterWithBackendState(backendState *mockBackendState) *heartbeater {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil).Maybe()
	groupManager := newGroupManager()
	return &heartbeater{
		logger:         logger,
		backendState:   backendState,
		policyManager:  mockPMgr,
		groupRetriever: &groupManager,
	}
}

func createTestHeartbeaterWithPolicyManager(backendState *mockBackendState, policyManager *mockPolicyManagerForHeartbeat) *heartbeater {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	groupManager := newGroupManager()
	return &heartbeater{
		logger:         logger,
		backendState:   backendState,
		policyManager:  policyManager,
		groupRetriever: &groupManager,
	}
}

func TestNewHeartbeater_HeartbeaterInitialization(t *testing.T) {
	// Act
	fleetManager := createTestHeartbeater()

	// Assert
	assert.NotNil(t, fleetManager)
	assert.NotNil(t, fleetManager.logger)
}

func TestHeartbeater_SendSingleHeartbeat_Success(t *testing.T) {
	// Arrange
	backendState := &mockBackendState{}
	hb := createTestHeartbeaterWithBackendState(backendState)

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()
	testTopic := "test/heartbeat"

	// We don't assert exact bytes; validate the marshalled heartbeat content
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(nil)

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, mockPublish.Publish, "test-agent-id", testTime, messages.Online, nil)

	// Assert: ensure one publish happened with a valid heartbeat payload
	calls := mockPublish.Calls
	require.Len(t, calls, 1)
	payload, ok := calls[0].Arguments.Get(2).([]byte)
	require.True(t, ok)

	var hbMsg messages.Heartbeat
	require.NoError(t, json.Unmarshal(payload, &hbMsg))
	assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, hbMsg.SchemaVersion)
	assert.Equal(t, messages.State(messages.Online), hbMsg.State)
	assert.False(t, hbMsg.TimeStamp.IsZero())
}

func TestHeartbeater_SendSingleHeartbeat_OfflineState(t *testing.T) {
	hb := createTestHeartbeater()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	mockPublish.On("Publish", ctx, "test/hb", mock.AnythingOfType("[]uint8")).Return(nil)

	hb.sendSingleHeartbeat(ctx, "test/hb", mockPublish.Publish, "agent-1", time.Now(), messages.Offline, nil)

	calls := mockPublish.Calls
	require.Len(t, calls, 1)
	payload, ok := calls[0].Arguments.Get(2).([]byte)
	require.True(t, ok)

	var hbMsg messages.Heartbeat
	require.NoError(t, json.Unmarshal(payload, &hbMsg))
	assert.Equal(t, messages.State(messages.Offline), hbMsg.State,
		"Offline heartbeat must carry State=Offline, not State=Online")
}

// TestHeartbeater_OfflineHeartbeat_IncludesFailedRunsAfterFailNonTerminalRuns verifies that
// after FailNonTerminalRuns (as in orbAgent.Stop before Fleet shutdown), an offline heartbeat
// payload includes failed runs with the shutdown reason (OBS-2686).
func TestHeartbeater_OfflineHeartbeat_IncludesFailedRunsAfterFailNonTerminalRuns(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	now := time.Now().UTC()
	before := now.Add(-30 * time.Minute)
	require.NoError(t, repo.Update(policies.PolicyData{
		ID:       "pol-id-1",
		Name:     "network-scan",
		Backend:  "network-discovery",
		Version:  1,
		Datasets: map[string]bool{"ds1": true},
		GroupIDs: map[string]bool{},
		State:    policies.Running,
		Runs: []policies.RunData{
			{ID: "run-a", Status: "running", CreatedAt: before, UpdatedAt: before},
			{ID: "run-b", Status: "completed", CreatedAt: before, UpdatedAt: before},
		},
	}))
	require.NoError(t, repo.FailNonTerminalRuns(policies.RunFailureReasonAgentStopped))

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pm := &testPolicyManagerWithRepo{repo: repo}
	groupManager := newGroupManager()
	hb := &heartbeater{
		logger:         logger,
		backendState:   &mockBackendState{},
		policyManager:  pm,
		groupRetriever: &groupManager,
	}

	var captured []byte
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		captured = payload
		return nil
	}

	hb.sendSingleHeartbeat(context.Background(), "fleet/hb", publishFunc, "agent-1", time.Now(), messages.Offline, nil)
	require.NotEmpty(t, captured)

	var msg messages.Heartbeat
	require.NoError(t, json.Unmarshal(captured, &msg))
	pi, ok := msg.PolicyState["pol-id-1"]
	require.True(t, ok, "policy state should include policy id key")
	require.Len(t, pi.Runs, 2)

	var runA, runB *messages.RunStateInfo
	for i := range pi.Runs {
		switch pi.Runs[i].ID {
		case "run-a":
			runA = &pi.Runs[i]
		case "run-b":
			runB = &pi.Runs[i]
		}
	}
	require.NotNil(t, runA)
	require.NotNil(t, runB)
	assert.Equal(t, "failed", runA.Status)
	assert.Equal(t, policies.RunFailureReasonAgentStopped, runA.Reason)
	assert.Equal(t, "completed", runB.Status)
}

func TestHeartbeater_SendSingleHeartbeat_PublishError(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()
	testTopic := "test/heartbeat"
	publishError := errors.New("publish failed")

	// Set up mock expectations - publish function returns error
	mockPublish.On("Publish", ctx, testTopic, mock.AnythingOfType("[]uint8")).Return(publishError)

	// Act - should not panic despite publish error
	hb.sendSingleHeartbeat(ctx, testTopic, mockPublish.Publish, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_HeartbeatContent(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

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

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	// Only the initial Online heartbeat is expected. The offline heartbeat is sent
	// by stop(), not by the goroutine reacting to ctx.Done().
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Act
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)

	// Give some time for initial heartbeat
	time.Sleep(10 * time.Millisecond)

	// Cancel context — goroutine exits cleanly without sending an offline heartbeat
	cancel()
	hb.wg.Wait()

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_PeriodicHeartbeats(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	// We expect at least 3 heartbeats: initial + at least 2 periodic. The offline
	// heartbeat is sent only by stop(), not by context cancellation.
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Times(3)

	// Act
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)

	// Wait for some periodic heartbeats (ticker is 50ms in test)
	time.Sleep(120 * time.Millisecond)

	// Cancel context
	cancel()
	hb.wg.Wait()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_ContextCancellation(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	publishFunc := func(ctx context.Context, topic string, payload []byte) error {
		return mockPublish.Publish(ctx, topic, payload)
	}

	// Expect only the initial Online heartbeat. Context cancellation no longer
	// triggers an offline heartbeat from the goroutine — stop() owns that.
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Act
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", publishFunc, nil)

	// Let it run briefly
	time.Sleep(10 * time.Millisecond)

	// Cancel context immediately
	cancel()
	hb.wg.Wait()

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_PublishErrors(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	publishError := errors.New("network error")

	// Expect initial + at least 2 periodic (no offline from context cancel).
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(publishError).Times(3)

	// Act
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)

	// Wait for some heartbeats with errors
	time.Sleep(120 * time.Millisecond)

	// Cancel context
	cancel()
	hb.wg.Wait()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert - even with publish errors, all calls should be made
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_ConcurrentCancellation(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	testTopic := "test/heartbeat"

	// Allow any number of publish calls since timing can vary
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Maybe()

	// Act - start heartbeats
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)

	// Cancel immediately in a separate goroutine
	go func() {
		time.Sleep(1 * time.Millisecond)
		cancel()
	}()

	// Give time for everything to complete
	time.Sleep(50 * time.Millisecond)
	hb.wg.Wait()

	// Assert - should not panic or hang
	// The test passes if we reach this point without deadlock
	assert.True(t, true, "Concurrent cancellation handled without deadlock")
}

func TestHeartbeater_SendHeartbeats_HeartbeatStates(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	var capturedPayloads [][]byte
	var mutex sync.Mutex
	testTopic := "test/heartbeat"

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
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", publishFunc, nil)

	// Wait for initial heartbeat
	time.Sleep(10 * time.Millisecond)

	// Cancel to trigger offline heartbeat
	cancel()
	hb.wg.Wait()

	// Assert - now safe to read capturedPayloads
	mutex.Lock()
	payloadsCopy := make([][]byte, len(capturedPayloads))
	copy(payloadsCopy, capturedPayloads)
	mutex.Unlock()

	// Context cancellation no longer triggers an offline heartbeat from the goroutine.
	// Only the initial Online heartbeat is guaranteed here.
	assert.GreaterOrEqual(t, len(payloadsCopy), 1, "Should have at least the initial heartbeat")

	// Verify all payloads are valid Online heartbeat messages.
	for i, payload := range payloadsCopy {
		var heartbeat messages.Heartbeat
		err := json.Unmarshal(payload, &heartbeat)
		require.NoError(t, err, "Heartbeat %d should be valid JSON", i)
		assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, heartbeat.SchemaVersion)
		assert.False(t, heartbeat.TimeStamp.IsZero())
		assert.Equal(t, messages.State(messages.Online), heartbeat.State)
	}
}

// Test edge cases for heartbeater: no long-lived ticker until a session starts
func TestFleetConfigManager_HeartbeaterTickerCleanup(t *testing.T) {
	heartBeater := createTestHeartbeater()
	assert.Nil(t, heartBeater.sessionCancel)
}

func TestHeartbeater_Stop_Success(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	mockPublish := &mockPublishFunc{}
	testTopic := "test/heartbeat"

	// Expect one heartbeat to be sent with Offline state
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Act
	hb.stop(testTopic, mockPublish.Publish)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_Stop_PublishError(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

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
	// The stop method sends an Offline heartbeat
	assert.Equal(t, messages.State(messages.Offline), heartbeat.State)
	assert.False(t, heartbeat.TimeStamp.IsZero())
}

// TestHeartbeater_ContextDone_OfflineHeartbeatSentByStop is a regression test for the
// race condition where monitorCtx cancellation caused the heartbeat goroutine to send
// the offline heartbeat against a simultaneously-closing MQTT connection (OBS-2686).
//
// After the fix: the goroutine exits cleanly on ctx.Done() without sending an offline
// heartbeat. stop() is the sole sender, always called when the connection is still alive.
func TestHeartbeater_ContextDone_OfflineHeartbeatSentByStop(t *testing.T) {
	hb := createTestHeartbeater()
	testTopic := "test/heartbeat"

	var mu sync.Mutex
	offlineCount := 0
	stopCalled := make(chan struct{})

	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		var hbData messages.Heartbeat
		if err := json.Unmarshal(payload, &hbData); err != nil {
			return nil
		}
		if hbData.State == messages.State(messages.Offline) {
			mu.Lock()
			offlineCount++
			mu.Unlock()
			// If offline was sent before stop() was called, the goroutine sent it
			// while the parent context was being cancelled — the race condition.
			select {
			case <-stopCalled:
			default:
				t.Errorf("offline heartbeat sent by goroutine reacting to ctx.Done(), not by stop()")
			}
		}
		return nil
	}

	parentCtx, parentCancel := context.WithCancel(context.Background())
	hb.StartHeartbeats(parentCtx, testTopic, "agent-id", publishFunc, nil)
	time.Sleep(20 * time.Millisecond) // let initial Online heartbeat send

	// Simulate monitorCtx cancellation — the race window.
	// Wait on the WaitGroup so we know the goroutine has fully exited before
	// calling stop(), eliminating the timing dependency.
	parentCancel()
	hb.wg.Wait()

	// Now call stop() (simulating Disconnect() in Stop())
	close(stopCalled)
	hb.stop(testTopic, publishFunc)

	mu.Lock()
	got := offlineCount
	mu.Unlock()
	if got != 1 {
		t.Errorf("expected exactly 1 offline heartbeat from stop(), got %d", got)
	}
}

func TestHeartbeater_SendSingleHeartbeat_WithBackendState(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	backendState := &mockBackendState{
		backendState: map[string]*backend.State{
			"pktvisor": {
				Status:            backend.Running,
				RestartCount:      3,
				LastError:         "connection timeout",
				LastRestartTS:     testTime,
				LastRestartReason: "policy update",
			},
			"snmp_discovery": {
				Status:            backend.BackendError,
				RestartCount:      1,
				LastError:         "initialization failed",
				LastRestartTS:     testTime.Add(-1 * time.Hour),
				LastRestartReason: "startup",
			},
		},
	}
	// Arrange
	hb := createTestHeartbeaterWithBackendState(backendState)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify backend state is populated
	assert.NotNil(t, heartbeat.BackendState)
	assert.Len(t, heartbeat.BackendState, 2)

	// Check pktvisor backend state
	pktvisorState, ok := heartbeat.BackendState["pktvisor"]
	assert.True(t, ok)
	assert.Equal(t, "running", pktvisorState.State)
	assert.Equal(t, int64(3), pktvisorState.RestartCount)
	assert.Equal(t, "connection timeout", pktvisorState.LastError)
	assert.Equal(t, testTime, pktvisorState.LastRestartTS)
	assert.Equal(t, "policy update", pktvisorState.LastRestartReason)

	// Check snmp_discovery backend state
	snmpState, ok := heartbeat.BackendState["snmp_discovery"]
	assert.True(t, ok)
	assert.Equal(t, "backend_error", snmpState.State)
	assert.Equal(t, int64(1), snmpState.RestartCount)
	assert.Equal(t, "initialization failed", snmpState.LastError)
	assert.Equal(t, testTime.Add(-1*time.Hour), snmpState.LastRestartTS)
	assert.Equal(t, "startup", snmpState.LastRestartReason)

	// Verify policy and group states are present (may be empty based on mock)
	assert.NotNil(t, heartbeat.PolicyState)
	assert.NotNil(t, heartbeat.GroupState)
	assert.Empty(t, heartbeat.GroupState)
}

func TestHeartbeater_SendSingleHeartbeat_WithoutBackendState(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	// Do not set backend state function
	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify backend state is empty but not nil
	assert.NotNil(t, heartbeat.BackendState)
	assert.Empty(t, heartbeat.BackendState)
}

func TestHeartbeater_SendSingleHeartbeat_WithEmptyBackendState(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify backend state is empty
	assert.NotNil(t, heartbeat.BackendState)
	assert.Empty(t, heartbeat.BackendState)
}

func TestHeartbeater_SendSingleHeartbeat_BackendStateAllStatuses(t *testing.T) {
	// Test all possible backend statuses
	testCases := []struct {
		name           string
		status         backend.RunningStatus
		expectedString string
	}{
		{"Unknown", backend.Unknown, "unknown"},
		{"Running", backend.Running, "running"},
		{"BackendError", backend.BackendError, "backend_error"},
		{"AgentError", backend.AgentError, "agent_error"},
		{"Offline", backend.Offline, "offline"},
		{"Waiting", backend.Waiting, "waiting"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			backendState := &mockBackendState{
				backendState: map[string]*backend.State{
					"test-backend": {
						Status:       tc.status,
						RestartCount: 0,
						LastError:    "",
					},
				},
			}
			hb := createTestHeartbeaterWithBackendState(backendState)

			var capturedPayload []byte
			testTopic := "test/heartbeat"
			publishFunc := func(_ context.Context, _ string, payload []byte) error {
				capturedPayload = payload
				return nil
			}

			ctx := context.Background()
			testTime := time.Now()

			// Act
			hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

			// Assert
			require.NotNil(t, capturedPayload)

			var heartbeat messages.Heartbeat
			err := json.Unmarshal(capturedPayload, &heartbeat)
			require.NoError(t, err)

			assert.Len(t, heartbeat.BackendState, 1)
			actualState := heartbeat.BackendState["test-backend"]
			assert.Equal(t, tc.expectedString, actualState.State)
		})
	}
}

func TestHeartbeater_GetPolicyState_Success(t *testing.T) {
	// Arrange
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:         "policy-1",
			Name:       "Test Policy 1",
			Backend:    "pktvisor",
			Version:    1,
			State:      policies.Running,
			BackendErr: "",
			Datasets:   map[string]bool{"dataset-1": true, "dataset-2": true},
		},
		{
			ID:         "policy-2",
			Name:       "Test Policy 2",
			Backend:    "snmp_discovery",
			Version:    2,
			State:      policies.FailedToApply,
			BackendErr: "connection timeout",
			Datasets:   map[string]bool{"dataset-3": true},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	// Act
	policyState := hb.getPolicyState()

	// Assert
	assert.Len(t, policyState, 2)

	// Verify policy-1
	policy1, ok := policyState["policy-1"]
	assert.True(t, ok)
	assert.Equal(t, "Test Policy 1", policy1.Name)
	assert.Equal(t, "pktvisor", policy1.Backend)
	assert.Equal(t, int32(1), policy1.Version)
	assert.Equal(t, "running", policy1.State)
	assert.Equal(t, "", policy1.Error)
	assert.Len(t, policy1.Datasets, 2)
	assert.Contains(t, policy1.Datasets, "dataset-1")
	assert.Contains(t, policy1.Datasets, "dataset-2")

	// Verify policy-2
	policy2, ok := policyState["policy-2"]
	assert.True(t, ok)
	assert.Equal(t, "Test Policy 2", policy2.Name)
	assert.Equal(t, "snmp_discovery", policy2.Backend)
	assert.Equal(t, int32(2), policy2.Version)
	assert.Equal(t, "failed_to_apply", policy2.State)
	assert.Equal(t, "connection timeout", policy2.Error)
	assert.Len(t, policy2.Datasets, 1)
	assert.Contains(t, policy2.Datasets, "dataset-3")

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_GetPolicyState_Error(t *testing.T) {
	// Arrange
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	expectedErr := errors.New("failed to retrieve policy state")
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, expectedErr)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	// Act
	policyState := hb.getPolicyState()

	// Assert - should return empty map on error
	assert.NotNil(t, policyState)
	assert.Empty(t, policyState)
	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_GetPolicyState_EmptyPolicies(t *testing.T) {
	// Arrange
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	// Act
	policyState := hb.getPolicyState()

	// Assert
	assert.NotNil(t, policyState)
	assert.Empty(t, policyState)
	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_GetPolicyState_AllPolicyStates(t *testing.T) {
	// Test all possible policy states
	testCases := []struct {
		name           string
		state          policies.PolicyState
		expectedString string
	}{
		{"Unknown", policies.Unknown, "unknown"},
		{"Running", policies.Running, "running"},
		{"FailedToApply", policies.FailedToApply, "failed_to_apply"},
		{"Offline", policies.Offline, "offline"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			mockPMgr := &mockPolicyManagerForHeartbeat{}
			mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
				{
					ID:       "test-policy",
					Name:     "Test Policy",
					Backend:  "pktvisor",
					Version:  1,
					State:    tc.state,
					Datasets: map[string]bool{"dataset-1": true},
				},
			}, nil)

			hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

			// Act
			policyState := hb.getPolicyState()

			// Assert
			assert.Len(t, policyState, 1)
			actualState := policyState["test-policy"]
			assert.Equal(t, tc.expectedString, actualState.State)
			mockPMgr.AssertExpectations(t)
		})
	}
}

func TestHeartbeater_SendSingleHeartbeat_WithPolicyState(t *testing.T) {
	// Arrange
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:         "policy-1",
			Name:       "Test Policy 1",
			Backend:    "pktvisor",
			Version:    1,
			State:      policies.Running,
			BackendErr: "",
			Datasets:   map[string]bool{"dataset-1": true, "dataset-2": true},
		},
		{
			ID:         "policy-2",
			Name:       "Test Policy 2",
			Backend:    "snmp_discovery",
			Version:    3,
			State:      policies.FailedToApply,
			BackendErr: "no interface match",
			Datasets:   map[string]bool{"dataset-3": true},
		},
	}, nil)

	backendState := &mockBackendState{
		backendState: map[string]*backend.State{
			"pktvisor": {
				Status:       backend.Running,
				RestartCount: 0,
				LastError:    "",
			},
		},
	}

	hb := createTestHeartbeaterWithPolicyManager(backendState, mockPMgr)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify policy state is populated
	assert.NotNil(t, heartbeat.PolicyState)
	assert.Len(t, heartbeat.PolicyState, 2)

	// Check policy-1
	policy1, ok := heartbeat.PolicyState["policy-1"]
	assert.True(t, ok)
	assert.Equal(t, "Test Policy 1", policy1.Name)
	assert.Equal(t, "pktvisor", policy1.Backend)
	assert.Equal(t, int32(1), policy1.Version)
	assert.Equal(t, "running", policy1.State)
	assert.Equal(t, "", policy1.Error)
	assert.Len(t, policy1.Datasets, 2)
	assert.Contains(t, policy1.Datasets, "dataset-1")
	assert.Contains(t, policy1.Datasets, "dataset-2")

	// Check policy-2
	policy2, ok := heartbeat.PolicyState["policy-2"]
	assert.True(t, ok)
	assert.Equal(t, "Test Policy 2", policy2.Name)
	assert.Equal(t, "snmp_discovery", policy2.Backend)
	assert.Equal(t, int32(3), policy2.Version)
	assert.Equal(t, "failed_to_apply", policy2.State)
	assert.Equal(t, "no interface match", policy2.Error)
	assert.Len(t, policy2.Datasets, 1)
	assert.Contains(t, policy2.Datasets, "dataset-3")

	// Verify backend state is also present
	assert.NotNil(t, heartbeat.BackendState)
	assert.Len(t, heartbeat.BackendState, 1)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_WithPolicyStateError(t *testing.T) {
	// Arrange
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, errors.New("policy manager error"))

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act - should not panic despite policy state error
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify policy state is empty but not nil
	assert.NotNil(t, heartbeat.PolicyState)
	assert.Empty(t, heartbeat.PolicyState)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_WithEmptyPolicyState(t *testing.T) {
	// Arrange
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify policy state is empty
	assert.NotNil(t, heartbeat.PolicyState)
	assert.Empty(t, heartbeat.PolicyState)

	mockPMgr.AssertExpectations(t)
}

func TestNewHeartbeater_WithPolicyManager(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	backendState := &mockBackendState{}
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	groupManager := newGroupManager()

	// Act
	hb := newHeartbeater(logger, backendState, mockPMgr, &groupManager, stubBundleRetriever{})

	// Assert
	assert.NotNil(t, hb)
	assert.NotNil(t, hb.logger)
	assert.NotNil(t, hb.backendState)
	assert.NotNil(t, hb.policyManager)
	assert.Equal(t, mockPMgr, hb.policyManager)
	assert.NotNil(t, hb.groupRetriever)
}

func createTestHeartbeaterWithGroupManager(groupManager *GroupManager) *heartbeater {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil).Maybe()
	return &heartbeater{
		logger:         logger,
		backendState:   &mockBackendState{},
		policyManager:  mockPMgr,
		groupRetriever: groupManager,
	}
}

func TestHeartbeater_SendSingleHeartbeat_WithEmptyGroupState(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	hb := createTestHeartbeaterWithGroupManager(&gm)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify group state is empty but not nil
	assert.NotNil(t, heartbeat.GroupState)
	assert.Empty(t, heartbeat.GroupState)
}

func TestHeartbeater_SendSingleHeartbeat_WithGroupState(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	})
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-2",
		Name:    "Test Group 2",
	})
	hb := createTestHeartbeaterWithGroupManager(&gm)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify group state is populated
	assert.NotNil(t, heartbeat.GroupState)
	assert.Len(t, heartbeat.GroupState, 2)

	// Check group-1
	group1, ok := heartbeat.GroupState["group-1"]
	assert.True(t, ok)
	assert.Equal(t, "Test Group 1", group1.GroupName)
	assert.Equal(t, "group-1", group1.GroupID)

	// Check group-2
	group2, ok := heartbeat.GroupState["group-2"]
	assert.True(t, ok)
	assert.Equal(t, "Test Group 2", group2.GroupName)
	assert.Equal(t, "group-2", group2.GroupID)
}

func TestHeartbeater_SendSingleHeartbeat_WithCompleteState(t *testing.T) {
	// Test heartbeat with backend, policy, and group states all populated
	// Arrange
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Setup backend state
	backendState := &mockBackendState{
		backendState: map[string]*backend.State{
			"pktvisor": {
				Status:       backend.Running,
				RestartCount: 1,
				LastError:    "",
			},
		},
	}

	// Setup policy manager
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:       "policy-1",
			Name:     "Test Policy",
			Backend:  "pktvisor",
			Version:  1,
			State:    policies.Running,
			Datasets: map[string]bool{"dataset-1": true},
		},
	}, nil)

	// Setup group manager
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	})

	// Create heartbeater with all components
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	hb := &heartbeater{
		logger: logger,

		backendState:   backendState,
		policyManager:  mockPMgr,
		groupRetriever: &gm,
	}

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify all state sections are present
	assert.NotNil(t, heartbeat.BackendState)
	assert.Len(t, heartbeat.BackendState, 1)
	assert.NotNil(t, heartbeat.PolicyState)
	assert.Len(t, heartbeat.PolicyState, 1)
	assert.NotNil(t, heartbeat.GroupState)
	assert.Len(t, heartbeat.GroupState, 1)

	// Verify backend state
	backend, ok := heartbeat.BackendState["pktvisor"]
	assert.True(t, ok)
	assert.Equal(t, "running", backend.State)

	// Verify policy state
	policy, ok := heartbeat.PolicyState["policy-1"]
	assert.True(t, ok)
	assert.Equal(t, "Test Policy", policy.Name)

	// Verify group state
	group, ok := heartbeat.GroupState["group-1"]
	assert.True(t, ok)
	assert.Equal(t, "Test Group 1", group.GroupName)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_GroupStateAfterRemoval(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	})
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-2",
		Name:    "Test Group 2",
	})
	hb := createTestHeartbeaterWithGroupManager(&gm)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Send initial heartbeat with 2 groups
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	require.NotNil(t, capturedPayload)

	var heartbeat1 messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat1)
	require.NoError(t, err)
	assert.Len(t, heartbeat1.GroupState, 2)

	// Remove one group
	gm.Remove("group-1")

	// Send second heartbeat after removal
	capturedPayload = nil
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	require.NotNil(t, capturedPayload)

	var heartbeat2 messages.Heartbeat
	err = json.Unmarshal(capturedPayload, &heartbeat2)
	require.NoError(t, err)

	// Assert - Should only have 1 group now
	assert.Len(t, heartbeat2.GroupState, 1)
	_, ok := heartbeat2.GroupState["group-1"]
	assert.False(t, ok)
	group2, ok := heartbeat2.GroupState["group-2"]
	assert.True(t, ok)
	assert.Equal(t, "Test Group 2", group2.GroupName)
}

func TestHeartbeater_SendSingleHeartbeat_GroupStateAfterRemoveAll(t *testing.T) {
	// Arrange
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	})
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-2",
		Name:    "Test Group 2",
	})
	hb := createTestHeartbeaterWithGroupManager(&gm)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Send initial heartbeat with 2 groups
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	require.NotNil(t, capturedPayload)

	var heartbeat1 messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat1)
	require.NoError(t, err)
	assert.Len(t, heartbeat1.GroupState, 2)

	// Remove all groups
	gm.RemoveAll()

	// Send second heartbeat after removal
	capturedPayload = nil
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	require.NotNil(t, capturedPayload)

	var heartbeat2 messages.Heartbeat
	err = json.Unmarshal(capturedPayload, &heartbeat2)
	require.NoError(t, err)

	// Assert - Should have no groups now
	assert.NotNil(t, heartbeat2.GroupState)
	assert.Empty(t, heartbeat2.GroupState)
}

func TestHeartbeater_SendSingleHeartbeat_DynamicGroupUpdates(t *testing.T) {
	// Test that group state reflects dynamic updates
	// Arrange
	gm := newGroupManager()
	hb := createTestHeartbeaterWithGroupManager(&gm)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Heartbeat 1: No groups
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	var hb1 messages.Heartbeat
	require.NoError(t, json.Unmarshal(capturedPayload, &hb1))
	assert.Empty(t, hb1.GroupState)

	// Add group
	gm.Add(messages.GroupMembershipData{GroupID: "group-1", Name: "Group 1"})

	// Heartbeat 2: 1 group
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	var hb2 messages.Heartbeat
	require.NoError(t, json.Unmarshal(capturedPayload, &hb2))
	assert.Len(t, hb2.GroupState, 1)

	// Add another group
	gm.Add(messages.GroupMembershipData{GroupID: "group-2", Name: "Group 2"})

	// Heartbeat 3: 2 groups
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	var hb3 messages.Heartbeat
	require.NoError(t, json.Unmarshal(capturedPayload, &hb3))
	assert.Len(t, hb3.GroupState, 2)

	// Remove one
	gm.Remove("group-1")

	// Heartbeat 4: 1 group
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)
	var hb4 messages.Heartbeat
	require.NoError(t, json.Unmarshal(capturedPayload, &hb4))
	assert.Len(t, hb4.GroupState, 1)
	_, ok := hb4.GroupState["group-2"]
	assert.True(t, ok)
}

func TestNewHeartbeater_WithGroupManager(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	backendState := &mockBackendState{}
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	gm := newGroupManager()
	gm.Add(messages.GroupMembershipData{
		GroupID: "group-1",
		Name:    "Test Group 1",
	})

	// Act
	hb := newHeartbeater(logger, backendState, mockPMgr, &gm, stubBundleRetriever{})

	// Assert
	assert.NotNil(t, hb)
	assert.NotNil(t, hb.groupRetriever)

	// Verify we can retrieve groups through the interface
	groups := hb.groupRetriever.GetAll()
	require.Len(t, groups, 1)
	assert.Equal(t, "group-1", groups[0].GroupID)
}

func TestHeartbeater_GetPolicyState_WithRuns(t *testing.T) {
	// Arrange
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:         "policy-1",
			Name:       "Test Policy 1",
			Backend:    "pktvisor",
			Version:    1,
			State:      policies.Running,
			BackendErr: "",
			Datasets:   map[string]bool{"dataset-1": true},
			Runs: []policies.RunData{
				{
					ID:        "run-1",
					Status:    "completed",
					CreatedAt: testTime,
					UpdatedAt: testTime.Add(5 * time.Minute),
				},
				{
					ID:        "run-2",
					Status:    "running",
					CreatedAt: testTime.Add(10 * time.Minute),
					UpdatedAt: testTime.Add(12 * time.Minute),
				},
			},
		},
		{
			ID:         "policy-2",
			Name:       "Test Policy 2",
			Backend:    "snmp_discovery",
			Version:    2,
			State:      policies.Running,
			BackendErr: "",
			Datasets:   map[string]bool{"dataset-2": true},
			Runs:       []policies.RunData{}, // Empty runs
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	// Act
	policyState := hb.getPolicyState()

	// Assert
	assert.Len(t, policyState, 2)

	// Verify policy-1 has runs
	policy1, ok := policyState["policy-1"]
	assert.True(t, ok)
	assert.Len(t, policy1.Runs, 2)
	assert.Equal(t, "run-1", policy1.Runs[0].ID)
	assert.Equal(t, "completed", policy1.Runs[0].Status)
	assert.Equal(t, testTime, policy1.Runs[0].CreatedAt)
	assert.Equal(t, "run-2", policy1.Runs[1].ID)
	assert.Equal(t, "running", policy1.Runs[1].Status)

	// Verify policy-2 has no runs (nil or empty)
	policy2, ok := policyState["policy-2"]
	assert.True(t, ok)
	assert.Nil(t, policy2.Runs)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_WithRuns(t *testing.T) {
	// Arrange
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:       "policy-1",
			Name:     "Test Policy",
			Backend:  "pktvisor",
			Version:  1,
			State:    policies.Running,
			Datasets: map[string]bool{"dataset-1": true},
			Runs: []policies.RunData{
				{
					ID:        "run-1",
					Status:    "completed",
					CreatedAt: testTime,
					UpdatedAt: testTime.Add(5 * time.Minute),
				},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify policy state includes runs
	assert.NotNil(t, heartbeat.PolicyState)
	assert.Len(t, heartbeat.PolicyState, 1)

	policy, ok := heartbeat.PolicyState["policy-1"]
	assert.True(t, ok)
	assert.Len(t, policy.Runs, 1)
	assert.Equal(t, "run-1", policy.Runs[0].ID)
	assert.Equal(t, "completed", policy.Runs[0].Status)
	assert.Equal(t, testTime, policy.Runs[0].CreatedAt)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_WithEntityCount(t *testing.T) {
	// Arrange
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	entityCount := int64(100)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:       "policy-1",
			Name:     "Test Policy",
			Backend:  "pktvisor",
			Version:  1,
			State:    policies.Running,
			Datasets: map[string]bool{"dataset-1": true},
			Runs: []policies.RunData{
				{
					ID:          "run-1",
					Status:      "completed",
					EntityCount: entityCount,
					CreatedAt:   testTime,
					UpdatedAt:   testTime.Add(5 * time.Minute),
				},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify policy state includes runs with entity_count
	assert.NotNil(t, heartbeat.PolicyState)
	assert.Len(t, heartbeat.PolicyState, 1)

	policy, ok := heartbeat.PolicyState["policy-1"]
	assert.True(t, ok)
	assert.Len(t, policy.Runs, 1)
	assert.Equal(t, "run-1", policy.Runs[0].ID)
	assert.Equal(t, "completed", policy.Runs[0].Status)
	assert.Equal(t, testTime, policy.Runs[0].CreatedAt)
	require.NotNil(t, policy.Runs[0].EntityCount, "Expected entity_count to be included in heartbeat")
	assert.Equal(t, int64(100), policy.Runs[0].EntityCount)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_WithoutEntityCount(t *testing.T) {
	// Test that entity_count is optional in heartbeats
	// Arrange
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:       "policy-1",
			Name:     "Test Policy",
			Backend:  "pktvisor",
			Version:  1,
			State:    policies.Running,
			Datasets: map[string]bool{"dataset-1": true},
			Runs: []policies.RunData{
				{
					ID:        "run-1",
					Status:    "completed",
					CreatedAt: testTime,
					UpdatedAt: testTime.Add(5 * time.Minute),
				},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	var capturedPayload []byte
	testTopic := "test/heartbeat"
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	hb.sendSingleHeartbeat(ctx, testTopic, publishFunc, "test-agent-id", testTime, messages.Online, nil)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	// Verify policy state includes runs without entity_count
	assert.NotNil(t, heartbeat.PolicyState)
	assert.Len(t, heartbeat.PolicyState, 1)

	policy, ok := heartbeat.PolicyState["policy-1"]
	assert.True(t, ok)
	assert.Len(t, policy.Runs, 1)
	assert.Equal(t, "run-1", policy.Runs[0].ID)
	assert.Equal(t, "completed", policy.Runs[0].Status)
	assert.Equal(t, testTime, policy.Runs[0].CreatedAt)
	assert.Zero(t, policy.Runs[0].EntityCount, "Expected entity_count to be zero when not provided")

	mockPMgr.AssertExpectations(t)
}

// TestHeartbeater_SecondSessionResumesPeriodicHeartbeats simulates MQTT reconnect: stop ends the
// first session; a new StartHeartbeats must tick again (regression for OBS-2315).
func TestHeartbeater_SecondSessionResumesPeriodicHeartbeats(t *testing.T) {
	hb := createTestHeartbeater()
	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTopic := "test/heartbeat"
	var publishCount atomic.Int32
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Run(func(_ mock.Arguments) {
		publishCount.Add(1)
	}).Maybe()

	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)
	time.Sleep(120 * time.Millisecond)
	n1 := int(publishCount.Load())
	require.GreaterOrEqual(t, n1, 2, "expected periodic heartbeats in first session")

	hb.stop(testTopic, mockPublish.Publish)
	n2 := int(publishCount.Load())
	require.Greater(t, n2, n1, "expected final offline after stop")

	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)
	time.Sleep(120 * time.Millisecond)
	n3 := int(publishCount.Load())
	require.GreaterOrEqual(t, n3-n2, 2, "expected periodic heartbeats in second session after reconnect simulation")
	hb.stop(testTopic, mockPublish.Publish)
}

// TestHeartbeater_StartHeartbeats_ReplacesPriorSession verifies a second StartHeartbeats cancels
// the first and does not deadlock (JWT refresh / reconnect path).
func TestHeartbeater_StartHeartbeats_ReplacesPriorSession(t *testing.T) {
	hb := createTestHeartbeater()
	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTopic := "test/heartbeat"
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Maybe()

	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)
	time.Sleep(5 * time.Millisecond)
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)
	time.Sleep(120 * time.Millisecond)
	hb.stop(testTopic, mockPublish.Publish)
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_GetPolicyState_PropagatesTargetsFromRunData(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "dev-policy",
			Backend: "device_discovery",
			Version: 1,
			State:   policies.Running,
			Runs: []policies.RunData{
				{
					ID:        "run-a",
					Status:    "running",
					CreatedAt: testTime,
					UpdatedAt: testTime,
					Targets:   []string{"192.168.1.1"},
				},
				{
					ID:        "run-b",
					Status:    "completed",
					CreatedAt: testTime,
					UpdatedAt: testTime.Add(5 * time.Minute),
					Targets:   []string{"10.0.0.5", "10.0.0.6"},
					Driver:    "ios",
				},
				{
					ID:        "run-c",
					Status:    "running",
					CreatedAt: testTime,
					UpdatedAt: testTime,
					// No Targets — must be nil in the heartbeat.
				},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	ps := hb.getPolicyState()

	require.Len(t, ps["policy-1"].Runs, 3)
	assert.Equal(t, []string{"192.168.1.1"}, ps["policy-1"].Runs[0].Targets)
	assert.Equal(t, []string{"10.0.0.5", "10.0.0.6"}, ps["policy-1"].Runs[1].Targets)
	assert.Nil(t, ps["policy-1"].Runs[2].Targets)
	assert.Equal(t, "ios", ps["policy-1"].Runs[1].Driver)
	assert.Empty(t, ps["policy-1"].Runs[0].Driver)
	assert.Empty(t, ps["policy-1"].Runs[2].Driver)

	mockPMgr.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_SerializesPerRunTargets(t *testing.T) {
	testTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockPMgr := &mockPolicyManagerForHeartbeat{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{
		{
			ID:      "policy-1",
			Name:    "dev-policy",
			Backend: "device_discovery",
			Version: 1,
			State:   policies.Running,
			Runs: []policies.RunData{
				{
					ID:        "run-1",
					Status:    "completed",
					CreatedAt: testTime,
					UpdatedAt: testTime,
					Targets:   []string{"10.0.0.1"},
					Driver:    "ios",
				},
			},
		},
	}, nil)

	hb := createTestHeartbeaterWithPolicyManager(&mockBackendState{}, mockPMgr)

	var capturedPayload []byte
	publishFunc := func(_ context.Context, _ string, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	hb.sendSingleHeartbeat(context.Background(), "test/topic", publishFunc, "agent-id", testTime, messages.Online, nil)

	require.NotNil(t, capturedPayload)

	var hb2 messages.Heartbeat
	require.NoError(t, json.Unmarshal(capturedPayload, &hb2))

	assert.Equal(t, "1.2", hb2.SchemaVersion)
	require.Len(t, hb2.PolicyState["policy-1"].Runs, 1)
	assert.Equal(t, []string{"10.0.0.1"}, hb2.PolicyState["policy-1"].Runs[0].Targets)
	assert.Equal(t, "ios", hb2.PolicyState["policy-1"].Runs[0].Driver)
	assert.Contains(t, string(capturedPayload), `"targets":["10.0.0.1"]`)
	assert.Contains(t, string(capturedPayload), `"driver":"ios"`)

	mockPMgr.AssertExpectations(t)
}
