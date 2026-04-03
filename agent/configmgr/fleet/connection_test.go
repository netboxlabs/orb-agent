package fleet

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

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

type mockBackendState struct {
	backendState map[string]*backend.State
}

func (m *mockBackendState) Get() map[string]*backend.State {
	if m.backendState == nil {
		return map[string]*backend.State{}
	}
	return m.backendState
}

func TestFleetConfigManager_Connect_InvalidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Act with invalid URL
	backends := make(map[string]backend.Backend)
	trt := TokenResponseTopics{Inbox: "test/topic"}
	err := connection.Connect(
		context.Background(),
		ConnectionDetails{MQTTURL: "://invalid-url", Token: "test_token", AgentID: "test-agent-id", Topics: trt, ClientID: "test-agent-id", Zone: "test-zone"},
		backends,
		map[string]string{},
		"",
	)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing protocol scheme") // URL parsing error
}

func TestFleetConfigManager_Connect_ValidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Act with valid URL but don't expect successful connection
	// since we don't have a real MQTT server
	backends := make(map[string]backend.Backend)
	trt2 := TokenResponseTopics{Inbox: "test/topic"}
	// Timeout after 100ms for faster test execution (connection will fail quickly)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := connection.Connect(ctx,
		ConnectionDetails{MQTTURL: "mqtt://localhost:1883", Token: "test_token", AgentID: "test-agent-id", Topics: trt2, ClientID: "test-agent-id", Zone: "test-zone"},
		backends,
		map[string]string{},
		"",
	)

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

func TestDispatchQueue_ProcessesJobsSequentially(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Track the order of job processing using a channel
	processedOrder := make([]int, 0, 10)
	var mu sync.Mutex
	jobProcessed := make(chan struct{}, 10)

	// Create a custom messaging handler that tracks processing order
	numJobs := 10

	// Start the dispatch worker
	connection.startDispatchWorker()

	// Enqueue multiple jobs rapidly
	for i := 0; i < numJobs; i++ {
		jobIndex := i
		// Create a group_membership RPC payload that will trigger Subscribe
		payload := []byte(`{"schema_version":"1.0","func":"group_membership","payload":{"full_list":false,"groups":[{"group_id":"test-group","name":"Test"}]}}`)
		connection.dispatchQueue <- dispatchJob{
			payload: payload,
			orgID:   "test-org",
			agentID: "test-agent",
			topicActions: TopicActions{
				Subscribe: func(_ string) error {
					mu.Lock()
					processedOrder = append(processedOrder, jobIndex)
					mu.Unlock()
					jobProcessed <- struct{}{}
					return nil
				},
				Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
				Unsubscribe: func(_ string) error { return nil },
			},
		}
	}

	// Wait for all jobs to be processed
	for i := 0; i < numJobs; i++ {
		select {
		case <-jobProcessed:
			// Job processed
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for jobs to be processed")
		}
	}

	// Stop the worker
	connection.stopDispatchWorker()

	// Assert - all jobs were processed in order (since they're processed sequentially)
	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, processedOrder, numJobs)
	for i := 0; i < numJobs; i++ {
		assert.Equal(t, i, processedOrder[i], "Jobs should be processed in order")
	}
}

// TestDispatchQueue_SendOnClosedChannel verifies the dispatchMu guard prevents
// panics when concurrent senders race with stopDispatchWorker closing the channel.
// Run with: go test -race -count=100 -run TestDispatchQueue_SendOnClosedChannel
func TestDispatchQueue_SendOnClosedChannel(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Start the dispatch worker so the channel is actively consumed.
	connection.startDispatchWorker()

	const numSenders = 20
	const msgsPerSender = 500

	// sendSafe replicates the exact locking protocol from OnPublishReceived:
	// hold dispatchMu while checking shuttingDown and sending on dispatchQueue.
	sendSafe := func() bool {
		connection.dispatchMu.Lock()
		if connection.shuttingDown {
			connection.dispatchMu.Unlock()
			return false
		}
		select {
		case connection.dispatchQueue <- dispatchJob{}:
			connection.dispatchMu.Unlock()
		default:
			connection.dispatchMu.Unlock()
		}
		return true
	}

	// Launch senders that will race with shutdown.
	var wg sync.WaitGroup
	wg.Add(numSenders)
	for i := 0; i < numSenders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < msgsPerSender; j++ {
				if !sendSafe() {
					return // channel closed, stop sending
				}
			}
		}()
	}

	// Let senders build some pressure, then shut down the worker.
	// If the mutex guard is broken this will panic with "send on closed channel".
	time.Sleep(1 * time.Millisecond)
	connection.stopDispatchWorker()

	wg.Wait() // all senders must finish without panic
}

// TestDispatchQueue_ReconnectCycle validates that dispatchQueue can be torn down
// and recreated (as Reconnect does) without panics from concurrent senders.
func TestDispatchQueue_ReconnectCycle(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	const cycles = 10
	const sendersPerCycle = 5
	const msgsPerSender = 200

	for cycle := 0; cycle < cycles; cycle++ {
		connection.startDispatchWorker()

		var wg sync.WaitGroup
		wg.Add(sendersPerCycle)
		for s := 0; s < sendersPerCycle; s++ {
			go func() {
				defer wg.Done()
				for j := 0; j < msgsPerSender; j++ {
					connection.dispatchMu.Lock()
					if connection.shuttingDown {
						connection.dispatchMu.Unlock()
						return
					}
					select {
					case connection.dispatchQueue <- dispatchJob{}:
					default:
					}
					connection.dispatchMu.Unlock()
				}
			}()
		}

		time.Sleep(500 * time.Microsecond)
		connection.stopDispatchWorker()
		wg.Wait()

		// Recreate channels exactly as Reconnect does.
		connection.dispatchMu.Lock()
		connection.dispatchQueue = make(chan dispatchJob, 100)
		connection.dispatchWorkerDone = make(chan struct{})
		connection.shuttingDown = false
		connection.dispatchMu.Unlock()
	}
}

// TestDispatchQueue_ConcurrentStopDispatchWorker validates that two goroutines
// calling stopDispatchWorker concurrently do not double-close the channel.
func TestDispatchQueue_ConcurrentStopDispatchWorker(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Run multiple iterations to increase the chance of triggering a race.
	for i := 0; i < 50; i++ {
		connection.startDispatchWorker()

		var wg sync.WaitGroup
		wg.Add(2)
		for c := 0; c < 2; c++ {
			go func() {
				defer wg.Done()
				connection.stopDispatchWorker()
			}()
		}
		wg.Wait()

		// Reset for next iteration.
		connection.dispatchMu.Lock()
		connection.dispatchQueue = make(chan dispatchJob, 100)
		connection.dispatchWorkerDone = make(chan struct{})
		connection.shuttingDown = false
		connection.dispatchMu.Unlock()
	}
}

func TestDispatchQueue_HandlesQueueFull(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Don't start the worker so the queue fills up
	// Just verify we can enqueue up to the buffer size
	for i := 0; i < 100; i++ {
		select {
		case connection.dispatchQueue <- dispatchJob{}:
			// Successfully enqueued
		default:
			t.Fatal("Queue should have capacity for 100 items")
		}
	}

	// The 101st item should not block (select with default)
	select {
	case connection.dispatchQueue <- dispatchJob{}:
		t.Fatal("Queue should be full")
	default:
		// Expected - queue is full
	}
}
