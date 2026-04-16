package fleet

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

// TestDispatchQueue_NoPanicOnConcurrentShutdown exercises the race window between
// sending on dispatchQueue and closing it during shutdown. The send path should
// follow the same locking protocol as production so stopDispatchWorker cannot
// close the queue between the shutdown check and the send.
//
// Run with: go test -race -count=100 -run TestDispatchQueue_NoPanicOnConcurrentShutdown
func TestDispatchQueue_NoPanicOnConcurrentShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	connection.startDispatchWorker()

	const numSenders = 50
	const sendsPerGoroutine = 200
	var wg sync.WaitGroup
	var panics atomic.Int32

	// Spawn many goroutines that mirror the OnPublishReceived send path
	for i := 0; i < numSenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
				}
			}()
			for j := 0; j < sendsPerGoroutine; j++ {
				connection.dispatchMu.Lock()
				if connection.shuttingDown {
					connection.dispatchMu.Unlock()
					return
				}
				select {
				case connection.dispatchQueue <- dispatchJob{
					payload: []byte(`{}`),
					orgID:   "test-org",
					agentID: "test-agent",
					topicActions: TopicActions{
						Subscribe:   func(_ string) error { return nil },
						Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
						Unsubscribe: func(_ string) error { return nil },
					},
				}:
					connection.dispatchMu.Unlock()
				default:
					connection.dispatchMu.Unlock()
				}
			}
		}()
	}

	// Let senders build up pressure, then trigger concurrent shutdown
	time.Sleep(1 * time.Millisecond)
	connection.stopDispatchWorker()

	wg.Wait()

	if p := panics.Load(); p > 0 {
		t.Fatalf("detected %d panic(s) from send on closed channel — race condition exists", p)
	}
}

// TestDispatchQueue_DrainsOnShutdown verifies that jobs already buffered in the
// dispatch queue are fully processed before the worker exits, even though we
// use a stop channel instead of closing the queue.
func TestDispatchQueue_DrainsOnShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	var processed atomic.Int32
	const numJobs = 50

	// Use a group_membership payload with at least one group so the handler
	// actually calls Subscribe, letting us count processed jobs.
	payload := []byte(`{"schema_version":"1.0","func":"group_membership","payload":{"full_list":false,"groups":[{"group_id":"drain-test","name":"Drain"}]}}`)

	// Fill the queue WITHOUT starting the worker, so all jobs are buffered.
	for i := 0; i < numJobs; i++ {
		connection.dispatchQueue <- dispatchJob{
			payload: payload,
			orgID:   "test-org",
			agentID: "test-agent",
			topicActions: TopicActions{
				Subscribe: func(_ string) error {
					processed.Add(1)
					return nil
				},
				Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
				Unsubscribe: func(_ string) error { return nil },
			},
		}
	}

	// Now start the worker and immediately stop it — the drain loop must
	// process all 50 buffered jobs before the worker reports done.
	connection.startDispatchWorker()
	connection.stopDispatchWorker()

	assert.Equal(t, int32(numJobs), processed.Load(),
		"all buffered jobs must be drained before worker exits")
}

// TestDispatchQueue_LateEnqueueAfterWorkerExit_IsNotOrphaned captures the race
// where a sender has already entered the guarded send path while shutdown is in
// progress. The lock coupling between the send path and stopDispatchWorker must
// ensure either the job is processed or the sender observes shutdown and skips it.
func TestDispatchQueue_LateEnqueueAfterWorkerExit_IsNotOrphaned(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	payload := []byte(`{"schema_version":"1.0","func":"group_membership","payload":{"full_list":false,"groups":[{"group_id":"late-send","name":"Late"}]}}`)
	var processed atomic.Int32
	checked := make(chan struct{})
	proceed := make(chan struct{})
	sendDone := make(chan bool, 1)
	stopDone := make(chan struct{})

	connection.startDispatchWorker()

	go func() {
		// Mirror the production send path: hold dispatchMu across the
		// shuttingDown check and the send attempt.
		connection.dispatchMu.Lock()
		if connection.shuttingDown {
			connection.dispatchMu.Unlock()
			sendDone <- false
			return
		}
		close(checked)
		<-proceed

		select {
		case connection.dispatchQueue <- dispatchJob{
			payload: payload,
			orgID:   "test-org",
			agentID: "test-agent",
			topicActions: TopicActions{
				Subscribe: func(_ string) error {
					processed.Add(1)
					return nil
				},
				Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
				Unsubscribe: func(_ string) error { return nil },
			},
		}:
			connection.dispatchMu.Unlock()
			sendDone <- true
		default:
			connection.dispatchMu.Unlock()
			sendDone <- false
		}
	}()

	<-checked

	go func() {
		connection.stopDispatchWorker()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		t.Fatal("stopDispatchWorker should wait for the in-flight guarded sender")
	case <-time.After(10 * time.Millisecond):
	}

	close(proceed)

	select {
	case sent := <-sendDone:
		if !sent {
			t.Fatal("expected in-flight guarded sender to enqueue successfully")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for guarded sender")
	}

	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for stopDispatchWorker to finish")
	}

	assert.Equal(t, int32(1), processed.Load(),
		"an in-flight guarded send should be processed before the worker exits")
}

// TestDispatchQueue_ConcurrentStopDispatchWorker_NoPanic verifies that two
// concurrent teardown callers do not both attempt to close dispatchStop.
func TestDispatchQueue_ConcurrentStopDispatchWorker_NoPanic(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	payload := []byte(`{"schema_version":"1.0","func":"group_membership","payload":{"full_list":false,"groups":[{"group_id":"stop-race","name":"StopRace"}]}}`)
	jobStarted := make(chan struct{})
	releaseJob := make(chan struct{})

	connection.dispatchQueue <- dispatchJob{
		payload: payload,
		orgID:   "test-org",
		agentID: "test-agent",
		topicActions: TopicActions{
			Subscribe: func(_ string) error {
				close(jobStarted)
				<-releaseJob
				return nil
			},
			Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
			Unsubscribe: func(_ string) error { return nil },
		},
	}

	connection.startDispatchWorker()

	select {
	case <-jobStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for dispatch worker to begin processing")
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var panics atomic.Int32

	stopper := func() {
		defer wg.Done()
		defer func() {
			if recover() != nil {
				panics.Add(1)
			}
		}()
		<-start
		connection.stopDispatchWorker()
	}

	wg.Add(2)
	go stopper()
	go stopper()

	close(start)
	time.Sleep(10 * time.Millisecond)
	close(releaseJob)
	wg.Wait()

	assert.Equal(t, int32(0), panics.Load(),
		"concurrent stopDispatchWorker calls should not panic")
}
