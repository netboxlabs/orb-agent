package fleet

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// syncBuffer is a bytes.Buffer safe to write from the dispatch worker while a
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// groupMembershipJob dispatches to Subscribe, which the test controls.
func groupMembershipJob(subscribe func(string) error) dispatchJob {
	return dispatchJob{
		payload: []byte(`{"schema_version":"1.0","func":"group_membership","payload":{"full_list":false,"groups":[{"group_id":"test-group","name":"Test"}]}}`),
		orgID:   "test-org",
		agentID: "test-agent",
		topicActions: TopicActions{
			Subscribe:   subscribe,
			Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
			Unsubscribe: func(_ string) error { return nil },
		},
	}
}

func newRecoverTestConnection(logs *syncBuffer) *MQTTConnection {
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewMQTTConnection(logger, &mockPolicyManagerForFleet{}, make(chan struct{}, 1), make(chan struct{}, 1), &mockBackendState{}, nil)
}

// A message whose handling panics costs that message, not the agent: the
// dispatch worker logs it and goes on to the next job.
func TestDispatchWorkerSurvivesAHandlerPanic(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)
	connection.startDispatchWorker()
	defer connection.stopDispatchWorker()

	next := make(chan struct{}, 1)
	connection.dispatchQueue <- groupMembershipJob(func(string) error { panic("handler failure") })
	connection.dispatchQueue <- groupMembershipJob(func(string) error { next <- struct{}{}; return nil })

	select {
	case <-next:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker stopped after the panicking job")
	}
	require.Contains(t, logs.String(), "panic handling MQTT message")
	require.Contains(t, logs.String(), "handler failure")
}

// With the queue full the message is handled on the callback's own goroutine,
// and a panic there is recovered too.
func TestFullQueueFallbackSurvivesAHandlerPanic(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)
	for range cap(connection.dispatchQueue) {
		connection.dispatchQueue <- dispatchJob{}
	}

	require.NotPanics(t, func() {
		connection.enqueueOrDispatch(groupMembershipJob(func(string) error { panic("handler failure") }), "orgs/test-org/agents/test-agent")
	})
	require.Contains(t, logs.String(), "panic handling MQTT message")
}

// A topic-specific handler runs on its own goroutine; a panic there is
// recovered rather than taking the process down.
func TestTopicHandlerPanicIsRecovered(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)

	require.NotPanics(t, func() {
		connection.runTopicHandler(func(string, []byte) error { panic("handler failure") }, "orgs/test-org/policies", nil)
	})
	require.Contains(t, logs.String(), "panic handling MQTT message")
	require.Contains(t, logs.String(), "orgs/test-org/policies")
}
