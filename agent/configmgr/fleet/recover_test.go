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

const recoverTestTopic = "orgs/test-org/agents/test-agent"

// groupMembershipJob dispatches to Subscribe, which the test controls.
func groupMembershipJob(subscribe func(string) error) dispatchJob {
	return dispatchJob{
		topic:   recoverTestTopic,
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

// A panic while dispatching a message is logged with its topic and stack, then
// raised again: the handler may have left agent state half applied, and only
// the process restart that follows rebuilds it from a known-good state.
func TestDispatchPanicIsLoggedThenRaised(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)

	job := groupMembershipJob(func(string) error { panic("handler failure") })
	require.PanicsWithValue(t, "handler failure", func() { connection.processJob(job) })
	require.Contains(t, logs.String(), "panic handling MQTT message")
	require.Contains(t, logs.String(), "handler failure")
	require.Contains(t, logs.String(), "topic="+recoverTestTopic)
}

// With the queue full the message is handled on the callback's own goroutine,
// and its panic is logged the same way before it is raised.
func TestFullQueueFallbackLogsThenRaisesAPanic(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)
	for range cap(connection.dispatchQueue) {
		connection.dispatchQueue <- dispatchJob{}
	}

	job := groupMembershipJob(func(string) error { panic("handler failure") })
	require.PanicsWithValue(t, "handler failure", func() { connection.enqueueOrDispatch(job) })
	require.Contains(t, logs.String(), "panic handling MQTT message")
	require.Contains(t, logs.String(), "topic="+recoverTestTopic)
}

// A topic-specific handler's panic is logged with its topic, then raised.
func TestTopicHandlerPanicIsLoggedThenRaised(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)

	require.PanicsWithValue(t, "handler failure", func() {
		connection.runTopicHandler(func(string, []byte) error { panic("handler failure") }, "orgs/test-org/secrets", nil)
	})
	require.Contains(t, logs.String(), "panic handling MQTT message")
	require.Contains(t, logs.String(), "topic=orgs/test-org/secrets")
}

// A received message on a topic with its own handler reaches that handler.
func TestReceivedMessageReachesItsTopicHandler(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)
	got := make(chan []byte, 1)
	connection.RegisterTopicHandler("orgs/test-org/secrets", func(_ string, payload []byte) error {
		got <- payload
		return nil
	})

	connection.onPublishReceived("orgs/test-org/secrets", []byte("payload"), "test-agent")
	select {
	case payload := <-got:
		require.Equal(t, []byte("payload"), payload)
	case <-time.After(5 * time.Second):
		t.Fatal("the topic handler was not called")
	}
}

// A received message with no topic handler is queued with its topic, so a
// panic while dispatching it can name the topic.
func TestReceivedMessageIsQueuedWithItsTopic(t *testing.T) {
	var logs syncBuffer
	connection := newRecoverTestConnection(&logs)

	connection.onPublishReceived(recoverTestTopic, []byte(`{}`), "test-agent")
	job := <-connection.dispatchQueue
	require.Equal(t, recoverTestTopic, job.topic)
	require.Equal(t, "test-org", job.orgID)
	require.Equal(t, "test-agent", job.agentID)
	require.Equal(t, []byte(`{}`), job.payload)
}
