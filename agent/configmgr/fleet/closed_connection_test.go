package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/packets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// testBroker is an MQTT 5 broker for one client at a time: it accepts each
// connection, acknowledges what needs it, and records what is published.
type testBroker struct {
	addr string

	mu          sync.Mutex
	conns       []net.Conn
	connects    int
	disconnects int
	published   []brokerPublish
}

// brokerPublish is a publish the broker received on its nth connection.
type brokerPublish struct {
	conn    int
	topic   string
	payload []byte
}

func startTestBroker(t *testing.T) *testBroker {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	b := &testBroker{addr: l.Addr().String()}
	var conns sync.WaitGroup
	accepting := make(chan struct{})
	t.Cleanup(func() {
		_ = l.Close()
		<-accepting // no conns.Add after this
		b.drop()
		conns.Wait()
	})
	go func() {
		defer close(accepting)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				b.serve(c)
			}()
		}
	}()
	return b
}

func (b *testBroker) serve(c net.Conn) {
	b.mu.Lock()
	b.conns = append(b.conns, c)
	b.mu.Unlock()
	defer func() { _ = c.Close() }()
	var n int
	for {
		p, err := packets.ReadPacket(c)
		if err != nil {
			return
		}
		var reply *packets.ControlPacket
		switch p.Type {
		case packets.CONNECT:
			b.mu.Lock()
			b.connects++
			n = b.connects
			b.mu.Unlock()
			reply = packets.NewControlPacket(packets.CONNACK)
		case packets.SUBSCRIBE:
			sub := p.Content.(*packets.Subscribe)
			reply = packets.NewControlPacket(packets.SUBACK)
			reply.Content.(*packets.Suback).PacketID = sub.PacketID
			reply.Content.(*packets.Suback).Reasons = make([]byte, len(sub.Subscriptions))
		case packets.PUBLISH:
			pub := p.Content.(*packets.Publish)
			b.mu.Lock()
			b.published = append(b.published, brokerPublish{conn: n, topic: pub.Topic, payload: pub.Payload})
			b.mu.Unlock()
			if pub.QoS == 1 {
				reply = packets.NewControlPacket(packets.PUBACK)
				reply.Content.(*packets.Puback).PacketID = pub.PacketID
			}
		case packets.PINGREQ:
			reply = packets.NewControlPacket(packets.PINGRESP)
		case packets.DISCONNECT:
			b.mu.Lock()
			b.disconnects++
			b.mu.Unlock()
			return
		}
		if reply != nil {
			if _, err := reply.WriteTo(c); err != nil {
				return
			}
		}
	}
}

// publishes returns how many publishes the broker received on topic, on any
// connection when conn is 0.
func (b *testBroker) publishes(topic string, conn int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := 0
	for _, p := range b.published {
		if p.topic == topic && (conn == 0 || p.conn == conn) {
			count++
		}
	}
	return count
}

// lastHeartbeat returns the last heartbeat the broker received.
func (b *testBroker) lastHeartbeat(t *testing.T) messages.Heartbeat {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := len(b.published) - 1; i >= 0; i-- {
		if b.published[i].topic == testHeartbeatTopic {
			var hb messages.Heartbeat
			require.NoError(t, json.Unmarshal(b.published[i].payload, &hb))
			return hb
		}
	}
	require.Fail(t, "no heartbeat")
	return messages.Heartbeat{}
}

func (b *testBroker) connections() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.connects
}

// drop closes the broker's end of every connection, as a broker restart does.
func (b *testBroker) drop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		_ = c.Close()
	}
}

// disconnected reports whether the broker has read n DISCONNECTs, and so
// every publish sent before them.
func (b *testBroker) disconnected(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.disconnects >= n
}

// logRecorder keeps the records logged at ERROR.
type logRecorder struct {
	mu     sync.Mutex
	errors []string
}

func (r *logRecorder) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelError }

func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	line := rec.Message
	rec.Attrs(func(a slog.Attr) bool {
		line += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		return true
	})
	r.mu.Lock()
	r.errors = append(r.errors, line)
	r.mu.Unlock()
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *logRecorder) WithGroup(string) slog.Handler { return r }

func (r *logRecorder) errorLines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.errors...)
}

const (
	testHeartbeatTopic = "agents/a1/heartbeats"
	testOutboxTopic    = "agents/a1/outbox"
)

// withGroupMembershipsRequestDelay sets how long a new connection waits to
// ask for its group memberships, for the test.
func withGroupMembershipsRequestDelay(t *testing.T, d time.Duration) {
	t.Helper()
	prev := groupMembershipsRequestDelay
	groupMembershipsRequestDelay = d
	t.Cleanup(func() { groupMembershipsRequestDelay = prev })
}

// newBrokerConnection returns a connection to b whose ERROR records rec keeps.
func newBrokerConnection(t *testing.T, b *testBroker) (*MQTTConnection, ConnectionDetails, *logRecorder) {
	t.Helper()
	rec := &logRecorder{}
	pMgr := &mockPolicyManagerForFleet{}
	pMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil).Maybe()
	conn := NewMQTTConnection(slog.New(rec), pMgr, make(chan struct{}, 1), make(chan struct{}, 1), &mockBackendState{}, nil)
	details := ConnectionDetails{
		MQTTURL:  "mqtt://" + b.addr,
		Token:    "token",
		AgentID:  "a1",
		ClientID: "a1",
		Zone:     "default",
		Topics: TokenResponseTopics{
			Heartbeat:    testHeartbeatTopic,
			Capabilities: "agents/a1/capabilities",
			Inbox:        "agents/a1/inbox",
			Outbox:       testOutboxTopic,
		},
	}
	return conn, details, rec
}

func connectToBroker(t *testing.T, conn *MQTTConnection, b *testBroker, details ConnectionDetails) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, conn.Connect(context.Background(), ctx, details, map[string]backend.Backend{}, map[string]string{}, ""))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Disconnect(ctx, testHeartbeatTopic)
	})
	connected := b.connections()
	require.Eventually(t, func() bool { return b.publishes(testHeartbeatTopic, connected) > 0 }, 5*time.Second, 10*time.Millisecond, "no heartbeat on the connection")
}

// A connection the agent has disconnected, after it gave up refreshing its
// token, is disconnected again when the next attempts give up too: that says
// nothing on it, and logs no ERROR.
func TestDisconnectingAClosedConnectionLogsNoError(t *testing.T) {
	withGroupMembershipsRequestDelay(t, 10*time.Millisecond)
	b := startTestBroker(t)
	conn, details, rec := newBrokerConnection(t, b)
	connectToBroker(t, conn, b, details)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, conn.Disconnect(ctx, testHeartbeatTopic))
	require.Eventually(t, func() bool { return b.disconnected(1) }, 5*time.Second, 10*time.Millisecond)
	heartbeats := b.publishes(testHeartbeatTopic, 0)
	require.NoError(t, conn.Disconnect(ctx, testHeartbeatTopic))
	time.Sleep(50 * time.Millisecond)

	assert.Empty(t, rec.errorLines())
	assert.Equal(t, heartbeats, b.publishes(testHeartbeatTopic, 0), "nothing published on the closed connection")
}

// The agent reconnects with a new token on a connection it disconnected,
// after Fleet refused its credentials or its attempts gave up: the recovery
// logs no ERROR.
func TestReconnectingAClosedConnectionLogsNoError(t *testing.T) {
	withGroupMembershipsRequestDelay(t, 10*time.Millisecond)
	b := startTestBroker(t)
	conn, details, rec := newBrokerConnection(t, b)
	connectToBroker(t, conn, b, details)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, conn.Disconnect(ctx, testHeartbeatTopic))
	require.NoError(t, conn.Reconnect(context.Background(), ctx, details, map[string]backend.Backend{}, map[string]string{}, "", time.Second))
	require.Eventually(t, func() bool { return b.publishes(testHeartbeatTopic, 2) > 0 }, 5*time.Second, 10*time.Millisecond, "no heartbeat on the new connection")

	assert.Empty(t, rec.errorLines())
}

// A reconnect can come while the connection is still waiting to ask for its
// group memberships: a signal sent during the attempts that just reconnected
// asks for the same refresh. The old connection is disconnected at once, its
// request is not sent, and the new connection's is.
func TestReconnectingRightAfterConnectingLogsNoError(t *testing.T) {
	withGroupMembershipsRequestDelay(t, 2*time.Second)
	b := startTestBroker(t)
	conn, details, rec := newBrokerConnection(t, b)
	connectToBroker(t, conn, b, details)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, conn.Reconnect(context.Background(), ctx, details, map[string]backend.Backend{}, map[string]string{}, "", 500*time.Millisecond))
	require.Eventually(t, func() bool { return b.publishes(testOutboxTopic, 2) == 1 }, 5*time.Second, 10*time.Millisecond, "no group memberships request on the new connection")
	time.Sleep(100 * time.Millisecond)

	assert.Empty(t, rec.errorLines())
	assert.Zero(t, b.publishes(testOutboxTopic, 1), "the old connection's request")
}

// A connection the broker drops while the agent waits to ask for its group
// memberships is noticed at once, not when the wait is over.
func TestAConnectionLostWhileWaitingToAskForGroupsIsNoticedAtOnce(t *testing.T) {
	withGroupMembershipsRequestDelay(t, 5*time.Second)
	b := startTestBroker(t)
	conn, details, _ := newBrokerConnection(t, b)
	lost := make(chan struct{}, 1)
	conn.AddOnDownHook(func() {
		select {
		case lost <- struct{}{}:
		default:
		}
	})
	connectToBroker(t, conn, b, details)

	b.drop()
	select {
	case <-lost:
	case <-time.After(2 * time.Second):
		t.Fatal("the lost connection was not noticed while the agent waited to ask for its groups")
	}
}

// The agent can disconnect a connection before the connection has started its
// heartbeats: Connect returns as the connection comes up, before autopaho
// runs OnConnectionUp. The heartbeats are not started on the closed
// connection, and the last heartbeat it sent says offline.
func TestDisconnectingRightAfterConnectingLeavesNoHeartbeats(t *testing.T) {
	withGroupMembershipsRequestDelay(t, 10*time.Millisecond)
	b := startTestBroker(t)
	conn, details, rec := newBrokerConnection(t, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, conn.Connect(context.Background(), ctx, details, map[string]backend.Backend{}, map[string]string{}, ""))

	require.NoError(t, conn.Disconnect(ctx, testHeartbeatTopic))
	require.Eventually(t, func() bool { return b.disconnected(1) }, 5*time.Second, 10*time.Millisecond)
	heartbeats := b.publishes(testHeartbeatTopic, 0)
	assert.Equal(t, messages.State(messages.Offline), b.lastHeartbeat(t).State, "the last heartbeat before the disconnect")
	time.Sleep(10 * heartbeatTickInterval)

	assert.Empty(t, rec.errorLines())
	assert.Equal(t, heartbeats, b.publishes(testHeartbeatTopic, 0), "heartbeats after the disconnect")
}

// A connection the broker drops while the agent waits to ask for its group
// memberships does not ask on the next one: the next connection asks once,
// after its own wait.
func TestAConnectionLostWhileWaitingToAskForGroupsAsksOnceOnTheNext(t *testing.T) {
	withGroupMembershipsRequestDelay(t, 500*time.Millisecond)
	b := startTestBroker(t)
	conn, details, rec := newBrokerConnection(t, b)
	connectToBroker(t, conn, b, details)

	b.drop()
	require.Eventually(t, func() bool { return b.publishes(testHeartbeatTopic, 2) > 0 }, 5*time.Second, 10*time.Millisecond, "no heartbeat on the next connection")
	require.Eventually(t, func() bool { return b.publishes(testOutboxTopic, 2) > 0 }, 5*time.Second, 10*time.Millisecond, "no group memberships request on the next connection")
	time.Sleep(time.Second)

	assert.Equal(t, 1, b.publishes(testOutboxTopic, 0), "group memberships requests")
	assert.Empty(t, rec.errorLines())
}
