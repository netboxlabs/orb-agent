package otlpbridge

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/packets"
	"github.com/eclipse/paho.golang/paho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBroker accepts one MQTT 5 client, answers its CONNECT and hands on
// every PUBLISH it reads, so a test sees the packet as it went on the wire.
func fakeBroker(t *testing.T) (string, <-chan *packets.Publish) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	pubs := make(chan *packets.Publish, 16)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			cp, err := packets.ReadPacket(conn)
			if err != nil {
				return
			}
			switch p := cp.Content.(type) {
			case *packets.Connect:
				ack := packets.NewControlPacket(packets.CONNACK)
				ack.Content.(*packets.Connack).ReasonCode = 0
				_, _ = ack.WriteTo(conn)
			case *packets.Publish:
				pubs <- p
			case *packets.Pingreq:
				_, _ = packets.NewControlPacket(packets.PINGRESP).WriteTo(conn)
			case *packets.Disconnect:
				return
			}
		}
	}()
	return "mqtt://" + lis.Addr().String(), pubs
}

func connectFakeBroker(t *testing.T, addr string) *autopaho.ConnectionManager {
	t.Helper()
	u, err := url.Parse(addr)
	require.NoError(t, err)
	cm, err := autopaho.NewConnection(context.Background(), autopaho.ClientConfig{
		ServerUrls: []*url.URL{u}, KeepAlive: 30, CleanStartOnInitialConnection: true,
		ClientConfig: paho.ClientConfig{ClientID: "otlp-bridge-wire-test"},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, cm.AwaitConnection(ctx))
	t.Cleanup(func() { _ = cm.Disconnect(context.Background()) })
	return cm
}

func nextPublish(t *testing.T, pubs <-chan *packets.Publish) *packets.Publish {
	t.Helper()
	select {
	case p := <-pubs:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no PUBLISH reached the broker")
		return nil
	}
}

func contentTypeOf(p *packets.Publish) string {
	if p.Properties == nil {
		return ""
	}
	return p.Properties.ContentType
}

// The telemetry enricher decodes a body as protobuf metrics only when its
// content type says so, and ignores a protobuf body without one. So the
// publisher the fleet path uses must put the content type on the wire.
func TestCMAdapterPublisher_PutsTheContentTypeOnTheWire(t *testing.T) {
	addr, pubs := fakeBroker(t)
	pub := NewCMAdapterPublisher(connectFakeBroker(t, addr))
	ctx := context.Background()

	require.NoError(t, pub.Publish(ctx, "orgs/o/agents/a/telemetry", []byte{0x0a, 0x00}, ContentTypeProtobuf))
	p := nextPublish(t, pubs)
	assert.Equal(t, ContentTypeProtobuf, contentTypeOf(p))
	assert.Equal(t, "orgs/o/agents/a/telemetry", p.Topic)
	assert.Equal(t, byte(0), p.QoS)

	require.NoError(t, pub.Publish(ctx, "orgs/o/agents/a/telemetry", []byte("{}"), ""))
	assert.Empty(t, contentTypeOf(nextPublish(t, pubs)), "no content type sends none")
}

func TestMQTTPublisher_PutsTheContentTypeOnTheWire(t *testing.T) {
	addr, pubs := fakeBroker(t)
	pub := &MQTTPublisher{cm: connectFakeBroker(t, addr)}
	require.NoError(t, pub.Publish(context.Background(), "orgs/o/agents/a/telemetry", []byte("{}"), ContentTypeJSON))
	assert.Equal(t, ContentTypeJSON, contentTypeOf(nextPublish(t, pubs)))
}
