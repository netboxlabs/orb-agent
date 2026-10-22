package otlpbridge

import (
	"sync/atomic"
)

const (
	// defaultMaxMessageBytes caps one published payload. An export over it is
	// split (metrics) or dropped (logs, traces). Four MiB keeps every message
	// well under RabbitMQ's 16 MiB default maximum and gives the telemetry
	// enricher bodies it can hold several of at once.
	defaultMaxMessageBytes = 4 << 20
	// defaultMaxPendingBytes bounds the payload bytes the pending queue holds
	// before the broker is ready or while it is slow, so a burst of large
	// exports cannot grow the agent's memory without limit. Sixteen messages
	// at the default cap.
	defaultMaxPendingBytes = 64 << 20
	// maxReceiveBytes is the largest OTLP request either listener accepts,
	// above the cap so a large export is split rather than refused: the
	// gRPC server's MaxRecvMsgSize and the HTTP body limit. A backend running
	// hundreds of devices in one process exports well past gRPC's 4 MiB
	// default, and a refusal there drops the export inside the backend where
	// nothing counts it.
	maxReceiveBytes = 64 << 20
)

// mqttPublishOverhead is the most bytes a QoS 0 PUBLISH to topic with
// contentType adds around its payload: the fixed header with its remaining
// length (1 + 4), the topic (2 + its length), the properties length (4) and
// the Content Type property (1 + 2 + its length). The broker's maximum
// packet size bounds the whole packet, so the payload cap is that much less.
func mqttPublishOverhead(topic, contentType string) int {
	return 5 + 2 + len(topic) + 4 + 3 + len(contentType)
}

// brokerCeiling is the MQTT server's maximum packet size, from its CONNACK,
// as the agent's connection reports it: zero while unknown or unlimited.
type brokerCeiling struct {
	maxPacketSize atomic.Uint32
}

// set records the broker's maximum packet size; zero means none was sent.
func (b *brokerCeiling) set(n uint32) { b.maxPacketSize.Store(n) }

// payloadCap is the most payload bytes a publish to topic with contentType
// may carry under the broker's limit, or 0 when there is no limit.
func (b *brokerCeiling) payloadCap(topic, contentType string) int {
	n := int(b.maxPacketSize.Load())
	if n == 0 {
		return 0
	}
	return max(n-mqttPublishOverhead(topic, contentType), 0)
}

// SetBrokerMaxPacketSize records the broker's maximum packet size from its
// CONNACK, so payloads are cut to fit under it and one that cannot is dropped
// rather than sent: an MQTT 5 server answers an oversized packet by closing
// the connection, which is the agent's one Fleet connection. Zero means the
// broker set none.
func (s *BridgeServer) SetBrokerMaxPacketSize(n uint32) {
	s.broker.set(n)
}

// BrokerMaxPacketSize is the broker's maximum packet size the bridge keeps
// its messages under, zero while none is known.
func (s *BridgeServer) BrokerMaxPacketSize() uint32 {
	return s.broker.maxPacketSize.Load()
}

// messageCap is the most payload bytes one message to topic with contentType
// may carry: the configured cap, or less when the broker's maximum packet
// size leaves less.
func (s *BridgeServer) messageCap(topic, contentType string) int {
	limit := s.maxMessageBytes
	if broker := s.broker.payloadCap(topic, contentType); broker > 0 && broker < limit {
		return broker
	}
	return limit
}
