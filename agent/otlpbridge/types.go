package otlpbridge

import (
	"context"
)

// Publisher abstracts message publication to a transport (e.g., MQTT).
// Implementations must be safe for concurrent use by multiple goroutines.
type Publisher interface {
	Publish(ctx context.Context, topic string, payload []byte) error
}

// Encoder abstracts protobuf message encoding strategies.
// Implementations convert protobuf messages to wire-ready bytes.
type Encoder interface {
	Marshal(msg ProtoMessage) ([]byte, error)
}

// ProtoMessage is the minimal interface satisfied by protobuf messages.
// Using an interface avoids importing protobuf types in this file.
type ProtoMessage interface {
	Reset()
	String() string
	ProtoMessage()
}

// BridgeConfig holds runtime configuration for the OTLP → MQTT bridge.
type BridgeConfig struct {
	ListenAddr   string
	MQTTURL      string
	MQTTJWT      string
	TracesTopic  string
	MetricsTopic string
	LogsTopic    string
	Encoding     string // "protobuf" | "json"
}
