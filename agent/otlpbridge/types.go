package otlpbridge

import (
	"context"
)

// Publisher abstracts message publication to a transport (e.g., MQTT).
// Implementations must be safe for concurrent use by multiple goroutines.
type Publisher interface {
	// Publish sends payload to topic. A non-empty contentType names the
	// payload's encoding, sent as the MQTT 5 Content Type property.
	Publish(ctx context.Context, topic string, payload []byte, contentType string) error
}

// Encoder abstracts protobuf message encoding strategies.
// Implementations convert protobuf messages to wire-ready bytes.
type Encoder interface {
	Marshal(msg ProtoMessage) ([]byte, error)
	// ContentType names the encoding, for consumers to choose a decoder by.
	ContentType() string
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
	ListenAddr     string // OTLP/gRPC listen address (always started)
	HTTPListenAddr string // OTLP/HTTP listen address; empty disables the HTTP listener
	Encoding       string // "protobuf" | "json"
	// MetricsEncoding encodes metrics bound for the telemetry topic; empty
	// uses Encoding. Metrics marked as Diode data go to the ingest topic in
	// Encoding, like every log and trace.
	MetricsEncoding string // "protobuf" (or "proto") | "json" | ""
	MaxPendingQueue int    // max queued messages before MQTT is ready; 0 = default (1000)
}
