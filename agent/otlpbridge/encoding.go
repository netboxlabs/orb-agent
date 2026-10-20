package otlpbridge

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Content types the encoders name, sent as the MQTT 5 Content Type property.
// RabbitMQ hands it to AMQP consumers as content-type, and the telemetry
// enricher decodes a body as protobuf metrics when it names protobuf.
const (
	ContentTypeProtobuf = "application/x-protobuf"
	ContentTypeJSON     = "application/json"
)

// ProtobufEncoder marshals protobuf messages using binary wire format.
type ProtobufEncoder struct{}

// ContentType names the protobuf encoding.
func (ProtobufEncoder) ContentType() string { return ContentTypeProtobuf }

// Marshal encodes a protobuf message using binary wire format.
func (ProtobufEncoder) Marshal(msg ProtoMessage) ([]byte, error) {
	// Convert to the modern proto.Message to leverage proto.Marshal
	if m, ok := msg.(proto.Message); ok {
		return proto.Marshal(m)
	}
	// Fallback: attempt via string JSON then marshal (should not happen in practice)
	return []byte(msg.String()), nil
}

// JSONEncoder marshals protobuf messages into JSON.
type JSONEncoder struct {
	opts protojson.MarshalOptions
}

// NewJSONEncoder creates a new JSONEncoder with standard options.
func NewJSONEncoder() JSONEncoder {
	return JSONEncoder{opts: protojson.MarshalOptions{EmitUnpopulated: true}}
}

// ContentType names the JSON encoding.
func (JSONEncoder) ContentType() string { return ContentTypeJSON }

// Marshal encodes a protobuf message as JSON.
func (e JSONEncoder) Marshal(msg ProtoMessage) ([]byte, error) {
	if m, ok := msg.(proto.Message); ok {
		return e.opts.Marshal(m)
	}
	return []byte(msg.String()), nil
}
