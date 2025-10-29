package otlpbridge

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ProtobufEncoder marshals protobuf messages using binary wire format.
type ProtobufEncoder struct{}

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

// Marshal encodes a protobuf message as JSON.
func (e JSONEncoder) Marshal(msg ProtoMessage) ([]byte, error) {
	if m, ok := msg.(proto.Message); ok {
		return e.opts.Marshal(m)
	}
	return []byte(msg.String()), nil
}
