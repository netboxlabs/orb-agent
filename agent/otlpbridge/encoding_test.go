package otlpbridge

import (
	"testing"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

func TestProtobufEncoder_Marshal_Basic(t *testing.T) {
	enc := ProtobufEncoder{}
	msg := &collectortrace.ExportTraceServiceRequest{}
	b, err := enc.Marshal(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("expected non-empty bytes")
	}
}

func TestJSONEncoder_Marshal_Basic(t *testing.T) {
	enc := NewJSONEncoder()
	msgs := []ProtoMessage{
		&collectortrace.ExportTraceServiceRequest{},
		&collectormetrics.ExportMetricsServiceRequest{},
		&collectorlogs.ExportLogsServiceRequest{},
	}
	for _, m := range msgs {
		b, err := enc.Marshal(m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(b) == 0 {
			t.Fatalf("expected non-empty bytes")
		}
		// Should be JSON starting with '{' or '[' for empty payloads
		if b[0] != '{' && b[0] != '[' {
			t.Fatalf("expected JSON output, got: %q", string(b))
		}
	}
}
