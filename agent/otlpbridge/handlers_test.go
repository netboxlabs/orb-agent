package otlpbridge

import (
	"context"
	"testing"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

type fakePublisher struct {
	topic   string
	payload []byte
}

func (f *fakePublisher) Publish(_ context.Context, topic string, payload []byte) error {
	f.topic = topic
	f.payload = append([]byte(nil), payload...)
	return nil
}

// diodeResource returns a resource carrying the diode.metadata.policy_name attribute.
func diodeResource() *resourcev1.Resource {
	return &resourcev1.Resource{
		Attributes: []*commonv1.KeyValue{
			{
				Key:   diodePolicyNameAttributeKey,
				Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "my-policy"}},
			},
		},
	}
}

func newBridgeWithTopics(enc Encoder) (*BridgeServer, *fakePublisher) {
	fp := &fakePublisher{}
	bridge := &BridgeServer{enc: enc, maxPending: defaultMaxPendingQueue}
	bridge.SetPublisher(fp)
	bridge.SetIngestTopic("ingest")
	bridge.SetTelemetryTopic("telemetry")
	return bridge, fp
}

// ---------------------------------------------------------------------------
// Trace handler
// ---------------------------------------------------------------------------

func TestTraceHandler_Export_AgentTelemetry_PublishesToTelemetry(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	s := &traceServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectortrace.ExportTraceServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "telemetry" {
		t.Fatalf("expected telemetry topic, got %q", fp.topic)
	}
}

func TestTraceHandler_Export_DiodeData_PublishesToIngest(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	s := &traceServer{bridge: bridge}
	req := &collectortrace.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{
			{Resource: diodeResource()},
		},
	}
	_, err := s.Export(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "ingest" {
		t.Fatalf("expected ingest topic, got %q", fp.topic)
	}
}

// ---------------------------------------------------------------------------
// Metrics handler
// ---------------------------------------------------------------------------

func TestMetricsHandler_Export_AgentTelemetry_PublishesToTelemetry(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	s := &metricsServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectormetrics.ExportMetricsServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "telemetry" {
		t.Fatalf("expected telemetry topic, got %q", fp.topic)
	}
}

func TestMetricsHandler_Export_DiodeData_PublishesToIngest(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	s := &metricsServer{bridge: bridge}
	req := &collectormetrics.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricsv1.ResourceMetrics{
			{Resource: diodeResource()},
		},
	}
	_, err := s.Export(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "ingest" {
		t.Fatalf("expected ingest topic, got %q", fp.topic)
	}
}

// ---------------------------------------------------------------------------
// Logs handler
// ---------------------------------------------------------------------------

func TestLogsHandler_Export_AgentTelemetry_PublishesToTelemetry(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	s := &logsServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectorlogs.ExportLogsServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "telemetry" {
		t.Fatalf("expected telemetry topic, got %q", fp.topic)
	}
}

// ---------------------------------------------------------------------------
// Pending queue
// ---------------------------------------------------------------------------

func TestBridge_Enqueue_QueuesDrainsOnReady(t *testing.T) {
	fp := &fakePublisher{}
	bridge := &BridgeServer{enc: ProtobufEncoder{}, maxPending: defaultMaxPendingQueue}

	// Enqueue before publisher is set — should queue, not error.
	if err := bridge.Enqueue(context.Background(), false, []byte("hello")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "" {
		t.Fatalf("expected no publish yet, got topic %q", fp.topic)
	}

	// Setting publisher + topics drains the queue.
	bridge.SetPublisher(fp)
	bridge.SetIngestTopic("ingest")
	bridge.SetTelemetryTopic("telemetry")

	if fp.topic != "telemetry" {
		t.Fatalf("expected queued message to drain to telemetry, got %q", fp.topic)
	}
	if string(fp.payload) != "hello" {
		t.Fatalf("expected payload 'hello', got %q", string(fp.payload))
	}
}
