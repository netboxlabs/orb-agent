package otlpbridge

import (
	"context"
	"log/slog"
	"testing"
	"time"

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
	done    chan struct{} // signals when Publish has been called
}

func newFakePublisher() *fakePublisher {
	return &fakePublisher{done: make(chan struct{}, 1)}
}

func (f *fakePublisher) Publish(_ context.Context, topic string, payload []byte) error {
	f.topic = topic
	f.payload = append([]byte(nil), payload...)
	select {
	case f.done <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakePublisher) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for publish")
	}
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
	fp := newFakePublisher()
	logger := slog.Default()
	bridge, _ := NewBridgeServer(BridgeConfig{Encoding: "protobuf"}, nil, logger)
	bridge.enc = enc
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
	fp.wait(t)
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
	fp.wait(t)
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
	fp.wait(t)
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
	fp.wait(t)
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
	fp.wait(t)
	if fp.topic != "telemetry" {
		t.Fatalf("expected telemetry topic, got %q", fp.topic)
	}
}
