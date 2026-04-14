package otlpbridge

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

type fakePublisher struct {
	mu      sync.Mutex
	topic   string
	payload []byte
}

func (f *fakePublisher) Publish(_ context.Context, topic string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.topic = topic
	f.payload = append([]byte(nil), payload...)
	return nil
}

func (f *fakePublisher) getTopic() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.topic
}

func (f *fakePublisher) getPayload() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.payload
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

func newBridgeWithTopics(_ Encoder) (*BridgeServer, *fakePublisher) {
	fp := &fakePublisher{}
	bridge, _ := NewBridgeServer(BridgeConfig{Encoding: "protobuf"}, nil, nil)
	bridge.initialBackoff = 5 * time.Millisecond
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
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &traceServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectortrace.ExportTraceServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.Eventually(t, func() bool {
		return fp.getTopic() == "telemetry"
	}, time.Second, time.Millisecond)
}

func TestTraceHandler_Export_DiodeData_PublishesToIngest(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	defer func() { _ = bridge.Stop(context.Background()) }()
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
	require.Eventually(t, func() bool {
		return fp.getTopic() == "ingest"
	}, time.Second, time.Millisecond)
}

// ---------------------------------------------------------------------------
// Metrics handler
// ---------------------------------------------------------------------------

func TestMetricsHandler_Export_AgentTelemetry_PublishesToTelemetry(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &metricsServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectormetrics.ExportMetricsServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.Eventually(t, func() bool {
		return fp.getTopic() == "telemetry"
	}, time.Second, time.Millisecond)
}

func TestMetricsHandler_Export_DiodeData_PublishesToIngest(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	defer func() { _ = bridge.Stop(context.Background()) }()
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
	require.Eventually(t, func() bool {
		return fp.getTopic() == "ingest"
	}, time.Second, time.Millisecond)
}

// ---------------------------------------------------------------------------
// Logs handler
// ---------------------------------------------------------------------------

func TestLogsHandler_Export_AgentTelemetry_PublishesToTelemetry(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &logsServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectorlogs.ExportLogsServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.Eventually(t, func() bool {
		return fp.getTopic() == "telemetry"
	}, time.Second, time.Millisecond)
}

// ---------------------------------------------------------------------------
// Pending queue
// ---------------------------------------------------------------------------

func TestBridge_Enqueue_QueuesDrainsOnReady(t *testing.T) {
	fp := &fakePublisher{}
	bridge, _ := NewBridgeServer(BridgeConfig{Encoding: "protobuf"}, nil, nil)
	bridge.initialBackoff = 5 * time.Millisecond
	defer func() { _ = bridge.Stop(context.Background()) }()

	// Enqueue before publisher is set — should queue, not error.
	if err := bridge.Enqueue(context.Background(), false, []byte("hello")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.getTopic() != "" {
		t.Fatalf("expected no publish yet, got topic %q", fp.getTopic())
	}

	// Setting publisher + topics lets the writer goroutine drain the queue.
	bridge.SetPublisher(fp)
	bridge.SetIngestTopic("ingest")
	bridge.SetTelemetryTopic("telemetry")

	require.Eventually(t, func() bool {
		return fp.getTopic() == "telemetry"
	}, time.Second, time.Millisecond)
	require.Equal(t, "hello", string(fp.getPayload()))
}
