package otlpbridge

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/netboxlabs/orb-agent/agent/policies"
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
	bridge, _ := NewBridgeServer(BridgeConfig{Encoding: "protobuf"}, nil, slog.Default())
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
	bridge, _ := NewBridgeServer(BridgeConfig{Encoding: "protobuf"}, nil, slog.Default())
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

// newBridgeWithRepo is newBridgeWithTopics with a policy repository, the way
// fleet mode builds the bridge.
func newBridgeWithRepo(t *testing.T, repo policies.PolicyRepo) (*BridgeServer, *fakePublisher) {
	t.Helper()
	fp := &fakePublisher{}
	bridge, err := NewBridgeServer(BridgeConfig{Encoding: "protobuf"}, repo, slog.Default())
	require.NoError(t, err)
	bridge.initialBackoff = 5 * time.Millisecond
	bridge.SetPublisher(fp)
	bridge.SetIngestTopic("ingest")
	bridge.SetTelemetryTopic("telemetry")
	return bridge, fp
}

func policyScopedRequest(policyName string) *collectormetrics.ExportMetricsServiceRequest {
	return &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{{
		ScopeMetrics: []*metricsv1.ScopeMetrics{{
			Scope: &commonv1.InstrumentationScope{Name: "pktvisor/" + policyName, Attributes: []*commonv1.KeyValue{
				{Key: "policy_name", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: policyName}}},
			}},
			Metrics: []*metricsv1.Metric{{Name: "packets_total"}},
		}},
	}}}
}

func publishedMetrics(t *testing.T, fp *fakePublisher) *collectormetrics.ExportMetricsServiceRequest {
	t.Helper()
	var out collectormetrics.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(fp.getPayload(), &out))
	return &out
}

// The published payload carries the stamps: what leaves the agent is what
// the platform validates, so the test reads the bytes the publisher got.
func TestMetricsHandler_Export_StampsPolicyIDOnScope(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	require.NoError(t, repo.Update(policies.PolicyData{ID: "id-edge", Name: "edge", Backend: "pktvisor"}))
	bridge, fp := newBridgeWithRepo(t, repo)
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &metricsServer{bridge: bridge}

	_, err = s.Export(context.Background(), policyScopedRequest("edge"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return fp.getTopic() == "telemetry" }, time.Second, time.Millisecond)

	got := publishedMetrics(t, fp).ResourceMetrics[0].ScopeMetrics[0].Scope.Attributes
	assert.Equal(t, map[string]string{"policy_name": "edge", "orb.policy_id": "id-edge", "orb.backend": "pktvisor"}, attrMap(got))
}

// A bridge with no policy repository (outside fleet mode) forwards metrics
// exactly as they arrived.
func TestMetricsHandler_Export_WithoutRepo_PassesThrough(t *testing.T) {
	bridge, fp := newBridgeWithTopics(ProtobufEncoder{})
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &metricsServer{bridge: bridge}
	req := policyScopedRequest("edge")
	want, err := proto.Marshal(req)
	require.NoError(t, err)

	_, err = s.Export(context.Background(), req)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return fp.getTopic() == "telemetry" }, time.Second, time.Millisecond)
	assert.Equal(t, want, fp.getPayload())
}

// Stamping does not change where the request goes: Diode-marked metrics
// still reach the ingest topic, stamped.
func TestMetricsHandler_Export_DiodeMarkedScopedMetrics_StillIngest(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	require.NoError(t, repo.Update(policies.PolicyData{ID: "id-core", Name: "core", Backend: "snmp_telemetry"}))
	bridge, fp := newBridgeWithRepo(t, repo)
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &metricsServer{bridge: bridge}
	req := policyScopedRequest("core")
	req.ResourceMetrics[0].Resource = diodeResource()

	_, err = s.Export(context.Background(), req)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return fp.getTopic() == "ingest" }, time.Second, time.Millisecond)
	assert.Equal(t, "id-core", attrMap(publishedMetrics(t, fp).ResourceMetrics[0].ScopeMetrics[0].Scope.Attributes)["orb.policy_id"])
}
