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
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

type fakePublisher struct {
	mu          sync.Mutex
	topic       string
	payload     []byte
	contentType string
}

func (f *fakePublisher) Publish(_ context.Context, topic string, payload []byte, contentType string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.topic = topic
	f.payload = append([]byte(nil), payload...)
	f.contentType = contentType
	return nil
}

func (f *fakePublisher) getContentType() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.contentType
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
	if err := bridge.Enqueue(context.Background(), false, []byte("hello"), "application/json"); err != nil {
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
func newBridgeWithRepo(t *testing.T, encoding string, repo policies.PolicyRepo) (*BridgeServer, *fakePublisher) {
	t.Helper()
	fp := &fakePublisher{}
	bridge, err := NewBridgeServer(BridgeConfig{Encoding: encoding}, repo, slog.Default())
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
	bridge, fp := newBridgeWithRepo(t, "protobuf", repo)
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
	require.NoError(t, repo.Update(policies.PolicyData{ID: "id-core", Name: "core", Backend: "pktvisor"}))
	bridge, fp := newBridgeWithRepo(t, "protobuf", repo)
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &metricsServer{bridge: bridge}
	req := policyScopedRequest("core")
	req.ResourceMetrics[0].Resource = diodeResource()

	_, err = s.Export(context.Background(), req)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return fp.getTopic() == "ingest" }, time.Second, time.Millisecond)
	assert.Equal(t, "id-core", attrMap(publishedMetrics(t, fp).ResourceMetrics[0].ScopeMetrics[0].Scope.Attributes)["orb.policy_id"])
}

// Fleet mode uses JSON encoding (see agent/configmgr/fleet.go ~174), so
// verify stamping works with JSON-marshalled payloads.
func TestMetricsHandler_Export_StampsPolicyIDOnScope_JSON(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	require.NoError(t, repo.Update(policies.PolicyData{ID: "id-edge", Name: "edge", Backend: "pktvisor"}))
	bridge, fp := newBridgeWithRepo(t, "json", repo)
	defer func() { _ = bridge.Stop(context.Background()) }()
	s := &metricsServer{bridge: bridge}

	_, err = s.Export(context.Background(), policyScopedRequest("edge"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return fp.getTopic() == "telemetry" }, time.Second, time.Millisecond)

	var out collectormetrics.ExportMetricsServiceRequest
	require.NoError(t, protojson.Unmarshal(fp.getPayload(), &out))
	got := out.ResourceMetrics[0].ScopeMetrics[0].Scope.Attributes
	assert.Equal(t, map[string]string{"policy_name": "edge", "orb.policy_id": "id-edge", "orb.backend": "pktvisor"}, attrMap(got))
}

// datasetIDValues returns the string elements of a scope's dataset_ids array.
func datasetIDValues(attrs []*commonv1.KeyValue) []string {
	for _, kv := range attrs {
		if kv == nil || kv.Key != "dataset_ids" || kv.Value == nil || kv.Value.GetArrayValue() == nil {
			continue
		}
		vals := kv.Value.GetArrayValue().GetValues()
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			out = append(out, v.GetStringValue())
		}
		return out
	}
	return nil
}

// enrichLogsWithDatasets stamps the dataset id stored for the policy named by
// diode.metadata.policy_name. The Diode SDK sends a scope with no attributes,
// so a nil attribute list still has to receive dataset_ids.
func TestEnrichLogsWithDatasets(t *testing.T) {
	const (
		policyName = "device-discovery"
		policyID   = "9b15a75b-6d44-4a93-ac13-dd163793a0b1"
		datasetID  = "3f63339c-be47-4c40-b525-ae36682b1c53"
	)

	repoWithDataset := func(t *testing.T) policies.PolicyRepo {
		t.Helper()
		repo, err := policies.NewMemRepo()
		require.NoError(t, err)
		require.NoError(t, repo.Update(policies.PolicyData{
			ID:       policyID,
			Name:     policyName,
			Datasets: map[string]bool{datasetID: true},
		}))
		return repo
	}

	policyResource := func(name string) *resourcev1.Resource {
		return &resourcev1.Resource{Attributes: []*commonv1.KeyValue{
			strAttr(diodePolicyNameAttributeKey, name),
		}}
	}

	logsWith := func(resource *resourcev1.Resource, scope *commonv1.InstrumentationScope) *collectorlogs.ExportLogsServiceRequest {
		return &collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
			Resource:  resource,
			ScopeLogs: []*logsv1.ScopeLogs{{Scope: scope}},
		}}}
	}

	t.Run("nil scope attributes receive the stored dataset id", func(t *testing.T) {
		scope := &commonv1.InstrumentationScope{Name: "netboxlabs-diode", Version: "1.14.2"}
		enrichLogsWithDatasets(logsWith(policyResource(policyName), scope), repoWithDataset(t))

		require.NotNil(t, scope.Attributes)
		assert.Equal(t, "dataset_ids", scope.Attributes[0].Key)
		assert.Equal(t, []string{datasetID}, datasetIDValues(scope.Attributes))
		assert.NotContains(t, datasetIDValues(scope.Attributes), policyID)
	})

	t.Run("existing scope attributes keep their values and gain dataset_ids", func(t *testing.T) {
		scope := &commonv1.InstrumentationScope{Attributes: []*commonv1.KeyValue{
			strAttr("diode.metadata.hostname", "edge-1"),
		}}
		enrichLogsWithDatasets(logsWith(policyResource(policyName), scope), repoWithDataset(t))

		assert.Equal(t, "edge-1", attrMap(scope.Attributes)["diode.metadata.hostname"])
		assert.Equal(t, []string{datasetID}, datasetIDValues(scope.Attributes))
		assert.Equal(t, 1, attrCount(scope.Attributes, "dataset_ids"))
	})

	t.Run("missing policy name stays unstamped", func(t *testing.T) {
		scope := &commonv1.InstrumentationScope{Name: "netboxlabs-diode", Version: "1.14.2"}
		enrichLogsWithDatasets(logsWith(&resourcev1.Resource{}, scope), repoWithDataset(t))

		assert.Nil(t, scope.Attributes)
	})

	t.Run("unknown policy name stays unstamped", func(t *testing.T) {
		scope := &commonv1.InstrumentationScope{Name: "netboxlabs-diode", Version: "1.14.2"}
		enrichLogsWithDatasets(logsWith(policyResource("not-a-known-policy"), scope), repoWithDataset(t))

		assert.Nil(t, scope.Attributes)
	})

	t.Run("nil scope is left alone", func(t *testing.T) {
		req := &collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
			Resource:  policyResource(policyName),
			ScopeLogs: []*logsv1.ScopeLogs{{Scope: nil}},
		}}}
		enrichLogsWithDatasets(req, repoWithDataset(t))

		assert.Nil(t, req.ResourceLogs[0].ScopeLogs[0].Scope)
	})
}
