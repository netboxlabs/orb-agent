package otlpbridge

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// newFleetEncodedBridge builds a bridge with the encodings the fleet config
// manager uses: metrics for the telemetry topic as protobuf, everything else
// as JSON.
func newFleetEncodedBridge(t *testing.T) (*BridgeServer, *fakePublisher) {
	t.Helper()
	fp := &fakePublisher{}
	bridge, err := NewBridgeServer(BridgeConfig{Encoding: "json", MetricsEncoding: "protobuf"}, nil, slog.Default())
	require.NoError(t, err)
	bridge.initialBackoff = 5 * time.Millisecond
	bridge.SetPublisher(fp)
	bridge.SetIngestTopic("ingest")
	bridge.SetTelemetryTopic("telemetry")
	t.Cleanup(func() { _ = bridge.Stop(context.Background()) })
	return bridge, fp
}

// awaitPublish waits for the bridge's writer to publish to topic.
func awaitPublish(t *testing.T, fp *fakePublisher, topic string) {
	t.Helper()
	require.Eventually(t, func() bool { return fp.getTopic() == topic }, time.Second, time.Millisecond)
}

func TestEncoders_NameTheirContentType(t *testing.T) {
	assert.Equal(t, "application/x-protobuf", ProtobufEncoder{}.ContentType())
	assert.Equal(t, "application/json", NewJSONEncoder().ContentType())
}

// Metrics for the telemetry topic go out as protobuf, about half the bytes of
// JSON, with the MQTT 5 content type that tells the telemetry enricher to
// decode them as protobuf metrics.
func TestFleetBridge_TelemetryMetricsArePublishedAsProtobuf(t *testing.T) {
	bridge, fp := newFleetEncodedBridge(t)
	_, err := (&metricsServer{bridge: bridge}).Export(context.Background(), metricsRequest())
	require.NoError(t, err)
	awaitPublish(t, fp, "telemetry")

	payload := fp.getPayload()
	require.NotEmpty(t, payload)
	assert.NotEqual(t, byte('{'), payload[0], "a protobuf body, not JSON")
	var got collectormetrics.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(payload, &got))
	assert.Equal(t, "dns_wire_packets_total", got.GetResourceMetrics()[0].GetScopeMetrics()[0].GetMetrics()[0].GetName())
	assert.Equal(t, "application/x-protobuf", fp.getContentType())
}

// The enricher tells JSON logs and traces apart from metrics by reading their
// first key; protobuf would make it decode them as metrics. They stay JSON.
func TestFleetBridge_LogsAndTracesStayJSON(t *testing.T) {
	t.Run("logs", func(t *testing.T) {
		bridge, fp := newFleetEncodedBridge(t)
		req := &collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{}}}
		_, err := (&logsServer{bridge: bridge}).Export(context.Background(), req)
		require.NoError(t, err)
		awaitPublish(t, fp, "telemetry")
		assert.Equal(t, "application/json", fp.getContentType())
		require.NoError(t, protojson.Unmarshal(fp.getPayload(), &collectorlogs.ExportLogsServiceRequest{}))
	})
	t.Run("traces", func(t *testing.T) {
		bridge, fp := newFleetEncodedBridge(t)
		req := &collectortrace.ExportTraceServiceRequest{ResourceSpans: []*tracev1.ResourceSpans{{}}}
		_, err := (&traceServer{bridge: bridge}).Export(context.Background(), req)
		require.NoError(t, err)
		awaitPublish(t, fp, "telemetry")
		assert.Equal(t, "application/json", fp.getContentType())
		require.NoError(t, protojson.Unmarshal(fp.getPayload(), &collectortrace.ExportTraceServiceRequest{}))
	})
}

// The ingest topic's consumer, orb-pro's OTLP Bridge service, reads JSON, so
// a metrics request marked as Diode data stays JSON on its way there.
func TestFleetBridge_IngestMetricsStayJSON(t *testing.T) {
	bridge, fp := newFleetEncodedBridge(t)
	req := &collectormetrics.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricsv1.ResourceMetrics{{Resource: diodeResource()}},
	}
	_, err := (&metricsServer{bridge: bridge}).Export(context.Background(), req)
	require.NoError(t, err)
	awaitPublish(t, fp, "ingest")
	assert.Equal(t, "application/json", fp.getContentType())
	require.NoError(t, protojson.Unmarshal(fp.getPayload(), &collectormetrics.ExportMetricsServiceRequest{}))
}

// A bridge configured with one encoding uses it for metrics too, as before.
func TestBridge_MetricsEncodingDefaultsToEncoding(t *testing.T) {
	fp := &fakePublisher{}
	bridge, err := NewBridgeServer(BridgeConfig{Encoding: "json"}, nil, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = bridge.Stop(context.Background()) })
	bridge.SetPublisher(fp)
	bridge.SetTelemetryTopic("telemetry")

	_, err = (&metricsServer{bridge: bridge}).Export(context.Background(), metricsRequest())
	require.NoError(t, err)
	awaitPublish(t, fp, "telemetry")
	assert.Equal(t, "application/json", fp.getContentType())
}

func TestBridge_UnsupportedMetricsEncodingIsRefused(t *testing.T) {
	_, err := NewBridgeServer(BridgeConfig{Encoding: "json", MetricsEncoding: "xml"}, nil, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xml")
}

// The MQTT publish carries the content type as the MQTT 5 Content Type
// property, which RabbitMQ hands to AMQP consumers as content-type. A payload
// with none leaves the properties unset, as before.
func TestMQTTPublish_CarriesTheContentType(t *testing.T) {
	p := mqttPublish("orgs/o/agents/a/telemetry", []byte("x"), "application/x-protobuf")
	require.NotNil(t, p.Properties)
	assert.Equal(t, "application/x-protobuf", p.Properties.ContentType)
	assert.Equal(t, "orgs/o/agents/a/telemetry", p.Topic)
	assert.Equal(t, []byte("x"), p.Payload)
	assert.Equal(t, byte(0), p.QoS)
	assert.False(t, p.Retain)

	assert.Nil(t, mqttPublish("t", []byte("x"), "").Properties)
}
