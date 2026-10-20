package configmgr

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/otlpbridge"
)

// publishedMessage is one payload the bridge handed to its publisher.
type publishedMessage struct {
	topic       string
	payload     []byte
	contentType string
}

// capturingPublisher keeps every payload the bridge publishes.
type capturingPublisher struct {
	mu   sync.Mutex
	sent []publishedMessage
}

func (c *capturingPublisher) Publish(_ context.Context, topic string, payload []byte, contentType string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, publishedMessage{topic: topic, payload: append([]byte(nil), payload...), contentType: contentType})
	return nil
}

func (c *capturingPublisher) messages() []publishedMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]publishedMessage(nil), c.sent...)
}

// The bridge the fleet config manager starts publishes metrics for the
// telemetry topic as protobuf, which the telemetry enricher decodes by its
// content type, and logs as JSON, which it reads by their first key.
func TestFleetConfigManager_StartOTLPBridge_PublishesMetricsAsProtobufAndLogsAsJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)
	mgr := newFleetConfigManager(logger, mockPMgr, nil, nil)

	grpcPort, httpPort := findAvailablePort(t), findAvailablePort(t)
	cfg := config.Config{}
	cfg.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort = &grpcPort
	cfg.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeHTTPPort = &httpPort
	ctx := context.Background()
	require.NoError(t, mgr.StartOTLPBridge(ctx, cfg))
	t.Cleanup(func() { _ = mgr.StopOTLPBridge(ctx) })

	pub := &capturingPublisher{}
	mgr.otlpBridge.SetPublisher(pub)
	mgr.otlpBridge.SetTelemetryTopic("telemetry")
	mgr.otlpBridge.SetIngestTopic("ingest")

	conn, err := grpc.NewClient(mgr.otlpBridge.ListenAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = collectormetrics.NewMetricsServiceClient(conn).Export(ctx, &collectormetrics.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricsv1.ResourceMetrics{{ScopeMetrics: []*metricsv1.ScopeMetrics{{
			Metrics: []*metricsv1.Metric{{Name: "snmp.ifinoctets"}},
		}}}},
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(pub.messages()) == 1 }, 5*time.Second, 5*time.Millisecond)
	_, err = collectorlogs.NewLogsServiceClient(conn).Export(ctx, &collectorlogs.ExportLogsServiceRequest{
		ResourceLogs: []*logsv1.ResourceLogs{{}},
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(pub.messages()) == 2 }, 5*time.Second, 5*time.Millisecond)

	msgs := pub.messages()
	assert.Equal(t, "telemetry", msgs[0].topic)
	assert.Equal(t, otlpbridge.ContentTypeProtobuf, msgs[0].contentType)
	var got collectormetrics.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(msgs[0].payload, &got))
	assert.Equal(t, "snmp.ifinoctets", got.GetResourceMetrics()[0].GetScopeMetrics()[0].GetMetrics()[0].GetName())

	assert.Equal(t, "telemetry", msgs[1].topic)
	assert.Equal(t, otlpbridge.ContentTypeJSON, msgs[1].contentType)
	assert.Equal(t, byte('{'), msgs[1].payload[0])
}
