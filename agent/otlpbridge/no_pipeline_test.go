package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// agentLog is a logs export that is not Diode data, as the agent's own log is
// in fleet mode: a resource naming the orb-agent service and one record.
func agentLog(body string) *collectorlogs.ExportLogsServiceRequest {
	return &collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
		Resource: &resourcev1.Resource{Attributes: []*commonv1.KeyValue{strAttr("service.name", "orb-agent")}},
		ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{
			Body: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: body}},
		}}}},
	}}}
}

// diodeLog is a Diode ingest export whose one record's body is n bytes.
func diodeLog(n int) *collectorlogs.ExportLogsServiceRequest {
	return &collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
		Resource: diodeResource(),
		ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{
			Body: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: strings.Repeat("d", n)}},
		}}}},
	}}}
}

// By default the bridge publishes no logs that are not Diode data, as the
// platform keeps none. Each such export is answered as accepted, so no
// exporter retries it or logs an error, and counted as no_pipeline; the first
// is logged once at INFO with the setting that forwards them.
func TestLogsExport_NotDiodeDataIsCountedNotPublishedByDefault(t *testing.T) {
	pub := &scriptedPublisher{}
	logs := &recordedLogs{}
	bridge := limitedBridgeLogging(t, BridgeConfig{}, pub, slog.New(logs))
	ctx := context.Background()

	for i := range 3 {
		_, err := (&logsServer{bridge: bridge}).Export(ctx, agentLog(fmt.Sprint("line ", i)))
		require.NoError(t, err)
	}
	// A Diode export after them is the only message published: none of the
	// three was queued ahead of it.
	_, err := (&logsServer{bridge: bridge}).Export(ctx, diodeLog(10))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return pub.callCount() == 1 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, "ingest", pub.published()[0].topic)

	assert.Equal(t, int64(3), bridge.dropped.total(signalLogs, reasonNoPipeline))
	infos := logs.at(slog.LevelInfo)
	require.Len(t, infos, 1, "logged once, not per export")
	assert.Contains(t, infos[0].msg, "send_agent_logs")
	assert.Equal(t, signalLogs, infos[0].attrs["signal"])
	assert.Equal(t, "orb-agent", infos[0].attrs["service_name"])
}

// With send_agent_logs on, logs that are not Diode data are
// published to the telemetry topic, as they were before the setting.
func TestLogsExport_NotDiodeDataIsPublishedWhenForwardingIsOn(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{ForwardLogs: true}, pub)

	_, err := (&logsServer{bridge: bridge}).Export(context.Background(), agentLog("forwarded line"))
	require.NoError(t, err)

	require.Eventually(t, func() bool { return pub.callCount() == 1 }, 5*time.Second, 5*time.Millisecond)
	msg := pub.published()[0]
	assert.Equal(t, "telemetry", msg.topic)
	assert.Contains(t, string(msg.payload), "forwarded line")
	assert.Zero(t, bridge.dropped.total(signalLogs, reasonNoPipeline))
}

// Traces are never published, Diode data or not and whatever the setting:
// nothing on the platform reads them, as the telemetry enricher drops them
// and orb-pro's OTLP Bridge reads the ingest topic as logs only.
func TestTracesExport_AreNeverPublished(t *testing.T) {
	for _, forward := range []bool{false, true} {
		for name, resource := range map[string]*resourcev1.Resource{
			"not Diode data": {Attributes: []*commonv1.KeyValue{strAttr("service.name", "a-backend")}},
			"Diode data":     diodeResource(),
		} {
			t.Run(fmt.Sprintf("%s, forward_logs=%v", name, forward), func(t *testing.T) {
				pub := &scriptedPublisher{}
				bridge := limitedBridge(t, BridgeConfig{ForwardLogs: forward}, pub)
				req := &collectortrace.ExportTraceServiceRequest{ResourceSpans: []*tracev1.ResourceSpans{{Resource: resource}}}
				ctx := context.Background()

				_, err := (&traceServer{bridge: bridge}).Export(ctx, req)
				require.NoError(t, err)
				assert.Equal(t, int64(1), bridge.dropped.total(signalTraces, reasonNoPipeline))

				// A Diode log after it is the only message published.
				_, err = (&logsServer{bridge: bridge}).Export(ctx, diodeLog(10))
				require.NoError(t, err)
				require.Eventually(t, func() bool { return pub.callCount() == 1 }, 5*time.Second, 5*time.Millisecond)
				assert.Contains(t, string(pub.published()[0].payload), "resourceLogs")
			})
		}
	}
}

// Logs and traces are logged at INFO once each, not once for both: the logs
// line is the one that names send_agent_logs.
func TestDiscards_LogOncePerSignal(t *testing.T) {
	logs := &recordedLogs{}
	bridge := limitedBridgeLogging(t, BridgeConfig{}, &scriptedPublisher{}, slog.New(logs))
	ctx := context.Background()

	_, err := (&traceServer{bridge: bridge}).Export(ctx, &collectortrace.ExportTraceServiceRequest{})
	require.NoError(t, err)
	_, err = (&logsServer{bridge: bridge}).Export(ctx, agentLog("line"))
	require.NoError(t, err)

	infos := logs.at(slog.LevelInfo)
	require.Len(t, infos, 2)
	assert.Equal(t, signalTraces, infos[0].attrs["signal"])
	assert.Equal(t, signalLogs, infos[1].attrs["signal"])
	assert.Contains(t, infos[1].msg, "send_agent_logs")
}

// Over HTTP, a logs export that is not Diode data is answered 200 and not
// published.
func TestHTTPLogsExport_NotDiodeDataIsAcceptedNotPublished(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{ListenAddr: "127.0.0.1:0", HTTPListenAddr: "127.0.0.1:0"}, pub)
	require.NoError(t, bridge.Start(context.Background()))

	resp := postBody(t, "http://"+bridge.HTTPListenAddr()+"/v1/logs", ContentTypeProtobuf, mustMarshal(t, agentLog("line")))

	assert.Equal(t, http.StatusOK, resp.status)
	assert.Equal(t, int64(1), bridge.dropped.total(signalLogs, reasonNoPipeline))
	assert.Zero(t, pub.callCount())
}

// MON-746: the agent's own log, debug lines included, shared the pending
// queue with the backends' metrics, so a burst of it could fill the queue and
// get metrics refused. Logs that are not Diode data no longer take room, and a
// metrics export is admitted however many of them came first.
func TestLogsExport_NotDiodeDataTakesNoRoomFromMetrics(t *testing.T) {
	pub := &steppedPublisher{entered: make(chan struct{}, 8), step: make(chan struct{})}
	bridge := limitedBridge(t, BridgeConfig{MaxPendingQueue: 2}, pub)
	ctx := context.Background()
	admitOne(t, bridge, 1)
	<-pub.entered

	for i := range 50 {
		_, err := (&logsServer{bridge: bridge}).Export(ctx, agentLog(fmt.Sprint("debug line ", i)))
		require.NoError(t, err)
	}
	_, err := (&metricsServer{bridge: bridge}).Export(ctx, metricsRequest())

	require.NoError(t, err, "a metrics export is admitted after the logs")
}

// A Diode export is held to the broker's limit, not to the configured cap,
// which sizes what the telemetry enricher receives: the bridge's JSON makes a
// discovery chunk 1.4 to 2.6 times the size the backend chunked it to. One
// over the broker's limit is still dropped and counted.
func TestLogsExport_DiodeDataIsHeldToTheBrokersLimitNotTheCap(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{MaxMessageBytes: 64 << 10}, pub)
	bridge.SetBrokerMaxPacketSize(1 << 20)
	ctx := context.Background()

	_, err := (&logsServer{bridge: bridge}).Export(ctx, diodeLog(200<<10))
	require.NoError(t, err, "over the 64 KiB cap, under the broker's 1 MiB")
	require.Eventually(t, func() bool { return pub.callCount() == 1 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, "ingest", pub.published()[0].topic)

	_, err = (&logsServer{bridge: bridge}).Export(ctx, diodeLog(2<<20))
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "over the broker's limit")
	assert.Equal(t, int64(1), bridge.dropped.total(signalLogs, reasonTooLarge))
}

// A Diode export also has to fit the pending queue, which it goes into whole,
// so a pending bound under the broker's limit holds it to that bound, and the
// refusal names the limit it met.
func TestLogsExport_DiodeDataIsHeldToThePendingBound(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{MaxMessageBytes: 64 << 10, MaxPendingBytes: 1 << 20}, pub)
	bridge.SetBrokerMaxPacketSize(16 << 20)
	ctx := context.Background()

	_, err := (&logsServer{bridge: bridge}).Export(ctx, diodeLog(512<<10))
	require.NoError(t, err, "over the cap, under the 1 MiB pending bound")

	_, err = (&logsServer{bridge: bridge}).Export(ctx, diodeLog(2<<20))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "Diode data")
	assert.Contains(t, status.Convert(err).Message(), fmt.Sprint(1<<20))
	assert.Equal(t, int64(1), bridge.dropped.total(signalLogs, reasonTooLarge))
}

// The most payload a Diode export may carry: the broker's limit once its
// CONNACK has set one, whatever the configured cap; before that, RabbitMQ's
// default maximum packet size, or the configured cap when it is larger; and
// never more than the pending queue holds.
func TestIngestCap(t *testing.T) {
	const topic = "orgs.o.agents.a.ingest"
	overhead := mqttPublishOverhead(topic, ContentTypeJSON)
	for _, tc := range []struct {
		name    string
		cap     int
		pending int64
		broker  uint32
		want    int
	}{
		{"broker unknown: RabbitMQ's default", 4 << 20, 0, 0, 16<<20 - overhead},
		{"broker unknown, a larger cap", 32 << 20, 0, 0, 32 << 20},
		{"broker's limit under the cap", 32 << 20, 0, 8 << 20, 8<<20 - overhead},
		{"broker's limit over the cap", 4 << 20, 0, 16 << 20, 16<<20 - overhead},
		{"broker leaves no room", 4 << 20, 0, 10, 0},
		{"pending bound under the broker's limit", 4 << 20, 8 << 20, 16 << 20, 8 << 20},
		{"pending bound under RabbitMQ's default", 4 << 20, 4 << 20, 0, 4 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bridge, err := NewBridgeServer(BridgeConfig{MaxMessageBytes: tc.cap, MaxPendingBytes: tc.pending}, nil, quietLogger())
			require.NoError(t, err)
			t.Cleanup(func() { _ = bridge.Stop(context.Background()) })
			bridge.SetBrokerMaxPacketSize(tc.broker)

			assert.Equal(t, tc.want, bridge.ingestCap(topic, ContentTypeJSON))
		})
	}
}
