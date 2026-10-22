package otlpbridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// scriptedPublisher records what it published and answers each call with the
// next error from errs, then nil.
type scriptedPublisher struct {
	mu       sync.Mutex
	calls    int
	errs     []error
	messages []publishedMsg
}

func (p *scriptedPublisher) Publish(_ context.Context, topic string, payload []byte, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if len(p.errs) > 0 {
		err := p.errs[0]
		p.errs = p.errs[1:]
		if err != nil {
			return err
		}
	}
	p.messages = append(p.messages, publishedMsg{topic: topic, payload: append([]byte(nil), payload...)})
	return nil
}

func (p *scriptedPublisher) published() []publishedMsg {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]publishedMsg(nil), p.messages...)
}

func (p *scriptedPublisher) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// limitedBridge is a bridge with the fleet manager's encodings, cfg's limits,
// and pub bound to both topics.
func limitedBridge(t *testing.T, cfg BridgeConfig, pub Publisher) *BridgeServer {
	t.Helper()
	cfg.Encoding, cfg.MetricsEncoding = "json", "protobuf"
	bridge, err := NewBridgeServer(cfg, nil, quietLogger())
	require.NoError(t, err)
	bridge.initialBackoff = time.Millisecond
	bridge.SetPublisher(pub)
	bridge.SetIngestTopic("ingest")
	bridge.SetTelemetryTopic("telemetry")
	t.Cleanup(func() { _ = bridge.Stop(context.Background()) })
	return bridge
}

// largeExport is two backends' worth of polled series: policies on two
// resources, each device with interfaces' gauges and counters.
func largeExport() *collectormetrics.ExportMetricsServiceRequest {
	return export(
		backendResource("snmp-telemetry",
			policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 300), sumMetric("snmp.ifhcinucastpkts", "10.0.0.1", 300)),
			policyScope("edge", gaugeMetric("snmp.ifinoctets", "10.0.1.1", 200)),
		),
		backendResource("gnmi-telemetry", policyScope("spine", gaugeMetric("gnmi.if_in_octets", "10.0.2.1", 250))),
	)
}

// The export a client sends over the cap reaches the telemetry topic as
// several messages under the cap, between them every point of it once, each
// with its resource and its scope with policy_name: through the handler both
// transports share.
func TestMetricsExport_OverTheCapArrivesAsMessagesUnderIt(t *testing.T) {
	req := largeExport()
	want := pointKeys(t, [][]byte{mustMarshal(t, req)}, decodeProto)
	whole := proto.Size(req)
	limit := whole / 4

	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{MaxMessageBytes: limit}, pub)
	_, err := (&metricsServer{bridge: bridge}).Export(context.Background(), req)
	require.NoError(t, err)

	var msgs []publishedMsg
	require.Eventually(t, func() bool {
		msgs = pub.published()
		return len(msgs) >= 4 && len(pointKeys(t, payloadsOf(msgs), decodeProto)) == len(want)
	}, 5*time.Second, 10*time.Millisecond)
	for _, m := range msgs {
		assert.Equal(t, "telemetry", m.topic)
		assert.LessOrEqual(t, len(m.payload), limit, "every message is under the cap")
	}
	assert.Equal(t, want, pointKeys(t, payloadsOf(msgs), decodeProto), "every point once, attributed as it came")
}

// The broker's maximum packet size from its CONNACK lowers the cap: every
// message, PUBLISH framing included, fits under it.
func TestMetricsExport_TheBrokersMaxPacketSizeLowersTheCap(t *testing.T) {
	req := largeExport()
	brokerMax := proto.Size(req) / 3

	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{}, pub)
	bridge.SetBrokerMaxPacketSize(uint32(brokerMax))
	_, err := (&metricsServer{bridge: bridge}).Export(context.Background(), req)
	require.NoError(t, err)

	want := pointKeys(t, [][]byte{mustMarshal(t, req)}, decodeProto)
	var msgs []publishedMsg
	require.Eventually(t, func() bool {
		msgs = pub.published()
		return len(pointKeys(t, payloadsOf(msgs), decodeProto)) == len(want)
	}, 5*time.Second, 10*time.Millisecond)
	assert.GreaterOrEqual(t, len(msgs), 3)
	for _, m := range msgs {
		assert.LessOrEqual(t, len(m.payload)+mqttPublishOverhead(m.topic, ContentTypeProtobuf), brokerMax)
	}
}

// A data point too large for a message on its own is dropped and counted;
// the rest of its export is published, and the count rides the next export
// to the telemetry topic in the agent's own resource.
func TestMetricsExport_APointThatCannotFitIsDroppedCountedAndReported(t *testing.T) {
	huge := gaugeMetric("snmp.sysdescr", "10.0.0.9", 1)
	huge.GetGauge().DataPoints[0].Attributes = append(huge.GetGauge().DataPoints[0].Attributes, strAttr("descr", strings.Repeat("d", 8<<10)))
	req := export(backendResource("snmp-telemetry", policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 20), huge)))

	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{MaxMessageBytes: 4 << 10}, pub)
	_, err := (&metricsServer{bridge: bridge}).Export(context.Background(), req)
	require.NoError(t, err, "the export is accepted: the point is the bridge's to drop, not the client's to retry")
	require.Eventually(t, func() bool { return len(pub.published()) > 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, int64(1), bridge.dropped.total(signalMetrics, reasonTooLarge))

	before := len(pub.published())
	_, err = (&metricsServer{bridge: bridge}).Export(context.Background(), export(backendResource("snmp-telemetry", policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 1)))))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(pub.published()) > before }, 5*time.Second, 10*time.Millisecond)

	counted := false
	for _, m := range pub.published()[before:] {
		for _, rm := range decodeProto(m.payload).GetResourceMetrics() {
			if attrMap(rm.GetResource().GetAttributes())["service.name"] != selfServiceName {
				continue
			}
			sm := rm.GetScopeMetrics()[0]
			assert.Equal(t, selfScopeName, sm.GetScope().GetName())
			assert.Empty(t, sm.GetScope().GetAttributes(), "the agent's own scope names no policy")
			metric := sm.GetMetrics()[0]
			assert.Equal(t, droppedMetricName, metric.GetName())
			pt := metric.GetSum().GetDataPoints()[0]
			assert.Equal(t, map[string]string{"signal": "metrics", "reason": "too_large"}, attrMap(pt.GetAttributes()))
			assert.Equal(t, int64(1), pt.GetAsInt())
			counted = true
		}
	}
	assert.True(t, counted, "the next export carries the drop count")
}

// Diode data on the ingest topic never carries the agent's own series.
func TestMetricsExport_TheDropCountStaysOffTheIngestTopic(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{}, pub)
	bridge.dropped.add(signalLogs, reasonTooLarge, 1)

	req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{{Resource: diodeResource()}}}
	_, err := (&metricsServer{bridge: bridge}).Export(context.Background(), req)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(pub.published()) == 1 }, 5*time.Second, 10*time.Millisecond)
	msg := pub.published()[0]
	assert.Equal(t, "ingest", msg.topic)
	assert.NotContains(t, string(msg.payload), droppedMetricName)
}

// A logs export over the cap is dropped and counted, and the client told
// with a status it does not retry: over gRPC InvalidArgument, over HTTP 400.
func TestLogsExport_OverTheCapIsRefusedAndCounted(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{MaxMessageBytes: 1 << 10, HTTPListenAddr: "127.0.0.1:0", ListenAddr: "127.0.0.1:0"}, pub)
	require.NoError(t, bridge.Start(context.Background()))
	req := &collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{ScopeLogs: []*logsv1.ScopeLogs{{
		LogRecords: []*logsv1.LogRecord{{SeverityText: strings.Repeat("x", 4<<10)}},
	}}}}}

	_, err := (&logsServer{bridge: bridge}).Export(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "exceeds the bridge's message cap")

	resp := postBody(t, "http://"+bridge.HTTPListenAddr()+"/v1/logs", ContentTypeProtobuf, mustMarshal(t, req))
	assert.Equal(t, http.StatusBadRequest, resp.status)
	assert.Equal(t, int64(2), bridge.dropped.total(signalLogs, reasonTooLarge))
	assert.Zero(t, pub.callCount(), "nothing was published")
}

// A payload over the broker's maximum packet size is never sent: the broker
// would close the agent's connection. It is dropped and counted, and the
// message behind it goes out.
func TestWriter_APayloadOverTheBrokersLimitIsDroppedAndTheQueueKeepsGoing(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{}, pub)
	bridge.SetBrokerMaxPacketSize(1 << 10)

	require.NoError(t, bridge.enqueue(context.Background(), signalTraces, false, [][]byte{[]byte(strings.Repeat("t", 2<<10))}, ContentTypeJSON))
	require.NoError(t, bridge.enqueue(context.Background(), signalTraces, false, [][]byte{[]byte("small")}, ContentTypeJSON))

	require.Eventually(t, func() bool { return len(pub.published()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, "small", string(pub.published()[0].payload))
	assert.Equal(t, 1, pub.callCount(), "the oversized payload was never handed to the publisher")
	assert.Equal(t, int64(1), bridge.dropped.total(signalTraces, reasonTooLarge))
}

// A publish the client refuses as invalid ends that payload's retries at
// once: the same arguments would fail again. A transient failure keeps the
// backoff and goes through.
func TestWriter_APermanentPublishErrorIsNotRetried(t *testing.T) {
	pub := &scriptedPublisher{errs: []error{
		fmt.Errorf("%w: cannot send Publish with QoS 2", paho.ErrInvalidArguments),
		errors.New("connection reset"),
	}}
	bridge := limitedBridge(t, BridgeConfig{}, pub)

	require.NoError(t, bridge.enqueue(context.Background(), signalMetrics, false, [][]byte{[]byte("refused")}, ContentTypeProtobuf))
	require.NoError(t, bridge.enqueue(context.Background(), signalMetrics, false, [][]byte{[]byte("retried")}, ContentTypeProtobuf))

	require.Eventually(t, func() bool { return len(pub.published()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, "retried", string(pub.published()[0].payload))
	assert.Equal(t, 3, pub.callCount(), "one call for the refused payload, two for the retried one")
	assert.Equal(t, int64(1), bridge.dropped.total(signalMetrics, reasonPublishFailed))
}

// The queue holds at most MaxPendingBytes of payload. An export whose
// messages would pass it is refused whole with ResourceExhausted, and room
// comes back as the writer takes what is queued.
func TestEnqueue_TheByteBoundHolds(t *testing.T) {
	pub := &blockingPublisher{entered: make(chan struct{}, 1), release: make(chan struct{})}
	bridge, err := NewBridgeServer(BridgeConfig{Encoding: "json", MaxPendingBytes: 100}, nil, quietLogger())
	require.NoError(t, err)
	bridge.SetPublisher(pub)
	bridge.SetTelemetryTopic("telemetry")
	t.Cleanup(func() {
		close(pub.release)
		_ = bridge.Stop(context.Background())
	})
	ctx := context.Background()

	// The writer takes the first and parks in Publish: its bytes are out
	// of the queue.
	require.NoError(t, bridge.enqueue(ctx, signalMetrics, false, [][]byte{make([]byte, 100)}, ContentTypeProtobuf))
	<-pub.entered

	require.NoError(t, bridge.enqueue(ctx, signalMetrics, false, [][]byte{make([]byte, 40), make([]byte, 40)}, ContentTypeProtobuf))
	err = bridge.enqueue(ctx, signalMetrics, false, [][]byte{make([]byte, 10), make([]byte, 11)}, ContentTypeProtobuf)
	require.Error(t, err, "21 more bytes would pass the bound")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	bridge.queueMu.Lock()
	assert.Equal(t, 2, bridge.pending, "a refused export adds none of its messages")
	assert.Equal(t, int64(80), bridge.pendingBytes)
	bridge.queueMu.Unlock()
	require.NoError(t, bridge.enqueue(ctx, signalMetrics, false, [][]byte{make([]byte, 20)}, ContentTypeProtobuf), "exactly at the bound fits")
}

// An export larger than the whole queue could never be admitted, so it is
// dropped and counted rather than refused as retryable forever.
func TestEnqueue_AnExportLargerThanTheWholeQueueIsDroppedNotRefusedForever(t *testing.T) {
	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{MaxPendingBytes: 100, MaxPendingQueue: 2}, pub)
	ctx := context.Background()

	err := bridge.enqueue(ctx, signalMetrics, false, [][]byte{make([]byte, 60), make([]byte, 41)}, ContentTypeProtobuf)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "past the byte bound alone")
	err = bridge.enqueue(ctx, signalMetrics, false, [][]byte{{1}, {2}, {3}}, ContentTypeProtobuf)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "past the message bound alone")
	assert.Equal(t, int64(2), bridge.dropped.total(signalMetrics, reasonTooLarge))
	assert.Zero(t, pub.callCount())
}

// An export over the cap with no data point to cut it by is dropped and
// counted as one.
func TestSplitMetrics_AnExportOverTheLimitWithNoPointIsDropped(t *testing.T) {
	req := export(backendResource(strings.Repeat("s", 2<<10)))
	payloads, dropped, err := splitMetrics(req, ProtobufEncoder{}, 1<<10)
	require.NoError(t, err)
	assert.Empty(t, payloads)
	require.Len(t, dropped, 1)
	assert.Empty(t, dropped[0].Metric)
	assert.Equal(t, proto.Size(req), dropped[0].Bytes)
}

// Over gRPC, an export past grpc-go's 4 MiB default reaches the bridge and is
// split, rather than refused inside the backend where nothing counts it.
func TestGRPC_AnExportPastTheDefaultReceiveLimitIsAcceptedAndSplit(t *testing.T) {
	var gauges []*metricsv1.Metric
	for d := range 30 {
		gauges = append(gauges, gaugeMetric("snmp.ifinoctets", fmt.Sprintf("10.0.%d.1", d), 1500))
	}
	req := export(backendResource("snmp-telemetry", policyScope("core", gauges...)))
	require.Greater(t, proto.Size(req), 5<<20, "the export is past 4 MiB")

	pub := &scriptedPublisher{}
	bridge := limitedBridge(t, BridgeConfig{ListenAddr: "127.0.0.1:0"}, pub)
	require.NoError(t, bridge.Start(context.Background()))
	conn, err := grpc.NewClient(bridge.ListenAddr(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(64<<20)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = collectormetrics.NewMetricsServiceClient(conn).Export(context.Background(), req)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(pub.published()) >= 2 }, 10*time.Second, 20*time.Millisecond)
	for _, m := range pub.published() {
		assert.LessOrEqual(t, len(m.payload), DefaultMaxMessageBytes)
	}
}

func payloadsOf(msgs []publishedMsg) [][]byte {
	out := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, m.payload)
	}
	return out
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	require.NoError(t, err)
	return b
}
