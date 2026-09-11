package otlpbridge

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
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

// startHTTPBridge starts a bridge with only the HTTP listener enabled (gRPC on
// an ephemeral port too, since Start always binds it) and returns its base URL.
func startHTTPBridge(t *testing.T, encoding string) (*BridgeServer, *fakePublisher, string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bridge, err := NewBridgeServer(BridgeConfig{ListenAddr: ":0", HTTPListenAddr: "127.0.0.1:0", Encoding: encoding}, nil, logger)
	require.NoError(t, err)
	bridge.initialBackoff = 5 * time.Millisecond
	fp := &fakePublisher{}
	bridge.SetPublisher(fp)
	bridge.SetIngestTopic("ingest")
	bridge.SetTelemetryTopic("telemetry")
	require.NoError(t, bridge.Start(context.Background()))
	t.Cleanup(func() { _ = bridge.Stop(context.Background()) })
	require.NotNil(t, bridge.httpListener, "HTTP listener must be bound when HTTPListenAddr is set")
	return bridge, fp, "http://" + bridge.httpListener.Addr().String()
}

func metricsRequest() *collectormetrics.ExportMetricsServiceRequest {
	return &collectormetrics.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricsv1.ResourceMetrics{{
			ScopeMetrics: []*metricsv1.ScopeMetrics{{
				Metrics: []*metricsv1.Metric{{Name: "dns_wire_packets_total"}},
			}},
		}},
	}
}

// postResult is an HTTP response with its body already read and closed.
type postResult struct {
	status      int
	contentType string
	retryAfter  string
	body        []byte
}

func postBody(t *testing.T, url, contentType string, body []byte) postResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return postResult{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), retryAfter: resp.Header.Get("Retry-After"), body: respBody}
}

func waitForPayload(t *testing.T, fp *fakePublisher) {
	t.Helper()
	require.Eventually(t, func() bool { return fp.getPayload() != nil }, 2*time.Second, 5*time.Millisecond)
}

func TestHTTP_MetricsProtobuf_PublishesToTelemetry(t *testing.T) {
	_, fp, base := startHTTPBridge(t, "json")
	body, err := proto.Marshal(metricsRequest())
	require.NoError(t, err)

	resp := postBody(t, base+"/v1/metrics", "application/x-protobuf", body)

	assert.Equal(t, http.StatusOK, resp.status)
	assert.Equal(t, "application/x-protobuf", resp.contentType)
	var out collectormetrics.ExportMetricsServiceResponse
	require.NoError(t, proto.Unmarshal(resp.body, &out), "response must be a valid ExportMetricsServiceResponse")

	waitForPayload(t, fp)
	assert.Equal(t, "telemetry", fp.getTopic())
	// The bridge re-encodes with its own encoder (JSON here), exactly like the gRPC path.
	var published collectormetrics.ExportMetricsServiceRequest
	require.NoError(t, protojson.Unmarshal(fp.getPayload(), &published))
	assert.Equal(t, "dns_wire_packets_total", published.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Name)
}

func TestHTTP_MetricsJSON_PublishesToTelemetry(t *testing.T) {
	_, fp, base := startHTTPBridge(t, "protobuf")
	body, err := protojson.Marshal(metricsRequest())
	require.NoError(t, err)

	resp := postBody(t, base+"/v1/metrics", "application/json", body)

	assert.Equal(t, http.StatusOK, resp.status)
	assert.Equal(t, "application/json", resp.contentType)
	waitForPayload(t, fp)
	assert.Equal(t, "telemetry", fp.getTopic())
	var published collectormetrics.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(fp.getPayload(), &published))
	assert.Equal(t, "dns_wire_packets_total", published.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Name)
}

func TestHTTP_MetricsWithDiodeAttribute_PublishesToIngest(t *testing.T) {
	_, fp, base := startHTTPBridge(t, "json")
	req := metricsRequest()
	req.ResourceMetrics[0].Resource = diodeResource()
	body, err := proto.Marshal(req)
	require.NoError(t, err)

	resp := postBody(t, base+"/v1/metrics", "application/x-protobuf", body)

	assert.Equal(t, http.StatusOK, resp.status)
	waitForPayload(t, fp)
	assert.Equal(t, "ingest", fp.getTopic())
}

func TestHTTP_LogsAndTraces_Accepted(t *testing.T) {
	_, fp, base := startHTTPBridge(t, "json")

	logs := &collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
		ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{}}}},
	}}}
	body, err := proto.Marshal(logs)
	require.NoError(t, err)
	resp := postBody(t, base+"/v1/logs", "application/x-protobuf", body)
	assert.Equal(t, http.StatusOK, resp.status)
	waitForPayload(t, fp)
	assert.Equal(t, "telemetry", fp.getTopic())

	fp.mu.Lock()
	fp.payload = nil
	fp.mu.Unlock()

	traces := &collectortrace.ExportTraceServiceRequest{ResourceSpans: []*tracev1.ResourceSpans{{
		ScopeSpans: []*tracev1.ScopeSpans{{Spans: []*tracev1.Span{{Name: "s"}}}},
	}}}
	body, err = proto.Marshal(traces)
	require.NoError(t, err)
	resp = postBody(t, base+"/v1/traces", "application/x-protobuf", body)
	assert.Equal(t, http.StatusOK, resp.status)
	waitForPayload(t, fp)
	assert.Equal(t, "telemetry", fp.getTopic())
}

func TestHTTP_GzipBodyAccepted(t *testing.T) {
	_, fp, base := startHTTPBridge(t, "json")
	raw, err := proto.Marshal(metricsRequest())
	require.NoError(t, err)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = zw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	req, err := http.NewRequest(http.MethodPost, base+"/v1/metrics", &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	waitForPayload(t, fp)
}

func TestHTTP_QueueFull_Returns429WithRetryAfter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	// Queue of one, no publisher: the writer takes one message and blocks
	// retrying it, the second fills the queue, the third must be refused.
	bridge, err := NewBridgeServer(BridgeConfig{ListenAddr: ":0", HTTPListenAddr: "127.0.0.1:0", Encoding: "json", MaxPendingQueue: 1}, nil, logger)
	require.NoError(t, err)
	require.NoError(t, bridge.Start(context.Background()))
	t.Cleanup(func() { _ = bridge.Stop(context.Background()) })
	base := "http://" + bridge.httpListener.Addr().String()

	body, err := proto.Marshal(metricsRequest())
	require.NoError(t, err)

	var last postResult
	for range 3 {
		last = postBody(t, base+"/v1/metrics", "application/x-protobuf", body)
	}
	assert.Equal(t, http.StatusTooManyRequests, last.status)
	assert.NotEmpty(t, last.retryAfter)
	assert.Contains(t, string(last.body), "queue is full")
}

func TestHTTP_BadRequests(t *testing.T) {
	_, _, base := startHTTPBridge(t, "json")
	good, err := proto.Marshal(metricsRequest())
	require.NoError(t, err)

	cases := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        []byte
		want        int
	}{
		{"wrong method", http.MethodGet, "/v1/metrics", "application/x-protobuf", nil, http.StatusMethodNotAllowed},
		{"unknown path", http.MethodPost, "/v1/profiles", "application/x-protobuf", good, http.StatusNotFound},
		{"unsupported content type", http.MethodPost, "/v1/metrics", "text/plain", good, http.StatusUnsupportedMediaType},
		{"undecodable protobuf", http.MethodPost, "/v1/metrics", "application/x-protobuf", []byte{0xff, 0xff, 0xff}, http.StatusBadRequest},
		{"undecodable json", http.MethodPost, "/v1/metrics", "application/json", []byte("{not json"), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, base+tc.path, bytes.NewReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", tc.contentType)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

func TestHTTP_OversizedBody_Returns413(t *testing.T) {
	_, _, base := startHTTPBridge(t, "json")
	body := []byte(strings.Repeat("x", int(maxHTTPBodyBytes)+1))
	resp := postBody(t, base+"/v1/metrics", "application/x-protobuf", body)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.status)
}

func TestHTTP_DisabledWhenAddrEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bridge, err := NewBridgeServer(BridgeConfig{ListenAddr: ":0", Encoding: "json"}, nil, logger)
	require.NoError(t, err)
	require.NoError(t, bridge.Start(context.Background()))
	t.Cleanup(func() { _ = bridge.Stop(context.Background()) })
	assert.Nil(t, bridge.httpListener)
	assert.Nil(t, bridge.httpServer)
}

func TestHTTP_PortInUse_StartFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = blocker.Close() }()

	bridge, err := NewBridgeServer(BridgeConfig{ListenAddr: ":0", HTTPListenAddr: blocker.Addr().String(), Encoding: "json"}, nil, logger)
	require.NoError(t, err)
	err = bridge.Start(context.Background())
	_ = bridge.Stop(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", blocker.Addr().(*net.TCPAddr).Port))
	assert.Contains(t, err.Error(), "port may be in use")
}

func TestHTTP_StopIsGraceful(t *testing.T) {
	bridge, _, base := startHTTPBridge(t, "json")
	require.NoError(t, bridge.Stop(context.Background()))
	_, err := http.Get(base + "/v1/metrics") //nolint:bodyclose // connection is refused, no body
	require.Error(t, err, "listener must be closed after Stop")
}
