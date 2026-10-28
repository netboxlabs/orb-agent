package otlpbridge

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A refusal for a full queue asks the client to come back: ResourceExhausted
// with a RetryInfo, which the OTLP exporters need before they retry it.
func TestEnqueue_AFullQueueRefusalCarriesARetryDelay(t *testing.T) {
	pub := &blockingPublisher{entered: make(chan struct{}, 1), release: make(chan struct{})}
	bridge := limitedBridge(t, BridgeConfig{MaxPendingQueue: 1}, pub)
	t.Cleanup(func() { close(pub.release) })
	ctx := context.Background()

	// The writer takes one message and parks in Publish; a second fills the
	// queue.
	require.NoError(t, bridge.enqueue(ctx, signalMetrics, false, [][]byte{{1}}, ContentTypeProtobuf))
	<-pub.entered
	require.NoError(t, bridge.enqueue(ctx, signalMetrics, false, [][]byte{{2}}, ContentTypeProtobuf))

	refused := status.Convert(bridge.enqueue(ctx, signalMetrics, false, [][]byte{{3}}, ContentTypeProtobuf))
	assert.Equal(t, codes.ResourceExhausted, refused.Code())
	assert.Equal(t, []time.Duration{queueFullRetryAfter}, retryDelays(refused))
}

// An export the full queue refuses is sent again by the OTLP exporter, which
// retries ResourceExhausted only when it carries a RetryInfo, and is published
// once the queue has room. Without the RetryInfo the exporter gives up at the
// first refusal and the export is lost.
func TestGRPCExport_TheExporterSendsAgainAnExportTheFullQueueRefused(t *testing.T) {
	pub := &gatedPublisher{entered: make(chan struct{}, 1), open: make(chan struct{})}
	bridge := limitedBridge(t, BridgeConfig{MaxPendingQueue: 1}, pub)
	bridge.retryAfter = 20 * time.Millisecond
	var openOnce sync.Once
	open := func() { openOnce.Do(func() { close(pub.open) }) }
	t.Cleanup(open)
	refused := make(chan struct{}, 1)
	addr := serveLogs(t, &refusalSpy{LogsServiceServer: &logsServer{bridge: bridge}, refused: refused})
	ctx := context.Background()

	require.NoError(t, bridge.enqueue(ctx, signalLogs, false, [][]byte{[]byte("first")}, ContentTypeJSON))
	<-pub.entered
	require.NoError(t, bridge.enqueue(ctx, signalLogs, false, [][]byte{[]byte("second")}, ContentTypeJSON))

	exporter, err := otlploggrpc.New(ctx,
		otlploggrpc.WithEndpoint(addr),
		otlploggrpc.WithInsecure(),
		otlploggrpc.WithRetry(otlploggrpc.RetryConfig{
			Enabled:         true,
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     50 * time.Millisecond,
			MaxElapsedTime:  10 * time.Second,
		}))
	require.NoError(t, err)
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })
	var record sdklog.Record
	record.SetBody(attribute.StringValue("sent again"))
	exported := make(chan error, 1)
	go func() { exported <- exporter.Export(ctx, []sdklog.Record{record}) }()

	select {
	case <-refused:
	case <-time.After(5 * time.Second):
		t.Fatal("the full queue never refused the export")
	}
	open()
	select {
	case err := <-exported:
		require.NoError(t, err, "the exporter sends the refused export again")
	case <-time.After(10 * time.Second):
		t.Fatal("the export never finished")
	}
	require.Eventually(t, func() bool { return len(pub.published()) == 3 }, 5*time.Second, 10*time.Millisecond)
	assert.Contains(t, string(pub.published()[2]), "sent again")
}

// Retry-After is whole seconds, rounded up, and never 0, which a client
// would read as "send again now".
func TestRetryAfterSeconds(t *testing.T) {
	assert.Equal(t, 5, retryAfterSeconds(queueFullRetryAfter))
	assert.Equal(t, 2, retryAfterSeconds(1500*time.Millisecond))
	assert.Equal(t, 1, retryAfterSeconds(20*time.Millisecond))
	assert.Equal(t, 1, retryAfterSeconds(0))
}

func retryDelays(s *status.Status) []time.Duration {
	var delays []time.Duration
	for _, detail := range s.Details() {
		if info, ok := detail.(*errdetails.RetryInfo); ok {
			delays = append(delays, info.GetRetryDelay().AsDuration())
		}
	}
	return delays
}

// serveLogs serves srv as the OTLP logs service on a loopback port, for an
// exporter to send to, and returns its address.
func serveLogs(t *testing.T, srv collectorlogs.LogsServiceServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	collectorlogs.RegisterLogsServiceServer(server, srv)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	return lis.Addr().String()
}

// refusalSpy is the bridge's logs service, telling the test when it refused
// an export for a full queue.
type refusalSpy struct {
	collectorlogs.LogsServiceServer
	refused chan<- struct{}
}

func (s *refusalSpy) Export(ctx context.Context, req *collectorlogs.ExportLogsServiceRequest) (*collectorlogs.ExportLogsServiceResponse, error) {
	resp, err := s.LogsServiceServer.Export(ctx, req)
	if status.Code(err) == codes.ResourceExhausted {
		select {
		case s.refused <- struct{}{}:
		default:
		}
	}
	return resp, err
}

// gatedPublisher holds every publish until open is closed, and records what
// it published.
type gatedPublisher struct {
	entered chan struct{}
	open    chan struct{}

	mu       sync.Mutex
	payloads [][]byte
}

func (p *gatedPublisher) Publish(ctx context.Context, _ string, payload []byte, _ string) error {
	select {
	case p.entered <- struct{}{}:
	default:
	}
	select {
	case <-p.open:
	case <-ctx.Done():
		return ctx.Err()
	}
	p.mu.Lock()
	p.payloads = append(p.payloads, append([]byte(nil), payload...))
	p.mu.Unlock()
	return nil
}

func (p *gatedPublisher) published() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]byte(nil), p.payloads...)
}
