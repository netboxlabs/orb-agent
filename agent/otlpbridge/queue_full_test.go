package otlpbridge

import (
	"context"
	"log/slog"
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
	bridge := limitedBridge(t, BridgeConfig{MaxPendingQueue: 1, ForwardLogs: true}, pub)
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

// A full queue logs its refusals by the spell: a WARN when it first refuses
// an export, saying how full it is, and an INFO when it admits an export after
// a quiet period with no refusal, saying how many it refused and when. An
// export admitted sooner, between refusals, ends nothing, so a queue that is
// full one moment and has room the next does not log each change. Nothing is
// logged while the queue's lock is held.
func TestEnqueue_AFullQueueLogsWhenItStartsAndStopsRefusing(t *testing.T) {
	bridge, pub, logs, clock := fullQueue(t)
	logs.checkUnlocked(&bridge.queueMu)

	// Three refusals over a minute and a half: the spell is older than the
	// quiet period, its latest refusal is not.
	for b := byte(3); b <= 5; b++ {
		refuseOne(t, bridge, b)
		clock.Advance(30 * time.Second)
	}
	warns := logs.at(slog.LevelWarn)
	require.Len(t, warns, 1, "three refusals log once")
	assert.Equal(t, "OTLP pending queue is full, refusing exports until it has room", warns[0].msg)
	assert.Equal(t, map[string]any{
		"signal":               signalMetrics,
		"messages":             int64(1),
		"bytes":                int64(1),
		"pending_messages":     int64(1),
		"pending_bytes":        int64(1),
		"max_pending_messages": int64(1),
		"max_pending_bytes":    int64(defaultMaxPendingBytes),
		"retry_after":          "5s",
		"spell":                int64(1),
		"refusals":             int64(1),
		"first_refusal":        "2026-10-30T12:00:00Z",
	}, warns[0].attrs)

	// The writer publishes the first message and takes the second, which
	// leaves room for one: admitted within the quiet period after the latest
	// refusal, though not after the first, then full again.
	pub.next()
	<-pub.entered
	admitOne(t, bridge, 6)
	refuseOne(t, bridge, 7)
	assert.Len(t, logs.at(slog.LevelWarn), 1, "a refusal soon after an admission is the same spell")
	assert.Empty(t, logs.at(slog.LevelInfo), "an admission within the quiet period ends nothing")

	// The first export admitted a quiet period after the latest refusal ends
	// the spell.
	clock.Advance(queueFullQuiet)
	pub.next()
	<-pub.entered
	admitOne(t, bridge, 8)
	infos := logs.at(slog.LevelInfo)
	require.Len(t, infos, 1)
	assert.Equal(t, "OTLP pending queue has room again, accepting exports", infos[0].msg)
	assert.Equal(t, map[string]any{
		"spell":         int64(1),
		"refusals":      int64(4),
		"first_refusal": "2026-10-30T12:00:00Z",
		"last_refusal":  "2026-10-30T12:01:30Z",
	}, infos[0].attrs)

	// The next refusal starts another spell.
	refuseOne(t, bridge, 9)
	warns = logs.at(slog.LevelWarn)
	require.Len(t, warns, 2)
	assert.Equal(t, int64(2), warns[1].attrs["spell"])
	assert.Equal(t, int64(1), warns[1].attrs["refusals"])
	assert.False(t, logs.loggedUnderLock(), "a line was logged while the queue's lock was held")
}

// A spell of refusals that goes on is logged again every queueFullRemind,
// with the refusals so far and when the first was, so a recent stretch of
// the log still shows it.
func TestEnqueue_ASpellThatGoesOnIsLoggedAgain(t *testing.T) {
	bridge, _, logs, clock := fullQueue(t)

	refuseOne(t, bridge, 3)
	clock.Advance(queueFullRemind - time.Second)
	refuseOne(t, bridge, 4)
	assert.Len(t, logs.at(slog.LevelWarn), 1)
	clock.Advance(time.Second)
	refuseOne(t, bridge, 5)
	clock.Advance(time.Minute)
	refuseOne(t, bridge, 6)

	warns := logs.at(slog.LevelWarn)
	require.Len(t, warns, 2)
	assert.Equal(t, int64(1), warns[1].attrs["spell"])
	assert.Equal(t, int64(3), warns[1].attrs["refusals"])
	assert.Equal(t, "2026-10-30T12:00:00Z", warns[1].attrs["first_refusal"])
	assert.Empty(t, logs.at(slog.LevelInfo))
}

// An export with nothing to queue, as when every point of a metrics export
// was dropped, ends no spell while the queue is still full.
func TestEnqueue_AnEmptyExportEndsNoSpell(t *testing.T) {
	bridge, _, logs, clock := fullQueue(t)

	refuseOne(t, bridge, 3)
	clock.Advance(queueFullQuiet)
	require.NoError(t, bridge.enqueue(context.Background(), signalMetrics, false, nil, ContentTypeProtobuf))
	assert.Empty(t, logs.at(slog.LevelInfo))
	refuseOne(t, bridge, 4)
	assert.Len(t, logs.at(slog.LevelWarn), 1, "the spell goes on")
}

// The byte bound refuses with the queue's messages well under theirs, and the
// WARN tells the queue's numbers apart from the refused export's.
func TestEnqueue_AQueueFullInBytesLogsItsNumbers(t *testing.T) {
	pub := &steppedPublisher{entered: make(chan struct{}, 8), step: make(chan struct{})}
	logs := &recordedLogs{}
	bridge := limitedBridgeLogging(t, BridgeConfig{MaxPendingBytes: 1050}, pub, slog.New(logs))
	logs.checkUnlocked(&bridge.queueMu)
	bridge.now = (&fakeClock{now: queueStart}).Now
	ctx := context.Background()
	require.NoError(t, bridge.enqueue(ctx, signalMetrics, false, [][]byte{make([]byte, 100)}, ContentTypeProtobuf))
	<-pub.entered
	require.NoError(t, bridge.enqueue(ctx, signalMetrics, false,
		[][]byte{make([]byte, 200), make([]byte, 200), make([]byte, 200)}, ContentTypeProtobuf))

	err := bridge.enqueue(ctx, signalLogs, false, [][]byte{make([]byte, 250), make([]byte, 250)}, ContentTypeJSON)
	require.Equal(t, codes.ResourceExhausted, status.Code(err))

	warns := logs.at(slog.LevelWarn)
	require.Len(t, warns, 1)
	assert.Equal(t, map[string]any{
		"signal":               signalLogs,
		"messages":             int64(2),
		"bytes":                int64(500),
		"pending_messages":     int64(3),
		"pending_bytes":        int64(600),
		"max_pending_messages": int64(defaultMaxPendingQueue),
		"max_pending_bytes":    int64(1050),
		"retry_after":          "5s",
		"spell":                int64(1),
		"refusals":             int64(1),
		"first_refusal":        "2026-10-30T12:00:00Z",
	}, warns[0].attrs)
	assert.False(t, logs.loggedUnderLock(), "a line was logged while the queue's lock was held")
}

// Exports refused at the same moment, by concurrent exporters, start one
// spell and log one WARN.
func TestEnqueue_ConcurrentRefusalsLogOnce(t *testing.T) {
	bridge, _, logs, _ := fullQueue(t)
	ctx := context.Background()

	begin := make(chan struct{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			<-begin
			err := bridge.enqueue(ctx, signalLogs, false, [][]byte{{3}}, ContentTypeJSON)
			assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		})
	}
	close(begin)
	wg.Wait()

	assert.Len(t, logs.at(slog.LevelWarn), 1)
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

// queueStart is when the fake clock of fullQueue starts.
var queueStart = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// fullQueue is a bridge with a queue of one message, full: the writer holds a
// first message in Publish and a second waits. It logs to logs, and its clock
// starts at queueStart.
func fullQueue(t *testing.T) (*BridgeServer, *steppedPublisher, *recordedLogs, *fakeClock) {
	t.Helper()
	pub := &steppedPublisher{entered: make(chan struct{}, 8), step: make(chan struct{})}
	logs := &recordedLogs{}
	bridge := limitedBridgeLogging(t, BridgeConfig{MaxPendingQueue: 1}, pub, slog.New(logs))
	clock := &fakeClock{now: queueStart}
	bridge.now = clock.Now
	admitOne(t, bridge, 1)
	<-pub.entered
	admitOne(t, bridge, 2)
	return bridge, pub, logs, clock
}

// admitOne sends a one-byte metrics export the queue admits.
func admitOne(t *testing.T, bridge *BridgeServer, b byte) {
	t.Helper()
	require.NoError(t, bridge.enqueue(context.Background(), signalMetrics, false, [][]byte{{b}}, ContentTypeProtobuf))
}

// refuseOne sends a one-byte metrics export the full queue refuses.
func refuseOne(t *testing.T, bridge *BridgeServer, b byte) {
	t.Helper()
	err := bridge.enqueue(context.Background(), signalMetrics, false, [][]byte{{b}}, ContentTypeProtobuf)
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

// steppedPublisher signals entered as each publish begins and holds it until
// the test lets it through with next.
type steppedPublisher struct {
	entered chan struct{}
	step    chan struct{}
}

func (p *steppedPublisher) Publish(ctx context.Context, _ string, _ []byte, _ string) error {
	select {
	case p.entered <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-p.step:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *steppedPublisher) next() { p.step <- struct{}{} }

// recordedLogs is a slog.Handler that keeps every record, for tests of what
// the bridge logs. With a lock to check, it also notes a record logged while
// that lock was held.
type recordedLogs struct {
	mu        sync.Mutex
	records   []loggedRecord
	lock      *sync.Mutex
	underLock bool
}

// checkUnlocked has every later record checked against lock.
func (h *recordedLogs) checkUnlocked(lock *sync.Mutex) {
	h.mu.Lock()
	h.lock = lock
	h.mu.Unlock()
}

// loggedUnderLock reports whether a record was logged while the checked lock
// was held.
func (h *recordedLogs) loggedUnderLock() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.underLock
}

type loggedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

func (h *recordedLogs) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordedLogs) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lock != nil {
		if h.lock.TryLock() {
			h.lock.Unlock()
		} else {
			h.underLock = true
		}
	}
	h.records = append(h.records, loggedRecord{level: r.Level, msg: r.Message, attrs: attrs})
	return nil
}

func (h *recordedLogs) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordedLogs) WithGroup(string) slog.Handler { return h }

// at returns the records logged at level.
func (h *recordedLogs) at(level slog.Level) []loggedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []loggedRecord
	for _, r := range h.records {
		if r.level == level {
			out = append(out, r)
		}
	}
	return out
}

// fakeClock is a clock the test moves by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
