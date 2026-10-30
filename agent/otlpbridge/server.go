package otlpbridge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/paho"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

const (
	defaultMaxPendingQueue = 1000
	initialRetryBackoff    = 2 * time.Second
	maxRetryBackoff        = 30 * time.Second
	maxPublishRetries      = 10
	// queueFullRetryAfter is how long a client is told to wait before it
	// sends again an export the full queue refused: RetryInfo on gRPC,
	// Retry-After on HTTP.
	queueFullRetryAfter = 5 * time.Second
	// queueFullQuiet is how long the queue goes without refusing an export
	// before the next export it admits ends the spell of refusals and logs
	// it, so a queue full one moment and with room the next logs its
	// refusals once, not each change.
	queueFullQuiet = time.Minute
	// queueFullRemind is how often a spell of refusals that goes on is
	// logged again, so a recent stretch of the log still shows it.
	queueFullRemind = 5 * time.Minute
)

// pendingPublish holds a marshaled OTLP payload queued for publishing.
type pendingPublish struct {
	// signal names what the payload carries (metrics, logs, traces), for
	// the drop counter.
	signal      string
	isIngest    bool
	payload     []byte
	contentType string
}

// BridgeServer holds the lifecycle for the OTLP → MQTT bridge server.
//
// Incoming OTLP payloads are placed on a buffered channel (msgCh) by Enqueue.
// A single writer goroutine consumes from the channel and publishes to MQTT,
// retrying with exponential backoff when the publisher is unavailable or a
// publish fails.
type BridgeServer struct {
	cfg              BridgeConfig
	enc              Encoder
	metricsEnc       Encoder // metrics for the telemetry topic
	ingestGRPCServer *grpc.Server
	listener         net.Listener
	httpServer       *http.Server
	httpListener     net.Listener
	closeOnce        sync.Once

	// Publisher and topics — set after the MQTT connection is established.
	mu             sync.RWMutex
	publisher      Publisher
	ingestTopic    string
	telemetryTopic string
	policyRepo     policies.PolicyRepo
	logger         *slog.Logger

	// Lifecycle context — cancelled by Stop() to unblock the writer goroutine.
	ctx    context.Context
	cancel context.CancelFunc

	// Buffered channel serves as the bounded FIFO queue. A single writer
	// goroutine consumes from it and publishes to MQTT.
	msgCh chan pendingPublish
	// queueMu guards the queue's accounting: pending is how many payloads
	// are queued, pendingBytes their payload bytes, and enqueue admits an
	// export's payloads all together or not at all under both bounds. The
	// channel's capacity is the count bound, so a send admitted here never
	// blocks. The one payload the writer holds while it publishes is not
	// counted, as it never was against the channel: at most one message
	// more than the bounds.
	queueMu         sync.Mutex
	pending         int
	pendingBytes    int64
	maxPendingBytes int64
	// The full queue's current spell of refusals, also under queueMu:
	// refusals counts them (0: no spell), firstRefusal and lastRefusal are
	// when the first and the latest were, lastWarned when the spell was last
	// logged, and spell numbers the spells since the bridge started, so a
	// spell's lines can be paired.
	refusals     int
	firstRefusal time.Time
	lastRefusal  time.Time
	lastWarned   time.Time
	spell        int

	// maxMessageBytes caps one published payload; broker lowers it to what
	// the MQTT server accepts once that is known.
	maxMessageBytes int
	broker          brokerCeiling
	// dropped counts what the bridge could not publish, and is published
	// with the agent's metrics.
	dropped *droppedCounter

	// initialBackoff is the starting retry delay used by the writer goroutine.
	// Defaults to initialRetryBackoff; tests override it for speed.
	initialBackoff time.Duration
	// retryAfter is the delay a refusal for a full queue asks the client to
	// wait. Defaults to queueFullRetryAfter; tests override it for speed.
	retryAfter time.Duration
	// now is the clock for the full queue's log lines; tests replace it.
	now func() time.Time
}

// NewBridgeServer builds a BridgeServer and starts its writer goroutine.
func NewBridgeServer(cfg BridgeConfig, policyRepo policies.PolicyRepo, logger *slog.Logger) (*BridgeServer, error) {
	enc, err := buildEncoder(cfg.Encoding)
	if err != nil {
		return nil, err
	}
	metricsEnc := enc
	if strings.TrimSpace(cfg.MetricsEncoding) != "" {
		if metricsEnc, err = buildEncoder(cfg.MetricsEncoding); err != nil {
			return nil, fmt.Errorf("metrics: %w", err)
		}
	}
	maxPending := cfg.MaxPendingQueue
	if maxPending <= 0 {
		maxPending = defaultMaxPendingQueue
	}
	maxPendingBytes := cfg.MaxPendingBytes
	if maxPendingBytes <= 0 {
		maxPendingBytes = defaultMaxPendingBytes
	}
	maxMessageBytes := cfg.MaxMessageBytes
	if maxMessageBytes <= 0 {
		maxMessageBytes = DefaultMaxMessageBytes
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &BridgeServer{
		cfg:             cfg,
		enc:             enc,
		metricsEnc:      metricsEnc,
		policyRepo:      policyRepo,
		logger:          logger,
		ctx:             ctx,
		cancel:          cancel,
		msgCh:           make(chan pendingPublish, maxPending),
		maxPendingBytes: maxPendingBytes,
		maxMessageBytes: maxMessageBytes,
		dropped:         newDroppedCounter(),
		initialBackoff:  initialRetryBackoff,
		retryAfter:      queueFullRetryAfter,
		now:             time.Now,
	}
	go s.writer()
	return s, nil
}

func buildEncoder(name string) (Encoder, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "protobuf", "proto":
		return ProtobufEncoder{}, nil
	case "json":
		return NewJSONEncoder(), nil
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", name)
	}
}

// SetPublisher sets the publisher for OTLP payloads.
func (s *BridgeServer) SetPublisher(pub Publisher) {
	s.mu.Lock()
	s.publisher = pub
	s.mu.Unlock()
}

// SetIngestTopic sets the topic for ingest publishing.
func (s *BridgeServer) SetIngestTopic(topic string) {
	s.mu.Lock()
	s.ingestTopic = topic
	s.mu.Unlock()
}

// SetTelemetryTopic sets the telemetry topic for publishing.
func (s *BridgeServer) SetTelemetryTopic(topic string) {
	s.mu.Lock()
	s.telemetryTopic = topic
	s.mu.Unlock()
}

// HasPublisher reports whether a publisher is set: without one the writer
// holds its messages.
func (s *BridgeServer) HasPublisher() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publisher != nil
}

// ClearPublisher clears the publisher, causing the writer goroutine to retry
// with backoff until a new publisher is set via SetPublisher.
func (s *BridgeServer) ClearPublisher() {
	s.mu.Lock()
	s.publisher = nil
	s.mu.Unlock()
}

// writer is the single goroutine that consumes from msgCh and publishes.
func (s *BridgeServer) writer() {
	for {
		select {
		case msg := <-s.msgCh:
			s.release(msg)
			s.publishWithRetry(msg)
		case <-s.ctx.Done():
			return
		}
	}
}

// publishWithRetry publishes a single message, retrying with exponential
// backoff when no publisher is available or a publish call fails for a
// reason a retry can get past. Only actual publish failures count toward
// the retry budget; waiting for publisher/topic readiness does not consume
// attempts.
//
// Two failures end the retries at once, the payload dropped and counted: a
// payload over the broker's maximum packet size, which the broker would
// answer by closing the agent's one connection, so it is never sent; and a
// publish the client refuses as invalid (paho.ErrInvalidArguments), which
// the same arguments would fail again. One message never stalls the queue
// behind it for good.
func (s *BridgeServer) publishWithRetry(msg pendingPublish) {
	backoff := s.initialBackoff
	failures := 0
	for {
		s.mu.RLock()
		pub := s.publisher
		topic := s.telemetryTopic
		if msg.isIngest {
			topic = s.ingestTopic
		}
		s.mu.RUnlock()

		if pub != nil && topic != "" {
			// Cut to the configured cap before the broker's limit was known
			// (the queue fills before the first connection), a payload can
			// still be over the broker's: a check here rather than nothing,
			// since the broker's answer would be to drop the connection.
			if limit, limited := s.broker.payloadCap(topic, msg.contentType); limited && len(msg.payload) > limit {
				s.dropped.add(msg.signal, reasonTooLarge, 1)
				s.logger.Warn("OTLP payload exceeds the broker's maximum packet size, dropping it",
					"signal", msg.signal, "bytes", len(msg.payload), "broker_payload_limit", limit)
				return
			}
			err := pub.Publish(s.ctx, topic, msg.payload, msg.contentType)
			if err == nil {
				return
			}
			if errors.Is(err, paho.ErrInvalidArguments) {
				s.dropped.add(msg.signal, reasonPublishFailed, 1)
				s.logger.Warn("OTLP publish refused, dropping message", "signal", msg.signal, "error", err)
				return
			}
			failures++
			s.logger.Warn("OTLP publish failed, retrying", "error", err, "attempt", failures, "backoff", backoff)
			if failures >= maxPublishRetries {
				s.dropped.add(msg.signal, reasonPublishFailed, 1)
				s.logger.Warn("OTLP publish retries exhausted, dropping message", "signal", msg.signal, "max_retries", maxPublishRetries)
				return
			}
		}

		select {
		case <-time.After(backoff):
			backoff = min(backoff*2, maxRetryBackoff)
		case <-s.ctx.Done():
			return
		}
	}
}

// Enqueue adds one marshaled OTLP payload to the publish queue. Returns
// ResourceExhausted, with a retry delay, if the queue is full, providing
// backpressure to the OTLP client.
func (s *BridgeServer) Enqueue(ctx context.Context, isIngest bool, payload []byte, contentType string) error {
	return s.enqueue(ctx, "", isIngest, [][]byte{payload}, contentType)
}

// enqueue adds an export's payloads to the publish queue, all of them or
// none: an export split into several messages is not half sent and then
// retried whole by its client. It returns ResourceExhausted when the queue
// has no room for them, in messages or in bytes, with a RetryInfo of
// retryAfter (queueFullError), so the client backs off and sends the export
// again.
// An export larger than the whole queue could never be admitted, so it is
// dropped and counted instead, with InvalidArgument, which the client does
// not retry.
//
// The full queue's refusals are logged by the spell, not each: a WARN at the
// first and every queueFullRemind while they go on, and an INFO at the first
// export admitted queueFullQuiet after the latest. They are not counted, as
// the client sends the export again.
func (s *BridgeServer) enqueue(_ context.Context, signal string, isIngest bool, payloads [][]byte, contentType string) error {
	if len(payloads) == 0 {
		// Nothing to queue, as when every point of a metrics export was
		// dropped: admitting it would end a spell of refusals while the
		// queue is still full.
		return nil
	}
	var bytes int64
	for _, p := range payloads {
		bytes += int64(len(p))
	}
	if len(payloads) > cap(s.msgCh) || bytes > s.maxPendingBytes {
		s.dropped.add(signal, reasonTooLarge, 1)
		s.logger.Warn("OTLP export is larger than the whole pending queue, dropping it",
			"signal", signal, "messages", len(payloads), "bytes", bytes,
			"max_pending_messages", cap(s.msgCh), "max_pending_bytes", s.maxPendingBytes)
		return status.Errorf(codes.InvalidArgument, "%s export of %d messages and %d bytes exceeds the bridge's pending queue; dropped", signal, len(payloads), bytes)
	}
	// The lines refuse and endRefusals return are written once queueMu is
	// released, so logging never holds up the queue. Lines of two spells
	// can then be written out of order; their spell number pairs them.
	s.queueMu.Lock()
	if s.pending+len(payloads) > cap(s.msgCh) || s.pendingBytes+bytes > s.maxPendingBytes {
		warn := s.refuse(signal, len(payloads), bytes)
		s.queueMu.Unlock()
		if warn != nil {
			warn()
		}
		return s.queueFullError()
	}
	s.pending += len(payloads)
	s.pendingBytes += bytes
	for _, p := range payloads {
		s.msgCh <- pendingPublish{signal: signal, isIngest: isIngest, payload: p, contentType: contentType}
	}
	ended := s.endRefusals()
	s.queueMu.Unlock()
	if ended != nil {
		ended()
	}
	return nil
}

// refuse records a refusal for a full queue of an export of messages and
// bytes, under queueMu. It returns the spell's WARN when the refusal starts
// a spell or the spell was last logged queueFullRemind ago, nil otherwise.
func (s *BridgeServer) refuse(signal string, messages int, bytes int64) func() {
	now := s.now()
	if s.refusals == 0 {
		s.spell++
		s.firstRefusal = now
	}
	s.refusals++
	s.lastRefusal = now
	if s.refusals > 1 && now.Sub(s.lastWarned) < queueFullRemind {
		return nil
	}
	s.lastWarned = now
	spell, refusals, first, pending, pendingBytes := s.spell, s.refusals, s.firstRefusal, s.pending, s.pendingBytes
	return func() {
		s.logger.Warn("OTLP pending queue is full, refusing exports until it has room",
			"signal", signal, "messages", messages, "bytes", bytes,
			"pending_messages", pending, "pending_bytes", pendingBytes,
			"max_pending_messages", cap(s.msgCh), "max_pending_bytes", s.maxPendingBytes,
			"retry_after", s.retryAfter.String(),
			"spell", spell, "refusals", refusals, "first_refusal", logTime(first))
	}
}

// endRefusals ends the spell of refusals, under queueMu, when an export is
// admitted queueFullQuiet or more after its latest refusal, and returns the
// spell's INFO; nil when there is no spell or it goes on.
func (s *BridgeServer) endRefusals() func() {
	if s.refusals == 0 || s.now().Sub(s.lastRefusal) < queueFullQuiet {
		return nil
	}
	spell, refusals, first, last := s.spell, s.refusals, s.firstRefusal, s.lastRefusal
	s.refusals = 0
	return func() {
		s.logger.Info("OTLP pending queue has room again, accepting exports",
			"spell", spell, "refusals", refusals,
			"first_refusal", logTime(first), "last_refusal", logTime(last))
	}
}

// logTime is t as a log attribute: RFC 3339 in UTC, which reads the same in
// the agent's own log and in its copy exported over OTLP, where a time
// becomes a count of nanoseconds.
func logTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// queueFullError is the refusal of an export the queue has no room for:
// ResourceExhausted, with a RetryInfo asking the client to wait retryAfter.
// The OTLP exporters retry ResourceExhausted only when it carries a
// RetryInfo; without one, an export refused once is lost.
func (s *BridgeServer) queueFullError() error {
	refused := status.New(codes.ResourceExhausted, "OTLP pending queue is full")
	withDelay, err := refused.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(s.retryAfter)})
	if err != nil {
		return refused.Err()
	}
	return withDelay.Err()
}

// release returns a payload's room to the queue as the writer takes it.
func (s *BridgeServer) release(msg pendingPublish) {
	s.queueMu.Lock()
	s.pending--
	s.pendingBytes -= int64(len(msg.payload))
	s.queueMu.Unlock()
}

// GetIngestTopic returns the current ingest topic.
func (s *BridgeServer) GetIngestTopic() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ingestTopic
}

// GetTelemetryTopic returns the current telemetry topic.
func (s *BridgeServer) GetTelemetryTopic() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.telemetryTopic
}

// ListenAddr returns the bound OTLP/gRPC address, or "" before Start.
func (s *BridgeServer) ListenAddr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// HTTPListenAddr returns the bound OTLP/HTTP address, or "" when disabled or before Start.
func (s *BridgeServer) HTTPListenAddr() string {
	if s.httpListener == nil {
		return ""
	}
	return s.httpListener.Addr().String()
}

// GetPolicyRepo returns the policy repo (for handlers).
func (s *BridgeServer) GetPolicyRepo() policies.PolicyRepo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policyRepo
}

// Start starts the OTLP/gRPC server and, when HTTPListenAddr is set, the
// OTLP/HTTP server, without establishing MQTT. Publisher and topic should be
// set before OTLP data arrives.
func (s *BridgeServer) Start(ctx context.Context) error {
	// Platform-specific socket configuration (SO_REUSEADDR on Unix for faster port reuse)
	lis, err := listen(ctx, s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (port may be in use by another service): %w", s.cfg.ListenAddr, err)
	}
	s.listener = lis

	// Above the message cap on purpose: a large export is split, not
	// refused.
	s.ingestGRPCServer = grpc.NewServer(grpc.MaxRecvMsgSize(maxReceiveBytes))

	// Register services with the bridge
	collectortrace.RegisterTraceServiceServer(s.ingestGRPCServer, &traceServer{bridge: s})
	collectormetrics.RegisterMetricsServiceServer(s.ingestGRPCServer, &metricsServer{bridge: s})
	collectorlogs.RegisterLogsServiceServer(s.ingestGRPCServer, &logsServer{bridge: s})

	go func() {
		if err := s.ingestGRPCServer.Serve(lis); err != nil {
			s.logger.Error("failed to serve gRPC server", "error", err)
		}
	}()

	if s.cfg.HTTPListenAddr != "" {
		if err := s.startHTTP(ctx); err != nil {
			return err
		}
	}
	s.logger.Info("OTLP bridge server started", "grpc_addr", lis.Addr().String(), "http_enabled", s.httpListener != nil)
	return nil
}

// startHTTP binds the OTLP/HTTP listener and serves the export endpoints.
func (s *BridgeServer) startHTTP(ctx context.Context) error {
	lis, err := listen(ctx, s.cfg.HTTPListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (port may be in use by another service): %w", s.cfg.HTTPListenAddr, err)
	}
	s.httpListener = lis
	s.httpServer = &http.Server{
		Handler:           s.otlpHTTPHandler(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		IdleTimeout:       httpIdleTimeout,
		ErrorLog:          slog.NewLogLogger(s.logger.Handler(), slog.LevelWarn),
	}
	go func() {
		if err := s.httpServer.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("failed to serve OTLP HTTP server", "error", err)
		}
	}()
	s.logger.Info("OTLP bridge HTTP listener started", "http_addr", lis.Addr().String())
	return nil
}

// Stop gracefully shuts down the server.
func (s *BridgeServer) Stop(_ context.Context) error {
	s.closeOnce.Do(func() {
		// Drain in-flight requests on both transports first so no Export
		// handler enqueues after the writer goroutine exits, then cancel the
		// writer context; anything still queued at that point is abandoned.
		if s.httpServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
			if shutdownErr := s.httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				// A stalled client kept a handler busy past the deadline; force
				// the connections closed so nothing outlives Stop.
				s.logger.Warn("OTLP HTTP server did not drain in time, closing connections", "error", shutdownErr)
				_ = s.httpServer.Close()
			}
			cancel()
		}
		if s.ingestGRPCServer != nil {
			s.ingestGRPCServer.GracefulStop()
		}
		if s.cancel != nil {
			s.cancel()
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
		if s.httpListener != nil {
			_ = s.httpListener.Close()
		}
	})
	return nil
}
