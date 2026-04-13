package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

const (
	defaultMaxPendingQueue = 1000
	initialRetryBackoff    = 2 * time.Second
	maxRetryBackoff        = 30 * time.Second
)

// pendingPublish holds a marshaled OTLP payload queued before the MQTT publisher was ready.
type pendingPublish struct {
	isIngest bool
	payload  []byte
}

// BridgeServer holds the lifecycle for the OTLP → MQTT bridge server.
type BridgeServer struct {
	cfg              BridgeConfig
	enc              Encoder
	ingestGRPCServer *grpc.Server
	listener         net.Listener
	closeOnce        sync.Once

	// Shared runtime state — publisher and topics are set by the OnReadyHook
	// after the MQTT connection is established.
	mu             sync.RWMutex
	publisher      Publisher
	ingestTopic    string
	telemetryTopic string
	policyRepo     policies.PolicyRepo
	logger         *slog.Logger

	// Lifecycle context — cancelled by Stop() to unblock in-flight drains and
	// scheduled retry goroutines.
	ctx    context.Context
	cancel context.CancelFunc

	// Pending publish queue — messages received before MQTT is ready are held
	// here and drained once publisher + topics are all set.
	pendingMu      sync.Mutex
	pending        []pendingPublish
	ready          bool
	draining       bool
	maxPending     int
	pendingDropped int64
	retryBackoff   time.Duration
}

// NewBridgeServer builds a BridgeServer but does not start it.
func NewBridgeServer(cfg BridgeConfig, policyRepo policies.PolicyRepo, logger *slog.Logger) (*BridgeServer, error) {
	enc, err := buildEncoder(cfg.Encoding)
	if err != nil {
		return nil, err
	}
	maxPending := cfg.MaxPendingQueue
	if maxPending <= 0 {
		maxPending = defaultMaxPendingQueue
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &BridgeServer{cfg: cfg, enc: enc, policyRepo: policyRepo, logger: logger, maxPending: maxPending, ctx: ctx, cancel: cancel}, nil
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
	s.checkReady()
}

// SetIngestTopic sets the topic for publishing.
func (s *BridgeServer) SetIngestTopic(topic string) {
	s.mu.Lock()
	s.ingestTopic = topic
	s.mu.Unlock()
	s.checkReady()
}

// SetTelemetryTopic sets the telemetry topic for publishing.
func (s *BridgeServer) SetTelemetryTopic(topic string) {
	s.mu.Lock()
	s.telemetryTopic = topic
	s.mu.Unlock()
	s.checkReady()
}

// ClearPublisher clears the publisher and marks the bridge as not ready,
// causing Enqueue to buffer messages until a new publisher is set via
// SetPublisher. Call this before MQTT disconnect/reconnect to prevent
// publish failures during the reconnect window.
func (s *BridgeServer) ClearPublisher() {
	for {
		s.pendingMu.Lock()
		if s.draining {
			s.pendingMu.Unlock()
			time.Sleep(time.Millisecond)
			continue
		}

		// Prevent new drains from starting while transitioning the bridge back
		// to the not-ready state, then clear the publisher.
		s.ready = false
		s.retryBackoff = 0

		s.mu.Lock()
		s.publisher = nil
		s.mu.Unlock()

		s.pendingMu.Unlock()
		return
	}
}

// checkReady checks whether publisher and both topics are set. If so, it drains
// any pending messages that were queued before the MQTT connection was ready.
func (s *BridgeServer) checkReady() {
	s.mu.RLock()
	allSet := s.publisher != nil && s.ingestTopic != "" && s.telemetryTopic != ""
	s.mu.RUnlock()
	if allSet {
		s.drainPending()
	}
}

// publishBatch publishes a slice of pending messages. On failure it re-queues the
// remaining messages (including the one that failed) and clears the draining flag.
// Returns true if all messages were published, false if a failure occurred.
func (s *BridgeServer) publishBatch(pub Publisher, msgs []pendingPublish, ingest, telemetry string, published *int) bool {
	for i, msg := range msgs {
		topic := telemetry
		if msg.isIngest {
			topic = ingest
		}
		if err := pub.Publish(s.ctx, topic, msg.payload); err != nil {
			if s.logger != nil {
				s.logger.Warn("publish failed during drain, re-queuing remaining messages",
					"published", *published, "remaining", len(msgs)-i, "error", err)
			}
			s.pendingMu.Lock()
			s.pending = append(msgs[i:], s.pending...)
			// Enforce the bounded-buffer guarantee: if the combined re-queued
			// batch + newly arrived messages exceeds maxPending, truncate to
			// cap. We keep the oldest (head) to preserve FIFO ordering —
			// consistent with Enqueue rejecting new messages when full.
			if s.maxPending > 0 && len(s.pending) > s.maxPending {
				excess := len(s.pending) - s.maxPending
				s.pending = s.pending[:s.maxPending]
				s.pendingDropped += int64(excess)
				if s.logger != nil {
					s.logger.Warn("truncated re-queued pending messages to maxPending",
						"max_pending", s.maxPending, "dropped", excess)
				}
			}
			s.draining = false
			s.pendingMu.Unlock()
			return false
		}
		(*published)++
	}
	return true
}

// drainPending flushes queued messages and marks the bridge as ready for direct
// publishing. Must only be called when publisher + topics are set.
// Ready is set *after* the drain completes so that concurrent Enqueue calls
// continue to queue (preserving FIFO order) until the backlog is flushed.
func (s *BridgeServer) drainPending() {
	s.pendingMu.Lock()
	if s.ready || s.draining {
		s.pendingMu.Unlock()
		return
	}
	s.draining = true
	queued := s.pending
	dropped := s.pendingDropped
	s.pending = nil
	s.pendingDropped = 0
	s.pendingMu.Unlock()

	s.mu.RLock()
	pub := s.publisher
	ingest := s.ingestTopic
	telemetry := s.telemetryTopic
	s.mu.RUnlock()

	// Guard against ClearPublisher() racing between setting draining=true and
	// here. Re-queue everything and let the next SetPublisher → checkReady
	// cycle re-trigger the drain.
	if pub == nil {
		s.pendingMu.Lock()
		s.pending = append(queued, s.pending...)
		if s.maxPending > 0 && len(s.pending) > s.maxPending {
			excess := len(s.pending) - s.maxPending
			s.pending = s.pending[:s.maxPending]
			s.pendingDropped += int64(excess)
		}
		s.draining = false
		s.pendingMu.Unlock()
		return
	}

	published := 0
	if !s.publishBatch(pub, queued, ingest, telemetry, &published) {
		s.scheduleRetryDrain()
		return
	}

	// Drain anything that arrived while we were flushing, then mark ready.
	s.pendingMu.Lock()
	for len(s.pending) > 0 {
		extra := s.pending
		dropped += s.pendingDropped
		s.pending = nil
		s.pendingDropped = 0
		s.pendingMu.Unlock()

		if !s.publishBatch(pub, extra, ingest, telemetry, &published) {
			s.scheduleRetryDrain()
			return
		}
		s.pendingMu.Lock()
	}
	s.draining = false
	s.ready = true
	s.retryBackoff = 0
	s.pendingMu.Unlock()

	if s.logger != nil && published > 0 {
		s.logger.Info("drained pending OTLP messages", "count", published, "dropped_while_pending", dropped)
	}
}

// scheduleRetryDrain re-triggers drainPending after a delay so that messages
// re-queued by a failed publishBatch are not stuck indefinitely. Uses
// exponential backoff (capped at maxRetryBackoff) and respects the server's
// lifecycle context so pending retries are cancelled on Stop().
func (s *BridgeServer) scheduleRetryDrain() {
	s.pendingMu.Lock()
	backoff := s.retryBackoff
	if backoff == 0 {
		backoff = initialRetryBackoff
	}
	s.retryBackoff = min(backoff*2, maxRetryBackoff)
	s.pendingMu.Unlock()

	go func() {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff):
			s.drainPending()
		}
	}()
}

// Enqueue marshaled OTLP data for publishing. Before the MQTT connection is
// ready the payload is queued in memory (up to maxPending messages). When the
// queue is full, new messages are rejected with ResourceExhausted so the OTLP
// client can back off and retry. Once ready, publishes directly.
func (s *BridgeServer) Enqueue(ctx context.Context, isIngest bool, payload []byte) error {
	s.pendingMu.Lock()
	if !s.ready {
		if s.maxPending > 0 && len(s.pending) >= s.maxPending {
			s.pendingDropped++
			if s.logger != nil && (s.pendingDropped == 1 || s.pendingDropped%100 == 0) {
				s.logger.Warn("pending OTLP queue full, rejecting message",
					"max_pending", s.maxPending, "total_dropped", s.pendingDropped)
			}
			s.pendingMu.Unlock()
			return status.Error(codes.ResourceExhausted, "OTLP pending queue is full")
		}
		s.pending = append(s.pending, pendingPublish{isIngest: isIngest, payload: payload})
		s.pendingMu.Unlock()
		return nil
	}
	s.pendingMu.Unlock()

	s.mu.RLock()
	pub := s.publisher
	topic := s.telemetryTopic
	if isIngest {
		topic = s.ingestTopic
	}
	s.mu.RUnlock()

	// Guard against ClearPublisher() racing between the ready check above and
	// the mu.RLock here. If publisher was cleared, buffer instead of panicking.
	if pub == nil {
		s.pendingMu.Lock()
		if s.maxPending > 0 && len(s.pending) >= s.maxPending {
			s.pendingDropped++
			s.pendingMu.Unlock()
			return status.Error(codes.ResourceExhausted, "OTLP pending queue is full")
		}
		s.pending = append(s.pending, pendingPublish{isIngest: isIngest, payload: payload})
		s.pendingMu.Unlock()
		return nil
	}

	return pub.Publish(ctx, topic, payload)
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

// GetPolicyRepo returns the policy repo (for handlers).
func (s *BridgeServer) GetPolicyRepo() policies.PolicyRepo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policyRepo
}

// Start starts the gRPC server without establishing MQTT.
// Publisher and topic should be set before OTLP data arrives.
func (s *BridgeServer) Start(ctx context.Context) error {
	// Platform-specific socket configuration (SO_REUSEADDR on Unix for faster port reuse)
	lis, err := listen(ctx, s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (port may be in use by another service): %w", s.cfg.ListenAddr, err)
	}
	s.listener = lis

	s.ingestGRPCServer = grpc.NewServer()

	// Register services with the bridge
	collectortrace.RegisterTraceServiceServer(s.ingestGRPCServer, &traceServer{bridge: s})
	collectormetrics.RegisterMetricsServiceServer(s.ingestGRPCServer, &metricsServer{bridge: s})
	collectorlogs.RegisterLogsServiceServer(s.ingestGRPCServer, &logsServer{bridge: s})

	go func() {
		if err := s.ingestGRPCServer.Serve(lis); err != nil {
			s.logger.Error("failed to serve gRPC server", "error", err)
		}
	}()
	s.logger.Info("OTLP bridge server started")
	return nil
}

// Stop gracefully shuts down the server.
func (s *BridgeServer) Stop(_ context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		// Cancel the lifecycle context first to unblock in-flight drains
		// and scheduled retry goroutines.
		if s.cancel != nil {
			s.cancel()
		}
		if s.ingestGRPCServer != nil {
			s.ingestGRPCServer.GracefulStop()
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
	return err
}
