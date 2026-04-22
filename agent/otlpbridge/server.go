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
	maxPublishRetries      = 10
)

// pendingPublish holds a marshaled OTLP payload queued for publishing.
type pendingPublish struct {
	isIngest bool
	payload  []byte
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
	ingestGRPCServer *grpc.Server
	listener         net.Listener
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

	// initialBackoff is the starting retry delay used by the writer goroutine.
	// Defaults to initialRetryBackoff; tests override it for speed.
	initialBackoff time.Duration
}

// NewBridgeServer builds a BridgeServer and starts its writer goroutine.
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
	s := &BridgeServer{
		cfg:            cfg,
		enc:            enc,
		policyRepo:     policyRepo,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
		msgCh:          make(chan pendingPublish, maxPending),
		initialBackoff: initialRetryBackoff,
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
			s.publishWithRetry(msg)
		case <-s.ctx.Done():
			return
		}
	}
}

// publishWithRetry publishes a single message, retrying with exponential
// backoff when no publisher is available or a publish call fails. Only
// actual publish failures count toward the retry budget; waiting for
// publisher/topic readiness does not consume attempts.
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
			err := pub.Publish(s.ctx, topic, msg.payload)
			if err == nil {
				return
			}
			failures++
			s.logger.Warn("OTLP publish failed, retrying", "error", err, "attempt", failures, "backoff", backoff)
			if failures >= maxPublishRetries {
				s.logger.Warn("OTLP publish retries exhausted, dropping message", "max_retries", maxPublishRetries)
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

// Enqueue adds a marshaled OTLP payload to the publish queue. Returns
// ResourceExhausted if the queue is full, providing backpressure to the
// OTLP client.
func (s *BridgeServer) Enqueue(_ context.Context, isIngest bool, payload []byte) error {
	select {
	case s.msgCh <- pendingPublish{isIngest: isIngest, payload: payload}:
		return nil
	default:
		return status.Error(codes.ResourceExhausted, "OTLP pending queue is full")
	}
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
		// Drain in-flight RPCs first so no Export handler enqueues after the
		// writer goroutine exits. GracefulStop blocks until all active RPCs
		// complete, then we cancel the writer context to flush remaining items.
		if s.ingestGRPCServer != nil {
			s.ingestGRPCServer.GracefulStop()
		}
		if s.cancel != nil {
			s.cancel()
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
	return err
}
