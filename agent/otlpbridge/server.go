package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

const defaultMaxPendingQueue = 1000

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

	// Pending publish queue — messages received before MQTT is ready are held
	// here and drained once publisher + topics are all set.
	pendingMu      sync.Mutex
	pending        []pendingPublish
	ready          bool
	maxPending     int
	pendingDropped int64
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
	return &BridgeServer{cfg: cfg, enc: enc, policyRepo: policyRepo, logger: logger, maxPending: maxPending}, nil
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

// drainPending flushes queued messages and marks the bridge as ready for direct
// publishing. Must only be called when publisher + topics are set.
func (s *BridgeServer) drainPending() {
	s.pendingMu.Lock()
	s.ready = true
	queued := s.pending
	dropped := s.pendingDropped
	s.pending = nil
	s.pendingDropped = 0
	s.pendingMu.Unlock()

	if len(queued) == 0 {
		return
	}

	s.mu.RLock()
	pub := s.publisher
	ingest := s.ingestTopic
	telemetry := s.telemetryTopic
	s.mu.RUnlock()

	for _, msg := range queued {
		topic := telemetry
		if msg.isIngest {
			topic = ingest
		}
		if err := pub.Publish(context.Background(), topic, msg.payload); err != nil {
			if s.logger != nil {
				s.logger.Warn("failed to publish queued OTLP data", "topic", topic, "error", err)
			}
		}
	}

	if s.logger != nil {
		s.logger.Info("drained pending OTLP messages", "count", len(queued), "dropped_while_pending", dropped)
	}
}

// Enqueue marshaled OTLP data for publishing. Before the MQTT connection is
// ready the payload is queued in memory (up to maxPending messages; oldest
// messages are dropped when the queue is full). Once ready, publishes directly.
func (s *BridgeServer) Enqueue(ctx context.Context, isIngest bool, payload []byte) error {
	s.pendingMu.Lock()
	if !s.ready {
		if s.maxPending > 0 && len(s.pending) >= s.maxPending {
			s.pendingDropped++
			if s.logger != nil {
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
		if s.ingestGRPCServer != nil {
			s.ingestGRPCServer.GracefulStop()
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
	return err
}
