package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// BridgeServer holds the lifecycle for the OTLP → MQTT bridge server.
type BridgeServer struct {
	cfg              BridgeConfig
	enc              Encoder
	ingestGRPCServer *grpc.Server
	listener         net.Listener
	closeOnce        sync.Once

	// Shared runtime state
	mu             sync.RWMutex
	publisher      Publisher
	ingestTopic    string
	telemetryTopic string
	policyRepo     policies.PolicyRepo
	logger         *slog.Logger
}

// NewBridgeServer builds a BridgeServer but does not start it.
func NewBridgeServer(cfg BridgeConfig, policyRepo policies.PolicyRepo, logger *slog.Logger) (*BridgeServer, error) {
	enc, err := buildEncoder(cfg.Encoding)
	if err != nil {
		return nil, err
	}
	return &BridgeServer{cfg: cfg, enc: enc, policyRepo: policyRepo, logger: logger}, nil
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
	defer s.mu.Unlock()
	s.publisher = pub
}

// SetIngestTopic sets the topic for publishing.
func (s *BridgeServer) SetIngestTopic(topic string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ingestTopic = topic
}

// GetPublisher returns the current publisher (for handlers).
func (s *BridgeServer) GetPublisher() Publisher {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publisher
}

// GetIngestTopic returns the current topic (for handlers).
func (s *BridgeServer) GetIngestTopic() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ingestTopic
}

// SetTelemetryTopic sets the telemetry topic for publishing.
func (s *BridgeServer) SetTelemetryTopic(topic string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telemetryTopic = topic
}

// GetTelemetryTopic returns the current telemetry topic (for handlers).
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
	// Use ListenConfig to enable SO_REUSEADDR for faster port reuse after restart
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockOptErr error
			if err := c.Control(func(fd uintptr) {
				// Enable SO_REUSEADDR to allow binding to TIME_WAIT sockets
				sockOptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return sockOptErr
		},
	}
	lis, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr)
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
		err := s.ingestGRPCServer.Serve(lis)
		if err != nil {
			s.logger.Error("failed to serve gRPC server", "error", err)
		} else {
			s.logger.Info("OTLP bridge server started")
		}
	}()
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
