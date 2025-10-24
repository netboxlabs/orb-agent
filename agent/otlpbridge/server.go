package otlpbridge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
)

// BridgeServer holds the lifecycle for the OTLP → MQTT bridge server.
type BridgeServer struct {
	cfg       BridgeConfig
	enc       Encoder
	pub       *MQTTPublisher
	grpcSrv   *grpc.Server
	listener  net.Listener
	closeOnce sync.Once
}

// NewBridgeServer builds a BridgeServer but does not start it.
func NewBridgeServer(cfg BridgeConfig) (*BridgeServer, error) {
	enc, err := buildEncoder(cfg.Encoding)
	if err != nil {
		return nil, err
	}
	return &BridgeServer{cfg: cfg, enc: enc}, nil
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

// Start starts MQTT connection and gRPC server.
func (s *BridgeServer) Start(ctx context.Context) error {
	pub, err := NewMQTTPublisher(ctx, s.cfg.MQTTURL, s.cfg.MQTTJWT)
	if err != nil {
		return err
	}
	s.pub = pub

	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		_ = s.pub.Close(ctx)
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = lis

	s.grpcSrv = grpc.NewServer()

	// Register services
	collectortrace.RegisterTraceServiceServer(s.grpcSrv, &traceServer{enc: s.enc, pub: s.pub, topic: s.cfg.TracesTopic})
	collectormetrics.RegisterMetricsServiceServer(s.grpcSrv, &metricsServer{enc: s.enc, pub: s.pub, topic: s.cfg.MetricsTopic})
	collectorlogs.RegisterLogsServiceServer(s.grpcSrv, &logsServer{enc: s.enc, pub: s.pub, topic: s.cfg.LogsTopic})

	go func() {
		_ = s.grpcSrv.Serve(lis)
	}()
	return nil
}

// Stop gracefully shuts down the server and MQTT connection.
func (s *BridgeServer) Stop(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		if s.grpcSrv != nil {
			s.grpcSrv.GracefulStop()
		}
		if s.pub != nil {
			if e := s.pub.Close(ctx); e != nil && err == nil {
				err = e
			}
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
	return err
}
