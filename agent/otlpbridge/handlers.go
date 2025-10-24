package otlpbridge

import (
	"context"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// Trace service handler
type traceServer struct {
	enc   Encoder
	pub   Publisher
	topic string
	collectortrace.UnimplementedTraceServiceServer
}

func (s *traceServer) Export(ctx context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	payload, err := s.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := s.pub.Publish(ctx, s.topic, payload); err != nil {
		return nil, err
	}
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

// Metrics service handler
type metricsServer struct {
	enc   Encoder
	pub   Publisher
	topic string
	collectormetrics.UnimplementedMetricsServiceServer
}

func (s *metricsServer) Export(ctx context.Context, req *collectormetrics.ExportMetricsServiceRequest) (*collectormetrics.ExportMetricsServiceResponse, error) {
	payload, err := s.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := s.pub.Publish(ctx, s.topic, payload); err != nil {
		return nil, err
	}
	return &collectormetrics.ExportMetricsServiceResponse{}, nil
}

// Logs service handler
type logsServer struct {
	enc   Encoder
	pub   Publisher
	topic string
	collectorlogs.UnimplementedLogsServiceServer
}

func (s *logsServer) Export(ctx context.Context, req *collectorlogs.ExportLogsServiceRequest) (*collectorlogs.ExportLogsServiceResponse, error) {
	payload, err := s.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := s.pub.Publish(ctx, s.topic, payload); err != nil {
		return nil, err
	}
	return &collectorlogs.ExportLogsServiceResponse{}, nil
}
