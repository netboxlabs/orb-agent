package otlpbridge

import (
	"context"
	"testing"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

type fakePublisher struct {
	topic   string
	payload []byte
}

func (f *fakePublisher) Publish(_ context.Context, topic string, payload []byte) error {
	f.topic = topic
	f.payload = append([]byte(nil), payload...)
	return nil
}

func TestTraceHandler_Export_Publishes(t *testing.T) {
	fp := &fakePublisher{}
	bridge := &BridgeServer{
		enc: ProtobufEncoder{},
	}
	bridge.SetPublisher(fp)
	bridge.SetTopic("traces")
	s := &traceServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectortrace.ExportTraceServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "traces" {
		t.Fatalf("unexpected topic: %s", fp.topic)
	}
	// Verify that Publish was called (topic should be set)
	// Empty requests produce empty or nil payloads, which is expected
}

func TestMetricsHandler_Export_Publishes(t *testing.T) {
	fp := &fakePublisher{}
	bridge := &BridgeServer{
		enc: ProtobufEncoder{},
	}
	bridge.SetPublisher(fp)
	bridge.SetTopic("metrics")
	s := &metricsServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectormetrics.ExportMetricsServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "metrics" {
		t.Fatalf("unexpected topic: %s", fp.topic)
	}
	// Verify that Publish was called (topic should be set)
	// Empty requests produce empty or nil payloads, which is expected
}

func TestLogsHandler_Export_Publishes(t *testing.T) {
	fp := &fakePublisher{}
	bridge := &BridgeServer{
		enc: ProtobufEncoder{},
	}
	bridge.SetPublisher(fp)
	bridge.SetTopic("logs")
	s := &logsServer{bridge: bridge}
	_, err := s.Export(context.Background(), &collectorlogs.ExportLogsServiceRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp.topic != "logs" {
		t.Fatalf("unexpected topic: %s", fp.topic)
	}
	// Verify that Publish was called (topic should be set)
	// Empty requests produce empty or nil payloads, which is expected
}
