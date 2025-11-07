package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
)

// Trace service handler
type traceServer struct {
	bridge *BridgeServer
	collectortrace.UnimplementedTraceServiceServer
}

func (s *traceServer) Export(ctx context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	pub := s.bridge.GetPublisher()
	if pub == nil {
		return nil, fmt.Errorf("publisher not yet initialized")
	}
	topic := s.bridge.GetIngestTopic()
	if topic == "" {
		return nil, fmt.Errorf("topic not yet initialized")
	}

	payload, err := s.bridge.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := pub.Publish(ctx, topic, payload); err != nil {
		return nil, err
	}
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

// Metrics service handler
type metricsServer struct {
	bridge *BridgeServer
	collectormetrics.UnimplementedMetricsServiceServer
}

func (s *metricsServer) Export(ctx context.Context, req *collectormetrics.ExportMetricsServiceRequest) (*collectormetrics.ExportMetricsServiceResponse, error) {
	pub := s.bridge.GetPublisher()
	if pub == nil {
		return nil, fmt.Errorf("publisher not yet initialized")
	}
	topic := s.bridge.GetIngestTopic()
	if topic == "" {
		return nil, fmt.Errorf("topic not yet initialized")
	}

	payload, err := s.bridge.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := pub.Publish(ctx, topic, payload); err != nil {
		return nil, err
	}
	return &collectormetrics.ExportMetricsServiceResponse{}, nil
}

// Logs service handler
type logsServer struct {
	bridge *BridgeServer
	collectorlogs.UnimplementedLogsServiceServer
}

func (s *logsServer) Export(ctx context.Context, req *collectorlogs.ExportLogsServiceRequest) (*collectorlogs.ExportLogsServiceResponse, error) {
	pub := s.bridge.GetPublisher()
	if pub == nil {
		return nil, fmt.Errorf("publisher not yet initialized")
	}
	topic := s.bridge.GetIngestTopic()
	if topic == "" {
		return nil, fmt.Errorf("topic not yet initialized")
	}
	repo := s.bridge.GetPolicyRepo()

	// Enrich logs with dataset_ids based on policy_name
	if repo != nil {
		enrichLogsWithDatasets(req, repo)
	}

	payload, err := s.bridge.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := pub.Publish(ctx, topic, payload); err != nil {
		return nil, err
	}
	return &collectorlogs.ExportLogsServiceResponse{}, nil
}

// enrichLogsWithDatasets adds dataset_ids to ScopeLogs attributes based on policy_name.
func enrichLogsWithDatasets(req *collectorlogs.ExportLogsServiceRequest, repo interface{}) {
	// Type assertion to allow for easier future mocking if needed
	policyRepo, ok := repo.(interface {
		GetByName(policyName string) (interface {
			GetDatasetIDs() []string
		}, error)
	})
	if !ok {
		// If repo doesn't have the right interface, skip enrichment
		return
	}

	for _, rl := range req.ResourceLogs {
		if rl == nil {
			continue
		}
		for _, sl := range rl.ScopeLogs {
			if sl == nil || sl.Scope == nil || sl.Scope.Attributes == nil {
				continue
			}

			// Find policy_name attribute
			policyName := ""
			for _, attr := range sl.Scope.Attributes {
				if attr != nil && attr.Key == "policy_name" && attr.Value != nil {
					if sv := attr.Value.GetStringValue(); sv != "" {
						policyName = sv
						break
					}
				}
			}

			if policyName == "" {
				continue
			}

			// Lookup policy and get dataset IDs
			policy, err := policyRepo.GetByName(policyName)
			if err != nil {
				// Policy not found; skip enrichment for this scope
				slog.Debug("policy not found", "name", policyName, "error", err)
				continue
			}

			datasetIDs := policy.GetDatasetIDs()
			if len(datasetIDs) == 0 {
				continue
			}

			// Create dataset_ids attribute with array of strings
			datasetIDsValues := make([]*commonv1.AnyValue, len(datasetIDs))
			for i, id := range datasetIDs {
				datasetIDsValues[i] = &commonv1.AnyValue{
					Value: &commonv1.AnyValue_StringValue{
						StringValue: id,
					},
				}
			}

			// Create ArrayValue
			arrayAttr := &commonv1.AnyValue{
				Value: &commonv1.AnyValue_ArrayValue{
					ArrayValue: &commonv1.ArrayValue{
						Values: datasetIDsValues,
					},
				},
			}

			// Find or create dataset_ids attribute
			found := false
			for _, attr := range sl.Scope.Attributes {
				if attr != nil && attr.Key == "dataset_ids" {
					attr.Value = arrayAttr
					found = true
					break
				}
			}

			if !found {
				// Add new dataset_ids attribute
				sl.Scope.Attributes = append(sl.Scope.Attributes, &commonv1.KeyValue{
					Key:   "dataset_ids",
					Value: arrayAttr,
				})
			}
		}
	}
}
