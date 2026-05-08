package otlpbridge

import (
	"context"
	"log/slog"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

const diodePolicyNameAttributeKey = "diode.metadata.policy_name"

// isIngestRequest reports whether any of the provided resources carry the
// diode.metadata.policy_name attribute, indicating the payload is Diode data
// that should be routed to the ingest topic rather than the telemetry topic.
func isIngestRequest(resources []*resourcev1.Resource) bool {
	for _, r := range resources {
		if r == nil {
			continue
		}
		for _, attr := range r.Attributes {
			if attr != nil && attr.Key == diodePolicyNameAttributeKey && attr.Value != nil {
				return true
			}
		}
	}
	return false
}

// Trace service handler
type traceServer struct {
	bridge *BridgeServer
	collectortrace.UnimplementedTraceServiceServer
}

func (s *traceServer) Export(ctx context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	resources := make([]*resourcev1.Resource, 0, len(req.ResourceSpans))
	for _, rs := range req.ResourceSpans {
		if rs != nil {
			resources = append(resources, rs.Resource)
		}
	}

	payload, err := s.bridge.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := s.bridge.Enqueue(ctx, isIngestRequest(resources), payload); err != nil {
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
	resources := make([]*resourcev1.Resource, 0, len(req.ResourceMetrics))
	for _, rm := range req.ResourceMetrics {
		if rm != nil {
			resources = append(resources, rm.Resource)
		}
	}

	payload, err := s.bridge.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := s.bridge.Enqueue(ctx, isIngestRequest(resources), payload); err != nil {
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
	isIngest := s.isIngestRequest(req)
	if isIngest {
		repo := s.bridge.GetPolicyRepo()
		enrichLogsWithDatasets(req, repo)
		s.bridge.logger.Debug("ingesting enriched logs with dataset_ids", "request", req)
	}

	payload, err := s.bridge.enc.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := s.bridge.Enqueue(ctx, isIngest, payload); err != nil {
		return nil, err
	}
	return &collectorlogs.ExportLogsServiceResponse{}, nil
}

// isIngestRequest checks if the request contains a policy_name attribute in
// resource attributes or, for backward compatibility, in scope attributes.
func (s *logsServer) isIngestRequest(req *collectorlogs.ExportLogsServiceRequest) bool {
	resources := make([]*resourcev1.Resource, 0, len(req.ResourceLogs))
	for _, rl := range req.ResourceLogs {
		if rl != nil {
			resources = append(resources, rl.Resource)
		}
	}
	if isIngestRequest(resources) {
		return true
	}
	// Backward compatibility: also check ScopeLogs attributes.
	for _, rl := range req.ResourceLogs {
		if rl == nil {
			continue
		}
		for _, sl := range rl.ScopeLogs {
			if sl == nil || sl.Scope == nil || sl.Scope.Attributes == nil {
				continue
			}
			for _, attr := range sl.Scope.Attributes {
				if attr != nil && attr.Key == diodePolicyNameAttributeKey && attr.Value != nil {
					return true
				}
			}
		}
	}
	return false
}

// enrichLogsWithDatasets adds dataset_ids to ScopeLogs attributes based on policy_name.
func enrichLogsWithDatasets(req *collectorlogs.ExportLogsServiceRequest, repo policies.PolicyRepo) {
	for _, rl := range req.ResourceLogs {
		if rl == nil {
			continue
		}

		// Find policy_name attribute in Resource attributes first
		policyName := ""
		if rl.Resource != nil && rl.Resource.Attributes != nil {
			for _, attr := range rl.Resource.Attributes {
				if attr != nil && attr.Key == diodePolicyNameAttributeKey && attr.Value != nil {
					if sv := attr.Value.GetStringValue(); sv != "" {
						policyName = sv
						break
					}
				}
			}
		}

		for _, sl := range rl.ScopeLogs {
			if sl == nil || sl.Scope == nil || sl.Scope.Attributes == nil {
				continue
			}

			// If not found in Resource, check Scope attributes for backward compatibility
			if policyName == "" {
				for _, attr := range sl.Scope.Attributes {
					if attr != nil && attr.Key == diodePolicyNameAttributeKey && attr.Value != nil {
						if sv := attr.Value.GetStringValue(); sv != "" {
							policyName = sv
							break
						}
					}
				}
			}

			if policyName == "" {
				continue
			}

			// Lookup policy and get dataset IDs
			policy, err := repo.GetByName(policyName)
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
