package otlpbridge

import (
	"context"
	"log/slog"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// Export takes a traces export and publishes nothing: no pipeline on the
// platform reads traces, as orb-pro's telemetry enricher drops them from the
// telemetry topic and its OTLP Bridge reads the ingest topic as logs only.
func (s *traceServer) Export(_ context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	resources := make([]*resourcev1.Resource, 0, len(req.ResourceSpans))
	for _, rs := range req.ResourceSpans {
		if rs != nil {
			resources = append(resources, rs.Resource)
		}
	}
	s.bridge.discardUnread(signalTraces, resources)
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

// discardUnread takes a logs export that is not Diode data, or any traces
// export, and publishes nothing: the platform keeps none (orb-pro's
// telemetry enricher acknowledges logs and traces and drops them), so
// queueing one would only take room and bandwidth from metrics. The export
// is answered as accepted, so no exporter retries it or logs an error each
// time; it is counted as no_pipeline, and the first of each signal is logged
// at INFO with the service that sent it.
func (s *BridgeServer) discardUnread(signal string, resources []*resourcev1.Resource) {
	s.dropped.add(signal, reasonNoPipeline, 1)
	once, msg := &s.unreadTraces, "not publishing OTLP traces: the platform keeps none"
	if signal == signalLogs {
		once, msg = &s.unreadLogs, "not publishing OTLP logs that are not Diode data: the platform keeps none; set send_agent_logs to publish them"
	}
	once.Do(func() {
		s.logger.Info(msg, "signal", signal, "service_name", serviceName(resources))
	})
}

// serviceName is the service.name of the first resource that has one.
func serviceName(resources []*resourcev1.Resource) string {
	for _, r := range resources {
		if r == nil {
			continue
		}
		for _, attr := range r.Attributes {
			if attr != nil && attr.Key == "service.name" && attr.Value != nil {
				return attr.Value.GetStringValue()
			}
		}
	}
	return ""
}

// exportWhole publishes a logs export as one message in the ingest encoding.
// One over the most a message may carry, the message cap or, for Diode data,
// what the broker and the pending queue take (ingestCap), is dropped and
// counted, and the client is told with InvalidArgument, which the OTLP
// exporters do not retry: the same export would be over it again.
func (s *BridgeServer) exportWhole(ctx context.Context, signal string, isIngest bool, req ProtoMessage) error {
	payload, err := s.enc.Marshal(req)
	if err != nil {
		return err
	}
	contentType := s.enc.ContentType()
	topic := s.topicFor(isIngest)
	if isIngest {
		if limit := s.ingestCap(topic, contentType); len(payload) > limit {
			s.dropped.add(signal, reasonTooLarge, 1)
			s.logger.Warn("OTLP export of Diode data exceeds what the broker and the pending queue take, dropping it",
				"signal", signal, "bytes", len(payload), "limit", limit)
			return status.Errorf(codes.InvalidArgument, "%s export of Diode data of %d bytes exceeds the %d bytes the broker and the bridge's pending queue take; dropped", signal, len(payload), limit)
		}
	} else if limit := s.messageCap(topic, contentType); len(payload) > limit {
		s.dropped.add(signal, reasonTooLarge, 1)
		s.logger.Warn("OTLP export exceeds the message cap, dropping it", "signal", signal, "bytes", len(payload), "cap", limit)
		return status.Errorf(codes.InvalidArgument, "%s export of %d bytes exceeds the bridge's message cap of %d bytes; dropped", signal, len(payload), limit)
	}
	return s.enqueue(ctx, signal, isIngest, [][]byte{payload}, contentType)
}

// topicFor is the topic an export goes to: the ingest topic for Diode
// data, the telemetry topic otherwise. Empty before the connection is up.
func (s *BridgeServer) topicFor(isIngest bool) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if isIngest {
		return s.ingestTopic
	}
	return s.telemetryTopic
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

	// Every metrics backend names its policy on the instrumentation scope;
	// stamp the id and backend the platform validates against, from the
	// policies this agent runs. Outside fleet mode there is no repository
	// and the request is forwarded as it arrived.
	enrichMetricsWithPolicy(req, s.bridge.GetPolicyRepo(), s.bridge.logger)

	// Metrics for the telemetry topic use the metrics encoding; Diode data
	// keeps the ingest topic's.
	isIngest := isIngestRequest(resources)
	enc := s.bridge.metricsEnc
	if isIngest {
		enc = s.bridge.enc
	}
	if !isIngest {
		// The bridge's own drop counts ride with the agent's metrics.
		s.bridge.dropped.appendTo(req)
	}
	// An export is published in messages under the cap, each carrying the
	// resource and the scope of every point in it; a single point that
	// cannot fit is dropped and counted rather than sent to fail.
	contentType := enc.ContentType()
	limit := s.bridge.messageCap(s.bridge.topicFor(isIngest), contentType)
	if limit == 0 {
		// The broker's maximum packet size leaves no room for a payload: no
		// piece of the export could be sent, so it is dropped and counted
		// once rather than point by point.
		s.bridge.dropped.add(signalMetrics, reasonTooLarge, 1)
		s.bridge.logger.Warn("the broker's maximum packet size leaves no room for an OTLP payload, dropping the metrics export",
			"broker_max_packet_size", s.bridge.BrokerMaxPacketSize())
		return nil, status.Error(codes.InvalidArgument, "the broker's maximum packet size leaves no room for a metrics export; dropped")
	}
	payloads, dropped, err := splitMetrics(req, enc, limit)
	if err != nil {
		return nil, err
	}
	if err := s.bridge.enqueue(ctx, signalMetrics, isIngest, payloads, contentType); err != nil {
		// Refused while the queue is full, the export is sent again whole, so
		// a point left out of it is counted by the attempt that is accepted,
		// not by every attempt. Refused for good, the export was counted once.
		return nil, err
	}
	for _, d := range dropped {
		s.bridge.dropped.add(signalMetrics, reasonTooLarge, 1)
		s.bridge.logger.Warn("OTLP metric data point exceeds the message cap on its own, dropping it",
			"metric", d.Metric, "bytes", d.Bytes, "cap", limit)
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
	if !isIngest && !s.bridge.cfg.ForwardLogs {
		resources := make([]*resourcev1.Resource, 0, len(req.ResourceLogs))
		for _, rl := range req.ResourceLogs {
			if rl != nil {
				resources = append(resources, rl.Resource)
			}
		}
		s.bridge.discardUnread(signalLogs, resources)
		return &collectorlogs.ExportLogsServiceResponse{}, nil
	}
	if isIngest {
		repo := s.bridge.GetPolicyRepo()
		enrichLogsWithDatasets(req, repo)
		s.bridge.logger.Debug("ingesting enriched logs with dataset_ids", "request", req)
	}

	if err := s.bridge.exportWhole(ctx, signalLogs, isIngest, req); err != nil {
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

		// A resource-level policy applies to every scope. A legacy scope-level
		// name is read again for each scope, so it cannot leak onto a later
		// scope that has no policy of its own.
		resourcePolicyName := ""
		if rl.Resource != nil && rl.Resource.Attributes != nil {
			for _, attr := range rl.Resource.Attributes {
				if attr != nil && attr.Key == diodePolicyNameAttributeKey && attr.Value != nil {
					if sv := attr.Value.GetStringValue(); sv != "" {
						resourcePolicyName = sv
						break
					}
				}
			}
		}

		for _, sl := range rl.ScopeLogs {
			if sl == nil || sl.Scope == nil {
				continue
			}

			policyName := resourcePolicyName
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

			// A scope that arrived without attributes still gets dataset_ids.
			if sl.Scope.Attributes == nil {
				sl.Scope.Attributes = make([]*commonv1.KeyValue, 0, 1)
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
