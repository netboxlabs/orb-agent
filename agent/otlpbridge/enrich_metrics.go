package otlpbridge

import (
	"log/slog"

	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

const (
	// policyNameScopeAttributeKey is the instrumentation-scope attribute every
	// metrics backend (pktvisor, snmp-telemetry, gnmi-telemetry) sets to the
	// Orb policy name, one scope per policy.
	policyNameScopeAttributeKey = "policy_name"
	// orbPolicyIDAttributeKey and orbBackendAttributeKey are what the bridge
	// stamps on such a scope, so the platform can validate the policy against
	// the organisation and label the series without resolving names itself.
	orbPolicyIDAttributeKey = "orb.policy_id"
	orbBackendAttributeKey  = "orb.backend"
)

// enrichMetricsWithPolicy stamps orb.policy_id and orb.backend on every
// ScopeMetrics whose scope names a policy through policy_name, resolving the
// name once per request through the agent's policy repository. A scope with
// no policy_name (process-level health metrics), a name the repository does
// not know, or a bridge without a repository leave the scope as it arrived:
// the platform treats such series as unattributed. Datapoints and resources
// are never touched; the policy is a property of the scope, and repeating it
// on every point would multiply the payload for nothing.
func enrichMetricsWithPolicy(req *collectormetrics.ExportMetricsServiceRequest, repo policies.PolicyRepo, logger *slog.Logger) {
	if req == nil || repo == nil {
		return
	}
	// resolved caches lookups for the request: a nil entry is a name the
	// repository did not know, kept so it is asked once.
	resolved := map[string]*policies.PolicyData{}
	for _, rm := range req.ResourceMetrics {
		if rm == nil {
			continue
		}
		for _, sm := range rm.ScopeMetrics {
			if sm == nil || sm.Scope == nil {
				continue
			}
			name := stringAttribute(sm.Scope.Attributes, policyNameScopeAttributeKey)
			if name == "" {
				continue
			}
			policy, seen := resolved[name]
			if !seen {
				p, err := repo.GetByName(name)
				switch {
				case err != nil:
					logger.Debug("policy not found for metrics scope", "name", name, "error", err)
				case p.ID == "":
					logger.Debug("policy has no id, metrics scope left unstamped", "name", name)
				default:
					policy = &p
				}
				resolved[name] = policy
			}
			if policy == nil {
				continue
			}
			sm.Scope.Attributes = setStringAttribute(sm.Scope.Attributes, orbPolicyIDAttributeKey, policy.ID)
			sm.Scope.Attributes = setStringAttribute(sm.Scope.Attributes, orbBackendAttributeKey, policy.Backend)
		}
	}
}

// stringAttribute returns the first non-empty string value under key, or "".
func stringAttribute(attrs []*commonv1.KeyValue, key string) string {
	for _, kv := range attrs {
		if kv == nil || kv.Key != key || kv.Value == nil {
			continue
		}
		if sv := kv.Value.GetStringValue(); sv != "" {
			return sv
		}
	}
	return ""
}

// setStringAttribute sets key to value in place on its first occurrence,
// drops any further occurrence so the key appears once, and appends when
// the key is absent. Nil entries are dropped along the way.
func setStringAttribute(attrs []*commonv1.KeyValue, key, value string) []*commonv1.KeyValue {
	out := attrs[:0]
	replaced := false
	for _, kv := range attrs {
		if kv == nil {
			continue
		}
		if kv.Key == key {
			if replaced {
				continue
			}
			kv.Value = &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}}
			replaced = true
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}}})
	}
	return out
}
