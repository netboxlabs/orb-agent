package otlpbridge

import (
	"log/slog"
	"strings"

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

// backendForScope maps the instrumentation scope name a backend exports
// under to the Orb backend name its policies are registered with. Policy
// names are unique within a backend, not across backends, so a name alone
// can be ambiguous: the scope name is what says which backend produced the
// metrics. pktvisor names its scopes "pktvisor/<policy>"; snmp-telemetry and
// gnmi-telemetry use their own names. An unrecognised scope name yields ""
// and the policy is then resolved by name alone, only when that name is
// unambiguous.
func backendForScope(scopeName string) string {
	switch {
	case scopeName == "pktvisor" || strings.HasPrefix(scopeName, "pktvisor/"):
		return "pktvisor"
	case scopeName == "snmp-telemetry":
		return "snmp_telemetry"
	case scopeName == "gnmi-telemetry":
		return "gnmi_telemetry"
	}
	return ""
}

// policyIndex is the agent's policies as seen by one enrichment pass: read
// from the repository once per request, indexed by (backend, name) and by
// name, so every scope of the request is resolved against one consistent
// snapshot and the repository is not asked once per scope.
type policyIndex struct {
	byBackendName map[[2]string]*policies.PolicyData
	byName        map[string][]*policies.PolicyData
}

func loadPolicyIndex(repo policies.PolicyRepo) (*policyIndex, error) {
	all, err := repo.GetAll()
	if err != nil {
		return nil, err
	}
	ix := &policyIndex{
		byBackendName: make(map[[2]string]*policies.PolicyData, len(all)),
		byName:        make(map[string][]*policies.PolicyData, len(all)),
	}
	for i := range all {
		p := &all[i]
		ix.byBackendName[[2]string{p.Backend, p.Name}] = p
		ix.byName[p.Name] = append(ix.byName[p.Name], p)
	}
	return ix, nil
}

// resolve returns the policy a scope refers to, or nil and the reason it
// stays unattributed. A known backend is matched exactly: a same-named
// policy on another backend never attributes its metrics. An unknown
// backend falls back to the name, but only when one policy carries it.
func (ix *policyIndex) resolve(backend, name string) (*policies.PolicyData, string) {
	var p *policies.PolicyData
	if backend != "" {
		p = ix.byBackendName[[2]string{backend, name}]
		if p == nil {
			return nil, "no such policy on this backend"
		}
	} else {
		candidates := ix.byName[name]
		switch len(candidates) {
		case 0:
			return nil, "policy not found"
		case 1:
			p = candidates[0]
		default:
			return nil, "policy name is ambiguous across backends and the scope names no backend"
		}
	}
	if p.ID == "" {
		return nil, "policy has no id"
	}
	return p, ""
}

// enrichMetricsWithPolicy stamps orb.policy_id and orb.backend on every
// ScopeMetrics whose scope names a policy through policy_name, resolving
// (backend, name) against a snapshot of the agent's policy repository taken
// once per request. A scope with no policy_name (process-level health
// metrics), a name the repository does not know for that backend, or a
// bridge without a repository leave the scope as it arrived: the platform
// treats such series as unattributed. Datapoints and resources are never
// touched; the policy is a property of the scope, and repeating it on every
// point would multiply the payload for nothing.
func enrichMetricsWithPolicy(req *collectormetrics.ExportMetricsServiceRequest, repo policies.PolicyRepo, logger *slog.Logger) {
	if req == nil || repo == nil {
		return
	}
	// The index is loaded on the first scope that names a policy, so a
	// request carrying only unscoped metrics never touches the repository.
	var ix *policyIndex
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
			if ix == nil {
				loaded, err := loadPolicyIndex(repo)
				if err != nil {
					logger.Debug("policy repository unavailable, metrics scopes left unstamped", "error", err)
					return
				}
				ix = loaded
			}
			backend := backendForScope(sm.Scope.Name)
			policy, reason := ix.resolve(backend, name)
			if policy == nil {
				logger.Debug("metrics scope left unstamped", "scope", sm.Scope.Name, "backend", backend, "name", name, "reason", reason)
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
