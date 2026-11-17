package otlpbridge

import (
	"log/slog"
	"strings"

	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

const (
	pktvisorScopePrefix     = "pktvisor/"
	pktvisorResourcesSuffix = "-resources"
)

// pktvisorResourcesInput returns the name n of a pktvisor scope
// "pktvisor/<n>" where n ends in "-resources", or "" for any other scope.
func pktvisorResourcesInput(scopeName string) string {
	n, ok := strings.CutPrefix(scopeName, pktvisorScopePrefix)
	if !ok || !strings.HasSuffix(n, pktvisorResourcesSuffix) {
		return ""
	}
	return n
}

// dropPktvisorResourcesScopes removes the ScopeMetrics pktvisor exports for
// its per-input "<input>-resources" policy. pktvisor creates one per input
// stream, shared by every policy on it, so no Orb policy owns it and the
// platform could only drop it as unattributed. A scope is kept when the repo
// holds a pktvisor policy of that name. Without a repository (outside Fleet),
// or when it cannot be read, nothing is removed. It returns how many scopes
// it removed. A ResourceMetrics left with no scopes stays in the request.
func dropPktvisorResourcesScopes(req *collectormetrics.ExportMetricsServiceRequest, repo policies.PolicyRepo) int {
	if req == nil || repo == nil {
		return 0
	}
	var ix *policyIndex
	removed := 0
	for _, rm := range req.ResourceMetrics {
		if rm == nil {
			continue
		}
		kept := rm.ScopeMetrics[:0]
		for _, sm := range rm.ScopeMetrics {
			n := pktvisorResourcesInput(sm.GetScope().GetName())
			if n == "" {
				kept = append(kept, sm)
				continue
			}
			if ix == nil {
				loaded, err := loadPolicyIndex(repo)
				if err != nil {
					slog.Debug("policy repository unavailable, pktvisor resources scopes kept", "error", err)
					kept = append(kept, sm)
					continue
				}
				ix = loaded
			}
			if _, ok := ix.byBackendName[[2]string{"pktvisor", n}]; ok {
				kept = append(kept, sm)
				continue
			}
			removed++
		}
		clear(rm.ScopeMetrics[len(kept):])
		rm.ScopeMetrics = kept
	}
	return removed
}
