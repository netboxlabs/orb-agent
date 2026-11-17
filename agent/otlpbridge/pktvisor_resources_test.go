package otlpbridge

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// failingRepo is a repository whose read fails.
type failingRepo struct{ policies.PolicyRepo }

func (failingRepo) GetAll() ([]policies.PolicyData, error) { return nil, errors.New("boom") }

func scopeNames(req *collectormetrics.ExportMetricsServiceRequest) []string {
	var names []string
	for _, rm := range req.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			names = append(names, sm.Scope.Name)
		}
	}
	return names
}

func requestWithScopes(names ...string) *collectormetrics.ExportMetricsServiceRequest {
	sms := make([]*metricsv1.ScopeMetrics, 0, len(names))
	for _, n := range names {
		sms = append(sms, scopeNamed(n))
	}
	return &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{{ScopeMetrics: sms}}}
}

func TestDropPktvisorResourcesScopes(t *testing.T) {
	edgeResources := policies.PolicyData{ID: "id-er", Name: "edge-resources", Backend: "pktvisor"}
	otherBackend := policies.PolicyData{ID: "id-o", Name: "edge-resources", Backend: "snmp_telemetry"}
	probe := policies.PolicyData{ID: "id-p", Name: "probe", Backend: "pktvisor"}

	tests := []struct {
		name        string
		repo        policies.PolicyRepo
		scopes      []string
		wantRemoved int
		wantScopes  []string
	}{
		{"resources scope no policy", repoWith(t, probe), []string{"pktvisor/fleet_netprobe-abc-resources"}, 1, nil},
		{"policy named like a resources scope", repoWith(t, edgeResources), []string{"pktvisor/edge-resources"}, 0, []string{"pktvisor/edge-resources"}},
		{"same name on another backend does not count", repoWith(t, otherBackend), []string{"pktvisor/edge-resources"}, 1, nil},
		{"policy scope", repoWith(t, probe), []string{"pktvisor/probe"}, 0, []string{"pktvisor/probe"}},
		{"other backend scope", repoWith(t, probe), []string{"snmp-telemetry"}, 0, []string{"snmp-telemetry"}},
		{"nil repo", nil, []string{"pktvisor/x-resources"}, 0, []string{"pktvisor/x-resources"}},
		{"beside a policy scope", repoWith(t, probe), []string{"pktvisor/probe", "pktvisor/in-resources"}, 1, []string{"pktvisor/probe"}},
		{"repo read error", failingRepo{}, []string{"pktvisor/in-resources"}, 0, []string{"pktvisor/in-resources"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := requestWithScopes(tt.scopes...)
			assert.Equal(t, tt.wantRemoved, dropPktvisorResourcesScopes(req, tt.repo))
			assert.Equal(t, tt.wantScopes, scopeNames(req))
		})
	}

	t.Run("repo not read without a candidate scope", func(t *testing.T) {
		repo := &countingRepo{PolicyRepo: repoWith(t, probe)}
		dropPktvisorResourcesScopes(requestWithScopes("pktvisor/probe", "snmp-telemetry"), repo)
		assert.Zero(t, repo.calls)
	})

	t.Run("repo read once for several candidates", func(t *testing.T) {
		repo := &countingRepo{PolicyRepo: repoWith(t, probe)}
		req := requestWithScopes("pktvisor/a-resources", "pktvisor/b-resources")
		require.Equal(t, 2, dropPktvisorResourcesScopes(req, repo))
		assert.Equal(t, 1, repo.calls)
	})

	t.Run("nil request", func(t *testing.T) {
		assert.Zero(t, dropPktvisorResourcesScopes(nil, repoWith(t)))
	})
}
