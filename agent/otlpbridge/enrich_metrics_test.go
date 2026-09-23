package otlpbridge

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

func strAttr(key, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}}}
}

// attrMap renders an attribute list as key -> string value, first occurrence wins.
func attrMap(attrs []*commonv1.KeyValue) map[string]string {
	out := map[string]string{}
	for _, kv := range attrs {
		if kv == nil || kv.Value == nil {
			continue
		}
		if _, seen := out[kv.Key]; !seen {
			out[kv.Key] = kv.Value.GetStringValue()
		}
	}
	return out
}

func attrCount(attrs []*commonv1.KeyValue, key string) int {
	n := 0
	for _, kv := range attrs {
		if kv != nil && kv.Key == key {
			n++
		}
	}
	return n
}

// scopeFor builds a ScopeMetrics the way the telemetry backends do: the
// policy on the scope, device dimensions on the datapoint.
func scopeFor(scopeAttrs ...*commonv1.KeyValue) *metricsv1.ScopeMetrics {
	return &metricsv1.ScopeMetrics{
		Scope: &commonv1.InstrumentationScope{Name: "snmp-telemetry", Attributes: scopeAttrs},
		Metrics: []*metricsv1.Metric{{
			Name: "snmp.cpuutil",
			Data: &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{DataPoints: []*metricsv1.NumberDataPoint{{
				Attributes: []*commonv1.KeyValue{strAttr("device_ip", "10.0.0.1")},
				Value:      &metricsv1.NumberDataPoint_AsInt{AsInt: 7},
			}}}},
		}},
	}
}

func repoWith(t *testing.T, ps ...policies.PolicyData) policies.PolicyRepo {
	t.Helper()
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	for _, p := range ps {
		require.NoError(t, repo.Update(p))
	}
	return repo
}

// countingRepo counts GetByName calls so a test can prove one lookup per
// distinct name per request.
type countingRepo struct {
	policies.PolicyRepo
	calls int
}

func (c *countingRepo) GetByName(name string) (policies.PolicyData, error) {
	c.calls++
	return c.PolicyRepo.GetByName(name)
}

func TestEnrichMetricsWithPolicy(t *testing.T) {
	core := policies.PolicyData{ID: "id-core", Name: "core", Backend: "snmp_telemetry"}
	edge := policies.PolicyData{ID: "id-edge", Name: "edge", Backend: "pktvisor"}

	t.Run("two policies and an unscoped scope", func(t *testing.T) {
		req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{{
			ScopeMetrics: []*metricsv1.ScopeMetrics{
				scopeFor(strAttr("policy_name", "core")),
				scopeFor(strAttr("policy_name", "edge")),
				scopeFor(), // process-level health metrics carry no policy
			},
		}}}
		enrichMetricsWithPolicy(req, repoWith(t, core, edge), slog.Default())

		scopes := req.ResourceMetrics[0].ScopeMetrics
		assert.Equal(t, map[string]string{"policy_name": "core", "orb.policy_id": "id-core", "orb.backend": "snmp_telemetry"}, attrMap(scopes[0].Scope.Attributes))
		assert.Equal(t, map[string]string{"policy_name": "edge", "orb.policy_id": "id-edge", "orb.backend": "pktvisor"}, attrMap(scopes[1].Scope.Attributes))
		assert.Empty(t, scopes[2].Scope.Attributes, "a scope naming no policy is left alone")
		for _, sm := range scopes {
			dp := sm.Metrics[0].GetGauge().DataPoints[0]
			assert.Equal(t, map[string]string{"device_ip": "10.0.0.1"}, attrMap(dp.Attributes), "datapoints are never touched")
		}
	})

	t.Run("unknown policy is left untouched", func(t *testing.T) {
		req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{{
			ScopeMetrics: []*metricsv1.ScopeMetrics{scopeFor(strAttr("policy_name", "gone"))},
		}}}
		enrichMetricsWithPolicy(req, repoWith(t, core), slog.Default())
		assert.Equal(t, map[string]string{"policy_name": "gone"}, attrMap(req.ResourceMetrics[0].ScopeMetrics[0].Scope.Attributes))
	})

	t.Run("stale and duplicated orb attributes are replaced once", func(t *testing.T) {
		req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{{
			ScopeMetrics: []*metricsv1.ScopeMetrics{scopeFor(
				strAttr("orb.policy_id", "stale"), strAttr("policy_name", "core"), strAttr("orb.policy_id", "stale-too"), strAttr("orb.backend", "wrong"),
			)},
		}}}
		enrichMetricsWithPolicy(req, repoWith(t, core), slog.Default())
		attrs := req.ResourceMetrics[0].ScopeMetrics[0].Scope.Attributes
		assert.Equal(t, "id-core", attrMap(attrs)["orb.policy_id"])
		assert.Equal(t, "snmp_telemetry", attrMap(attrs)["orb.backend"])
		assert.Equal(t, 1, attrCount(attrs, "orb.policy_id"))
		assert.Equal(t, 1, attrCount(attrs, "orb.backend"))
		assert.Equal(t, "core", attrMap(attrs)["policy_name"], "the policy name stays")
	})

	t.Run("one lookup per distinct name per request", func(t *testing.T) {
		repo := &countingRepo{PolicyRepo: repoWith(t, core, edge)}
		req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{
			{ScopeMetrics: []*metricsv1.ScopeMetrics{scopeFor(strAttr("policy_name", "core")), scopeFor(strAttr("policy_name", "core"))}},
			{ScopeMetrics: []*metricsv1.ScopeMetrics{scopeFor(strAttr("policy_name", "edge")), scopeFor(strAttr("policy_name", "missing")), scopeFor(strAttr("policy_name", "missing"))}},
		}}
		enrichMetricsWithPolicy(req, repo, slog.Default())
		assert.Equal(t, 3, repo.calls, "core, edge and missing are each looked up once")
	})

	t.Run("nil request, repo, resource and scope are safe", func(t *testing.T) {
		assert.NotPanics(t, func() { enrichMetricsWithPolicy(nil, repoWith(t, core), slog.Default()) })
		req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{
			nil,
			{ScopeMetrics: []*metricsv1.ScopeMetrics{nil, {Scope: nil}, scopeFor(strAttr("policy_name", "core"))}},
		}}
		assert.NotPanics(t, func() { enrichMetricsWithPolicy(req, nil, slog.Default()) })
		assert.Equal(t, map[string]string{"policy_name": "core"}, attrMap(req.ResourceMetrics[1].ScopeMetrics[2].Scope.Attributes), "no repo, no stamping")
		assert.NotPanics(t, func() { enrichMetricsWithPolicy(req, repoWith(t, core), slog.Default()) })
		assert.Equal(t, "id-core", attrMap(req.ResourceMetrics[1].ScopeMetrics[2].Scope.Attributes)["orb.policy_id"])
	})

	t.Run("a policy without an id is not stamped", func(t *testing.T) {
		req := &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricsv1.ResourceMetrics{{
			ScopeMetrics: []*metricsv1.ScopeMetrics{scopeFor(strAttr("policy_name", "noid"))},
		}}}
		enrichMetricsWithPolicy(req, repoWith(t, policies.PolicyData{ID: "", Name: "noid", Backend: "pktvisor"}), slog.Default())
		assert.Equal(t, map[string]string{"policy_name": "noid"}, attrMap(req.ResourceMetrics[0].ScopeMetrics[0].Scope.Attributes))
	})
}

func TestSetStringAttribute(t *testing.T) {
	attrs := []*commonv1.KeyValue{strAttr("a", "1"), strAttr("k", "old"), nil, strAttr("k", "dup")}
	out := setStringAttribute(attrs, "k", "new")
	assert.Equal(t, "new", attrMap(out)["k"])
	assert.Equal(t, 1, attrCount(out, "k"))
	assert.Equal(t, "1", attrMap(out)["a"])
	out = setStringAttribute(out, "b", "2")
	assert.Equal(t, "2", attrMap(out)["b"])
	assert.Equal(t, "", stringAttribute(out, "missing"))
	assert.Equal(t, "new", stringAttribute(out, "k"))
}
