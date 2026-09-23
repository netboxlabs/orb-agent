package collector

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/profiles"
)

func testReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithCardinalityLimit(metrics.CardinalityLimit))
	metrics.SetMeterProviderForTest(provider)
	t.Cleanup(metrics.ResetMeter)
	return reader
}

func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

// collectByPolicy runs one collection and indexes metrics by the policy_name
// of the scope they were exported under ("" for the process scope), then by
// name. collect flattens scopes, which is right for a single-policy test;
// this is for tests that care which scope a series left under.
func collectByPolicy(t *testing.T, reader *sdkmetric.ManualReader) map[string]map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		policy := ""
		if v, ok := sm.Scope.Attributes.Value(attribute.Key(metrics.PolicyNameAttribute)); ok {
			policy = v.AsString()
		}
		if out[policy] == nil {
			out[policy] = map[string]metricdata.Metrics{}
		}
		for _, m := range sm.Metrics {
			out[policy][m.Name] = m
		}
	}
	return out
}

// fallbacks totals the gnmi.mode_fallback_total counter. testReader installs
// the meter the metrics package hands its health counters out on, so the
// ladder's own accounting arrives through the same manual reader as the series.
func fallbacks(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	m, ok := collect(t, reader)["gnmi.mode_fallback_total"]
	if !ok {
		return 0
	}
	var total int64
	for _, pt := range m.Data.(metricdata.Sum[int64]).DataPoints {
		total += pt.Value
	}
	return total
}

// reconnects totals gnmi.subscription_reconnects_total, the way fallbacks
// totals the ladder's counter: what the run loop counts each time it dials a
// target again after an attempt of its own ended.
func reconnects(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	m, ok := collect(t, reader)["gnmi.subscription_reconnects_total"]
	if !ok {
		return 0
	}
	var total int64
	for _, pt := range m.Data.(metricdata.Sum[int64]).DataPoints {
		total += pt.Value
	}
	return total
}

// drops totals gnmi.updates_dropped_total for one reason, the way fallbacks
// totals the ladder's counter.
func drops(t *testing.T, reader *sdkmetric.ManualReader, reason string) int64 {
	t.Helper()
	m, ok := collect(t, reader)["gnmi.updates_dropped_total"]
	if !ok {
		return 0
	}
	var total int64
	for _, pt := range m.Data.(metricdata.Sum[int64]).DataPoints {
		if v, ok := pt.Attributes.Value("reason"); ok && v.AsString() == reason {
			total += pt.Value
		}
	}
	return total
}

func TestConvertValue(t *testing.T) {
	gauge := profiles.Metric{Type: "gauge"}
	enum := profiles.Metric{Type: "gauge", Enum: map[string]int64{"UP": 1, "DOWN": 0}}
	boolean := profiles.Metric{Type: "gauge", Bool: true}
	counter := profiles.Metric{Type: "counter"}

	f, ok := gaugeValue(gauge, uint64(7))
	require.True(t, ok)
	assert.Equal(t, 7.0, f)
	f, ok = gaugeValue(gauge, int64(-3))
	require.True(t, ok)
	assert.Equal(t, -3.0, f)
	f, ok = gaugeValue(gauge, 50.5)
	require.True(t, ok)
	assert.Equal(t, 50.5, f)
	f, ok = gaugeValue(enum, "DOWN")
	require.True(t, ok)
	assert.Equal(t, 0.0, f)
	_, ok = gaugeValue(enum, "FLAPPING")
	assert.False(t, ok, "an unmapped enum value is dropped")
	f, ok = gaugeValue(boolean, true)
	require.True(t, ok)
	assert.Equal(t, 1.0, f)
	_, ok = gaugeValue(gauge, "text")
	assert.False(t, ok)
	// A Get result is decoded from JSON, which hands every number over as a
	// float64 and every 64-bit YANG integer as a string (RFC 7951).
	f, ok = gaugeValue(gauge, "1.25")
	require.True(t, ok, "a numeric string is a gauge value")
	assert.Equal(t, 1.25, f)

	i, ok := counterValue(counter, uint64(1394))
	require.True(t, ok)
	assert.Equal(t, int64(1394), i)
	i, ok = counterValue(counter, int64(5))
	require.True(t, ok)
	assert.Equal(t, int64(5), i)
	_, ok = counterValue(counter, 1.5)
	assert.False(t, ok, "a counter must be integral")
	_, ok = counterValue(counter, uint64(1<<63))
	assert.False(t, ok, "a counter above int64 is dropped rather than wrapped")
	i, ok = counterValue(counter, 100.0)
	require.True(t, ok, "an integral float64 is a counter value")
	assert.Equal(t, int64(100), i)
	_, ok = counterValue(counter, -1.0)
	assert.False(t, ok, "a negative float64 is not a cumulative count")
	i, ok = counterValue(counter, "42")
	require.True(t, ok, "a numeric string is a counter value")
	assert.Equal(t, int64(42), i)
	_, ok = counterValue(counter, "18446744073709551615")
	assert.False(t, ok, "a string counter above int64 is dropped rather than wrapped")
	_, ok = counterValue(counter, int64(-1))
	assert.False(t, ok, "a negative int64 is not a cumulative count")
	_, ok = counterValue(counter, "-1")
	assert.False(t, ok, "a negative numeric string is not a cumulative count")
	i, ok = counterValue(counter, int64(0))
	require.True(t, ok, "zero is a cumulative count")
	assert.Equal(t, int64(0), i)
	i, ok = counterValue(counter, "0")
	require.True(t, ok, "zero as a string is a cumulative count")
	assert.Equal(t, int64(0), i)

	// A target that serializes its updates as JSON hands every number over as a
	// json.Number, which keeps the digits the device sent: a counter64 past 2^53
	// rounds the moment it passes through a float64.
	i, ok = counterValue(counter, json.Number("9007199254740993"))
	require.True(t, ok, "a JSON number is a counter value")
	assert.Equal(t, int64(9007199254740993), i)
	_, ok = counterValue(counter, json.Number("1.5"))
	assert.False(t, ok, "a non-integral JSON number is not a counter value")
	f, ok = gaugeValue(gauge, json.Number("1.5"))
	require.True(t, ok, "a JSON number is a gauge value")
	assert.Equal(t, 1.5, f)
	_, ok = counterValue(counter, json.Number("-1"))
	assert.False(t, ok, "a negative JSON number is not a cumulative count")
}

func TestExporterObservesStoreAsCounterAndGauge(t *testing.T) {
	reader := testReader(t)
	e := newExporter(newStore(100), nil, nil)
	attrs := []attribute.KeyValue{attribute.String("device_ip", "10.0.0.1"), attribute.String("interface_name", "e1")}
	require.Empty(t, e.observeCounter("p", "if_in_octets", "By", attrs, 1394, time.Now().UnixNano(), age))
	require.Empty(t, e.observeGauge("p", "if_oper_status", "", attrs, 1, time.Now().UnixNano(), age))

	got := collect(t, reader)
	sum, ok := got["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	require.True(t, ok, "counters export as an int64 sum")
	assert.True(t, sum.IsMonotonic)
	assert.Equal(t, metricdata.CumulativeTemporality, sum.Temporality)
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1394), sum.DataPoints[0].Value)
	assert.Equal(t, "By", got["gnmi.if_in_octets"].Unit)
	v, _ := sum.DataPoints[0].Attributes.Value("interface_name")
	assert.Equal(t, "e1", v.AsString())

	g, ok := got["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
	require.True(t, ok, "gauges export as a float64 gauge")
	require.Len(t, g.DataPoints, 1)
	assert.Equal(t, 1.0, g.DataPoints[0].Value)

	byPolicy := collectByPolicy(t, reader)
	_, inScope := byPolicy["p"]["gnmi.if_in_octets"]
	assert.True(t, inScope, "the series left under its policy's scope")
	_, hasPolicy := sum.DataPoints[0].Attributes.Value("policy")
	assert.False(t, hasPolicy, "the policy is on the scope, not the datapoint")
}

func TestExporterWithholdsStaleSeries(t *testing.T) {
	reader := testReader(t)
	e := newExporter(newStore(100), nil, nil)
	attrs := []attribute.KeyValue{attribute.String("device_ip", "1")}
	require.Empty(t, e.observeGauge("p", "cpu_utilization", "%", attrs, 12, time.Now().Add(-time.Minute).UnixNano(), age))
	_, stored := e.store.get(seriesKey{metric: "cpu_utilization", policy: "p", attrs: attrKey(attrs)})
	require.True(t, stored, "the store accepted the write")
	got := collect(t, reader)
	assert.NotContains(t, got, "gnmi.cpu_utilization", "a series older than its age is withheld from export")
}

// The same metric under two policies is two instruments on two meters, so
// each policy's series export under its own scope and never merge.
func TestExporterExportsEachPolicyUnderItsOwnScope(t *testing.T) {
	reader := testReader(t)
	e := newExporter(newStore(100), nil, nil)
	attrs := []attribute.KeyValue{attribute.String("device_ip", "10.0.0.1"), attribute.String("interface_name", "e1")}
	now := time.Now().UnixNano()
	require.Empty(t, e.observeCounter("core", "if_in_octets", "By", attrs, 10, now, age))
	require.Empty(t, e.observeCounter("edge", "if_in_octets", "By", attrs, 20, now, age))

	byPolicy := collectByPolicy(t, reader)
	core := byPolicy["core"]["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	edge := byPolicy["edge"]["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	require.Len(t, core.DataPoints, 1)
	require.Len(t, edge.DataPoints, 1)
	assert.Equal(t, int64(10), core.DataPoints[0].Value)
	assert.Equal(t, int64(20), edge.DataPoints[0].Value)
	_, unscoped := byPolicy[""]["gnmi.if_in_octets"]
	assert.False(t, unscoped, "nothing of a policy's leaves on the process scope")
}

// forgetPolicy gives the policy's callbacks back and drops its instrument
// entries, so its scope goes quiet, another policy's is untouched, and a
// later observation under the same name registers afresh.
func TestExporterForgetPolicyStopsThatPolicysExport(t *testing.T) {
	reader := testReader(t)
	e := newExporter(newStore(100), nil, nil)
	attrs := []attribute.KeyValue{attribute.String("device_ip", "10.0.0.1")}
	now := time.Now().UnixNano()
	require.Empty(t, e.observeGauge("core", "cpu", "%", attrs, 1, now, age))
	require.Empty(t, e.observeGauge("edge", "cpu", "%", attrs, 2, now, age))
	require.Len(t, collectByPolicy(t, reader), 2)

	e.store.forgetPolicy("core")
	e.forgetPolicy("core")

	byPolicy := collectByPolicy(t, reader)
	_, coreLeft := byPolicy["core"]["gnmi.cpu"]
	assert.False(t, coreLeft, "a forgotten policy exports nothing")
	_, edgeLeft := byPolicy["edge"]["gnmi.cpu"]
	assert.True(t, edgeLeft, "the other policy is untouched")
	e.mu.Lock()
	_, stillKeyed := e.gauges[instrumentKey{policy: "core", name: "cpu"}]
	_, regsLeft := e.regs["core"]
	e.mu.Unlock()
	assert.False(t, stillKeyed)
	assert.False(t, regsLeft)

	require.Empty(t, e.observeGauge("core", "cpu", "%", attrs, 3, time.Now().UnixNano(), age))
	byPolicy = collectByPolicy(t, reader)
	g := byPolicy["core"]["gnmi.cpu"].Data.(metricdata.Gauge[float64])
	require.Len(t, g.DataPoints, 1)
	assert.Equal(t, 3.0, g.DataPoints[0].Value, "a policy of the same name registers afresh")
}

func TestFlattenUpdate(t *testing.T) {
	scalar := gnmi.Update{Path: "/system/memory/state/physical", Value: uint64(1)}
	assert.Equal(t, []gnmi.Update{scalar}, flattenUpdate(scalar), "a scalar update is already one leaf")

	got := flattenUpdate(gnmi.Update{Path: "/system/memory/state", Value: map[string]any{
		"physical": float64(1),
		"counters": map[string]any{"used": float64(2)},
		"slots":    []any{float64(1), float64(2)},
	}})
	assert.Equal(t, []gnmi.Update{
		{Path: "/system/memory/state/counters/used", Value: float64(2)},
		{Path: "/system/memory/state/physical", Value: float64(1)},
		{Path: "/system/memory/state/slots", Value: []any{float64(1), float64(2)}},
	}, got, "a nested container yields one update per scalar and leaves a list whole")

	// JSON_IETF qualifies a key with the YANG module that defines it, and the
	// profile paths carry no qualifier.
	qualified := flattenUpdate(gnmi.Update{Path: "/system/memory", Value: map[string]any{
		"openconfig-system:state": map[string]any{"openconfig-system:physical": float64(1)},
	}})
	assert.Equal(t, []gnmi.Update{{Path: "/system/memory/state/physical", Value: float64(1)}}, qualified,
		"a module qualifier is dropped from every key")

	empty := gnmi.Update{Path: "/system/memory/state", Value: map[string]any{}}
	assert.Equal(t, []gnmi.Update{empty}, flattenUpdate(empty),
		"an empty container stays one update, so it is counted rather than dropped without a trace")
}

// With the export disabled by flag there is no meter, no callback to read
// the store and nothing to evict an aged series: an observation is not stored,
// rather than held in memory until the budget fills.
func TestObservationsAreNotStoredWithoutAMeter(t *testing.T) {
	require.Nil(t, metrics.GetMeter(), "this test runs with the export disabled")
	st := newStore(100)
	e := newExporter(st, nil, nil)
	assert.Equal(t, "", e.observeGauge("p", "g", "", []attribute.KeyValue{attribute.String("device_ip", "h")}, 1, time.Now().UnixNano(), 0))
	assert.Equal(t, "", e.observeCounter("p", "c", "", []attribute.KeyValue{attribute.String("device_ip", "h")}, 1, time.Now().UnixNano(), 0))
	st.mu.RLock()
	defer st.mu.RUnlock()
	assert.Empty(t, st.series, "nothing is stored when nothing can be exported")
}

// A schema claim lives as long as an exporter holds it: once the last
// exporter writing a name has closed, another may register the name under
// another kind or unit. While one still holds it, the disagreement is refused.
func TestASchemaClaimIsReleasedWhenItsLastExporterCloses(t *testing.T) {
	shared := NewSchemas()
	first := newExporter(newStore(100), nil, shared)
	second := newExporter(newStore(100), nil, shared)
	require.Equal(t, "", first.admit("if_in_octets", kindCounter, "By"))
	require.Equal(t, "", second.admit("if_in_octets", kindCounter, "By"), "an agreeing exporter holds the name too")
	first.close()
	third := newExporter(newStore(100), nil, shared)
	assert.Equal(t, dropSchemaConflict, third.admit("if_in_octets", kindGauge, ""), "the second exporter still holds the claim")
	second.close()
	assert.Equal(t, "", third.admit("if_in_octets", kindGauge, ""), "with no holder left, the name is free to register anew")
}
