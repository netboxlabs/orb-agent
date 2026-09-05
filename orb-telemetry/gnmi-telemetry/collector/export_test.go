package collector

import (
	"context"
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
	metrics.SetMeterForTest(provider.Meter("test"))
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
}

func TestExporterObservesStoreAsCounterAndGauge(t *testing.T) {
	reader := testReader(t)
	e := newExporter(newStore(100), nil, nil)
	attrs := []attribute.KeyValue{attribute.String("device_ip", "10.0.0.1"), attribute.String("policy", "p"), attribute.String("interface_name", "e1")}
	require.Empty(t, e.observeCounter("if_in_octets", "By", attrs, 1394, time.Now().UnixNano(), age))
	require.Empty(t, e.observeGauge("if_oper_status", "", attrs, 1, time.Now().UnixNano(), age))

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
}

func TestExporterWithholdsStaleSeries(t *testing.T) {
	reader := testReader(t)
	e := newExporter(newStore(100), nil, nil)
	attrs := []attribute.KeyValue{attribute.String("device_ip", "1"), attribute.String("policy", "p")}
	require.Empty(t, e.observeGauge("cpu_utilization", "%", attrs, 12, time.Now().Add(-time.Minute).UnixNano(), age))
	_, stored := e.store.get(seriesKey{metric: "cpu_utilization", attrs: attrKey(attrs)})
	require.True(t, stored, "the store accepted the write")
	got := collect(t, reader)
	assert.NotContains(t, got, "gnmi.cpu_utilization", "a series older than its age is withheld from export")
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
