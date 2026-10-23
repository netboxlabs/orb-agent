package collector

import (
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// exportLogs is, per reader, everything its collections have exported so far.
// Each update leaves once, by the collection after it, so a test waiting for
// several series, or reading one after another helper's collection took it,
// reads it from here rather than from the one collection it expects it in:
// this is what the backend downstream holds, one sample per update.
var exportLogs = map[*sdkmetric.ManualReader]map[string]map[string]metricdata.Metrics{}

// record merges one collection of reader into its log, by policy and metric
// name, a series' later point replacing its earlier one.
func record(reader *sdkmetric.ManualReader, by map[string]map[string]metricdata.Metrics) {
	log := exportLogs[reader]
	if log == nil {
		log = map[string]map[string]metricdata.Metrics{}
		exportLogs[reader] = log
	}
	for policy, metrics := range by {
		if log[policy] == nil {
			log[policy] = map[string]metricdata.Metrics{}
		}
		for name, m := range metrics {
			log[policy][name] = mergeMetric(log[policy][name], m)
		}
	}
}

// exportedByPolicy runs one collection and returns everything reader has
// exported so far, by the policy of its scope ("" for the process scope)
// and then by name.
func exportedByPolicy(t *testing.T, reader *sdkmetric.ManualReader) map[string]map[string]metricdata.Metrics {
	t.Helper()
	collectByPolicy(t, reader)
	return exportLogs[reader]
}

// exported is exportedByPolicy with the scopes merged, for a single-policy
// test.
func exported(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	out := map[string]metricdata.Metrics{}
	for _, metrics := range exportedByPolicy(t, reader) {
		for name, m := range metrics {
			out[name] = mergeMetric(out[name], m)
		}
	}
	return out
}

// forgetExported starts reader's log afresh, so a test can tell what is
// exported from now on from what was exported before.
func forgetExported(reader *sdkmetric.ManualReader) {
	delete(exportLogs, reader)
}

// exportedWithin collects for the length of within and returns what reader
// exported in that time, nothing from before it, by policy as
// exportedByPolicy does.
func exportedWithin(t *testing.T, reader *sdkmetric.ManualReader, within time.Duration) map[string]map[string]metricdata.Metrics {
	t.Helper()
	forgetExported(reader)
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		collectByPolicy(t, reader)
	}
	return exportedByPolicy(t, reader)
}

func mergeMetric(prev, next metricdata.Metrics) metricdata.Metrics {
	if prev.Data == nil {
		return next
	}
	merged := next
	switch d := next.Data.(type) {
	case metricdata.Gauge[int64]:
		if p, ok := prev.Data.(metricdata.Gauge[int64]); ok {
			d.DataPoints = mergePoints(p.DataPoints, d.DataPoints)
		}
		merged.Data = d
	case metricdata.Gauge[float64]:
		if p, ok := prev.Data.(metricdata.Gauge[float64]); ok {
			d.DataPoints = mergePoints(p.DataPoints, d.DataPoints)
		}
		merged.Data = d
	case metricdata.Sum[int64]:
		if p, ok := prev.Data.(metricdata.Sum[int64]); ok {
			d.DataPoints = mergePoints(p.DataPoints, d.DataPoints)
		}
		merged.Data = d
	case metricdata.Sum[float64]:
		if p, ok := prev.Data.(metricdata.Sum[float64]); ok {
			d.DataPoints = mergePoints(p.DataPoints, d.DataPoints)
		}
		merged.Data = d
	}
	return merged
}

// mergePoints keeps one point per attribute set, the later one.
func mergePoints[N int64 | float64](prev, next []metricdata.DataPoint[N]) []metricdata.DataPoint[N] {
	out := append([]metricdata.DataPoint[N](nil), prev...)
	for _, pt := range next {
		replaced := false
		for i := range out {
			if out[i].Attributes.Equals(&pt.Attributes) {
				out[i] = pt
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, pt)
		}
	}
	return out
}

// held is what c's store holds for policy now, in the shape a collection
// exports it: a metric per name, a point per series, past-age series
// withheld as an export would withhold them. A collection carries a series
// only when an update has set it since the last, so a test about which
// series a reconcile, a delete or an age withdraws reads the store here.
func held(c *Collector, policy string) map[string]metricdata.Metrics {
	c.exporter.mu.Lock()
	counters := map[string]bool{}
	for k := range c.exporter.counters {
		if k.policy == policy {
			counters[k.name] = true
		}
	}
	c.exporter.mu.Unlock()

	c.store.mu.RLock()
	defer c.store.mu.RUnlock()
	now := time.Now().UnixNano()
	out := map[string]metricdata.Metrics{}
	for name, byKey := range c.store.index[policy] {
		var sums []metricdata.DataPoint[int64]
		var gauges []metricdata.DataPoint[float64]
		for _, pt := range byKey {
			if pt.maxAge > 0 && pt.ts < now-int64(pt.maxAge) {
				continue
			}
			attrs := attribute.NewSet(pt.attrs...)
			if counters[name] {
				sums = append(sums, metricdata.DataPoint[int64]{Attributes: attrs, Value: pt.i})
			} else {
				gauges = append(gauges, metricdata.DataPoint[float64]{Attributes: attrs, Value: pt.f})
			}
		}
		switch {
		case len(sums) > 0:
			out["gnmi."+name] = metricdata.Metrics{Name: "gnmi." + name, Data: metricdata.Sum[int64]{DataPoints: sums, IsMonotonic: true}}
		case len(gauges) > 0:
			out["gnmi."+name] = metricdata.Metrics{Name: "gnmi." + name, Data: metricdata.Gauge[float64]{DataPoints: gauges}}
		}
	}
	return out
}

// latest is the point of pts collected last.
func latest[N int64 | float64](pts []metricdata.DataPoint[N]) metricdata.DataPoint[N] {
	var out metricdata.DataPoint[N]
	for _, pt := range pts {
		if !pt.Time.Before(out.Time) {
			out = pt
		}
	}
	return out
}
