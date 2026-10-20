package metrics

import (
	"context"
	"log/slog"
	"sync"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/octets"
)

// InvalidUTF8RepairedName counts the attributes and strings the exporter
// repaired because they were not valid UTF-8, by attribute key. The collector
// renders device text before recording it, so a count here means a path that
// skipped that.
const InvalidUTF8RepairedName = "snmp.invalid_utf8_repaired"

// validUTF8Exporter repairs every string of an export that is not valid UTF-8
// before the OTLP exporter marshals it.
//
// OTLP strings must be valid UTF-8, and the gRPC exporter refuses to marshal a
// request holding one that is not. One export carries every policy this
// process runs, so a single bad value would drop all of their telemetry, and
// nothing outside the process would count it. The collector renders device
// text with octets.Text before recording it; this is the net for any path
// that does not, such as one added later.
//
// A repaired string is the hex of all its bytes, octets.Hex, which is
// one-to-one, so a repair never makes two attribute sets alike.
type validUTF8Exporter struct {
	sdkmetric.Exporter

	logger *slog.Logger
	// warned holds the attribute keys already logged, so a device answering
	// the same bad value every poll is logged once and counted every time.
	warned sync.Map

	counterOnce sync.Once
	counter     metric.Int64Counter
}

// site is where a repaired string was, for the warning: the policy whose
// scope holds it and the metric, when there is one.
type site struct {
	scope  *metricdata.ScopeMetrics
	metric string
}

func (s site) policy() string {
	if s.scope == nil {
		return ""
	}
	v, _ := s.scope.Scope.Attributes.Value(PolicyNameAttribute)
	return v.AsString()
}

func newValidUTF8Exporter(next sdkmetric.Exporter, logger *slog.Logger) *validUTF8Exporter {
	return &validUTF8Exporter{Exporter: next, logger: logger}
}

// Export repairs rm in place and hands it on. The reader refills rm on every
// collection, so the repairs never outlive this export. An export with nothing
// to repair is scanned, not copied.
func (e *validUTF8Exporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if rm != nil {
		e.repairResourceMetrics(ctx, rm)
	}
	return e.Exporter.Export(ctx, rm)
}

// repaired counts one repaired attribute or string, and logs its key, with
// where it was, the first time.
func (e *validUTF8Exporter) repaired(ctx context.Context, at site, key string) {
	e.counterOnce.Do(func() {
		if meter != nil {
			e.counter, _ = meter.Int64Counter(InvalidUTF8RepairedName,
				metric.WithDescription("Attributes and strings of an export repaired because they were not valid UTF-8, by attribute key"))
		}
	})
	if e.counter != nil {
		e.counter.Add(ctx, 1, metric.WithAttributes(attribute.String("attribute", key)))
	}
	if _, logged := e.warned.LoadOrStore(key, struct{}{}); !logged && e.logger != nil {
		e.logger.Warn("Repaired a value that is not valid UTF-8 before export; the collector should have rendered it",
			"attribute", key, "policy", at.policy(), "metric", at.metric)
	}
}

func (e *validUTF8Exporter) repairResourceMetrics(ctx context.Context, rm *metricdata.ResourceMetrics) {
	if rm.Resource != nil {
		it := rm.Resource.Iter()
		if !iterValid(&it) {
			kvs := e.repairKVs(ctx, site{metric: "resource"}, rm.Resource.Attributes())
			rm.Resource = resource.NewWithAttributes(rm.Resource.SchemaURL(), kvs...)
		}
	}
	for i := range rm.ScopeMetrics {
		sm := &rm.ScopeMetrics[i]
		at := site{scope: sm}
		sm.Scope.Name = e.repairString(ctx, at, "scope name", sm.Scope.Name)
		sm.Scope.Version = e.repairString(ctx, at, "scope version", sm.Scope.Version)
		sm.Scope.Attributes = e.repairSet(ctx, at, sm.Scope.Attributes)
		for j := range sm.Metrics {
			m := &sm.Metrics[j]
			m.Name = e.repairString(ctx, at, "metric name", m.Name)
			at := site{scope: sm, metric: m.Name}
			m.Description = e.repairString(ctx, at, "metric description", m.Description)
			m.Unit = e.repairString(ctx, at, "metric unit", m.Unit)
			e.repairData(ctx, at, m.Data)
		}
	}
}

// repairData repairs the data points of every aggregation the SDK produces.
// The data points are in a slice the aggregation shares with m.Data, so
// writing through it repairs m.Data.
func (e *validUTF8Exporter) repairData(ctx context.Context, at site, data metricdata.Aggregation) {
	switch d := data.(type) {
	case metricdata.Gauge[int64]:
		repairPoints(ctx, e, at, d.DataPoints)
	case metricdata.Gauge[float64]:
		repairPoints(ctx, e, at, d.DataPoints)
	case metricdata.Sum[int64]:
		repairPoints(ctx, e, at, d.DataPoints)
	case metricdata.Sum[float64]:
		repairPoints(ctx, e, at, d.DataPoints)
	case metricdata.Histogram[int64]:
		for i := range d.DataPoints {
			d.DataPoints[i].Attributes = e.repairSet(ctx, at, d.DataPoints[i].Attributes)
			repairExemplars(ctx, e, at, d.DataPoints[i].Exemplars)
		}
	case metricdata.Histogram[float64]:
		for i := range d.DataPoints {
			d.DataPoints[i].Attributes = e.repairSet(ctx, at, d.DataPoints[i].Attributes)
			repairExemplars(ctx, e, at, d.DataPoints[i].Exemplars)
		}
	case metricdata.ExponentialHistogram[int64]:
		for i := range d.DataPoints {
			d.DataPoints[i].Attributes = e.repairSet(ctx, at, d.DataPoints[i].Attributes)
			repairExemplars(ctx, e, at, d.DataPoints[i].Exemplars)
		}
	case metricdata.ExponentialHistogram[float64]:
		for i := range d.DataPoints {
			d.DataPoints[i].Attributes = e.repairSet(ctx, at, d.DataPoints[i].Attributes)
			repairExemplars(ctx, e, at, d.DataPoints[i].Exemplars)
		}
	case metricdata.Summary:
		for i := range d.DataPoints {
			d.DataPoints[i].Attributes = e.repairSet(ctx, at, d.DataPoints[i].Attributes)
		}
	}
}

func repairPoints[N int64 | float64](ctx context.Context, e *validUTF8Exporter, at site, dps []metricdata.DataPoint[N]) {
	for i := range dps {
		dps[i].Attributes = e.repairSet(ctx, at, dps[i].Attributes)
		repairExemplars(ctx, e, at, dps[i].Exemplars)
	}
}

// repairExemplars replaces a repaired copy of the filtered attributes, since
// the slice may be the exemplar reservoir's own.
func repairExemplars[N int64 | float64](ctx context.Context, e *validUTF8Exporter, at site, exs []metricdata.Exemplar[N]) {
	for i := range exs {
		if !kvsValid(exs[i].FilteredAttributes) {
			exs[i].FilteredAttributes = e.repairKVs(ctx, at, exs[i].FilteredAttributes)
		}
	}
}

// repairSet returns s, or a repaired copy of it when it holds a string that is
// not valid UTF-8.
func (e *validUTF8Exporter) repairSet(ctx context.Context, at site, s attribute.Set) attribute.Set {
	it := s.Iter()
	if iterValid(&it) {
		return s
	}
	return attribute.NewSet(e.repairKVs(ctx, at, s.ToSlice())...)
}

// repairKVs returns a repaired copy of kvs, counting each attribute repaired.
func (e *validUTF8Exporter) repairKVs(ctx context.Context, at site, kvs []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, len(kvs))
	for i, kv := range kvs {
		if kvValid(kv) {
			out[i] = kv
			continue
		}
		out[i] = repairKV(kv)
		e.repaired(ctx, at, string(out[i].Key))
	}
	return out
}

// repairString repairs one of the export's own strings, a name or a unit.
func (e *validUTF8Exporter) repairString(ctx context.Context, at site, what, s string) string {
	if utf8.ValidString(s) {
		return s
	}
	e.repaired(ctx, at, what)
	return octets.Hex([]byte(s))
}

func iterValid(it *attribute.Iterator) bool {
	for it.Next() {
		if !kvValid(it.Attribute()) {
			return false
		}
	}
	return true
}

func kvsValid(kvs []attribute.KeyValue) bool {
	for _, kv := range kvs {
		if !kvValid(kv) {
			return false
		}
	}
	return true
}

func kvValid(kv attribute.KeyValue) bool {
	return utf8.ValidString(string(kv.Key)) && valueValid(kv.Value)
}

// valueValid reports whether every string in v, at any depth, is valid UTF-8.
func valueValid(v attribute.Value) bool {
	switch v.Type() {
	case attribute.STRING:
		return utf8.ValidString(v.AsString())
	case attribute.STRINGSLICE:
		for _, s := range v.AsStringSlice() {
			if !utf8.ValidString(s) {
				return false
			}
		}
	case attribute.SLICE:
		for _, el := range v.AsSlice() {
			if !valueValid(el) {
				return false
			}
		}
	case attribute.MAP:
		return kvsValid(v.AsMap())
	}
	return true
}

// repairKV repairs the key and every string of the value, at any depth.
func repairKV(kv attribute.KeyValue) attribute.KeyValue {
	key := string(kv.Key)
	if !utf8.ValidString(key) {
		key = octets.Hex([]byte(key))
	}
	return attribute.KeyValue{Key: attribute.Key(key), Value: repairValue(kv.Value)}
}

func repairValue(v attribute.Value) attribute.Value {
	switch v.Type() {
	case attribute.STRING:
		if s := v.AsString(); !utf8.ValidString(s) {
			return attribute.StringValue(octets.Hex([]byte(s)))
		}
	case attribute.STRINGSLICE:
		ss := v.AsStringSlice()
		for i, s := range ss {
			if !utf8.ValidString(s) {
				ss[i] = octets.Hex([]byte(s))
			}
		}
		return attribute.StringSliceValue(ss)
	case attribute.SLICE:
		els := v.AsSlice()
		for i := range els {
			els[i] = repairValue(els[i])
		}
		return attribute.SliceValue(els...)
	case attribute.MAP:
		kvs := v.AsMap()
		for i := range kvs {
			kvs[i] = repairKV(kvs[i])
		}
		return attribute.MapValue(kvs...)
	}
	return v
}
