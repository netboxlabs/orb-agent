package collector

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/profiles"
)

// staleAfterIntervals is how many metrics_intervals without an update
// arriving withhold a series from export. It does not apply to a series the
// device streams on change, which carries no age.
const staleAfterIntervals = 3

// gaugeValue converts an update value for a gauge metric: numbers as is,
// enum strings through the map, booleans to 1 and 0. A Get result is decoded
// from JSON, so a number arrives as a json.Number and a 64-bit YANG integer as
// a numeric string; the string is parsed after the enum lookup, which keeps an
// enum whose values are digits working.
func gaugeValue(m profiles.Metric, v any) (float64, bool) {
	switch x := v.(type) {
	case uint64:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case bool:
		if !m.Bool {
			return 0, false
		}
		if x {
			return 1, true
		}
		return 0, true
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return f, true
		}
		return 0, false
	case string:
		if n, ok := m.Enum[x]; ok {
			return float64(n), true
		}
		if f, err := strconv.ParseFloat(x, 64); err == nil {
			return f, true
		}
		return 0, false
	}
	return 0, false
}

// counterValue converts an update value for a counter: integral, non-negative
// and within int64. gNMI counters are counter64; a value past int64 is dropped
// rather than wrapped into a false reset. A Get result is decoded from JSON,
// which yields a json.Number for every number and a string for every 64-bit
// integer (RFC 7951), so both shapes are accepted here or the Get rung would
// drop every counter it polls. The float64 a PROTO update carries is accepted
// on the same terms.
func counterValue(_ profiles.Metric, v any) (int64, bool) {
	switch x := v.(type) {
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case int64:
		if x < 0 {
			return 0, false
		}
		return x, true
	case int:
		if x < 0 {
			return 0, false
		}
		return int64(x), true
	case float64:
		if x < 0 || x != math.Trunc(x) || x >= math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case json.Number:
		if n, err := x.Int64(); err == nil {
			if n < 0 {
				return 0, false
			}
			return n, true
		}
		// Int64 refuses a value past int64 and a value that is not whole alike;
		// only the first of those is a count, and only up to int64, where a
		// counter64 is dropped rather than wrapped into a false reset.
		if n, err := strconv.ParseUint(x.String(), 10, 64); err == nil {
			if n > math.MaxInt64 {
				return 0, false
			}
			return int64(n), true
		}
		return 0, false
	case string:
		if n, err := strconv.ParseUint(x, 10, 64); err == nil {
			if n > math.MaxInt64 {
				return 0, false
			}
			return int64(n), true
		}
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			if n < 0 {
				return 0, false
			}
			return n, true
		}
		return 0, false
	}
	return 0, false
}

// exporter owns the observable instruments, one per metric name, whose
// callbacks read the store on every export cycle. There is one per
// collector: a second exporter over the same store would observe every
// series twice and the SDK would sum them.
type exporter struct {
	store  *store
	logger *slog.Logger
	// schemas is the process-wide record of what each metric name is already
	// exported as, so this exporter never creates an instrument another
	// collector holds under the same name with a different kind or unit.
	schemas  *Schemas
	mu       sync.Mutex
	closed   bool
	counters map[string]metric.Int64ObservableCounter
	gauges   map[string]metric.Float64ObservableGauge
	regs     []metric.Registration
}

// newExporter builds an exporter over a store. A nil registry gives it one of
// its own, which is what a test observing a single exporter wants; a collector
// is handed the process registry.
func newExporter(st *store, logger *slog.Logger, schemas *Schemas) *exporter {
	if logger == nil {
		logger = slog.Default()
	}
	if schemas == nil {
		schemas = NewSchemas()
	}
	return &exporter{
		store: st, logger: logger, schemas: schemas,
		counters: map[string]metric.Int64ObservableCounter{}, gauges: map[string]metric.Float64ObservableGauge{},
	}
}

// observeCounter stores a cumulative value with its arrival time and
// staleness age, and ensures its instrument. It returns "" when the value was
// stored, or the reason it was dropped. The instrument is ensured FIRST: a
// series refused there must not be left in the store, holding a budget slot
// against a name this collector will never export.
func (e *exporter) observeCounter(name, unit string, attrs []attribute.KeyValue, v int64, ts int64, maxAge time.Duration) string {
	if reason := e.ensureCounter(name, unit); reason != "" {
		return reason
	}
	if !e.store.setCounter(seriesKey{metric: name, attrs: attrKey(attrs)}, v, ts, maxAge, attrs) {
		return dropSeriesLimit
	}
	return ""
}

// observeGauge stores a gauge value with its arrival time and staleness age,
// and ensures its instrument, returning the reason it was dropped or "".
func (e *exporter) observeGauge(name, unit string, attrs []attribute.KeyValue, v float64, ts int64, maxAge time.Duration) string {
	if reason := e.ensureGauge(name, unit); reason != "" {
		return reason
	}
	if !e.store.setGauge(seriesKey{metric: name, attrs: attrKey(attrs)}, v, ts, maxAge, attrs) {
		return dropSeriesLimit
	}
	return ""
}

// admit consults the process registry for a metric name, logging the first
// refusal of each name so a profile set that disagrees says so once rather
// than once per update. It returns "" when the name is this exporter's to
// write, or the reason to drop the observation.
func (e *exporter) admit(name, kind, unit string) string {
	held, first := e.schemas.admit(name, kind, unit)
	if held == nil {
		return ""
	}
	if first {
		e.logger.Warn("refusing a metric that disagrees with the schema its name is already exported with",
			"name", name, "type", kind, "unit", unit, "exported_type", held.kind, "exported_unit", held.unit)
	}
	return dropSchemaConflict
}

// ensureCounter registers the name as a counter in the process registry and
// creates the instrument on first use. It returns the reason to drop the
// observation, or "".
func (e *exporter) ensureCounter(name, unit string) string {
	if reason := e.admit(name, kindCounter, unit); reason != "" {
		return reason
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ""
	}
	if _, ok := e.counters[name]; ok {
		return ""
	}
	m := metrics.GetMeter()
	if m == nil {
		return ""
	}
	inst, err := m.Int64ObservableCounter("gnmi."+name, metric.WithUnit(unit))
	if err != nil {
		e.logger.Error("failed to create counter", "name", name, "error", err)
		return ""
	}
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		e.store.forEach(name, time.Now(), func(_ seriesKey, pt point) {
			o.ObserveInt64(inst, pt.i, metric.WithAttributes(pt.attrs...))
		})
		return nil
	}, inst)
	if err != nil {
		e.logger.Error("failed to register counter callback", "name", name, "error", err)
		return ""
	}
	e.counters[name] = inst
	e.regs = append(e.regs, reg)
	return ""
}

// ensureGauge is ensureCounter for a gauge: the same registration, and the
// same reason back.
func (e *exporter) ensureGauge(name, unit string) string {
	if reason := e.admit(name, kindGauge, unit); reason != "" {
		return reason
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ""
	}
	if _, ok := e.gauges[name]; ok {
		return ""
	}
	m := metrics.GetMeter()
	if m == nil {
		return ""
	}
	inst, err := m.Float64ObservableGauge("gnmi."+name, metric.WithUnit(unit))
	if err != nil {
		e.logger.Error("failed to create gauge", "name", name, "error", err)
		return ""
	}
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		e.store.forEach(name, time.Now(), func(_ seriesKey, pt point) {
			o.ObserveFloat64(inst, pt.f, metric.WithAttributes(pt.attrs...))
		})
		return nil
	}, inst)
	if err != nil {
		e.logger.Error("failed to register gauge callback", "name", name, "error", err)
		return ""
	}
	e.gauges[name] = inst
	e.regs = append(e.regs, reg)
	return ""
}

// register adds a callback the collector owns (the target_up gauge) so
// close unregisters it with the rest.
func (e *exporter) register(reg metric.Registration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.regs = append(e.regs, reg)
}

// close unregisters every callback. Unregister waits for a running
// collection, which takes the store's lock, so it runs with no lock of the
// exporter or the store held.
func (e *exporter) close() {
	e.mu.Lock()
	e.closed = true
	regs := e.regs
	e.regs = nil
	e.mu.Unlock()
	for _, r := range regs {
		_ = r.Unregister()
	}
}
