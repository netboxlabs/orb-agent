package collector

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/profiles"
)

// staleAfterIntervals is how many metrics_intervals without a notification
// withhold a series from export.
const staleAfterIntervals = 3

// gaugeValue converts an update value for a gauge metric: numbers as is,
// enum strings through the map, booleans to 1 and 0.
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
	case string:
		if n, ok := m.Enum[x]; ok {
			return float64(n), true
		}
		return 0, false
	}
	return 0, false
}

// counterValue converts an update value for a counter: integral, within
// int64. gNMI counters are counter64; a value past int64 is dropped rather
// than wrapped into a false reset.
func counterValue(_ profiles.Metric, v any) (int64, bool) {
	switch x := v.(type) {
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	}
	return 0, false
}

// exporter owns the observable instruments, one per metric name, whose
// callbacks read the store on every export cycle. There is one per
// collector: a second exporter over the same store would observe every
// series twice and the SDK would sum them.
type exporter struct {
	store    *store
	logger   *slog.Logger
	mu       sync.Mutex
	closed   bool
	counters map[string]metric.Int64ObservableCounter
	gauges   map[string]metric.Float64ObservableGauge
	regs     []metric.Registration
}

func newExporter(st *store, logger *slog.Logger) *exporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &exporter{
		store: st, logger: logger,
		counters: map[string]metric.Int64ObservableCounter{}, gauges: map[string]metric.Float64ObservableGauge{},
	}
}

// observeCounter stores a cumulative value with its staleness age and
// ensures its instrument.
func (e *exporter) observeCounter(name, unit string, attrs []attribute.KeyValue, v int64, ts int64, maxAge time.Duration) bool {
	if !e.store.setCounter(seriesKey{metric: name, attrs: attrKey(attrs)}, v, ts, maxAge, attrs) {
		return false
	}
	e.ensureCounter(name, unit)
	return true
}

// observeGauge stores a gauge value with its staleness age and ensures its
// instrument.
func (e *exporter) observeGauge(name, unit string, attrs []attribute.KeyValue, v float64, ts int64, maxAge time.Duration) bool {
	if !e.store.setGauge(seriesKey{metric: name, attrs: attrKey(attrs)}, v, ts, maxAge, attrs) {
		return false
	}
	e.ensureGauge(name, unit)
	return true
}

func (e *exporter) ensureCounter(name, unit string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	if _, ok := e.counters[name]; ok {
		return
	}
	m := metrics.GetMeter()
	if m == nil {
		return
	}
	inst, err := m.Int64ObservableCounter("gnmi."+name, metric.WithUnit(unit))
	if err != nil {
		e.logger.Error("failed to create counter", "name", name, "error", err)
		return
	}
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		e.store.forEach(name, time.Now(), func(_ seriesKey, pt point) {
			o.ObserveInt64(inst, pt.i, metric.WithAttributes(pt.attrs...))
		})
		return nil
	}, inst)
	if err != nil {
		e.logger.Error("failed to register counter callback", "name", name, "error", err)
		return
	}
	e.counters[name] = inst
	e.regs = append(e.regs, reg)
}

func (e *exporter) ensureGauge(name, unit string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	if _, ok := e.gauges[name]; ok {
		return
	}
	m := metrics.GetMeter()
	if m == nil {
		return
	}
	inst, err := m.Float64ObservableGauge("gnmi."+name, metric.WithUnit(unit))
	if err != nil {
		e.logger.Error("failed to create gauge", "name", name, "error", err)
		return
	}
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		e.store.forEach(name, time.Now(), func(_ seriesKey, pt point) {
			o.ObserveFloat64(inst, pt.f, metric.WithAttributes(pt.attrs...))
		})
		return nil
	}, inst)
	if err != nil {
		e.logger.Error("failed to register gauge callback", "name", name, "error", err)
		return
	}
	e.gauges[name] = inst
	e.regs = append(e.regs, reg)
}

// register adds a callback the collector owns (the target_up gauge) so
// close unregisters it with the rest.
func (e *exporter) register(reg metric.Registration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.regs = append(e.regs, reg)
}

// close unregisters every callback. Unregister waits for a running
// collection, which takes the store's read lock, so it runs with no lock of
// the exporter or the store held.
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
