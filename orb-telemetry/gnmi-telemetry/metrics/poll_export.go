package metrics

import (
	"context"
	"sync"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// IdleExportInterval bounds how often an export carrying none of a policy's
// series is sent.
const IdleExportInterval = time.Minute

// pollExporter sends an export that carries a policy's series as it comes,
// and one carrying only the process's own series (the health counters: drops,
// reconnects, fallbacks, notifications, active targets) at most once per
// IdleExportInterval.
//
// The collector exports each update once, by the first collection after it,
// and a value the device streams on change, and target_up, once per
// metrics_interval while they hold, so the collections between those carry
// none of a policy's series. Sending them anyway would still be one export,
// and one message to the broker, per otel_export_period, which is most of what
// exporting once per update saves. The process's series are cumulative sums,
// so an export skipped here loses nothing: the next one carries the totals.
// They leave with every export that carries a policy's series, and the idle
// bound keeps them current while none is due.
type pollExporter struct {
	sdkmetric.Exporter

	now  func() time.Time
	mu   sync.Mutex
	last time.Time // when an export was last sent; zero before the first
}

func newPollExporter(next sdkmetric.Exporter) *pollExporter {
	return &pollExporter{Exporter: next, now: time.Now}
}

// Export hands rm on when it carries a policy's series, or when no export
// has been sent for IdleExportInterval, and otherwise drops it.
func (e *pollExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if !e.sends(rm) {
		return nil
	}
	return e.Exporter.Export(ctx, rm)
}

func (e *pollExporter) sends(rm *metricdata.ResourceMetrics) bool {
	if rm == nil || len(rm.ScopeMetrics) == 0 {
		return false
	}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !carriesPolicySeries(rm) && !e.last.IsZero() && now.Sub(e.last) < IdleExportInterval {
		return false
	}
	e.last = now
	return true
}

// carriesPolicySeries reports whether rm holds a scope of a policy's. The SDK
// leaves out a scope with no datapoint, so one that is there has data.
func carriesPolicySeries(rm *metricdata.ResourceMetrics) bool {
	for _, sm := range rm.ScopeMetrics {
		if _, ok := sm.Scope.Attributes.Value(PolicyNameAttribute); ok && len(sm.Metrics) > 0 {
			return true
		}
	}
	return false
}
