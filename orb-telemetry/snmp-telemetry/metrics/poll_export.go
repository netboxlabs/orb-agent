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

// ExportsFailedName counts the exports that still failed after the OTLP
// exporter's own retries. Each poll's values are sent once, so the polls such
// an export carried are lost, and this is where that shows: the count leaves
// with the next export that gets through.
const ExportsFailedName = "snmp.exports_failed"

// pollExporter sends an export that carries a policy's series as it comes,
// and one carrying only the process's own series (the trap receiver's datagram
// and drop counts, the UTF-8 repairs) at most once per IdleExportInterval.
//
// The collector exports each poll's values once, by the first collection
// after the poll, so the collections between two polls carry none of them.
// Sending those anyway would still be one export, and one message to the
// broker, per otel_export_period, which is most of what exporting once per
// poll saves. The process's series are cumulative counters, so an export
// skipped here loses nothing: the next one carries the totals. They leave
// with every poll's export, and the idle bound keeps them current while no
// poll is due.
type pollExporter struct {
	sdkmetric.Exporter

	now  func() time.Time
	mu   sync.Mutex
	last time.Time // when an export was last sent; zero before the first
	// all has every export sent whatever it carries. Shutdown sets it before
	// the provider's own shutdown, whose last collection is the process's
	// final totals: held back, they would wait for an idle interval that
	// never comes.
	all bool
}

func newPollExporter(next sdkmetric.Exporter) *pollExporter {
	return &pollExporter{Exporter: next, now: time.Now}
}

// Export hands rm on when it carries a policy's series, when no export has
// been sent for IdleExportInterval, or after sendAll, and otherwise drops it.
// An export that fails is counted in ExportsFailedName.
func (e *pollExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if !e.sends(rm) {
		return nil
	}
	err := e.Exporter.Export(ctx, rm)
	if err != nil {
		if failed := GetCounter(ExportsFailedName, "Exports that failed after the OTLP exporter's retries, so the polls they carried were lost"); failed != nil {
			failed.Add(ctx, 1)
		}
	}
	return err
}

// sendAll lifts the idle bound: every export from here on is sent.
func (e *pollExporter) sendAll() {
	e.mu.Lock()
	e.all = true
	e.mu.Unlock()
}

func (e *pollExporter) sends(rm *metricdata.ResourceMetrics) bool {
	if rm == nil || len(rm.ScopeMetrics) == 0 {
		return false
	}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.all && !carriesPolicySeries(rm) && !e.last.IsZero() && now.Sub(e.last) < IdleExportInterval {
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
