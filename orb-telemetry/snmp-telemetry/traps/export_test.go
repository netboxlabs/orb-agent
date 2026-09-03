package traps

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// F6: a synchronous counter cannot be forgotten. The tally is a map the
// package owns, so a withdrawn policy's series disappears, which is the
// contract every other metric in this backend honours.
func TestTally_WithdrawDropsAPolicysSeries(t *testing.T) {
	ta := NewTally(testLogger)
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	ta.Received("10.0.0.5", "edge", "linkDown", V2c)
	ta.Received("10.0.0.5", "core", "linkDown", V2c)

	assert.Equal(t, int64(2), ta.receivedCount("10.0.0.5", "core", "linkDown", V2c))
	ta.Withdraw("core")
	assert.Equal(t, int64(0), ta.receivedCount("10.0.0.5", "core", "linkDown", V2c))
	assert.Equal(t, int64(1), ta.receivedCount("10.0.0.5", "edge", "linkDown", V2c), "edge is untouched")
}

func TestTally_CountsDropsAndDatagrams(t *testing.T) {
	ta := NewTally(testLogger)
	ta.Datagram()
	ta.Datagram()
	ta.Dropped(DropUnknownSource)
	assert.Equal(t, int64(2), ta.datagramCount())
	assert.Equal(t, int64(1), ta.droppedCount(DropUnknownSource))
	assert.Equal(t, int64(0), ta.droppedCount(DropMalformed))
}

// F8: with no OTLP endpoint there is no meter. Registering must be a no-op,
// not a nil dereference in the receive goroutine.
func TestTally_RegisterWithoutAMeterIsSafe(t *testing.T) {
	metrics.ResetMeter()
	ta := NewTally(testLogger)
	assert.NotPanics(t, func() { ta.Register(); ta.Received("10.0.0.5", "p", "linkDown", V2c); ta.Close() })
}

// The observable counters report what the map holds, with the attribute names
// the polled series already use, so trap counts join to poll metrics.
func TestTally_ExportsThroughObservableCounters(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	metrics.SetMeterForTest(provider.Meter("test"))
	t.Cleanup(metrics.ResetMeter)

	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.Datagram()
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	ta.Dropped(DropUnknownSource)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok, "%s must be a sum", m.Name)
			assert.True(t, sum.IsMonotonic, "%s must be monotonic", m.Name)
			for _, dp := range sum.DataPoints {
				key := m.Name
				for _, kv := range dp.Attributes.ToSlice() {
					key += "|" + string(kv.Key) + "=" + kv.Value.String()
				}
				got[key] = dp.Value
			}
		}
	}
	assert.Equal(t, int64(2), got["snmp.traps_received|device_ip=10.0.0.5|policy=core|trap_name=linkDown|version=2c"])
	assert.Equal(t, int64(1), got["snmp.traps_dropped|reason=unknown_source"])
	assert.Equal(t, int64(1), got["snmp.traps_datagrams"])
}
