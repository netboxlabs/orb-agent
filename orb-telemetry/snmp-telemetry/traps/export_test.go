package traps

import (
	"context"
	"fmt"
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

// The map is bounded from the network side. Real series stop at seriesLimit,
// below the SDK's cardinality limit by a reserve; past it, a series that does
// not exist yet is counted under its policy's overflow series, an existing
// series still counts, and a withdrawal frees room.
func TestTally_FoldsNewSeriesPastTheCap(t *testing.T) {
	tally := NewTally(testLogger)
	for i := range seriesLimit {
		tally.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "core", "linkDown", V2c)
	}
	require.Equal(t, seriesLimit, tally.seriesCount())

	tally.Received("192.0.2.1", "core", "linkUp", V2c)
	assert.Equal(t, int64(0), tally.receivedCount("192.0.2.1", "core", "linkUp", V2c), "a new series past the cap is not inserted")
	assert.Equal(t, int64(1), tally.receivedCount(OtherName, "core", OtherName, V2c), "it is counted under the policy's overflow series")

	tally.Received("10.0.0.1", "core", "linkDown", V2c)
	assert.Equal(t, int64(2), tally.receivedCount("10.0.0.1", "core", "linkDown", V2c), "an existing series still counts")

	tally.Received("192.0.2.2", "edge", "linkUp", V3)
	assert.Equal(t, int64(1), tally.receivedCount(OtherName, "edge", OtherName, V3), "the overflow series is per policy and version")

	tally.Withdraw("core")
	tally.Activate("core")
	tally.Received("192.0.2.1", "core", "linkUp", V2c)
	assert.Equal(t, int64(1), tally.receivedCount("192.0.2.1", "core", "linkUp", V2c), "withdrawal frees room")
}

// The overflow series live in the reserve, and the reserve is bounded too:
// once it is down to the slots kept for the process-wide overflow series,
// one per version, a policy whose overflow series does not exist yet is
// counted there. So the map never holds more than the SDK's limit and the
// SDK never folds a series the tally chose to keep.
func TestTally_NeverExceedsTheCardinalityLimit(t *testing.T) {
	tally := NewTally(testLogger)
	for i := range seriesLimit {
		tally.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "core", "linkDown", V2c)
	}
	perPolicyRoom := maxSeries - versionCount - seriesLimit
	extra := 10
	for i := range perPolicyRoom + extra {
		tally.Received("198.51.100.1", fmt.Sprintf("p%d", i), "linkUp", V2c)
	}
	assert.LessOrEqual(t, tally.seriesCount(), maxSeries)
	assert.Equal(t, int64(1), tally.receivedCount(OtherName, "p0", OtherName, V2c), "the first overflowing policy got its own series")
	assert.Equal(t, int64(0), tally.receivedCount(OtherName, fmt.Sprintf("p%d", perPolicyRoom), OtherName, V2c), "the first past the reserve did not")
	assert.Equal(t, int64(extra), tally.receivedCount(OtherName, OtherName, OtherName, V2c), "and every one past the reserve counted process-wide")
}

// The counters are monotonic and the SDK reports a series from the provider's
// start time, so a withdrawn series that reappears under the same attributes
// must not start again at one. A withdrawn series stops being exported, keeps
// its total, and resumes from it.
func TestTally_ResumesATotalWhenAWithdrawnSeriesReappears(t *testing.T) {
	ta := NewTally(testLogger)
	for range 3 {
		ta.Received("10.0.0.5", "core", "linkDown", V2c)
	}
	ta.Withdraw("core")
	assert.Equal(t, int64(0), ta.receivedCount("10.0.0.5", "core", "linkDown", V2c), "not exported while withdrawn")
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	assert.Equal(t, int64(4), ta.receivedCount("10.0.0.5", "core", "linkDown", V2c), "the counter never goes backwards")
}

// A datagram that was past its registry lookup when its policy was withdrawn
// still reaches the tally. It must not bring the series back: a count for a
// withdrawn policy stays dormant, total kept, until the policy is acquired
// again.
func TestTally_CountsForAWithdrawnPolicyStayDormantUntilActivated(t *testing.T) {
	ta := NewTally(testLogger)
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	ta.Withdraw("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	assert.Equal(t, int64(0), ta.receivedCount("10.0.0.5", "core", "linkDown", V2c), "an in-flight count does not revive the series")
	ta.Received("10.0.0.6", "core", "linkUp", V2c)
	assert.Equal(t, int64(0), ta.receivedCount("10.0.0.6", "core", "linkUp", V2c), "nor create a live one")
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	assert.Equal(t, int64(3), ta.receivedCount("10.0.0.5", "core", "linkDown", V2c), "every count was kept")
}

// A retained total is worth less than a live series: at the cap, a dormant
// entry is evicted to make room for a new live one rather than the new one
// being folded.
func TestTally_EvictsDormantSeriesBeforeFolding(t *testing.T) {
	ta := NewTally(testLogger)
	for i := range seriesLimit {
		ta.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "core", "linkDown", V2c)
	}
	ta.Withdraw("core")
	ta.Received("192.0.2.1", "edge", "linkUp", V2c)
	assert.Equal(t, int64(1), ta.receivedCount("192.0.2.1", "edge", "linkUp", V2c), "inserted, not folded")
	assert.Equal(t, int64(0), ta.receivedCount(OtherName, "edge", OtherName, V2c))
	assert.Equal(t, seriesLimit, ta.seriesCount(), "one dormant entry made way")
}

// What the export sees: a withdrawn series is absent from the next
// collection, and when it reappears the exported value is the resumed total,
// never a smaller number than the SDK already reported for that series.
func TestTally_DormantSeriesAreNotExportedAndResumeOnReturn(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	metrics.SetMeterForTest(provider.Meter("test"))
	t.Cleanup(metrics.ResetMeter)

	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	const key = "snmp.traps_received|device_ip=10.0.0.5|policy=core|trap_name=linkDown|version=2c"
	export := func() (int64, bool) {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					k := m.Name
					for _, kv := range dp.Attributes.ToSlice() {
						k += "|" + string(kv.Key) + "=" + kv.Value.String()
					}
					if k == key {
						return dp.Value, true
					}
				}
			}
		}
		return 0, false
	}

	for range 3 {
		ta.Received("10.0.0.5", "core", "linkDown", V2c)
	}
	v, ok := export()
	require.True(t, ok)
	assert.Equal(t, int64(3), v)

	ta.Withdraw("core")
	_, ok = export()
	assert.False(t, ok, "a withdrawn series is not exported")

	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	v, ok = export()
	require.True(t, ok)
	assert.Equal(t, int64(4), v, "the series resumes from its total")
}
