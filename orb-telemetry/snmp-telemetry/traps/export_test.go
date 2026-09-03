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
// once it is used up, a policy whose overflow series does not exist yet has
// its trap counted as a drop under series_limit rather than under a series
// no policy owns. So the map never holds more than the SDK's limit, the SDK
// never folds a series the tally chose to keep, and every series carries the
// policy that can withdraw it.
func TestTally_NeverExceedsTheCardinalityLimit(t *testing.T) {
	tally := NewTally(testLogger)
	for i := range seriesLimit {
		tally.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "core", "linkDown", V2c)
	}
	perPolicyRoom := maxSeries - seriesLimit
	extra := 10
	for i := range perPolicyRoom + extra {
		tally.Received("198.51.100.1", fmt.Sprintf("p%d", i), "linkUp", V2c)
	}
	assert.Equal(t, maxSeries, tally.seriesCount())
	assert.Equal(t, int64(1), tally.receivedCount(OtherName, "p0", OtherName, V2c), "the first overflowing policy got its own series")
	assert.Equal(t, int64(0), tally.receivedCount(OtherName, fmt.Sprintf("p%d", perPolicyRoom), OtherName, V2c), "the first past the reserve did not")
	assert.Equal(t, int64(extra), tally.droppedCount(DropSeriesLimit), "and every one past the reserve is a series_limit drop")
	assert.Equal(t, int64(0), tally.receivedCount(OtherName, OtherName, OtherName, V2c), "no series without a policy")

	tally.Withdraw("p0")
	assert.Equal(t, int64(0), tally.receivedCount(OtherName, "p0", OtherName, V2c), "an overflow series is withdrawn with its policy")
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

// Dormant series are tracked in a set of their own, so the overflow path
// with nothing dormant costs a length check and an eviction costs one pop,
// never a scan of the map. The set follows every transition: withdrawal
// fills it, a revived series leaves it, an eviction takes from it, and a
// count for a still-withdrawn policy leaves it in place.
func TestTally_TracksDormantSeriesInASet(t *testing.T) {
	ta := NewTally(testLogger)
	for i := range seriesLimit {
		ta.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "core", "linkDown", V2c)
	}
	assert.Equal(t, 0, ta.dormantCount())
	ta.Withdraw("core")
	assert.Equal(t, seriesLimit, ta.dormantCount(), "withdrawal makes every series dormant")

	ta.Received("10.0.0.1", "core", "linkDown", V2c)
	assert.Equal(t, seriesLimit, ta.dormantCount(), "a count for a still-withdrawn policy stays dormant")
	ta.Activate("core")
	ta.Received("10.0.0.1", "core", "linkDown", V2c)
	assert.Equal(t, seriesLimit-1, ta.dormantCount(), "a revived series leaves the set")

	ta.Received("192.0.2.1", "edge", "linkUp", V2c)
	assert.Equal(t, seriesLimit-2, ta.dormantCount(), "an eviction takes one from the set")
	assert.Equal(t, seriesLimit, ta.seriesCount())
	assert.Equal(t, int64(1), ta.receivedCount("192.0.2.1", "edge", "linkUp", V2c))
}

// An evicted dormant series keeps its total in a baseline tier, so a series
// that comes back after eviction resumes rather than restarts, and the
// monotonic counter never reads lower than it did.
func TestTally_EvictedSeriesResumeFromTheirBaseline(t *testing.T) {
	ta := NewTally(testLogger)
	for i := range seriesLimit {
		ta.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "core", "linkDown", V2c)
	}
	ta.Received("10.0.0.1", "core", "linkDown", V2c)
	require.Equal(t, int64(2), ta.receivedCount("10.0.0.1", "core", "linkDown", V2c))
	ta.Withdraw("core")
	for i := range seriesLimit {
		ta.Received(fmt.Sprintf("192.%d.%d.%d", i>>16&255, i>>8&255, i&255), "edge", "linkUp", V2c)
	}
	require.Equal(t, seriesLimit, ta.seriesCount(), "every dormant core series was evicted for a live edge one")
	assert.Equal(t, seriesLimit, ta.baselineCount(), "and each left its total behind")

	ta.Withdraw("edge")
	ta.Activate("core")
	ta.Received("10.0.0.1", "core", "linkDown", V2c)
	assert.Equal(t, int64(3), ta.receivedCount("10.0.0.1", "core", "linkDown", V2c), "resumed from the evicted total")
	assert.Equal(t, seriesLimit, ta.baselineCount(), "core's baseline was consumed and the edge series evicted for it left one")
	ta.Received("10.0.0.1", "core", "linkDown", V2c)
	assert.Equal(t, int64(4), ta.receivedCount("10.0.0.1", "core", "linkDown", V2c))
}

// The baseline tier is bounded at the series limit, evicting its oldest
// entry, so the tally's memory is bounded at twice the cap whatever a sender
// or an operator's policy churn does.
func TestTally_BaselinesAreBounded(t *testing.T) {
	ta := NewTally(testLogger)
	fill := func(prefix, policy string) {
		for i := range seriesLimit {
			ta.Received(fmt.Sprintf("%s.%d.%d.%d", prefix, i>>16&255, i>>8&255, i&255), policy, "linkDown", V2c)
		}
		ta.Withdraw(policy)
	}
	fill("10", "a")
	fill("172", "b")
	fill("192", "c")
	assert.Equal(t, maxBaselines, ta.baselineCount())
	assert.LessOrEqual(t, ta.seriesCount()+ta.baselineCount(), 2*maxSeries)
}
