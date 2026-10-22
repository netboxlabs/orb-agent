package collector

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
)

// exportTick is otel_export_period's default, the cadence the reader collects
// at in these tests.
const exportTick = 10 * time.Second

// visited is the values exportDue hands a collection for one metric of one
// policy at now.
func visited(s *store, metric, policy string, now time.Time) []float64 {
	var out []float64
	s.exportDue(metric, policy, now, func(_ seriesKey, pt point) { out = append(out, pt.f) })
	return out
}

// A sampled value leaves with the first collection after it arrives and with
// none of the collections until the next sample: at a 30 second sample and
// the default export period, one of three collections carries it.
func TestStoreExportsASampleOnce(t *testing.T) {
	s := newStore(10)
	s.setResend("p", 30*time.Second)
	k, attrs := series("g", "1", "p", "a")
	start := time.Unix(1000, 0)
	for sample := range 3 {
		at := start.Add(time.Duration(sample) * 30 * time.Second)
		require.True(t, s.setGauge(k, float64(sample), at.UnixNano(), 3*30*time.Second, attrs))
		assert.Equal(t, []float64{float64(sample)}, visited(s, "g", "p", at.Add(5*time.Second)), "sample %d: the first collection after it", sample)
		assert.Empty(t, visited(s, "g", "p", at.Add(15*time.Second)), "sample %d: the second collection", sample)
		assert.Empty(t, visited(s, "g", "p", at.Add(25*time.Second)), "sample %d: the third collection", sample)
	}
}

// A series the device streams on change carries no age and arrives only when
// it changes. It leaves when it arrives and, while its value holds, once per
// its policy's metrics_interval, not with every collection.
func TestStoreResendsAnOnChangeValueOncePerInterval(t *testing.T) {
	s := newStore(10)
	s.setResend("p", 30*time.Second)
	k, attrs := series("g", "1", "p", "a")
	start := time.Unix(1000, 0)
	require.True(t, s.setGauge(k, 1, start.UnixNano(), 0, attrs))

	var sentAt []time.Duration
	for tick := range 12 {
		at := start.Add(time.Duration(tick)*exportTick + 5*time.Second)
		if len(visited(s, "g", "p", at)) > 0 {
			sentAt = append(sentAt, at.Sub(start))
		}
	}
	assert.Equal(t, []time.Duration{5 * time.Second, 35 * time.Second, 65 * time.Second, 95 * time.Second}, sentAt,
		"with the first collection, then once every 30 seconds")

	// A change leaves at once, and restarts the interval.
	at := start.Add(101 * time.Second)
	require.True(t, s.setGauge(k, 2, at.UnixNano(), 0, attrs))
	assert.Equal(t, []float64{2}, visited(s, "g", "p", at.Add(4*time.Second)))
	assert.Empty(t, visited(s, "g", "p", at.Add(14*time.Second)))
	assert.Empty(t, visited(s, "g", "p", at.Add(24*time.Second)))
	assert.Equal(t, []float64{2}, visited(s, "g", "p", at.Add(34*time.Second)))
}

// A policy whose interval the store does not know re-sends nothing: a value
// with no age that was exported waits for the next change.
func TestStoreWithoutAnIntervalDoesNotResend(t *testing.T) {
	s := newStore(10)
	k, attrs := series("g", "1", "p", "a")
	start := time.Unix(1000, 0)
	require.True(t, s.setGauge(k, 1, start.UnixNano(), 0, attrs))
	assert.Equal(t, []float64{1}, visited(s, "g", "p", start.Add(5*time.Second)))
	assert.Empty(t, visited(s, "g", "p", start.Add(time.Hour)))
}

// Two policies on different intervals, 30 and 300 seconds, in one store and
// one reader collecting every 10 seconds, for ten minutes: each sample of
// each policy leaves exactly once, with the collection after it, whatever
// the other policy is doing.
func TestStorePoliciesOnDifferentIntervalsEachExportOncePerSample(t *testing.T) {
	s := newStore(10)
	intervals := map[string]time.Duration{"every-30s": 30 * time.Second, "every-300s": 300 * time.Second}
	keys := map[string]seriesKey{}
	attrs := map[string][]attribute.KeyValue{}
	for policy, interval := range intervals {
		s.setResend(policy, interval)
		keys[policy], attrs[policy] = series("g", "1", policy, "a")
	}
	start := time.Unix(1000, 0)
	sampled := map[string][]float64{}
	exported := map[string][]float64{}
	for second := 0; second < 600; second++ {
		at := start.Add(time.Duration(second) * time.Second)
		for policy, interval := range intervals {
			if second%int(interval/time.Second) == 0 {
				// The value is the second of the sample, so each export can
				// be traced to the sample it came from.
				require.True(t, s.setGauge(keys[policy], float64(second), at.UnixNano(), 3*interval, attrs[policy]))
				sampled[policy] = append(sampled[policy], float64(second))
			}
		}
		// The collections fall between samples, as they do when the reader
		// and the device's clock start apart.
		if second%10 != 5 {
			continue
		}
		for policy := range intervals {
			for _, v := range visited(s, "g", policy, at) {
				assert.Equal(t, float64(second-5), v, "%s: the collection at %ds exports only the sample just before it", policy, second)
				exported[policy] = append(exported[policy], v)
			}
		}
	}
	require.Len(t, sampled["every-30s"], 20)
	require.Len(t, sampled["every-300s"], 2)
	for policy := range intervals {
		assert.Equal(t, sampled[policy], exported[policy], "%s: every sample exported once, in order", policy)
	}
}

// Through the exporter: an update is observed by the collection after it and
// not by the next, and the next update is observed again, so a reader
// collecting more often than the device samples carries each sample once.
func TestExporterObservesEachUpdateOnce(t *testing.T) {
	reader := testReader(t)
	e := newExporter(newStore(100), nil, nil)
	attrs := []attribute.KeyValue{attribute.String("device_ip", "10.0.0.1")}
	for i, value := range []float64{1, 2, 3} {
		require.Empty(t, e.observeGauge("p", "cpu", "%", attrs, value, time.Now().UnixNano(), age))
		g, ok := collect(t, reader)["gnmi.cpu"].Data.(metricdata.Gauge[float64])
		require.True(t, ok, "update %d: the collection after it carries it", i)
		require.Len(t, g.DataPoints, 1)
		assert.Equal(t, value, g.DataPoints[0].Value)
		_, again := collect(t, reader)["gnmi.cpu"]
		assert.False(t, again, "update %d: the collection after that does not", i)
	}
}

// target_up is observed when it changes and otherwise once per
// metrics_interval, like a value the device streams on change.
func TestLoopUpDueOnChangeAndOncePerInterval(t *testing.T) {
	l := &loop{interval: 30 * time.Second}
	start := time.Unix(1000, 0)
	assert.True(t, l.upDue(1, "on_change", start), "never exported")
	l.upSent = upSample{at: start, value: 1, mode: "on_change"}
	assert.False(t, l.upDue(1, "on_change", start.Add(10*time.Second)))
	assert.False(t, l.upDue(1, "on_change", start.Add(20*time.Second)))
	assert.True(t, l.upDue(1, "on_change", start.Add(30*time.Second)), "an interval has passed")
	assert.True(t, l.upDue(0, "on_change", start.Add(10*time.Second)), "the value changed")
	assert.True(t, l.upDue(1, "sample", start.Add(10*time.Second)), "the mode changed")
}

// Through the collector: a target's up point leaves with the first collection
// after its loop starts, and not with the collections that follow within the
// interval, while the sampled series leave once each as they arrive.
func TestCollectTargetExportsTargetUpOncePerInterval(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Nokia", Encodings: []string{"PROTO"}},
		SubscribeManyFn: streamOf(sample(1394, time.Now().UnixNano())),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("10.0.0.1", "42"), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		by := exportedByPolicy(t, reader)
		_, up := by["p"]["gnmi.target_up"]
		_, octets := by["p"]["gnmi.if_in_octets"]
		return up && octets
	})
	within := exportedWithin(t, reader, 200*time.Millisecond)["p"]
	_, up := within["gnmi.target_up"]
	assert.False(t, up, "target_up left already and its interval has not passed")
	_, octets := within["gnmi.if_in_octets"]
	assert.False(t, octets, "the sample left already and no other arrived")
}
