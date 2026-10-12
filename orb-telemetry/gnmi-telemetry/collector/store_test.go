package collector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

// series builds a key and the attribute set behind it, the way the exporter
// does: the policy is part of the key and never an attribute, since the
// exporter names it on the scope.
func series(metric, device, policy, iface string) (seriesKey, []attribute.KeyValue) {
	attrs := []attribute.KeyValue{
		attribute.String("device_ip", device), attribute.String("interface_name", iface),
	}
	return seriesKey{metric: metric, policy: policy, attrs: attrKey(attrs)}, attrs
}

const age = 30 * time.Second

func TestStoreCounterResetStartsANewWindow(t *testing.T) {
	s := newStore(1000)
	k, attrs := series("if_in_octets", "10.0.0.1", "p", "e1")
	require.True(t, s.setCounter(k, 100, 1, age, attrs))
	require.True(t, s.setCounter(k, 150, 2, age, attrs))
	require.True(t, s.setCounter(k, 20, 3, age, attrs), "a lower value is a reset, still stored")
	pt, ok := s.get(k)
	require.True(t, ok)
	assert.Equal(t, int64(20), pt.i)
	assert.Equal(t, 1, pt.resets)
}

func TestStoreBoundsSeriesPerMetric(t *testing.T) {
	s := newStore(2)
	ka, aa := series("g", "1", "p", "a")
	kb, ab := series("g", "1", "p", "b")
	kc, ac := series("g", "1", "p", "c")
	ko, ao := series("other", "1", "p", "a")
	assert.True(t, s.setGauge(ka, 1, 1, age, aa))
	assert.True(t, s.setGauge(kb, 1, 1, age, ab))
	assert.False(t, s.setGauge(kc, 1, 1, age, ac), "the third series of the metric is refused")
	assert.True(t, s.setGauge(ka, 2, 2, age, aa), "an existing series is updated")
	assert.True(t, s.setGauge(ko, 1, 1, age, ao), "the bound is per metric name")
}

func TestStoreForgetPolicyAndDeleteByAttributes(t *testing.T) {
	s := newStore(10)
	k1, a1 := series("g", "1", "p1", "a")
	k2, a2 := series("g", "1", "p2", "a")
	k3, a3 := series("g", "1", "p2", "b")
	require.True(t, s.setGauge(k1, 1, 1, age, a1))
	require.True(t, s.setGauge(k2, 1, 1, age, a2))
	require.True(t, s.setGauge(k3, 1, 1, age, a3))
	s.forgetPolicy("p1")
	_, ok := s.get(k1)
	assert.False(t, ok, "the policy's series is gone")
	_, ok = s.get(k2)
	assert.True(t, ok, "another policy's series stays")
	s.deleteMatching("p2", map[string]struct{}{"g": {}}, []attribute.KeyValue{attribute.String("interface_name", "a")})
	_, ok = s.get(k2)
	assert.False(t, ok, "a series carrying every named attribute is withdrawn")
	_, ok = s.get(k3)
	assert.True(t, ok, "a series differing in one named attribute stays")
}

func TestStoreStalenessIsPerSeries(t *testing.T) {
	s := newStore(10)
	now := time.Unix(1000, 0)
	kf, af := series("g", "1", "p", "fresh")
	ks, as := series("g", "1", "p", "stale")
	kl, al := series("g", "1", "p", "long")
	require.True(t, s.setGauge(kf, 1, now.Add(-10*time.Second).UnixNano(), age, af))
	require.True(t, s.setGauge(ks, 1, now.Add(-100*time.Second).UnixNano(), age, as))
	require.True(t, s.setGauge(kl, 1, now.Add(-100*time.Second).UnixNano(), 10*time.Minute, al))
	var seen []string
	s.forEach("g", "p", now, func(k seriesKey, _ point) { seen = append(seen, k.attrs) })
	assert.ElementsMatch(t, []string{kf.attrs, kl.attrs}, seen, "a series is withheld only past its own policy's age")
	_, ok := s.get(ks)
	assert.False(t, ok, "the series it withheld is dropped, not kept forever")
}

func TestStoreReclaimsStaleSeriesAtItsLimit(t *testing.T) {
	s := newStore(2)
	now := time.Unix(1000, 0)
	kf, af := series("g", "1", "p", "fresh")
	ks, as := series("g", "1", "p", "stale")
	kn, an := series("g", "1", "p", "new")
	require.True(t, s.setGauge(kf, 1, now.Add(-10*time.Second).UnixNano(), age, af))
	require.True(t, s.setGauge(ks, 1, now.Add(-100*time.Second).UnixNano(), age, as))
	require.False(t, s.setGauge(kn, 1, now.UnixNano(), age, an), "the metric is at its limit")
	s.forEach("g", "p", now, func(seriesKey, point) {})
	assert.Len(t, s.series, 1, "the stale series is reclaimed, not only withheld")
	assert.True(t, s.setGauge(kn, 1, now.UnixNano(), age, an), "the slot it freed takes a new series")
}

func TestAttrKeyEscapesValues(t *testing.T) {
	a := attrKey([]attribute.KeyValue{attribute.String("k", "a=b;c")})
	b := attrKey([]attribute.KeyValue{attribute.String("k", "a"), attribute.String("b", "c")})
	assert.NotEqual(t, a, b)
}

func TestStoreSeriesWithNoAgeIsNeverStale(t *testing.T) {
	s := newStore(10)
	now := time.Unix(1000, 0)
	k, attrs := series("g", "1", "p", "on-change")
	require.True(t, s.setGauge(k, 1, now.Add(-time.Hour).UnixNano(), 0, attrs))
	var seen int
	s.forEach("g", "p", now, func(seriesKey, point) { seen++ })
	assert.Equal(t, 1, seen, "a series with no age is exported however old it is")
	_, ok := s.get(k)
	assert.True(t, ok, "and it is not evicted")
}

// The reconcile leans on this: a target back on the SAMPLE rung restates an
// element the on_change rung left ageless, and the restatement has to carry
// the age away with it, or the series is never withheld again.
func TestStoreRestatingASeriesReplacesItsAge(t *testing.T) {
	s := newStore(10)
	now := time.Unix(1000, 0)
	k, attrs := series("g", "1", "p", "e1")
	require.True(t, s.setGauge(k, 1, now.Add(-time.Hour).UnixNano(), 0, attrs))
	require.True(t, s.setGauge(k, 2, now.UnixNano(), age, attrs))
	pt, ok := s.get(k)
	require.True(t, ok)
	assert.Equal(t, age, pt.maxAge, "the restatement's age replaces the one the series had")
}

// The bound protects one SDK instrument per metric name, and every store in
// the process writes to that instrument, so two stores have to count against
// one allowance rather than one each.
func TestStoresShareOneSeriesBudget(t *testing.T) {
	budget := newBudget(2)
	first, second := newStoreOn(budget), newStoreOn(budget)
	k1, a1 := series("g", "10.0.0.1", "p1", "a")
	k2, a2 := series("g", "10.0.0.2", "p2", "b")
	k3, a3 := series("g", "10.0.0.3", "p3", "c")
	require.True(t, first.setGauge(k1, 1, 1, age, a1))
	require.True(t, second.setGauge(k2, 1, 1, age, a2))
	assert.False(t, second.setGauge(k3, 1, 1, age, a3), "the other store's series count against the same bound")
	_, ok := second.get(k3)
	assert.False(t, ok, "a refused series is not stored")

	first.forgetPolicy("p1")
	assert.True(t, second.setGauge(k3, 1, 1, age, a3), "the slot one store frees is one another can take")

	require.False(t, first.setGauge(k1, 1, 1, age, a1), "the allowance is full again")
	second.deleteMatching("p2", map[string]struct{}{"g": {}}, []attribute.KeyValue{
		attribute.String("interface_name", "b"),
	})
	assert.True(t, first.setGauge(k1, 1, 1, age, a1), "a slot a delete frees in one store is one another can take")
}

// Two policies writing the same metric with the same attributes are two
// series: the policy is part of the key, so nothing about the attributes
// has to tell them apart.
func TestStoreKeepsPoliciesApart(t *testing.T) {
	s := newStore(10)
	k1, a1 := series("g", "1", "p1", "a")
	k2, a2 := series("g", "1", "p2", "a")
	require.NotEqual(t, k1, k2)
	require.True(t, s.setGauge(k1, 1, 1, age, a1))
	require.True(t, s.setGauge(k2, 2, 1, age, a2))
	pt1, ok := s.get(k1)
	require.True(t, ok)
	pt2, ok := s.get(k2)
	require.True(t, ok)
	assert.Equal(t, 1.0, pt1.f)
	assert.Equal(t, 2.0, pt2.f)
}

// A delete or a reconcile speaks for one policy's target. With the policy
// gone from the attributes, the policy argument is what keeps it from
// withdrawing another policy's series on the same device.
func TestStoreDeleteAndEvictAreScopedToThePolicy(t *testing.T) {
	s := newStore(10)
	k1, a1 := series("g", "1", "p1", "a")
	k2, a2 := series("g", "1", "p2", "a")
	require.True(t, s.setGauge(k1, 1, 5, 0, a1))
	require.True(t, s.setGauge(k2, 1, 5, 0, a2))

	s.deleteMatching("p1", nil, []attribute.KeyValue{attribute.String("device_ip", "1")})
	_, ok := s.get(k1)
	assert.False(t, ok, "the named policy's series is withdrawn")
	_, ok = s.get(k2)
	assert.True(t, ok, "the other policy's series on the same device stays")

	require.True(t, s.setGauge(k1, 1, 5, 0, a1))
	s.evictBefore("p2", nil, []attribute.KeyValue{attribute.String("device_ip", "1")}, 10)
	_, ok = s.get(k2)
	assert.False(t, ok, "the named policy's ageless series older than the mark is evicted")
	_, ok = s.get(k1)
	assert.True(t, ok, "the other policy's series stays")
}

// forEach visits one policy's series of a metric and nobody else's, and
// still evicts the aged series it visits.
func TestStoreForEachIsScopedToThePolicy(t *testing.T) {
	s := newStore(10)
	now := time.Unix(1000, 0)
	k1, a1 := series("g", "1", "p1", "a")
	k2, a2 := series("g", "1", "p2", "a")
	ks, as := series("g", "1", "p1", "stale")
	require.True(t, s.setGauge(k1, 1, now.UnixNano(), age, a1))
	require.True(t, s.setGauge(k2, 2, now.UnixNano(), age, a2))
	require.True(t, s.setGauge(ks, 3, now.Add(-2*age).UnixNano(), age, as))

	var seen []float64
	s.forEach("g", "p1", now, func(_ seriesKey, pt point) { seen = append(seen, pt.f) })
	assert.Equal(t, []float64{1}, seen, "only p1's fresh series is visited")
	_, ok := s.get(ks)
	assert.False(t, ok, "p1's stale series is dropped in the same pass")
	_, ok = s.get(k2)
	assert.True(t, ok, "p2's series is neither visited nor touched")
}

// indexKeys flattens the store's policy index back to a flat key set, so a
// test can compare it against series's key set directly: the two must hold
// exactly the same keys after every operation that inserts into or removes
// from the store, or forEach would either miss a live series through the
// index or visit one that series no longer has.
func indexKeys(s *store) map[seriesKey]struct{} {
	out := map[seriesKey]struct{}{}
	for _, byMetric := range s.index {
		for _, byKey := range byMetric {
			for k := range byKey {
				out[k] = struct{}{}
			}
		}
	}
	return out
}

func seriesKeys(s *store) map[seriesKey]struct{} {
	out := map[seriesKey]struct{}{}
	for k := range s.series {
		out[k] = struct{}{}
	}
	return out
}

// Every path that inserts into or removes from series has its own copy of
// the same bookkeeping against the policy index: a fresh set, a stale drop
// inside forEach, deleteMatching, evictBefore, forgetPolicy and releaseAll.
// This walks all six and checks after each one that the index reaches
// exactly the keys series does, no more and no fewer.
func TestStoreIndexStaysInStepWithSeries(t *testing.T) {
	s := newStore(100)
	now := time.Unix(1000, 0)
	assertInStep := func() {
		t.Helper()
		assert.Equal(t, seriesKeys(s), indexKeys(s), "index and series must hold exactly the same keys")
	}
	assertInStep()

	k1, a1 := series("m1", "1", "p1", "a")
	k2, a2 := series("m1", "1", "p1", "b")
	k3, a3 := series("m2", "1", "p1", "a")
	k4, a4 := series("m1", "1", "p2", "a")
	kStale, aStale := series("m2", "1", "p1", "stale")
	require.True(t, s.setGauge(k1, 1, now.UnixNano(), age, a1))
	require.True(t, s.setGauge(k2, 1, now.UnixNano(), age, a2))
	require.True(t, s.setGauge(k3, 1, now.UnixNano(), age, a3))
	require.True(t, s.setGauge(k4, 1, now.UnixNano(), age, a4))
	require.True(t, s.setGauge(kStale, 1, now.Add(-2*age).UnixNano(), age, aStale))
	assertInStep()

	// forEach's stale drop removes kStale in the same pass it visits m2/p1.
	var seen []seriesKey
	s.forEach("m2", "p1", now, func(k seriesKey, _ point) { seen = append(seen, k) })
	assert.Equal(t, []seriesKey{k3}, seen)
	_, ok := s.get(kStale)
	assert.False(t, ok)
	assertInStep()

	// deleteMatching withdraws k1 by its attributes and leaves k2.
	s.deleteMatching("p1", map[string]struct{}{"m1": {}}, []attribute.KeyValue{attribute.String("interface_name", "a")})
	_, ok = s.get(k1)
	assert.False(t, ok)
	_, ok = s.get(k2)
	assert.True(t, ok)
	assertInStep()

	// evictBefore withdraws an ageless series older than the mark.
	kOld, aOld := series("m1", "1", "p1", "old")
	require.True(t, s.setGauge(kOld, 1, now.Add(-time.Hour).UnixNano(), 0, aOld))
	assertInStep()
	s.evictBefore("p1", nil, nil, now.UnixNano())
	_, ok = s.get(kOld)
	assert.False(t, ok)
	assertInStep()

	// forgetPolicy withdraws everything p1 still has (k2, k3) and leaves p2's.
	s.forgetPolicy("p1")
	_, ok = s.get(k2)
	assert.False(t, ok)
	_, ok = s.get(k3)
	assert.False(t, ok)
	_, ok = s.get(k4)
	assert.True(t, ok, "p2's series survives p1's forgetPolicy")
	assertInStep()

	// releaseAll withdraws everything left, including p2's.
	s.releaseAll()
	assert.Empty(t, s.series)
	assertInStep()
}
