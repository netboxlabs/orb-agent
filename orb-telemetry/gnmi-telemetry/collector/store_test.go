package collector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

// series builds a key and the attribute set behind it, the way the exporter
// does, so the store learns the policy from the attributes.
func series(metric, device, policy, iface string) (seriesKey, []attribute.KeyValue) {
	attrs := []attribute.KeyValue{
		attribute.String("device_ip", device), attribute.String("policy", policy), attribute.String("interface_name", iface),
	}
	return seriesKey{metric: metric, attrs: attrKey(attrs)}, attrs
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
	s.deleteMatching([]attribute.KeyValue{attribute.String("policy", "p2"), attribute.String("interface_name", "a")})
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
	kl, al := series("g", "1", "slow", "long")
	require.True(t, s.setGauge(kf, 1, now.Add(-10*time.Second).UnixNano(), age, af))
	require.True(t, s.setGauge(ks, 1, now.Add(-100*time.Second).UnixNano(), age, as))
	require.True(t, s.setGauge(kl, 1, now.Add(-100*time.Second).UnixNano(), 10*time.Minute, al))
	var seen []string
	s.forEach("g", now, func(k seriesKey, _ point) { seen = append(seen, k.attrs) })
	assert.ElementsMatch(t, []string{kf.attrs, kl.attrs}, seen, "a series is withheld only past its own policy's age")
}

func TestAttrKeyEscapesValues(t *testing.T) {
	a := attrKey([]attribute.KeyValue{attribute.String("k", "a=b;c")})
	b := attrKey([]attribute.KeyValue{attribute.String("k", "a"), attribute.String("b", "c")})
	assert.NotEqual(t, a, b)
}
