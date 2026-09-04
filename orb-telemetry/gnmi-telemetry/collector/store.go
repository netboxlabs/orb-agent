package collector

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

// seriesKey identifies one exported series: a metric name and its attribute
// set rendered as a stable string.
type seriesKey struct {
	metric string
	attrs  string
}

// attrKey renders attributes sorted by key, each value quoted, so two
// orders make one series and no value can forge a separator.
func attrKey(attrs []attribute.KeyValue) string {
	sorted := append([]attribute.KeyValue(nil), attrs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	var b strings.Builder
	for _, kv := range sorted {
		b.WriteString(strconv.Quote(string(kv.Key)))
		b.WriteByte('=')
		b.WriteString(strconv.Quote(kv.Value.String()))
		b.WriteByte(';')
	}
	return b.String()
}

// point is a series' last value: i for counters, f for gauges, the device
// timestamp that set it, the age past which it is withheld from export, and
// how many resets were seen.
type point struct {
	i      int64
	f      float64
	ts     int64
	maxAge time.Duration
	resets int
	attrs  []attribute.KeyValue
	policy string
}

// store keeps the last value per series, bounded per metric name. Bounding
// here rather than only in the SDK keeps a series the backend chose over one
// the SDK would fold into its overflow set.
type store struct {
	mu      sync.RWMutex
	limit   int
	series  map[seriesKey]*point
	perName map[string]int
}

func newStore(perMetricLimit int) *store {
	return &store{limit: perMetricLimit, series: map[seriesKey]*point{}, perName: map[string]int{}}
}

// setCounter records a cumulative value; a value below the last is a reset.
func (s *store) setCounter(k seriesKey, v int64, ts int64, maxAge time.Duration, attrs []attribute.KeyValue) bool {
	return s.set(k, ts, maxAge, attrs, func(pt *point, fresh bool) {
		if !fresh && v < pt.i {
			pt.resets++
		}
		pt.i = v
	})
}

// setGauge records the latest value.
func (s *store) setGauge(k seriesKey, v float64, ts int64, maxAge time.Duration, attrs []attribute.KeyValue) bool {
	return s.set(k, ts, maxAge, attrs, func(pt *point, _ bool) { pt.f = v })
}

func (s *store) set(k seriesKey, ts int64, maxAge time.Duration, attrs []attribute.KeyValue, apply func(*point, bool)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	pt, ok := s.series[k]
	fresh := !ok
	if fresh {
		if s.perName[k.metric] >= s.limit {
			return false
		}
		pt = &point{attrs: attrs, policy: policyOf(attrs)}
		s.series[k] = pt
		s.perName[k.metric]++
	}
	apply(pt, fresh)
	pt.ts = ts
	pt.maxAge = maxAge
	return true
}

func policyOf(attrs []attribute.KeyValue) string {
	for _, kv := range attrs {
		if kv.Key == "policy" {
			return kv.Value.AsString()
		}
	}
	return ""
}

func (s *store) get(k seriesKey) (point, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pt, ok := s.series[k]
	if !ok {
		return point{}, false
	}
	return *pt, true
}

// forEach visits every series of one metric whose device timestamp is within
// its own maxAge of now; a zero timestamp or age is never withheld.
func (s *store) forEach(metric string, now time.Time, visit func(seriesKey, point)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, pt := range s.series {
		if k.metric != metric {
			continue
		}
		if pt.ts != 0 && pt.maxAge > 0 && pt.ts < now.Add(-pt.maxAge).UnixNano() {
			continue
		}
		visit(k, *pt)
	}
}

// forgetPolicy withdraws every series the policy wrote.
func (s *store) forgetPolicy(policy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, pt := range s.series {
		if pt.policy == policy {
			delete(s.series, k)
			s.perName[k.metric]--
		}
	}
}

// deleteMatching withdraws every series carrying all the given attributes,
// whatever else it carries: a deleted list element takes its metrics with it.
func (s *store) deleteMatching(want []attribute.KeyValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, pt := range s.series {
		if hasAll(pt.attrs, want) {
			delete(s.series, k)
			s.perName[k.metric]--
		}
	}
}

func hasAll(have, want []attribute.KeyValue) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h.Key == w.Key && h.Value.String() == w.Value.String() {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
