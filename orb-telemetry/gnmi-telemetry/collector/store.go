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

// point is a series' last value: i for counters, f for gauges, the local time
// the update that set it arrived, the age past which it is withheld from
// export, and how many resets were seen.
type point struct {
	i      int64
	f      float64
	ts     int64
	maxAge time.Duration
	resets int
	attrs  []attribute.KeyValue
	policy string
}

// store keeps the last value per series, bounded per metric name by a budget.
// Bounding here rather than only in the SDK keeps a series the backend chose
// over one the SDK would fold into its overflow set. The count lives on the
// budget rather than here because every store in the process writes to the
// same instruments and so draws on one allowance.
type store struct {
	mu     sync.RWMutex
	budget *Budget
	series map[seriesKey]*point
}

// newStore gives one store a budget of its own. A collector sharing the
// process budget is built on newStoreOn instead.
func newStore(perMetricLimit int) *store {
	return newStoreOn(newBudget(perMetricLimit))
}

func newStoreOn(budget *Budget) *store {
	return &store{budget: budget, series: map[seriesKey]*point{}}
}

// setCounter records a cumulative value at its arrival time; a value below
// the last is a reset.
func (s *store) setCounter(k seriesKey, v int64, ts int64, maxAge time.Duration, attrs []attribute.KeyValue) bool {
	return s.set(k, ts, maxAge, attrs, func(pt *point, fresh bool) {
		if !fresh && v < pt.i {
			pt.resets++
		}
		pt.i = v
	})
}

// setGauge records the latest value at its arrival time.
func (s *store) setGauge(k seriesKey, v float64, ts int64, maxAge time.Duration, attrs []attribute.KeyValue) bool {
	return s.set(k, ts, maxAge, attrs, func(pt *point, _ bool) { pt.f = v })
}

func (s *store) set(k seriesKey, ts int64, maxAge time.Duration, attrs []attribute.KeyValue, apply func(*point, bool)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	pt, ok := s.series[k]
	fresh := !ok
	if fresh {
		if !s.budget.take(k.metric) {
			return false
		}
		pt = &point{attrs: attrs, policy: policyOf(attrs)}
		s.series[k] = pt
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

// forEach visits every series of one metric whose last update arrived within
// its own maxAge of now. A series with no age is never withheld, which is how
// a leaf the device streams on change keeps its last value until the device
// deletes it. A series past its age is dropped as it is withheld, in the same
// pass: withholding it alone would leave it holding a slot of the metric's
// bound forever, and a device that renamed its interfaces would eventually
// refuse every new series. Deleting during the range is defined behaviour in
// Go, and the write lock is held for it; visit must not call back into the
// store.
func (s *store) forEach(metric string, now time.Time, visit func(seriesKey, point)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, pt := range s.series {
		if k.metric != metric {
			continue
		}
		if pt.maxAge > 0 && pt.ts < now.Add(-pt.maxAge).UnixNano() {
			delete(s.series, k)
			s.budget.release(k.metric)
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
			s.budget.release(k.metric)
		}
	}
}

// releaseAll withdraws every series the store holds and returns each one's
// slot to the budget. A closed collector's series are never exported again, so
// a slot it kept would be one no store in the process could ever use. The
// manager forgets a policy before it releases the collector that ran it, which
// frees them by the other path, but a collector must not depend on its caller
// for that.
func (s *store) releaseAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.series {
		s.budget.release(k.metric)
	}
	s.series = map[seriesKey]*point{}
}

// deleteMatching withdraws every series of one of the named metrics that
// carries all the given attributes, whatever else it carries: a deleted list
// element takes its metrics with it. The names bound the blast radius: a
// delete of a container names an ancestor of several subscriptions and
// carries no keys, so the attributes alone would match every series of the
// device and policy, including subtrees the delete says nothing about.
func (s *store) deleteMatching(names map[string]struct{}, want []attribute.KeyValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, pt := range s.series {
		if _, ok := names[k.metric]; !ok {
			continue
		}
		if hasAll(pt.attrs, want) {
			delete(s.series, k)
			s.budget.release(k.metric)
		}
	}
}

// evictBefore withdraws every never-stale series of one of the named metrics
// that carries all the given attributes and whose last update arrived before
// the given time. It is how a reconnected stream withdraws what its initial
// dump no longer mentions: a series with no age is refreshed only when the
// device sends the leaf, so an element removed while the stream was down would
// otherwise keep its last value for ever. An aged series is left alone, its own
// age being what withdraws it.
//
// A nil name set means every metric, which is what a stream that subscribed to
// the whole profile reconciles against. A caller that covered only part of the
// profile names the metrics it covered: a snapshot says nothing about a
// subtree it never asked for, so it must not withdraw one.
func (s *store) evictBefore(names map[string]struct{}, want []attribute.KeyValue, before int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, pt := range s.series {
		if pt.maxAge != 0 || pt.ts >= before {
			continue
		}
		if names != nil {
			if _, ok := names[k.metric]; !ok {
				continue
			}
		}
		if hasAll(pt.attrs, want) {
			delete(s.series, k)
			s.budget.release(k.metric)
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
