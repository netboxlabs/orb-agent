package collector

import "sync"

// The reasons the exporter refuses an observation, counted on
// gnmi.updates_dropped_total.
const (
	dropSeriesLimit    = "series_limit"
	dropSchemaConflict = "schema_conflict"
)

// The instrument kinds a profile metric becomes.
const (
	kindCounter = "counter"
	kindGauge   = "gauge"
)

// schema is how one metric name reaches the SDK: the kind of instrument it
// becomes and the unit it carries.
type schema struct {
	kind string
	unit string
}

// Schemas records the kind and unit each exported metric name was first
// registered with. It belongs to the process, not to a collector, for the
// reason the Budget does: the SDK holds one instrument per metric name however
// many collectors write to it, and the profiles a collector loads are only
// checked for agreement within their own store. Two profile sets that disagree
// about if_in_octets would otherwise have that one instrument created twice
// with different kinds or units and exported as duplicate streams. Safe for
// concurrent use.
//
// A claim is held by the exporters writing the name and released when the
// last of them closes: a claim that outlived its exporters kept a name pinned
// to the schema of a policy long stopped, and a later policy exporting it
// under another kind or unit was refused until the process restarted.
type Schemas struct {
	mu      sync.Mutex
	byName  map[string]schema
	warned  map[string]bool
	holders map[string]int
}

// NewSchemas returns an empty registry, in which the first registration of a
// name is the one the process keeps for as long as an exporter holds it.
func NewSchemas() *Schemas {
	return &Schemas{byName: map[string]schema{}, warned: map[string]bool{}, holders: map[string]int{}}
}

// admit registers a metric name's kind and unit the first time it is seen and
// reports whether this registration agrees with the one held: nil when the
// name is the caller's to write, otherwise the schema it disagrees with.
// firstRefusal is true only on the first refusal of a name, so a profile that
// disagrees is logged once rather than once per update. newHolder says the
// caller does not yet hold the name; an agreeing registration then counts it
// as a holder, to be released by release.
func (s *Schemas) admit(name, kind, unit string, newHolder bool) (conflict *schema, firstRefusal bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, seen := s.byName[name]
	switch {
	case !seen:
		s.byName[name] = schema{kind: kind, unit: unit}
		if newHolder {
			s.holders[name]++
		}
		return nil, false
	case held.kind == kind && held.unit == unit:
		if newHolder {
			s.holders[name]++
		}
		return nil, false
	}
	first := !s.warned[name]
	s.warned[name] = true
	return &held, first
}

// release drops one holder from each name; a name with none left is
// forgotten, so the next registration of it is the one the process keeps.
func (s *Schemas) release(names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range names {
		s.holders[name]--
		if s.holders[name] <= 0 {
			delete(s.holders, name)
			delete(s.byName, name)
			delete(s.warned, name)
		}
	}
}
