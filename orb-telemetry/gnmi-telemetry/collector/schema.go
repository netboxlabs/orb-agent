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
type Schemas struct {
	mu     sync.Mutex
	byName map[string]schema
	warned map[string]bool
}

// NewSchemas returns an empty registry, in which the first registration of a
// name is the one the process keeps.
func NewSchemas() *Schemas {
	return &Schemas{byName: map[string]schema{}, warned: map[string]bool{}}
}

// admit registers a metric name's kind and unit the first time it is seen and
// reports whether this registration agrees with the one held: nil when the
// name is the caller's to write, otherwise the schema it disagrees with.
// firstRefusal is true only on the first refusal of a name, so a profile that
// disagrees is logged once rather than once per update.
func (s *Schemas) admit(name, kind, unit string) (conflict *schema, firstRefusal bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, seen := s.byName[name]
	switch {
	case !seen:
		s.byName[name] = schema{kind: kind, unit: unit}
		return nil, false
	case held.kind == kind && held.unit == unit:
		return nil, false
	}
	first := !s.warned[name]
	s.warned[name] = true
	return &held, first
}
