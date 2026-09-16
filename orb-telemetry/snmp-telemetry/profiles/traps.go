package profiles

import "strings"

// TrapNames collects every trap definition in a resolved set into one map from
// normalised OID to name. Definitions are written with and without a leading
// dot, and gosnmp reports every parsed OID with one, so the key is the form
// with none, matching how the collector normalises.
//
// A definition is either an entry under `traps:` or a flat metric entry whose
// `type` is trap. The loader leaves the latter unfolded, since nothing polls
// a trap, and one bundled file declares all of its traps that way.
//
// A later profile's name for an OID replaces an earlier one's. The bundled set
// has one such collision, in cisco/traps.yml, and this reports the file as
// written; the trap receiver applies the RFC 1215 names on top.
func TrapNames(all []*Profile) map[string]string {
	names := make(map[string]string)
	add := func(oid, name string) {
		oid = normalizeOID(oid)
		if oid == "" || name == "" {
			return
		}
		names[oid] = name
	}
	for _, p := range all {
		for _, def := range p.Traps {
			add(def.OID, def.Name)
		}
		for _, m := range p.Metrics {
			if strings.EqualFold(strings.TrimSpace(m.Type), "trap") {
				add(m.OID, m.Name)
			}
		}
	}
	return names
}
