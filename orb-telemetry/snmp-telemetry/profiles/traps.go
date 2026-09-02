package profiles

import "strings"

// TrapNames collects every trap definition in a resolved set into one map from
// normalised OID to name. Definitions are written with and without a leading
// dot, and gosnmp reports every parsed OID with one, so the key is the form
// with none, matching how the collector normalises.
//
// A later profile's name for an OID replaces an earlier one's. The bundled set
// has one such collision, in cisco/traps.yml, and this reports the file as
// written; the trap receiver applies the RFC 1215 names on top.
func TrapNames(all []*Profile) map[string]string {
	names := make(map[string]string)
	for _, p := range all {
		for _, def := range p.Traps {
			oid := strings.TrimPrefix(strings.TrimSpace(def.OID), ".")
			if oid == "" || def.Name == "" {
				continue
			}
			names[oid] = def.Name
		}
	}
	return names
}
