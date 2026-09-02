package traps

import "maps"

// OtherName labels a trap whose OID is in neither the RFC 1215 table nor the
// bundled definitions. It is the only label a sender cannot choose, which is
// the point: a raw OID in a metric label is attacker-controlled and
// unbounded, and the SDK folds everything past its cardinality limit into one
// overflow bucket that answers no question at all.
const OtherName = "other"

// rfc1215 names the six generic traps by the OIDs RFC 3584 section 3.1(3)
// assigns them. It takes precedence over the bundled definitions, one of which
// maps 1.3.6.1.6.3.1.1.5.6 to authenticationFailure.
var rfc1215 = map[string]string{
	"1.3.6.1.6.3.1.1.5.1": "coldStart",
	"1.3.6.1.6.3.1.1.5.2": "warmStart",
	"1.3.6.1.6.3.1.1.5.3": "linkDown",
	"1.3.6.1.6.3.1.1.5.4": "linkUp",
	"1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
	"1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
}

// BuildNames returns the closed set of trap names: the bundled definitions with
// the RFC 1215 names laid over them. Keys are normalised OIDs with no leading
// dot, which is what profiles.TrapNames produces and what Decode emits.
func BuildNames(bundled map[string]string) map[string]string {
	names := make(map[string]string, len(bundled)+len(rfc1215))
	maps.Copy(names, bundled)
	maps.Copy(names, rfc1215)
	return names
}

// NameFor returns the closed-set name for an OID, or OtherName.
func NameFor(names map[string]string, oid string) string {
	if name, ok := names[oid]; ok {
		return name
	}
	return OtherName
}
