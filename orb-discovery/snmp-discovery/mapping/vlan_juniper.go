package mapping

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping/qbridge"
)

// oidJnxExVlanTag is JUNIPER-VLAN-MIB jnxExVlanTag, the real 802.1Q tag of a
// VLAN the switch indexes internally. Walked only on Juniper, and absent on
// the Junos platforms that index dot1qVlanStaticTable by the tag already.
const oidJnxExVlanTag = ".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5."

// dot1qVlanStaticColumns are the columns of dot1qVlanStaticTable, all of them
// keyed by the same VlanIndex. Rekeying one and not the others would pair a
// VLAN's name with another VLAN's ports.
var dot1qVlanStaticColumns = []string{
	oidDot1qVlanStaticName,
	oidDot1qVlanStaticEgressPorts,
	oidDot1qVlanStaticUntaggedPorts,
	oidDot1qVlanStaticRowStatus,
}

// ResolveJuniperVlanIndices rewrites dot1qVlanStaticTable rows so they are
// keyed by the VLAN's real tag rather than the switch's internal index.
//
// RFC 4363 defines dot1qVlanIndex as "the VLAN-ID **or other identifier**",
// and some Junos platforms take the second half of that: the table is indexed
// by an internal number, so a VLAN configured as 156 is read as VLAN 17. The
// tag is only available from the enterprise table, which is why this is
// vendor-scoped rather than a general repair.
//
// Rewriting the walked rows, rather than translating at each place an index
// becomes a VID, is deliberate: PostMap hands the same map to the catalog,
// the port masks and the row-status reader, and a translation applied at some
// of those and not others would pair one VLAN's name with another's ports.
// Doing it once, before anything reads them, makes that class of mistake
// unavailable.
//
// Translation is all-or-nothing, and happens only when the enterprise table
// explains EVERY static-table index. Presence of that table is not evidence
// that the static table is index-keyed: the two are independent properties of
// a Junos build, and a device publishing the enterprise table while already
// keying the static table by the tag would have every lookup miss. Acting on
// the weaker signal would delete every VLAN such a device reports correctly
// today, or, where a tag happens to also be a valid index, emit one VLAN's
// rows under another VLAN's ID.
//
// Requiring full coverage also settles the partial walk. The walk layer keeps
// what it collected when a table ends early, so a truncated enterprise table
// arrives short but non-empty; translating then would silently delete every
// static row past the cut. An incomplete answer is not grounds to remove
// VLANs that are being emitted today.
//
// So the input is returned untouched whenever the table is absent, empty,
// incomplete, or keyed in a different space. That covers every non-Juniper
// device and the Junos platforms whose indices are already tags, which are
// correct as they are.
// Idempotent: a second call finds the static table keyed by tags, which the
// enterprise table does not describe, so the coverage check returns the input
// unchanged. That is what lets the runner and VlanMapper each normalise
// without coordinating.
func ResolveJuniperVlanIndices(all ObjectIDValueMap, logger *slog.Logger) ObjectIDValueMap {
	tagByIndex, described := juniperVlanTags(all, logger)
	if len(described) == 0 {
		return all
	}
	// Coverage is checked against every index the table DESCRIBED, including
	// those whose tag was refused as ambiguous. The two questions are
	// different: coverage asks whether the table is keyed in the same space
	// as the static table, ambiguity asks whether one row is usable. Counting
	// a refused row as unexplained would let a single contradictory tag
	// abandon the translation for the whole device, which falls back to
	// emitting internal indices as VLAN IDs: worse than dropping the one
	// VLAN nobody can resolve.
	if missing, total := staticIndicesNotIn(all, described); missing > 0 {
		logger.Warn("vlan: not translating Juniper VLAN indices; the enterprise table does not describe them",
			"static_rows", total, "unexplained", missing,
			"reason", "table incomplete, or keyed in a different space from the static table")
		return all
	}

	out := make(ObjectIDValueMap, len(all))
	dropped := 0
	for oid, v := range all {
		col, index, ok := splitStaticVlanOID(oid)
		if !ok {
			out[oid] = v
			continue
		}
		// CoerceVid owns what counts as a VLAN ID, sentinels included. Junos
		// reports its default VLAN with tag 0, which it rejects: neither that
		// tag nor the index it came from may be emitted.
		tag, usable := tagByIndex[index]
		vid := qbridge.CoerceVid(tag)
		if !usable || vid == nil {
			dropped++
			continue
		}
		out[col+strconv.Itoa(*vid)] = v
	}
	if dropped > 0 {
		// Debug rather than warn. Junos reports its default VLAN with tag 0,
		// so a healthy switch reaches this on every poll forever, and a
		// warning that fires on normal operation is one nobody reads.
		logger.Debug("vlan: dropped Juniper static-table rows whose tag is not a VLAN ID",
			"rows", dropped, "reason", "tag outside 1-4094, which is how Junos reports an untagged domain")
	}
	return out
}

// staticIndicesNotIn reports how many distinct dot1qVlanStaticTable indices
// the tag map does not describe, and how many there were in total.
func staticIndicesNotIn(all ObjectIDValueMap, described map[int]struct{}) (missing, total int) {
	seen := map[int]struct{}{}
	for oid := range all {
		_, index, ok := splitStaticVlanOID(oid)
		if !ok {
			continue
		}
		if _, dup := seen[index]; dup {
			continue
		}
		seen[index] = struct{}{}
		total++
		if _, known := described[index]; !known {
			missing++
		}
	}
	return missing, total
}

// juniperVlanTags reads the enterprise table into index -> tag, dropping any
// tag more than one index claims.
//
// A tag two indices both claim cannot be resolved, and guessing is worse than
// it looks: the rows are rewritten one OID at a time, so the name column would
// keep whichever index Go's map iteration happened to yield last while the
// ports column kept the other, pairing one VLAN's name with another VLAN's
// ports. Map order is not stable, so that pairing would differ between polls
// of identical data and the VLAN would be rewritten on every ingest. Neither
// index survives, because nothing available says which one owns the tag.
//
// Not observed on the reported switches, whose tags are distinct. Guarded
// because the cost of being wrong is silent and recurring, and the device is
// the one asserting something impossible.
// Returns the usable index -> tag map, and the set of indices the table
// described at all, refused ones included. The caller needs both: see
// ResolveJuniperVlanIndices for why they answer different questions.
func juniperVlanTags(all ObjectIDValueMap, logger *slog.Logger) (map[int]int, map[int]struct{}) {
	indicesByTag := map[int][]int{}
	for oid, v := range all {
		if !strings.HasPrefix(oid, oidJnxExVlanTag) {
			continue
		}
		index, ok := atoi(strings.TrimPrefix(oid, oidJnxExVlanTag))
		if !ok {
			continue
		}
		tag, ok := atoi(trimSNMPString(v.Value))
		if !ok {
			continue
		}
		indicesByTag[tag] = append(indicesByTag[tag], index)
	}

	out := map[int]int{}
	described := map[int]struct{}{}
	for tag, indices := range indicesByTag {
		for _, i := range indices {
			described[i] = struct{}{}
		}
		if len(indices) > 1 {
			logger.Warn("vlan: refusing an ambiguous Juniper VLAN tag",
				"tag", tag, "claimed_by_indices", len(indices),
				"reason", "more than one internal index reports this tag")
			continue
		}
		out[indices[0]] = tag
	}
	return out, described
}

// splitStaticVlanOID splits a dot1qVlanStaticTable OID into its column prefix
// and its VlanIndex. Reports false for anything else, including the other
// Q-BRIDGE tables: dot1qPvid carries a VLAN value rather than a VLAN index in
// its OID, and on the reported switch that value is already the real tag, so
// putting it through this translation would read a tag as an index.
func splitStaticVlanOID(oid string) (column string, index int, ok bool) {
	for _, col := range dot1qVlanStaticColumns {
		if !strings.HasPrefix(oid, col) {
			continue
		}
		index, ok := atoi(strings.TrimPrefix(oid, col))
		if !ok {
			return "", 0, false
		}
		return col, index, true
	}
	return "", 0, false
}

// stripVlanNameTagSuffix removes the "+<tag>" a Junos ELS switch appends to a
// bridge domain's name, leaving the name an operator would recognise.
//
// Anchored on the VLAN's own id rather than on the separator: an operator may
// legitimately put a plus and a number in a name, and only the device's own
// convention pairs the suffix with the id it is describing. A name that is
// nothing but the suffix keeps it, since removing it would leave the VLAN
// nameless.
func stripVlanNameTagSuffix(name string, vid int) string {
	suffix := "+" + strconv.Itoa(vid)
	if !strings.HasSuffix(name, suffix) {
		return name
	}
	trimmed := strings.TrimSuffix(name, suffix)
	if trimmed == "" {
		return name
	}
	return trimmed
}

// isJuniper reports whether the walked sysObjectID is under Juniper's
// enterprise arc.
func isJuniper(all ObjectIDValueMap) bool {
	v, ok := all[oidSysObjectIDScalar]
	if !ok {
		return false
	}
	return strings.HasPrefix("."+strings.TrimPrefix(trimSNMPString(v.Value), "."), juniperEnterprise)
}
