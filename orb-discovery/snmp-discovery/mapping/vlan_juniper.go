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

// resolveJuniperVlanIndices rewrites dot1qVlanStaticTable rows so they are
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
// Returns the input untouched when the enterprise table was not walked or
// carried nothing. That is the pass-through for every non-Juniper device, and
// also for the Junos platforms whose indices are already tags and answer this
// OID with No Such Object. Those are correct today and must stay that way.
func resolveJuniperVlanIndices(all ObjectIDValueMap, logger *slog.Logger) ObjectIDValueMap {
	tagByIndex := juniperVlanTags(all)
	if len(tagByIndex) == 0 {
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
		tag, known := tagByIndex[index]
		if !known {
			// The static table named a VLAN the enterprise table does not.
			// Its index is not a tag and nothing can say what is, so the row
			// is dropped rather than emitted under a VLAN ID the device never
			// reported.
			dropped++
			continue
		}
		// CoerceVid owns what counts as a VLAN ID, sentinels included. Junos
		// reports its default VLAN with tag 0, which it rejects: neither that
		// tag nor the index it came from may be emitted.
		vid := qbridge.CoerceVid(tag)
		if vid == nil {
			dropped++
			continue
		}
		out[col+strconv.Itoa(*vid)] = v
	}
	if dropped > 0 {
		logger.Warn("vlan: dropped Juniper static-table rows with no usable tag",
			"rows", dropped, "reason", "internal index resolves to no VLAN ID")
	}
	return out
}

// juniperVlanTags reads the enterprise table into index -> tag.
func juniperVlanTags(all ObjectIDValueMap) map[int]int {
	var out map[int]int
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
		if out == nil {
			out = map[int]int{}
		}
		out[index] = tag
	}
	return out
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
