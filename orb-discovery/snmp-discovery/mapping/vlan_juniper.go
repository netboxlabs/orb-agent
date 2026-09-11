package mapping

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping/qbridge"
)

// JUNIPER-VLAN-MIB jnxExVlanTable columns. Walked only on Juniper, and absent
// on the Junos platforms that index dot1qVlanStaticTable by the tag already.
//
// jnxExVlanTag carries the real 802.1Q tag of a VLAN the switch indexes
// internally. jnxExVlanName carries the same name dot1qVlanStaticName does,
// and is what lets the two tables be checked against each other.
const (
	oidJnxExVlanName = ".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.2."
	oidJnxExVlanTag  = ".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5."
)

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
// becomes a VID, is deliberate: the same map reaches the VLAN catalog, the
// port masks, the row-status reader and the SVI resolver, and a translation
// applied at some of those and not others would pair one VLAN's name with
// another's ports. Doing it once, before anything reads them, makes that class
// of mistake unavailable. Call it exactly once per target, from the runner.
//
// # What has to be true before anything is rewritten
//
// Rewriting is all-or-nothing, and every gate below has to pass. Presence of
// the enterprise table is NOT on its own evidence that the static table is
// index-keyed: the two are independent properties of a Junos build, and a
// device publishing the enterprise table while already keying the static table
// by the tag would have every row rewritten to some other VLAN's ID. That
// device's VLANs are correct today, so the bar is evidence, not plausibility.
//
//  1. The enterprise table must resolve EVERY static row to a readable tag.
//     Partial coverage means the two are keyed in different spaces, or the walk
//     was truncated — the walk layer keeps what it collected when a table ends
//     early, so a truncated table arrives short but non-empty. Rewriting then
//     would silently delete every static row past the cut.
//  2. No two static rows may claim the same tag. Nothing available says which
//     one owns it.
//  3. The two tables must agree on at least one VLAN's name, and disagree
//     about none. This is the gate that catches a tag-keyed static table whose
//     keys happen to also be valid enterprise indices, where counting rows
//     alone is satisfied and every VLAN would be re-emitted under a stranger's
//     ID. The device generates both names from one configuration, so equality
//     at an index is the device confirming the two rows describe one VLAN;
//     inequality is it denying the premise.
//
// Failing any of them returns the input untouched, with a warning naming which
// one and why. The device then reports internal indices as VLAN IDs, which is
// the bug this fixes — but an unrepaired VLAN an operator can see in a log is
// recoverable, and a VLAN silently re-identified as a different one is not.
//
// Returned untouched and silently when there is no enterprise table at all:
// that is every non-Juniper device and the Junos platforms whose indices are
// already tags, which are correct as they are.
func ResolveJuniperVlanIndices(all ObjectIDValueMap, logger *slog.Logger) ObjectIDValueMap {
	staticIndices := staticVlanIndices(all)
	if len(staticIndices) == 0 {
		return all
	}
	tagByIndex, nameByIndex, described := juniperVlanTable(all)
	if len(described) == 0 {
		return all
	}

	if missing, unreadable := staticRowsUnresolved(staticIndices, tagByIndex, described); missing+unreadable > 0 {
		logger.Warn("vlan: not translating Juniper VLAN indices; the tag table does not resolve every static row",
			"static_rows", len(staticIndices), "not_described", missing, "tag_unreadable", unreadable,
			"reason", "the tag table is incomplete, keyed in a different space from the static table, or answered with a value that is not a tag")
		return all
	}
	if tag, claimants, ambiguous := ambiguousStaticTag(staticIndices, tagByIndex); ambiguous {
		logger.Warn("vlan: not translating Juniper VLAN indices; two static rows claim one tag",
			"tag", tag, "claimed_by_indices", claimants,
			"reason", "the device reports one 802.1Q tag for more than one VLAN, so no row can be attributed to it")
		return all
	}
	agreed, disagreed, firstDisagreement := corroborateVlanNames(all, staticIndices, tagByIndex, nameByIndex)
	if disagreed > 0 {
		logger.Warn("vlan: not translating Juniper VLAN indices; the two VLAN tables disagree about what they describe",
			"agreed", agreed, "disagreed", disagreed, "first_disagreeing_index", firstDisagreement,
			"reason", "dot1qVlanStaticName and jnxExVlanName name different VLANs at the same index, so the static table is keyed in a different space")
		return all
	}
	if agreed == 0 {
		logger.Warn("vlan: not translating Juniper VLAN indices; nothing corroborates that the two VLAN tables are keyed alike",
			"static_rows", len(staticIndices),
			"reason", "no index carries a name in both dot1qVlanStaticName and jnxExVlanName")
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
		// reports an untagged bridge domain with tag 0, which it rejects.
		//
		// This is the one per-row drop, and the only one that is safe to make.
		// A dropped row leaves no VLAN entity, so anything still naming that
		// VID would have VlanMapper fabricate a "VLAN<vid>" placeholder for it
		// — and Diode PATCHes, so the placeholder would rename the operator's
		// VLAN in NetBox. Nothing can name this one: the only other reference
		// is dot1qPvid, gated by the same CoerceVid. The gates above exist so
		// that every row we cannot resolve for any OTHER reason abandons the
		// translation entirely rather than dropping a row whose VID something
		// else still names.
		vid := qbridge.CoerceVid(tagByIndex[index])
		if vid == nil {
			dropped++
			continue
		}
		out[col+strconv.Itoa(*vid)] = v
	}
	if dropped > 0 {
		// Debug rather than warn: a healthy switch reaches this on every poll
		// forever, and a warning that fires during normal operation is one
		// nobody reads.
		logger.Debug("vlan: dropped Juniper static-table rows whose tag is not a VLAN ID",
			"rows", dropped, "reason", "tag outside 1-4094, which is how Junos reports an untagged bridge domain")
	}
	return out
}

// staticVlanIndices collects the distinct VlanIndex values dot1qVlanStaticTable
// was walked with.
func staticVlanIndices(all ObjectIDValueMap) map[int]struct{} {
	out := map[int]struct{}{}
	for oid := range all {
		if _, index, ok := splitStaticVlanOID(oid); ok {
			out[index] = struct{}{}
		}
	}
	return out
}

// juniperVlanTable reads jnxExVlanTable into index -> tag and index -> name,
// plus the set of indices the table has a row for at all.
//
// described is deliberately wider than tagByIndex: an index whose tag will not
// parse still proves the table HAS that row, which is a different fact from
// whether the row is usable. Reporting only the parsed tags would let the
// caller read an unreadable value as "the table is keyed in another space".
func juniperVlanTable(all ObjectIDValueMap) (tagByIndex map[int]int, nameByIndex map[int]string, described map[int]struct{}) {
	tagByIndex = map[int]int{}
	nameByIndex = map[int]string{}
	described = map[int]struct{}{}
	for oid, v := range all {
		switch {
		case strings.HasPrefix(oid, oidJnxExVlanTag):
			index, ok := atoi(strings.TrimPrefix(oid, oidJnxExVlanTag))
			if !ok {
				continue
			}
			described[index] = struct{}{}
			if tag, ok := atoi(trimSNMPString(v.Value)); ok {
				tagByIndex[index] = tag
			}
		case strings.HasPrefix(oid, oidJnxExVlanName):
			index, ok := atoi(strings.TrimPrefix(oid, oidJnxExVlanName))
			if !ok {
				continue
			}
			described[index] = struct{}{}
			if name := trimSNMPString(v.Value); name != "" {
				nameByIndex[index] = name
			}
		}
	}
	return tagByIndex, nameByIndex, described
}

// staticRowsUnresolved counts the static indices the enterprise table has no
// row for (missing) and those whose row carries a value that is not a number
// (unreadable). They are counted apart because they say different things about
// the device, and the warning names both.
func staticRowsUnresolved(staticIndices map[int]struct{}, tagByIndex map[int]int, described map[int]struct{}) (missing, unreadable int) {
	for index := range staticIndices {
		if _, ok := tagByIndex[index]; ok {
			continue
		}
		if _, ok := described[index]; ok {
			unreadable++
			continue
		}
		missing++
	}
	return missing, unreadable
}

// ambiguousStaticTag reports the first tag that more than one static row claims.
//
// Judged over the static rows only. An enterprise row for an index the static
// table never used describes a VLAN nothing is about to be rewritten to, so
// letting it collide would refuse a device over a row that does not matter.
//
// The smallest claimant is reported so the warning reads the same on every
// poll rather than naming whichever index map iteration happened to yield.
func ambiguousStaticTag(staticIndices map[int]struct{}, tagByIndex map[int]int) (tag, claimants int, ambiguous bool) {
	count := map[int]int{}
	for index := range staticIndices {
		count[tagByIndex[index]]++
	}
	for t, n := range count {
		if n > 1 && (!ambiguous || t < tag) {
			tag, claimants, ambiguous = t, n, true
		}
	}
	return tag, claimants, ambiguous
}

// corroborateVlanNames asks the device whether the two tables describe the same
// VLANs, by comparing the name each gives for one index.
//
// Only indices carrying a name in both tables are counted; the rest are
// evidence of nothing either way. The ELS "+<tag>" suffix is stripped from both
// sides first, since only one table may carry it.
//
// firstDisagreement is the lowest disagreeing index, so the warning names the
// same VLAN on every poll.
func corroborateVlanNames(all ObjectIDValueMap, staticIndices map[int]struct{}, tagByIndex map[int]int, nameByIndex map[int]string) (agreed, disagreed, firstDisagreement int) {
	for index := range staticIndices {
		enterprise, ok := nameByIndex[index]
		if !ok {
			continue
		}
		v, ok := all[oidDot1qVlanStaticName+strconv.Itoa(index)]
		if !ok {
			continue
		}
		static := trimSNMPString(v.Value)
		if static == "" {
			continue
		}
		tag := tagByIndex[index]
		if stripVlanNameTagSuffix(static, tag) == stripVlanNameTagSuffix(enterprise, tag) {
			agreed++
			continue
		}
		if disagreed == 0 || index < firstDisagreement {
			firstDisagreement = index
		}
		disagreed++
	}
	return agreed, disagreed, firstDisagreement
}

// splitStaticVlanOID splits a dot1qVlanStaticTable OID into its column prefix
// and its VlanIndex. Reports false for anything else, including the other
// Q-BRIDGE tables: dot1qPvid carries a VLAN value rather than a VLAN index in
// its OID, and on the reported switches that value is already the real tag, so
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
