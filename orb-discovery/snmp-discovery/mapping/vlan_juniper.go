package mapping

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping/qbridge"
)

// JUNIPER-VLAN-MIB jnxExVlanTable columns. Walked only on Juniper.
//
// jnxExVlanTag carries the real 802.1Q tag of a VLAN the switch indexes
// internally. jnxExVlanName carries the same name dot1qVlanStaticName does,
// and is what lets the two tables be checked against each other.
//
// Absent on the Junos platforms measured that index dot1qVlanStaticTable by the
// tag already. Whether that holds across every Junos build is not established,
// which is why nothing here treats the table's presence as proof of anything:
// a platform that publishes both is refused by the name gate rather than
// mis-rekeyed.
const (
	oidJnxExVlanName = ".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.2."
	oidJnxExVlanTag  = ".1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5."
)

// dot1qVlanStaticColumns are the columns of dot1qVlanStaticTable this backend
// walks, every one of them keyed by the same VlanIndex. Rekeying one and not
// the others would pair a VLAN's name with another VLAN's ports, so this list
// and the table's entry in the shipped policy have to stay in step.
// dot1qVlanForbiddenEgressPorts is the table's remaining column and is not
// walked, so no row of it ever arrives to be rekeyed.
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
// one and why. That is not a no-write path: ingest still happens and the device
// still reports internal indices as VLAN IDs, so refusing preserves the status
// quo write rather than avoiding one. It is the right trade anyway, because the
// alternative is not silence but a different write — an unrepaired VLAN an
// operator can see in a log is recoverable, and a VLAN silently re-identified
// as a different one is not.
//
// Returned untouched and silently when there is no enterprise table at all:
// that is every non-Juniper device and the Junos platforms whose indices are
// already tags, which are correct as they are.
//
// A refusal warns on every poll, and deliberately so, even though the dropped
// tag-0 row below is demoted to Debug for firing every poll. The two are not
// the same event. Tag 0 is how a healthy switch reports an untagged bridge
// domain: nothing is wrong and there is nothing to do, so a recurring warning
// would be noise. A refusal says this device's VLAN IDs are wrong in NetBox
// and the agent cannot fix them, which stays true and stays actionable until
// someone acts on it. Logging that once and falling silent would hide an
// unresolved problem from whoever reads the logs next.
func ResolveJuniperVlanIndices(all ObjectIDValueMap, logger *slog.Logger) ObjectIDValueMap {
	// The enterprise columns are vendor-scoped in the shipped policy, so only a
	// Juniper target walks them. Checked here too rather than relying on that:
	// the reasoning below is about how Junos numbers VLANs, and it should not
	// be a policy edit away from running against another vendor's OIDs.
	if !isJuniper(all) {
		return all
	}
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

	// The tags of the rows actually being rekeyed — the catalog this device
	// will report. NOT every tag the enterprise table mentions: gate 1 only
	// requires that table to cover the static rows, so it may describe VLANs
	// with no static row (a protocol-learned bridge domain looks exactly like
	// that). Such a tag names no VLAN in the emitted catalog, so keeping a
	// PVID for it fabricates the placeholder this guard exists to prevent.
	//
	// Built from the raw tags rather than the coerced VIDs, so the untagged
	// bridge domain's tag 0 stays in the set: a PVID of 0 must survive, since
	// the Q-BRIDGE reader takes it as "bridged, nothing untagged".
	resolved := make(map[int]struct{}, len(staticIndices))
	for index := range staticIndices {
		resolved[tagByIndex[index]] = struct{}{}
	}

	out := make(ObjectIDValueMap, len(all))
	dropped, unnameable := 0, 0
	for oid, v := range all {
		if strings.HasPrefix(oid, oidDot1qPvid) {
			if pvidIsUnnameable(v.Value, resolved) {
				// Zeroed rather than removed. The row's PRESENCE is what tells
				// the Q-BRIDGE reader this port is bridged at all; deleting it
				// would make an L3-capable port classify as routed, turning
				// "nothing is known about this port" into a positive claim
				// about it. A PVID of 0 is already the device's own way of
				// saying bridged with no untagged VLAN, which is exactly what
				// is true here.
				v.Value = "0"
				out[oid] = v
				unnameable++
				continue
			}
			out[oid] = v
			continue
		}
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
		// VLAN in NetBox. Nothing can name this one. The only other reference
		// to a VID is dot1qPvid, and the Q-BRIDGE reader discards a PVID of 0
		// as "bridged, nothing untagged" before it can reach a VLAN lookup —
		// note that is the reader's own zero test rather than CoerceVid, which
		// only sees the value later, inside the classifier. Both layers reject
		// it; the first is what makes this drop safe.
		//
		// The gates above exist so that every row we cannot resolve for any
		// OTHER reason abandons the translation entirely rather than dropping a
		// row whose VID something else still names.
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
	if unnameable > 0 {
		logger.Warn("vlan: reported Juniper PVIDs the rekeyed VLAN catalog cannot name as 0",
			"ports", unnameable,
			"reason", "this device numbers VLANs internally, so a PVID naming no known tag cannot be told from an internal index; fabricating a VLAN for it would rename the operator's VLAN of that number")
	}
	return out
}

// pvidIsUnnameable reports whether a dot1qPvid value must be discarded because
// nothing on a rekeyed device can say which VLAN it means.
//
// This is the hazard the rekey itself introduces, and it is not the same
// question as whether the value is in range. RFC 4363 types dot1qPvid as
// VlanIndex — the same convention as dot1qVlanIndex — so an agent that answers
// dot1qVlanIndex with an internal number is being self-consistent if it
// answers dot1qPvid the same way, and an internal number is a perfectly
// in-range small integer that qbridge.CoerceVid cannot distinguish from a tag.
//
// Left alone, such a PVID names a VID that the rekeyed catalog no longer holds,
// and VlanMapper fabricates a "VLAN<vid>" placeholder for it — which Diode
// PATCHes over the name of whatever real VLAN the operator has at that number,
// and binds a port to it. Before the rekey that PVID matched its static row and
// no placeholder was created, so this is a corruption path the rekey opens
// rather than one it inherits.
//
// Translating it instead is not available: a value absent from the tag set
// could be an internal index, or the tag of a VLAN with no static row, and
// nothing distinguishes them. So the port loses its untagged VLAN, which under
// Diode's partial updates leaves whatever NetBox already holds untouched.
//
// A value that will not parse is kept: it can name no VID, so it can fabricate
// nothing, and discarding it would only hide a malformed agent.
//
// On the reported switch this drops nothing — every PVID there is a resolved
// tag — which is why it costs the fix's own device nothing.
func pvidIsUnnameable(value string, resolvedTags map[int]struct{}) bool {
	pvid, ok := atoi(trimSNMPString(value))
	if !ok {
		return false
	}
	// 0 is the device saying "bridged, nothing untagged", which is how every
	// all-tagged trunk reports. It names no VLAN, so it can fabricate none, and
	// it is already the value this function would write. Short-circuited so a
	// switch with no untagged bridge domain — whose tag 0 is therefore not in
	// the resolved set — does not warn on every poll about ports that lost
	// nothing.
	if pvid == 0 {
		return false
	}
	_, known := resolvedTags[pvid]
	return !known
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
		// Tags no row will be rewritten TO are not contested. Junos reports an
		// untagged bridge domain with tag 0 and a switch may have more than
		// one, which would otherwise refuse the whole device over rows that are
		// both dropped a few lines later — a refusal that buys nothing, since
		// there is no VLAN for the two to be confused about. Same reasoning as
		// scoping this to the static rows at all.
		if qbridge.CoerceVid(tagByIndex[index]) == nil {
			continue
		}
		count[tagByIndex[index]]++
	}
	for t, n := range count {
		if n > 1 && (!ambiguous || t < tag) {
			tag, claimants, ambiguous = t, n, true
		}
	}
	return tag, claimants, ambiguous
}

// dot1qVlanStaticNameMax is the SIZE bound RFC 4363 puts on
// dot1qVlanStaticName. jnxExVlanName carries no such bound, so a longer name
// reaches the two tables truncated in one and whole in the other.
const dot1qVlanStaticNameMax = 32

// corroborateVlanNames asks the device whether the two tables describe the same
// VLANs, by comparing the name each gives for one index.
//
// Only indices carrying a name in both tables are counted; the rest are
// evidence of nothing either way. The ELS "+<tag>" suffix is stripped from both
// sides first, since only one table may carry it.
//
// The gate's discriminating power rests on VLAN names being distinct among the
// rows it compares: agreement at index k on a tag-keyed table would require the
// VLAN tagged k and the VLAN at internal index k to share a name, which under
// distinct names forces k to equal the tag and is excluded below. Junos makes
// the name a configuration key, which gives that within a bridge domain space;
// names can repeat across routing-instances, so this is the platform's habit
// rather than a guarantee. Requiring the agreement to come from an uncut name
// does not repair that — two VLANs may legitimately share a name at any length
// — it only keeps truncation from manufacturing collisions that the assumption
// would then have to absorb.
//
// An index whose tag EQUALS it is not counted as agreement. Such a row reads
// the same whether the static table is keyed by index or by tag, so it cannot
// discriminate between the two hypotheses this gate exists to decide — and the
// row most likely to be shaped that way is the one most devices have, VLAN 1
// named "default" at index 1. Letting it corroborate would hand the rekey a
// free pass on the single coincidence the gate is for. It costs the reported
// device nothing: none of its 39 indices equals its tag.
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
		// Rows that will be dropped rather than rewritten are evidence of
		// nothing, the same way they are not contested for ambiguity. Without
		// this, a device can be rekeyed where every corroborating row is
		// discarded moments later — and the index != tag exclusion below, which
		// exists to deny the rekey a free pass on "VLAN 1 named default at
		// index 1", misses that very row on a box whose default bridge domain
		// is untagged, since its tag is 0 and 1 != 0.
		tag := tagByIndex[index]
		if qbridge.CoerceVid(tag) == nil {
			continue
		}
		switch compareVlanNames(static, enterprise, tag) {
		case namesDisagree:
			if disagreed == 0 || index < firstDisagreement {
				firstDisagreement = index
			}
			disagreed++
		case namesAgree:
			if index != tag {
				agreed++
			}
		case namesInconclusive:
		}
	}
	return agreed, disagreed, firstDisagreement
}

// nameVerdict is what one VLAN's two names say about the tables' keying.
type nameVerdict int

const (
	namesAgree nameVerdict = iota
	namesDisagree
	// namesInconclusive is the name the standard column cut short. It neither
	// corroborates nor contradicts, and must be counted as neither.
	namesInconclusive
)

// compareVlanNames asks what the two tables' names for one row are evidence of.
//
// RFC 4363 bounds dot1qVlanStaticName at 32 octets and JUNIPER-VLAN-MIB does
// not bound jnxExVlanName, so a VLAN named past that arrives cut in one table
// and whole in the other. Reading that as a contradiction would disable the fix
// for an entire switch over one long name, which Junos names routinely are.
//
// But a cut name cannot corroborate either, and that half matters more. Two
// different VLANs on one switch sharing a 32-octet prefix is ordinary under
// structured naming ("<site>-<building>-<floor>-vlanNNN"), and once cut they
// are indistinguishable — so treating a prefix match as agreement would let a
// device whose static table is ALREADY tag-keyed satisfy the gate and have
// every VLAN re-emitted under a stranger's ID. That is the exact catastrophe
// the gate exists to prevent, so a cut name is evidence of nothing and the
// rekey still needs a full agreement somewhere on the device.
//
// Agreement is judged on the stripped names, which subsumes raw equality. The
// truncation test uses the raw ones, because a cut can land in the middle of
// the ELS "+<tag>" suffix and leave one side strippable and the other not.
// That rescues the case where the UNCUT side is the decorated one; where the
// cut side is, the surviving text no longer prefixes the other and the row
// contradicts. Unattested on either captured device — the pre-ELS switch
// decorates nothing and the ELS one publishes no enterprise table — and it
// fails toward a refusal rather than a write.
//
// See maybeCutAtColumnBound for what counts as possibly cut, and for the blind
// spot that remains.
func compareVlanNames(static, enterprise string, tag int) nameVerdict {
	staticCut := maybeCutAtColumnBound(static, tag)
	enterpriseCut := maybeCutAtColumnBound(enterprise, tag)

	// Neither name could have been cut, so both speak for themselves.
	if !staticCut && !enterpriseCut {
		if stripVlanNameTagSuffix(static, tag) == stripVlanNameTagSuffix(enterprise, tag) {
			return namesAgree
		}
		return namesDisagree
	}

	// One of them might be a truncation, so equality is not agreement: it may
	// be an artifact of the cut, which is the danger — two VLANs sharing a
	// 32-octet prefix, cut, are indistinguishable.
	//
	// Asked in a direction. Under the model this file uses, a name below the
	// bound is complete, so two observed strings can be one name ONLY if the
	// possibly-cut one is a prefix of the other. An undirected test also
	// abstained when a complete SHORT name was a prefix of a cut long one —
	// "campus" against a 32-octet name, which under this model are different
	// VLANs — and the hard refusal that should follow was lost.
	//
	// Both sides are asked because bounding dot1qVlanStaticName at 32 octets
	// is RFC 4363, while jnxExVlanName carrying no such bound is an assumption
	// the captures cannot confirm: every name on them is short. If some Junos
	// build bounds it too, a device with structured names has both columns cut
	// to the same octets, arriving EQUAL, and this gate would stop
	// discriminating at the moment it matters most.
	if staticCut && strings.HasPrefix(enterprise, static) {
		return namesInconclusive
	}
	if enterpriseCut && strings.HasPrefix(static, enterprise) {
		return namesInconclusive
	}
	// The surviving prefixes differ, and a cut cannot change what survived.
	return namesDisagree
}

// maybeCutAtColumnBound reports whether a name might have lost its end to the
// standard column's length limit, so its content past that point is unknown.
//
// Three things decide it.
//
// A name whose "+<tag>" suffix is still visible cannot have been cut: the end
// is right there. That is the same question everyNameCarriesItsTagSuffix asks
// before consulting a length, and asking it here keeps the two gates consistent
// — without it, an ELS name landing exactly on the bound with its suffix intact
// would abstain instead of corroborating.
//
// A name LONGER than the bound proves this agent does not truncate there, so it
// cannot have lost anything that way and its content is real evidence.
//
// The window is the bound and one octet below it. trimSNMPString strips NUL
// bytes, so an agent that writes into a 32-octet buffer and NUL-terminates — an
// ordinary C idiom — delivers 31 octets of text that would otherwise read as a
// complete name. Reaching that case silently re-emits every VLAN under another
// VLAN's identity, which is the worst outcome in this file, while the cost of
// covering it is only that a name of exactly that length corroborates nothing.
// This gate can afford that: abstaining loses a vote, and the rekey simply needs
// its evidence elsewhere.
//
// The ELS convention gate deliberately does NOT widen the same way, and the two
// are independent windows rather than one shared rule. There, a name that
// abstains is a veto discarded, and a discarded veto renames the operator's
// VLANs — so the cost of widening runs the opposite direction and is paid
// silently. It keeps the tighter window and documents the same blind spot.
func maybeCutAtColumnBound(name string, tag int) bool {
	if stripVlanNameTagSuffix(name, tag) != name {
		return false
	}
	return len(name) == dot1qVlanStaticNameMax || len(name) == dot1qVlanStaticNameMax-1
}

// splitStaticVlanOID splits a dot1qVlanStaticTable OID into its column prefix
// and its VlanIndex. Reports false for anything else, including the other
// Q-BRIDGE tables: dot1qPvid is indexed by bridge port and carries its VLAN as
// the VALUE, so it holds no VlanIndex to rekey. What its value needs is a
// different question, handled by pvidIsUnnameable.
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
