package qbridge

import "sort"

// CISCOSB private-MIB VLAN overlay.
//
// On Cisco's small-business switches (CISCOSB: Catalyst 1200/1300, CBS/SG
// series) dot1qPvid is not merely absent but wrong: it answers 1 for every
// port regardless of the configured VLAN, and the per-VLAN
// dot1qVlanStaticEgressPorts / UntaggedPorts masks come back empty. A C1200
// with ports on VLANs 2128/2137/112/1399 therefore reports the whole switch as
// access VLAN 1 from the standard tables alone (issue #482).
//
// The same devices populate a private per-port table with the real untagged
// VLAN, keyed by ifIndex directly rather than by bridge port:
//
//	vlanAccessPortModeVlanId       per-port access VLAN
//	vlanTrunkPortModeNativeVlanId  per-port trunk native VLAN
//
// This overlay corrects the untagged VLAN from those columns.
//
// It deliberately does not attempt tagged membership, and derives access-vs-trunk
// mode only from the access column, only for a port nothing else could classify.
// The MIB does expose per-port egress bitmaps (rldot1qPortVlanStaticTable) that
// would carry both, but they come back empty in practice, so there is nothing to
// derive them from — and walking that table is expensive, since it is twelve
// 128-byte columns per port. The other candidate mode signal, vlanPortModeState,
// does not discriminate: a port configured as a trunk reports the same value as
// its access neighbours.

// CiscoSBRows carries the CISCOSB per-port VLAN columns, keyed by ifIndex.
type CiscoSBRows struct {
	AccessVlan map[int]int
	NativeVlan map[int]int
}

// HasData reports whether the walk returned any CISCOSB VLAN rows. These OIDs
// are walked on every Cisco device because they share the "cisco" vendor gate,
// so callers use this to skip the overlay entirely on the majority of hosts
// that do not answer them.
func (r CiscoSBRows) HasData() bool {
	return len(r.AccessVlan) > 0 || len(r.NativeVlan) > 0
}

// IfIndexes returns every ifIndex the rows mention, ascending, so callers
// visit ports deterministically.
func (r CiscoSBRows) IfIndexes() []int {
	seen := map[int]struct{}{}
	for _, m := range []map[int]int{r.AccessVlan, r.NativeVlan} {
		for ifx := range m {
			seen[ifx] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for ifx := range seen {
		out = append(out, ifx)
	}
	sort.Ints(out)
	return out
}

// ApplyCiscoSB corrects the untagged VLAN of each port from the CISCOSB
// private-MIB columns.
//
// Only ifIndices already present in infos are touched, matching ApplyCisco, so
// a stale row cannot conjure a port out of nothing. A port with no usable
// CISCOSB value keeps whatever the generic pass decided, which matters because
// these OIDs are walked on every Cisco device and most will not answer them.
//
// The tagged VLAN set is deliberately left untouched, and so is the mode of any
// port that already has one: these columns say which VLAN a port is untagged on,
// and reading a mode out of them in general would demote a correctly classified
// trunk and drop its tagged VLANs.
//
// The one exception is a port with no mode at all, where the access column is
// the only thing that could supply one. See the end of the loop for why that
// case exists and why it cannot demote anything.
func ApplyCiscoSB(infos map[int]*SwitchportInfo, rows CiscoSBRows) {
	for _, ifIndex := range rows.IfIndexes() {
		info, ok := infos[ifIndex]
		if !ok {
			continue
		}

		// CoerceVid rejects the 0 these columns default to, so an unconfigured
		// column reads as "no opinion" rather than VLAN 0.
		native := CoerceVid(rows.AccessVlan[ifIndex])
		fromAccessColumn := native != nil
		if native == nil {
			if vid := CoerceVid(rows.NativeVlan[ifIndex]); vid != nil &&
				(*vid != 1 || info.AdminMode == AdminTrunk) {
				// The trunk-native column reads 1 on a factory-default port,
				// indistinguishable from unset, so on its own it is not
				// evidence. Honour it only for a port already known to be a
				// trunk, or when it names something other than the default.
				native = vid
			}
		}
		if native == nil {
			continue
		}

		// Where the VLAN this replaces was read from an untagged mask, the
		// device stated the port egresses it untagged, so it is not a tagged
		// VLAN. Leaving it in the allowed set publishes it as one, the same
		// inversion the generic extractor drops it to avoid, and it cannot be
		// reported at all because these columns have just named a different
		// VLAN for the one untagged_vlan slot.
		//
		// A native that came from dot1qPvid is left alone. That says nothing
		// about how the port tags its egress, so the port may be a tagged
		// member and dropping it would lose a real VLAN.
		if prev := CoerceVid(deref(info.NativeVlan)); info.NativeUntaggedByMask &&
			prev != nil && *prev != *native {
			info.AllowedVlans.Vids = withoutVlan(info.AllowedVlans.Vids, *prev)
		}

		info.AccessVlan = native
		info.NativeVlan = native

		// vlanAccessPortModeVlanId says the port IS an access port on that
		// VLAN, so it can supply the mode where nothing else could — which is
		// every one of these switches whose generic rows give no membership
		// masks and no VLAN catalog, leaving the default PVID refused upstream.
		// Without this the overlay names a VLAN that no mode ever reaches, and
		// the port these columns exist to classify is emitted as nothing at all.
		//
		// Only into a vacuum, and only from the access column. A port already
		// read as a trunk keeps that, so this cannot demote one or drop its
		// tagged VLANs, and the trunk-native column above is not access
		// evidence — a port whose only CISCOSB value is a trunk native VLAN
		// still ends up with no mode, and no VLAN.
		//
		// Narrower than the precedence ApplyCisco gives vmMembership, which
		// also demotes a one-tagged-VLAN trunk. That is a claim these columns
		// do not make, and it is still declined.
		if fromAccessColumn && info.AdminMode == AdminUnknown {
			info.AdminMode = AdminAccess
		}

		// The routed inference is overridden, which ApplyCisco also does.
		// It is drawn from a missing dot1qPvid row, and a port the access
		// column names is a port the device says is an access port, so it is
		// bridged: positive evidence against an inference from absence, the
		// same precedence the generic extractor gives membership masks.
		//
		// It matters because Classify answers routed before it reads the mode
		// set above and returns no VLAN at all. These switches do answer
		// dot1qPvid for every port, which is why this went unnoticed, but the
		// PVID column is walked separately and a failed or truncated walk
		// leaves every port of an otherwise healthy device looking routed,
		// discarding the one column that could still classify it.
		if fromAccessColumn && info.OperMode == OperRouted {
			info.OperMode = OperUnknown
		}
	}
}
