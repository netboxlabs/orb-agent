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
// It deliberately does not attempt tagged membership or access-vs-trunk mode.
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
// Mode and the tagged VLAN set are deliberately left untouched. These columns
// say which VLAN a port is untagged on, not whether it is an access port or a
// trunk; deriving mode from them would demote a correctly classified trunk and
// drop its tagged VLANs.
func ApplyCiscoSB(infos map[int]*SwitchportInfo, rows CiscoSBRows) {
	for _, ifIndex := range rows.IfIndexes() {
		info, ok := infos[ifIndex]
		if !ok {
			continue
		}

		// CoerceVid rejects the 0 these columns default to, so an unconfigured
		// column reads as "no opinion" rather than VLAN 0.
		native := CoerceVid(rows.AccessVlan[ifIndex])
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

		info.AccessVlan = native
		info.NativeVlan = native
	}
}
