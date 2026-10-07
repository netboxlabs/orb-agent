package qbridge

import "sort"

// CISCOSB private-MIB VLAN overlay.
//
// On Cisco's small-business switches (CISCOSB: Catalyst 1200/1300, CBS/SG
// series) the standard sources are wrong rather than absent. dot1qPvid answers
// 1 for every port whatever it is configured for, and the per-VLAN
// dot1qVlanStaticEgressPorts / UntaggedPorts masks come back empty, so
// Q-BRIDGE alone reports the whole switch as access VLAN 1.
//
// The same devices describe each port in private tables keyed by ifIndex
// rather than by bridge port:
//
//	vlanPortModeState              11 for an access port, 12 for a trunk
//	vlanAccessPortModeVlanId       the access VLAN
//	vlanTrunkPortModeNativeVlanId  the trunk native VLAN
//	vlanTrunkModeList1to1024 ...   the trunk member VLANs, four bitmaps
//
// The MIB leaves vlanPortModeState an undocumented INTEGER. The two values
// are read from switches whose dot1qVlanCurrentTable agrees with them port by
// port. Each port keeps both its access and its trunk settings whichever mode
// it is in, so the mode decides which of them describes it.

// CISCOSB vlanPortModeState values.
const (
	ciscoSBModeAccess = 11
	ciscoSBModeTrunk  = 12
)

// CiscoSBRows carries the CISCOSB per-port VLAN columns, keyed by ifIndex.
type CiscoSBRows struct {
	AccessVlan map[int]int
	NativeVlan map[int]int
	PortMode   map[int]int

	// TrunkLists holds vlanTrunkModeList1to1024 through 3073to4094, keyed by
	// ifIndex and then by list, 0 to 3. List n covers VLANs n*1024+1 onwards,
	// the most significant bit of each octet naming the lowest VLAN.
	TrunkLists map[int]map[int][]byte

	// Vlans is the device's VLAN catalog. The member lists can name VLANs that
	// were never created, and the switch carries only those it has.
	Vlans map[int]struct{}
}

// HasData reports whether the walk returned any CISCOSB VLAN rows. These OIDs
// are walked on every Cisco device because they share the "cisco" vendor gate,
// so callers use this to skip the overlay entirely on the majority of hosts
// that do not answer them.
func (r CiscoSBRows) HasData() bool {
	return len(r.AccessVlan) > 0 || len(r.NativeVlan) > 0 || len(r.PortMode) > 0 || len(r.TrunkLists) > 0
}

// IfIndexes returns every ifIndex the rows mention, ascending, so callers
// visit ports deterministically.
func (r CiscoSBRows) IfIndexes() []int {
	seen := map[int]struct{}{}
	for _, m := range []map[int]int{r.AccessVlan, r.NativeVlan, r.PortMode} {
		for ifx := range m {
			seen[ifx] = struct{}{}
		}
	}
	for ifx := range r.TrunkLists {
		seen[ifx] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for ifx := range seen {
		out = append(out, ifx)
	}
	sort.Ints(out)
	return out
}

// ApplyCiscoSB overlays the CISCOSB private-MIB columns onto the generic
// result.
//
// Only ifIndices already present in infos are touched, matching ApplyCisco, so
// a stale row cannot conjure a port out of nothing.
//
// A port the device calls access or trunk is described by that mode's columns
// alone, replacing what the standard tables gave. Any other port gets only its
// untagged VLAN corrected.
func ApplyCiscoSB(infos map[int]*SwitchportInfo, rows CiscoSBRows) {
	for _, ifIndex := range rows.IfIndexes() {
		info, ok := infos[ifIndex]
		if !ok {
			continue
		}
		switch rows.PortMode[ifIndex] {
		case ciscoSBModeAccess:
			// CoerceVid rejects the 0 the column defaults to.
			applyCiscoSBAccess(info, CoerceVid(rows.AccessVlan[ifIndex]))
		case ciscoSBModeTrunk:
			applyCiscoSBTrunk(info, rows, ifIndex)
		default:
			correctCiscoSBUntaggedVlan(info, rows, ifIndex)
		}
	}
}

// applyCiscoSBAccess describes an access port by its access VLAN.
func applyCiscoSBAccess(info *SwitchportInfo, vid *int) {
	if vid == nil {
		leaveOut(info)
		return
	}
	info.AdminMode = AdminAccess
	info.OperMode = OperUnknown
	info.AccessVlan = vid
}

// applyCiscoSBTrunk describes a trunk by its member lists and native VLAN.
//
// The native VLAN is untagged only where the port is a member of it, and the
// tagged VLANs are the members the device has. Lists naming all of 1-4094 are
// "allowed vlan all", which makes the port tagged-all.
func applyCiscoSBTrunk(info *SwitchportInfo, rows CiscoSBRows, ifIndex int) {
	lists := rows.TrunkLists[ifIndex]
	for n := 0; n < 4; n++ {
		// A VLAN in a list that was not walked is unknown, not excluded.
		if _, ok := lists[n]; !ok {
			leaveOut(info)
			return
		}
	}
	var native *int
	if vid := CoerceVid(rows.NativeVlan[ifIndex]); vid != nil && listsName(lists, *vid) {
		native = vid
	}
	var tagged []int
	every := true
	for vid := 1; vid <= 4094; vid++ {
		if !listsName(lists, vid) {
			every = false
			continue
		}
		if _, ok := rows.Vlans[vid]; ok {
			tagged = append(tagged, vid)
		}
	}
	info.AdminMode = AdminTrunk
	info.OperMode = OperUnknown
	info.NativeVlan = native
	info.AllowedVlans = AllowedVlans{Vids: tagged, IsWildcard: every}
}

// listsName reports whether a trunk's member lists name vid.
func listsName(lists map[int][]byte, vid int) bool {
	bit := (vid - 1) % 1024
	list := lists[(vid-1)/1024]
	return bit/8 < len(list) && list[bit/8]&(0x80>>(bit%8)) != 0
}

// leaveOut withdraws a port's classification, so nothing is written for it.
// It is for a port whose mode the device states but whose columns for that
// mode are missing: the standard tables are what this platform gets wrong, and
// NetBox keeps what it holds.
func leaveOut(info *SwitchportInfo) {
	info.AdminMode = AdminUnknown
	info.OperMode = OperUnknown
}

// correctCiscoSBUntaggedVlan corrects the untagged VLAN of a port whose mode is
// not known, from the access column and failing that the native column.
//
// The tagged VLAN set is left untouched, and so is the mode of any port that
// already has one: without the mode these columns say only which VLAN a port
// is untagged on, and reading a mode out of them would demote a correctly
// classified trunk and drop its tagged VLANs. The one exception is a port with
// no mode at all, where the access column is the only thing that could supply
// one.
func correctCiscoSBUntaggedVlan(info *SwitchportInfo, rows CiscoSBRows, ifIndex int) {
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
		return
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

	// Without a mode row the access column is the best evidence there is,
	// so it can supply the mode where nothing else could — which is
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
