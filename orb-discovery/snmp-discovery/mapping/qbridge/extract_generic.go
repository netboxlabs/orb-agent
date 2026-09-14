package qbridge

import (
	"fmt"
	"sort"
)

// GenericRows is the per-host bundle of raw SNMP rows VlanMapper builds
// from Q-BRIDGE + BRIDGE-MIB OIDs and hands to ExtractGeneric. Keeping the
// shape behind a single struct keeps test setup explicit and lets new
// fields be added without breaking call sites.
type GenericRows struct {
	// BasePortToIfIndex from BRIDGE-MIB dot1dBasePortIfIndex
	// (1.3.6.1.2.1.17.1.4.1.2). Required; empty/nil produces an error.
	BasePortToIfIndex map[int]int

	// PortPvid from Q-BRIDGE dot1qPvid (1.3.6.1.2.1.17.7.1.4.5.1.1),
	// keyed by ifIndex (after bridge-port translation).
	PortPvid map[int]int

	// VlanEgressPorts from dot1qVlanStaticEgressPorts
	// (1.3.6.1.2.1.17.7.1.4.3.1.2), keyed by VID.
	VlanEgressPorts map[int][]byte

	// VlanUntaggedPorts from dot1qVlanStaticUntaggedPorts
	// (1.3.6.1.2.1.17.7.1.4.3.1.4), keyed by VID.
	VlanUntaggedPorts map[int][]byte

	// IfAdminStatus from IF-MIB ifAdminStatus, keyed by ifIndex.
	// 1=up, 2=down, 3=testing.
	IfAdminStatus map[int]int

	// IfTypes from IF-MIB ifType (text form like "ethernetCsmacd"),
	// keyed by ifIndex. Used to distinguish routed (membership-empty +
	// L3-able ifType) from non-bridge entries.
	IfTypes map[int]string

	// TextPortLists says the device is of a vendor that publishes the port
	// lists as text, comma-separated bridge port numbers, in place of the
	// bitmap the MIB defines: Junos does by default. Only then are lists
	// that read as text, and could not be bitmaps, read as text; a value of
	// digit and comma bytes is a legal bitmap on any other platform, however
	// it parses.
	TextPortLists bool

	// VlansFromCurrentTable names the VLANs whose masks came from
	// dot1qVlanCurrentTable rather than dot1qVlanStaticTable.
	//
	// The two tables do not mean the same thing and cannot be read the same
	// way. RFC 4363 defines the static untagged mask as configuration, the set
	// of ports "permanently assigned" to egress untagged, while the current
	// one is operational: the ports actually "transmitting traffic for this
	// VLAN as untagged frames". A port that is administratively up but not
	// forwarding is absent from the current mask while dot1qPvid still reports
	// the VLAN it is configured for.
	//
	// That difference only matters where absence from a mask is read as a
	// statement. Membership is taken from either table alike.
	VlansFromCurrentTable map[int]struct{}

	// VlanCatalogPresent says the device named VLANs of its own: a static
	// name or row-status row, a membership mask, or a VTP catalog entry.
	//
	// Without one, the agent has learned no VLAN from this device except
	// through dot1qPvid, and RFC 4363 gives dot1qPvid a DEFVAL of 1 — so a
	// port answering 1 there may be saying nothing at all. See the default
	// PVID branch in ExtractGeneric.
	VlanCatalogPresent bool
}

// defaultPvid is the DEFVAL RFC 4363 gives dot1qPvid. A port reporting it on
// a device that publishes no VLAN catalog has told us nothing.
const defaultPvid = 1

// fromCurrentTable reports whether a VLAN's masks came from the operational
// table rather than the configured one.
func fromCurrentTable(current map[int]struct{}, vid int) bool {
	_, ok := current[vid]
	return ok
}

// withoutVlans returns masks excluding the named VLANs, for the decisions that
// may only consider what the static table said.
func withoutVlans(masks map[int][]byte, exclude map[int]struct{}) map[int][]byte {
	if len(exclude) == 0 {
		return masks
	}
	out := make(map[int][]byte, len(masks))
	for vid, mask := range masks {
		if _, skip := exclude[vid]; !skip {
			out[vid] = mask
		}
	}
	return out
}

// ExtractGeneric builds a per-ifIndex SwitchportInfo map from Q-BRIDGE
// rows. The bridge-port→ifIndex translation table is consulted exactly
// once (here); downstream extractors (e.g. extract_cisco) work in
// ifIndex space and do not see bridge port numbers.
func ExtractGeneric(rows GenericRows) (map[int]*SwitchportInfo, error) {
	if len(rows.BasePortToIfIndex) == 0 {
		return nil, ErrMissingTranslation
	}

	// Reverse map: ifIndex -> []bridgePort, for membership lookup.
	// BRIDGE-MIB allows multiple bridge ports to reference the same
	// ifIndex (e.g., a member of multiple bridges, or LAG sub-ports
	// on some platforms). Aggregating preserves all mappings; the
	// later membership check unions across them so VLAN data set on
	// any bridge port for the ifIndex is preserved.
	ifIndexToBridge := make(map[int][]int, len(rows.BasePortToIfIndex))
	for bp, ifx := range rows.BasePortToIfIndex {
		ifIndexToBridge[ifx] = append(ifIndexToBridge[ifx], bp)
	}

	// Iterate ifIndexToBridge so each ifIndex is processed once, even
	// when multiple bridge ports map to the same ifIndex. Iterating
	// rows.BasePortToIfIndex directly would visit such ifIndices
	// repeatedly with identical results (since membershipFromMasks
	// unions all bridge ports for the ifIndex anyway), wasting work.
	// Whether this host publishes its port lists as text is decided once,
	// over every list it sent, so one value is never read one way and the
	// next the other, and only for a vendor known to publish text. Text
	// lists are decoded once into bitmaps here; everything below reads
	// bitmaps.
	egress, untagged := rows.VlanEgressPorts, rows.VlanUntaggedPorts
	if rows.TextPortLists && listsAreText(
		withoutVlans(egress, rows.VlansFromCurrentTable),
		withoutVlans(untagged, rows.VlansFromCurrentTable),
		rows.BasePortToIfIndex,
	) {
		egress, untagged = listsToBitmaps(egress), listsToBitmaps(untagged)
	}

	// Whether this device's PVID table carries information at all. If any port
	// reports a PVID the operator had to set, the table is being maintained,
	// so a 1 elsewhere on the same device is a report rather than a default.
	// Judged per device, not per port, because that is the scope of the
	// evidence: one port cannot tell us its own value is meaningful, but its
	// neighbour reporting VLAN 130 tells us the column is not stuck at DEFVAL.
	everyPvidIsDefault := true
	for _, pvid := range rows.PortPvid {
		// Only a value that names a VLAN counts. CoerceVid rejects 0 and the
		// reserved ids, so a port answering a sentinel such as 4095 is not
		// evidence that anyone maintains this column — and treating it as such
		// would hand every neighbour back the access VLAN 1 this refusal
		// exists to withhold, on the strength of a value that names no VLAN.
		if vid := CoerceVid(pvid); vid != nil && *vid != defaultPvid {
			everyPvidIsDefault = false
			break
		}
	}

	out := make(map[int]*SwitchportInfo, len(ifIndexToBridge))
	for ifIndex := range ifIndexToBridge {
		info := &SwitchportInfo{
			Enabled:           rows.IfAdminStatus[ifIndex] == 1,
			BridgePortPresent: true,
		}
		pvid, bridged := rows.PortPvid[ifIndex]
		if bridged && pvid > 0 {
			// A PVID of 0 says the port has no untagged VLAN, which is how a
			// trunk with every VLAN tagged reports; it is not a VLAN to
			// classify on. The row's presence still says the port is bridged.
			info.NativeVlan = intPtr(pvid)
			info.AccessVlan = intPtr(pvid)
		} else if !bridged {
			// In bridge table but no PVID -> positive "not currently
			// bridged" signal -> routed if ifType supports L3.
			if isL3Capable(rows.IfTypes[ifIndex]) {
				info.OperMode = OperRouted
			}
		}

		// Build allowed/native from membership masks.
		allowed, isWildcard, native, err := membershipFromMasks(
			ifIndex, ifIndexToBridge, egress, untagged,
		)
		if err != nil {
			return nil, fmt.Errorf("ifIndex %d: %w", ifIndex, err)
		}
		info.AllowedVlans = AllowedVlans{Vids: allowed, IsWildcard: isWildcard}
		// Membership is the stronger evidence: a port the device places in a
		// VLAN is bridged, however its PVID table reads. The routed inference
		// from a missing PVID row stands only for a port with no membership.
		if info.OperMode == OperRouted && (isWildcard || len(allowed) > 0) {
			info.OperMode = OperUnknown
		}
		switch {
		case native != nil:
			info.NativeVlan = native
			info.AccessVlan = native
		case bridged && pvid > 0 && hasRow(untagged, pvid) &&
			!fromCurrentTable(rows.VlansFromCurrentTable, pvid):
			// The device publishes an untagged row for the PVID's VLAN and
			// leaves this port out of it: the port is tagged there, and the
			// PVID names no untagged VLAN. The PVID stands in for the row
			// only where the device publishes none.
			//
			// Read only from the static table, which RFC 4363 defines as the
			// ports permanently assigned to egress untagged — configuration,
			// so a port's absence from it is a statement about that port. The
			// current table says which ports are transmitting untagged right
			// now, and a port that is administratively up but not forwarding
			// is simply not in it while dot1qPvid still reports the VLAN it is
			// configured for. Reading absence there the same way withdrew the
			// access VLAN from every such port: six of them on a recorded
			// Arista walk, the very platform the PVID-only branch below cites.
			info.NativeVlan = nil
			info.AccessVlan = nil
		}

		// Default mode hint, from the tagging evidence rather than from how
		// many VLANs the port carries: one VLAN the port is untagged in, or
		// that its PVID names when the device publishes no untagged table,
		// is an access port; any VLAN the port is only tagged in makes it a
		// trunk, however few there are. Counting VLANs read a trunk carrying
		// one tagged VLAN as access, and with the PVID of 0 such a trunk
		// reports, the port came out access with no VLAN at all.
		// This is overridden by the Cisco overlay if vendor-specific intent rows exist.
		switch {
		case info.OperMode == OperRouted:
		case isWildcard:
			info.AdminMode = AdminTrunk
		case len(allowed) == 1 && info.AccessVlan != nil && *info.AccessVlan == allowed[0]:
			// Untagged in its one VLAN, or a PVID naming it where the device
			// publishes no untagged row for it.
			info.AdminMode = AdminAccess
		case len(allowed) >= 1:
			info.AdminMode = AdminTrunk
			info.TrunkFromOneTaggedVlan = len(allowed) == 1
		case len(allowed) == 0 && info.AccessVlan != nil &&
			!rows.VlanCatalogPresent && everyPvidIsDefault &&
			*info.AccessVlan == defaultPvid:
			// This device published no VLAN of its own, and every port it has
			// answers the MIB's default PVID. All three matter. A bridge with
			// VLAN filtering off still answers 1 because RFC 4363 says it
			// must, so the value alone is not a configured assignment; with no
			// catalog there is nothing to corroborate it against; and with no
			// port anywhere reporting a real PVID there is no sign the column
			// is maintained at all. Reading it as "access on VLAN 1" then
			// invents a VLAN the operator never configured and attaches every
			// bridge port to it.
			//
			// Scoped to the device rather than the port because that is the
			// scope of the evidence. A switch reporting VLAN 130 on one port
			// and 1 on another is telling us both, and silencing only the
			// second would leave one device described two ways: its VLAN-130
			// ports classified and its VLAN-1 ports absent.
			//
			// Left unclassified rather than called routed: the port is
			// bridged, we simply cannot say into what.
		case len(allowed) == 0 && info.AccessVlan != nil:
			// PVID-only signal: switches like Arista EOS expose dot1qPvid but
			// omit dot1qVlanStaticEgressPorts/UntaggedPorts. The PVID alone is
			// sufficient — a port with a PVID participates in bridging, and the
			// safe default is "access on PVID" when membership masks are absent.
			// Arista publishes a static name catalog, so the branch above does
			// not take this case away from it.
			info.AdminMode = AdminAccess
		}
		out[ifIndex] = info
	}
	return out, nil
}

// hasRow reports whether the table carries a row for vid, empty or not.
func hasRow(table map[int][]byte, vid int) bool {
	_, ok := table[vid]
	return ok
}

// membershipFromMasks scans the VlanEgressPorts/VlanUntaggedPorts maps
// and returns (egress VIDs for this port, wildcard?, untagged VID).
//
// Iterates the egress map keys (the VIDs that actually exist in the
// device's dot1qVlanStaticEgressPorts) rather than walking 1..4094 —
// this keeps work proportional to the discovered VLAN count instead of
// the full 12-bit VID space, which matters on switches with thousands
// of ports and only a handful of VLANs configured. Results are sorted
// for deterministic output (Go map iteration is randomized).
//
// When the same ifIndex maps to multiple bridge ports (rare but
// permitted by BRIDGE-MIB), membership for the ifIndex is the union of
// per-bridge-port memberships: a VID counts as egress if any bridge
// port for that ifIndex is in its egress mask, and as untagged if any
// bridge port is in the untagged mask. "wildcard" is set when the
// resulting egress set covers all 4094 VIDs.
func membershipFromMasks(
	ifIndex int,
	ifIndexToBridge map[int][]int,
	egress, untagged map[int][]byte,
) ([]int, bool, *int, error) {
	bridgePorts, ok := ifIndexToBridge[ifIndex]
	if !ok || len(bridgePorts) == 0 {
		return nil, false, nil, nil
	}
	allowed := make([]int, 0, len(egress))
	for vid, mask := range egress {
		if vid < 1 || vid > 4094 {
			continue
		}
		if !anyBridgePortInMask(mask, bridgePorts) {
			continue
		}
		allowed = append(allowed, vid)
	}
	sort.Ints(allowed)
	var nativeVid *int
	for _, vid := range allowed {
		if utg, ok := untagged[vid]; ok && anyBridgePortInMask(utg, bridgePorts) {
			v := vid
			nativeVid = &v
		}
	}
	if len(allowed) == 4094 {
		return nil, true, nativeVid, nil
	}
	return allowed, false, nativeVid, nil
}

// anyBridgePortInMask reports whether any of the given bridge ports has
// its bit set in mask.
func anyBridgePortInMask(mask []byte, bridgePorts []int) bool {
	for _, bp := range bridgePorts {
		if bridgePortInMask(mask, bp) {
			return true
		}
	}
	return false
}

// bridgePortInMask reports whether bit (port-1) is set MSB-first in mask.
// Mirrors the convention in DecodePortMask but operates without a
// translation table (caller already has the bridgePort number).
func bridgePortInMask(mask []byte, bridgePort int) bool {
	if bridgePort < 1 {
		return false
	}
	idx := (bridgePort - 1) / 8
	bit := (bridgePort - 1) % 8
	if idx >= len(mask) {
		return false
	}
	return mask[idx]&(1<<(7-bit)) != 0
}

// isL3Capable returns true for ifType strings that meaningfully
// participate in L3. Used to gate the "no PVID -> routed" inference; a
// loopback or tunnel interface absent from the bridge table is not a
// routed-switchport candidate.
func isL3Capable(ifType string) bool {
	switch ifType {
	case "ethernetCsmacd", "gigabitEthernet", "ieee8023adLag", "fastEther":
		return true
	}
	return false
}
