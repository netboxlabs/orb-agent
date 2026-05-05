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
	out := make(map[int]*SwitchportInfo, len(ifIndexToBridge))
	for ifIndex := range ifIndexToBridge {
		info := &SwitchportInfo{
			Enabled:           rows.IfAdminStatus[ifIndex] == 1,
			BridgePortPresent: true,
		}
		if pvid, ok := rows.PortPvid[ifIndex]; ok {
			info.NativeVlan = intPtr(pvid)
			info.AccessVlan = intPtr(pvid)
		} else {
			// In bridge table but no PVID -> positive "not currently
			// bridged" signal -> routed if ifType supports L3.
			if isL3Capable(rows.IfTypes[ifIndex]) {
				info.OperMode = OperRouted
			}
		}

		// Build allowed/native from membership masks.
		allowed, isWildcard, native, err := membershipFromMasks(
			ifIndex, ifIndexToBridge, rows.VlanEgressPorts, rows.VlanUntaggedPorts,
		)
		if err != nil {
			return nil, fmt.Errorf("ifIndex %d: %w", ifIndex, err)
		}
		info.AllowedVlans = AllowedVlans{Vids: allowed, IsWildcard: isWildcard}
		if native != nil {
			info.NativeVlan = native
			info.AccessVlan = native
		}

		// Default mode hint: trunk if more than one egress VLAN, access if exactly one.
		// This is overridden by the Cisco overlay if vendor-specific intent rows exist.
		switch {
		case isWildcard:
			info.AdminMode = AdminTrunk
		case len(allowed) >= 2:
			info.AdminMode = AdminTrunk
		case len(allowed) == 1 && info.OperMode != OperRouted:
			info.AdminMode = AdminAccess
		case len(allowed) == 0 && info.AccessVlan != nil && info.OperMode != OperRouted:
			// PVID-only signal: switches like Arista EOS expose dot1qPvid but
			// omit dot1qVlanStaticEgressPorts/UntaggedPorts. The PVID alone is
			// sufficient — a port with a PVID participates in bridging, and the
			// safe default is "access on PVID" when membership masks are absent.
			info.AdminMode = AdminAccess
		}
		out[ifIndex] = info
	}
	return out, nil
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
