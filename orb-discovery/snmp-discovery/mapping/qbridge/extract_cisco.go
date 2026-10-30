package qbridge

import "log/slog"

// CiscoRows is the per-host bundle of Cisco-overlay SNMP rows that
// VlanMapper passes to ApplyCisco and ApplyCiscoTrunks.
// It covers access and voice VLAN refinement and Cisco trunk membership.
// All maps are keyed by ifIndex.
type CiscoRows struct {
	// MembershipAccessVlan from CISCO-VLAN-MEMBERSHIP-MIB
	// vmVlan (1.3.6.1.4.1.9.9.68.1.2.2.1.2): the access VLAN configured on
	// the port. IOS publishes it for access ports; NX-OS for trunks as well.
	MembershipAccessVlan map[int]int

	// VoiceVlanByIfIndex from CISCO-VOICE-VLAN-MIB
	// vmVoiceVlanId (1.3.6.1.4.1.9.9.68.1.5.1.1).
	// Sentinel values: 0 = none, 4095 = dot1p-only, 4096 = untagged.
	// Only valid VIDs in [1, 4094] are forwarded onto SwitchportInfo.
	VoiceVlanByIfIndex map[int]int

	// TrunkDynamicState from CISCO-VTP-MIB vlanTrunkPortDynamicState
	// (1.3.6.1.4.1.9.9.46.1.6.1.1.13): the configured mode. on(1) and
	// onNoNegotiate(5) are configured trunks, whatever the link is doing.
	TrunkDynamicState map[int]int

	// TrunkStatus from CISCO-VTP-MIB vlanTrunkPortDynamicStatus
	// (1.3.6.1.4.1.9.9.46.1.6.1.1.14): trunking(1) or notTrunking(2).
	TrunkStatus map[int]int

	// TrunkEncapsulation from CISCO-VTP-MIB
	// vlanTrunkPortEncapsulationOperType (1.3.6.1.4.1.9.9.46.1.6.1.1.16):
	// notApplicable(6) on a port that does not trunk. NX-OS reports it from
	// the configuration, so a trunk that is down still reads dot1Q.
	TrunkEncapsulation map[int]int

	// NativeVlan from CISCO-VTP-MIB vlanTrunkPortNativeVlan (.5).
	NativeVlan map[int]int

	// Configured allowed VLANs from CISCO-VTP-MIB (.4, .17, .18, .19).
	// Each bitmap covers 1024 VLAN IDs, starting at 0, 1024, 2048, 3072.
	ConfiguredVlans [4]map[int][]byte

	// Active VLAN membership from CISCO-VTP-MIB (.30 and .31).
	// These bitmaps are indexed by VLAN ID, not bridge-port number.
	// First2k covers VLANs 0-2047; Second2k covers 2048-4095.
	ActiveFirst2k  map[int][]byte
	ActiveSecond2k map[int][]byte

	// IfAdminStatus from IF-MIB, for ports the bridge-port table omits.
	IfAdminStatus map[int]int
}

const (
	trunkStateOn            = 1
	trunkStateOnNoNegotiate = 5
	trunkStatusTrunking     = 1
	trunkStatusNotTrunking  = 2
	encapNotApplicable      = 6
)

// trunking reports whether any column says the port trunks, and whether the
// operational columns gave a verdict. The dynamic status is operational, so a
// configured trunk that is down reads notTrunking; the configured mode, or on
// NX-OS the encapsulation, still marks it.
func (r CiscoRows) trunking(ifIndex int) (trunks, known bool) {
	state := r.TrunkDynamicState[ifIndex]
	status, hasStatus := r.TrunkStatus[ifIndex]
	encap, hasEncap := r.TrunkEncapsulation[ifIndex]
	if state == trunkStateOn || state == trunkStateOnNoNegotiate ||
		status == trunkStatusTrunking || (hasEncap && encap != encapNotApplicable) {
		return true, true
	}
	return false, (hasStatus && status == trunkStatusNotTrunking) || hasEncap
}

// ApplyCisco mutates a per-ifIndex SwitchportInfo map in place,
// overlaying Cisco-specific intent.
//
// Rules:
//   - vmVlan (MembershipAccessVlan) on a port that does not trunk is a
//     positive access signal. It overrides AdminMode==AdminUnknown and
//     OperMode==OperRouted (which extract_generic infers when no Q-BRIDGE
//     PVID/masks are present). NX-OS publishes vmVlan rows for trunks too,
//     carrying the configured access VLAN, so a port either trunk column
//     says trunks is skipped.
//   - VoiceVlan: parsed via CoerceVid so sentinels (0/4095/4096) drop out.
//     Promotion logic lives in Classify, not here.
//   - A port with a vmVlan row but no entry in infos is added as an access
//     port when the trunk table gave a verdict and neither column says it
//     trunks. Cisco keeps a BRIDGE-MIB instance per VLAN, so the default
//     context lists only the ports in VLAN 1, while vmMembershipTable is
//     indexed by ifIndex. Without a verdict such a port cannot be told from a
//     trunk that does not carry VLAN 1, and is left alone. A voice row alone
//     adds no port.
func ApplyCisco(infos map[int]*SwitchportInfo, rows CiscoRows) {
	for ifIndex, vlan := range rows.MembershipAccessVlan {
		vid := CoerceVid(vlan)
		if vid == nil {
			continue
		}
		trunks, known := rows.trunking(ifIndex)
		if trunks {
			continue
		}
		info, ok := infos[ifIndex]
		if !ok {
			if !known {
				continue
			}
			info = &SwitchportInfo{
				Enabled: rows.IfAdminStatus[ifIndex] == 1,
				// The vmVlan row stands in for the bridge port Cisco leaves
				// out of the default context.
				BridgePortPresent: true,
			}
			infos[ifIndex] = info
		}
		if info.AdminMode == AdminTrunk && !info.TrunkFromOneTaggedVlan {
			// If extract_generic already classified this as a trunk from
			// membership in several VLANs, that wins over the Cisco overlay.
			continue
		}
		if info.TrunkFromOneTaggedVlan {
			// A trunk inferred from one tagged VLAN alone is the weakest
			// reading the generic extractor makes, and this row is positive
			// access evidence for the port: the port is access on the row's
			// VLAN.
			info.AdminMode = AdminAccess
			info.TrunkFromOneTaggedVlan = false
		}
		// On a port no column says trunks, vmVlan is a positive "this IS an
		// access port on VID X" signal. It overrides:
		//   - AdminMode == AdminUnknown (extract_generic couldn't infer mode
		//     because the device lacks Q-BRIDGE membership masks)
		//   - OperMode == OperRouted (extract_generic inferred routed from
		//     "no PVID + L3-able ifType", but vmMembership trumps that)
		info.AccessVlan = vid
		if info.AdminMode == AdminUnknown {
			info.AdminMode = AdminAccess
		}
		if info.OperMode == OperRouted {
			info.OperMode = OperAccess
		}
	}
	for ifIndex, vlan := range rows.VoiceVlanByIfIndex {
		info, ok := infos[ifIndex]
		if !ok {
			continue
		}
		if vid := CoerceVid(vlan); vid != nil {
			info.VoiceVlan = vid
		}
	}
}

// decodeCiscoActiveVlans decodes the two CISCO-VTP-MIB active VLAN bitmaps.
// The first covers VLANs 0-2047 and the second covers VLANs 2048-4095.
// Within each byte, the most significant bit represents the lowest VLAN ID.
//
// Both rows must be present. A missing row means the SNMP snapshot is
// incomplete; an explicitly present empty row is valid. Cisco may truncate
// trailing zero bytes, so neither bitmap must be exactly 256 bytes long.
//
// The returned VLAN IDs are unique, sorted, and restricted to 1-4094.
func decodeCiscoActiveVlans(first, second []byte, hasFirst, hasSecond bool) ([]int, bool) {
	if !hasFirst || !hasSecond {
		return nil, false
	}
	if len(first) > 256 || len(second) > 256 {
		return nil, false
	}

	vlans := make([]int, 0)

	decode := func(bitmap []byte, offset int) {
		for byteIndex, b := range bitmap {
			if b == 0 {
				continue
			}
			for bit := 0; bit < 8; bit++ {
				if b&(0x80>>uint(bit)) == 0 {
					continue
				}
				vid := offset + byteIndex*8 + bit
				if vid >= 1 && vid <= 4094 {
					vlans = append(vlans, vid)
				}
			}
		}
	}

	decode(first, 0)
	decode(second, 2048)

	return vlans, true
}

// decodeCiscoConfiguredVlans decodes all four configured allowed-VLAN
// bitmaps. Missing or oversized segments invalidate the snapshot.
func decodeCiscoConfiguredVlans(rows CiscoRows, ifIndex int) ([]int, bool) {
	vlans := make([]int, 0)
	for segment, bitmapRows := range rows.ConfiguredVlans {
		bitmap, present := bitmapRows[ifIndex]
		if !present || len(bitmap) > 128 {
			return nil, false
		}
		for byteIndex, b := range bitmap {
			for bit := 0; bit < 8; bit++ {
				if b&(0x80>>uint(bit)) == 0 {
					continue
				}
				vid := segment*1024 + byteIndex*8 + bit
				if vid >= 1 && vid <= 4094 {
					vlans = append(vlans, vid)
				}
			}
		}
	}
	return vlans, true
}

// ciscoTrunkMembership intersects configured and active VLANs.
// taggedAll is true only when every valid VLAN (1-4094) is configured.
func ciscoTrunkMembership(configured, active []int) (carried []int, taggedAll bool) {
	taggedAll = len(configured) == 4094

	activeSet := make(map[int]bool, len(active))
	for _, vid := range active {
		activeSet[vid] = true
	}

	for _, vid := range configured {
		if activeSet[vid] {
			carried = append(carried, vid)
		}
	}
	return carried, taggedAll
}

// ApplyCiscoTrunks overlays Cisco trunk VLAN membership onto positively
// identified trunk ports. It leaves access and voice VLAN handling to ApplyCisco.
//
// All configured and active bitmap rows must be present and valid, and active
// membership must be nonempty. Carried VLANs are configured intersected with
// active; a full configured range uses tagged-all. Native VLAN is retained
// only when carried. Incomplete or empty active data leaves the port unchanged.
func ApplyCiscoTrunks(infos map[int]*SwitchportInfo, rows CiscoRows, logger *slog.Logger) map[int][]int {
	accepted := make(map[int][]int)
	for ifIndex, first := range rows.ActiveFirst2k {
		trunks, _ := rows.trunking(ifIndex)
		if !trunks {
			continue
		}

		second, hasSecond := rows.ActiveSecond2k[ifIndex]
		active, complete := decodeCiscoActiveVlans(first, second, true, hasSecond)
		if !complete || len(active) == 0 {
			logger.Debug("vlan: Cisco trunk refused", "ifindex", ifIndex, "reason", "missing-or-empty-active-vlans")
			continue
		}

		configured, complete := decodeCiscoConfiguredVlans(rows, ifIndex)
		if !complete {
			logger.Debug("vlan: Cisco trunk refused", "ifindex", ifIndex, "reason", "incomplete-configured-vlans")
			continue
		}

		carried, taggedAll := ciscoTrunkMembership(configured, active)

		if len(carried) == 0 && !taggedAll {
			logger.Debug("vlan: Cisco trunk refused", "ifindex", ifIndex, "reason", "no-carried-vlans")
			continue
		}

		info, exists := infos[ifIndex]
		if !exists {
			adminStatus, hasAdminStatus := rows.IfAdminStatus[ifIndex]
			if !hasAdminStatus {
				logger.Debug("vlan: Cisco trunk refused", "ifindex", ifIndex, "reason", "missing-if-admin-status")
				continue
			}
			info = &SwitchportInfo{
				Enabled:           adminStatus == 1,
				BridgePortPresent: true,
			}
			infos[ifIndex] = info
		}

		accepted[ifIndex] = carried
		info.AdminMode = AdminTrunk
		info.OperMode = OperTrunk
		info.TrunkFromOneTaggedVlan = false
		info.AllowedVlans = AllowedVlans{
			Vids:       carried,
			IsWildcard: taggedAll,
		}

		// A configured native VLAN is only valid when it is actually
		// carried. Clear any stale native inferred by generic discovery.
		info.NativeVlan = nil
		if native, ok := rows.NativeVlan[ifIndex]; ok {
			if vid := CoerceVid(native); vid != nil {
				for _, carriedVID := range carried {
					if carriedVID == *vid {
						info.NativeVlan = vid
						break
					}
				}
			}
		}
	}
	return accepted
}
