package qbridge

// CiscoRows is the per-host bundle of Cisco-overlay SNMP rows that
// VlanMapper passes to ApplyCisco. All maps are keyed by ifIndex.
//
// Scope per spec rev. 3: this overlay covers only ACCESS-VLAN refinement
// on non-trunk ports + VOICE-VLAN promotion. It does NOT fill the trunk
// allowed/native gap.
type CiscoRows struct {
	// MembershipAccessVlan from CISCO-VLAN-MEMBERSHIP-MIB
	// vmVlan (1.3.6.1.4.1.9.9.68.1.2.2.1.2). Only populated by Cisco for
	// ports configured in non-trunk (static-access) mode.
	MembershipAccessVlan map[int]int

	// VoiceVlanByIfIndex from CISCO-VOICE-VLAN-MIB
	// vmVoiceVlanId (1.3.6.1.4.1.9.9.68.1.5.1.1).
	// Sentinel values: 0 = none, 4095 = dot1p-only, 4096 = untagged.
	// Only valid VIDs in [1, 4094] are forwarded onto SwitchportInfo.
	VoiceVlanByIfIndex map[int]int

	// TrunkStatus from CISCO-VTP-MIB vlanTrunkPortDynamicStatus
	// (1.3.6.1.4.1.9.9.46.1.6.1.1.14): trunking(1) or notTrunking(2).
	TrunkStatus map[int]int

	// TrunkEncapsulation from CISCO-VTP-MIB
	// vlanTrunkPortEncapsulationOperType (1.3.6.1.4.1.9.9.46.1.6.1.1.16):
	// notApplicable(6) on a port that does not trunk. Read only where
	// TrunkStatus has no row.
	TrunkEncapsulation map[int]int

	// IfAdminStatus from IF-MIB, for ports the bridge-port table omits.
	IfAdminStatus map[int]int
}

const (
	trunkStatusTrunking    = 1
	trunkStatusNotTrunking = 2
	encapNotApplicable     = 6
)

// trunking reports whether the device says the port trunks, and whether it
// said anything at all.
func (r CiscoRows) trunking(ifIndex int) (trunks, known bool) {
	switch r.TrunkStatus[ifIndex] {
	case trunkStatusTrunking:
		return true, true
	case trunkStatusNotTrunking:
		return false, true
	}
	if encap, ok := r.TrunkEncapsulation[ifIndex]; ok {
		return encap != encapNotApplicable, true
	}
	return false, false
}

// ApplyCisco mutates a per-ifIndex SwitchportInfo map in place,
// overlaying Cisco-specific intent.
//
// Rules:
//   - vmVlan (MembershipAccessVlan) is a positive "this IS an access port"
//     signal. It overrides AdminMode==AdminUnknown and OperMode==OperRouted
//     (which extract_generic infers when no Q-BRIDGE PVID/masks are present).
//     Trunk ports are left untouched: NX-OS publishes vmVlan rows for trunks
//     too, carrying the configured access VLAN, so a port the trunk table
//     says trunks is skipped.
//   - VoiceVlan: parsed via CoerceVid so sentinels (0/4095/4096) drop out.
//     Promotion logic lives in Classify, not here.
//   - A port with a vmVlan row but no entry in infos is added as an access
//     port when the trunk table says it does not trunk. Cisco keeps a
//     BRIDGE-MIB instance per VLAN, so the default context lists only the
//     ports in VLAN 1, while vmMembershipTable is indexed by ifIndex. Without
//     a trunk row such a port cannot be told from a trunk that does not carry
//     VLAN 1, and is left alone. A voice row alone adds no port.
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
			// vmMembership is non-trunk-only by spec; if extract_generic
			// already classified this as trunk from membership in several
			// VLANs, that wins over the Cisco overlay.
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
		// vmVlan is a positive "this IS an access port on VID X" signal from
		// CISCO-VLAN-MEMBERSHIP-MIB. It overrides:
		//   - AdminMode == AdminUnknown (extract_generic couldn't infer mode
		//     because the device lacks Q-BRIDGE membership masks)
		//   - OperMode == OperRouted (extract_generic inferred routed from
		//     "no PVID + L3-able ifType", but vmMembership trumps that)
		// Trunk ports remain untouched: vmMembership is non-trunk-only by spec
		// (CISCO-VLAN-MEMBERSHIP-MIB documentation), so seeing a row implies
		// access regardless of what extract_generic guessed.
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
