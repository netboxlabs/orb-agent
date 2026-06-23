package qbridge

// CiscoRows is the per-host bundle of Cisco-overlay SNMP rows that
// VlanMapper passes to ApplyCisco. All maps are keyed by ifIndex (after
// bridge-port translation).
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
}

// ApplyCisco mutates a per-ifIndex SwitchportInfo map in place,
// overlaying Cisco-specific intent.
//
// Rules:
//   - vmVlan (MembershipAccessVlan) is a positive "this IS an access port"
//     signal. It overrides AdminMode==AdminUnknown and OperMode==OperRouted
//     (which extract_generic infers when no Q-BRIDGE PVID/masks are present).
//     Trunk ports are left untouched — vmMembership is non-trunk-only by spec.
//   - VoiceVlan: parsed via CoerceVid so sentinels (0/4095/4096) drop out.
//     Promotion logic lives in Classify, not here.
//
// Unknown ifIndex (in CiscoRows but not in infos) is ignored — defense
// against drift between Q-BRIDGE and Cisco-overlay walks.
func ApplyCisco(infos map[int]*SwitchportInfo, rows CiscoRows) {
	for ifIndex, vlan := range rows.MembershipAccessVlan {
		info, ok := infos[ifIndex]
		if !ok {
			continue
		}
		if info.AdminMode == AdminTrunk {
			// vmMembership is non-trunk-only by spec; if extract_generic
			// already classified this as trunk from membership masks, that
			// wins over the Cisco overlay.
			continue
		}
		vid := CoerceVid(vlan)
		if vid == nil {
			continue
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
