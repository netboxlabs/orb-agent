package qbridge

// Classify maps a SwitchportInfo to a Classification using the rules
// documented in spec rev. 3 §"Output contract" and §"Voice VLAN handling".
//
// The function is pure: no SNMP, no logging, no allocation tied to global
// state. Drives ~all unit-test coverage in this package.
func Classify(info SwitchportInfo) Classification {
	empty := Classification{Mode: ModeUnknown, Tagged: []int{}, Untagged: nil}

	if !info.Enabled {
		return empty
	}
	if !info.BridgePortPresent {
		return empty
	}
	if info.OperMode == OperRouted {
		return Classification{Mode: ModeRouted, Tagged: []int{}, Untagged: nil}
	}

	effective := resolveEffectiveMode(info.AdminMode, info.OperMode)
	switch effective {
	case AdminAccess:
		access := CoerceVid(deref(info.AccessVlan))
		voice := CoerceVid(deref(info.VoiceVlan))
		// Voice promotion: only on access ports, only when voice != access.
		// Mirrors device-discovery/custom_napalm/_vlan.py:177-186.
		if voice != nil && (access == nil || *voice != *access) {
			return Classification{Mode: ModeTrunk, Tagged: []int{*voice}, Untagged: access}
		}
		return Classification{Mode: ModeAccess, Tagged: []int{}, Untagged: access}
	case AdminTrunk:
		native := CoerceVid(deref(info.NativeVlan))
		if info.AllowedVlans.IsWildcard {
			return Classification{Mode: ModeTrunkAll, Tagged: []int{}, Untagged: native}
		}
		tagged := make([]int, 0, len(info.AllowedVlans.Vids))
		for _, v := range info.AllowedVlans.Vids {
			vid := CoerceVid(v)
			if vid == nil {
				continue
			}
			if native != nil && *vid == *native {
				continue
			}
			tagged = append(tagged, *vid)
		}
		return Classification{Mode: ModeTrunk, Tagged: tagged, Untagged: native}
	default:
		return empty
	}
}

// resolveEffectiveMode applies the DTP fallback: an admin mode of
// "dynamic" or "unknown" defers to the operational mode. Returns
// AdminUnknown when neither admin nor oper is conclusive — the caller
// treats that as ModeUnknown.
func resolveEffectiveMode(admin AdminMode, oper OperMode) AdminMode {
	switch admin {
	case AdminAccess, AdminTrunk:
		return admin
	}
	switch oper {
	case OperAccess:
		return AdminAccess
	case OperTrunk:
		return AdminTrunk
	}
	return AdminUnknown
}

// deref returns the int value of p, or 0 if p is nil. The 0 signals "no
// value" to CoerceVid (which rejects 0 as out-of-range), so chaining
// CoerceVid(deref(p)) is safe for nil inputs.
func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
