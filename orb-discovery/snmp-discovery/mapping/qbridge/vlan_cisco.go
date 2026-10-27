package qbridge

// DecodeCiscoActiveVlans decodes the two CISCO-VTP-MIB active VLAN bitmaps.
// The first covers VLANs 0-2047 and the second covers VLANs 2048-4095.
// Within each byte, the most significant bit represents the lowest VLAN ID.
//
// Both rows must be present. A missing row means the SNMP snapshot is
// incomplete; an explicitly present empty row is valid. Cisco may truncate
// trailing zero bytes, so neither bitmap must be exactly 256 bytes long.
//
// The returned VLAN IDs are unique, sorted, and restricted to 1-4094.
func DecodeCiscoActiveVlans(first, second []byte, hasFirst, hasSecond bool) ([]int, bool) {
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

// ApplyCiscoTrunks overlays complete Cisco VTP active-VLAN membership onto
// positively identified trunk ports. It leaves access and voice VLAN handling
// to ApplyCisco.
//
// A trunk is updated only when both active bitmap rows are present and valid.
// This avoids replacing a known membership list with a partial SNMP snapshot.
func ApplyCiscoTrunks(infos map[int]*SwitchportInfo, rows CiscoRows) {
	for ifIndex, first := range rows.ActiveFirst2k {
		trunks, _ := rows.trunking(ifIndex)
		if !trunks {
			continue
		}

		second, hasSecond := rows.ActiveSecond2k[ifIndex]
		vlans, complete := DecodeCiscoActiveVlans(
			first, second, true, hasSecond,
		)
		if !complete {
			continue
		}

		info, exists := infos[ifIndex]
		if !exists {
			// Without a bridge-port entry, require an explicit IF-MIB
			// administrative state before creating a switchport.
			adminStatus, hasAdminStatus := rows.IfAdminStatus[ifIndex]
			if !hasAdminStatus {
				continue
			}
			info = &SwitchportInfo{
				Enabled:           adminStatus == 1,
				BridgePortPresent: true,
			}
			infos[ifIndex] = info
		}

		// A positively identified Cisco trunk supersedes an incomplete
		// generic inference, including an inferred routed port.
		info.AdminMode = AdminTrunk
		info.OperMode = OperTrunk
		info.TrunkFromOneTaggedVlan = false
		info.AllowedVlans = AllowedVlans{Vids: vlans}

		// Only replace the native VLAN when Cisco reports a valid VID.
		// Otherwise preserve any native VLAN found by the generic extractor.
		if native, ok := rows.NativeVlan[ifIndex]; ok {
			if vid := CoerceVid(native); vid != nil {
				info.NativeVlan = vid
			}
		}
	}
}
