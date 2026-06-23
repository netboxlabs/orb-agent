package qbridge

import (
	"testing"
)

func TestExtractGeneric_AccessPort(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101, 2: 102},
		PortPvid:          map[int]int{101: 10, 102: 20},
		VlanEgressPorts: map[int][]byte{
			10: {0x80}, // port 1
			20: {0x40}, // port 2
		},
		VlanUntaggedPorts: map[int][]byte{
			10: {0x80},
			20: {0x40},
		},
		IfTypes: map[int]string{
			101: "ethernetCsmacd",
			102: "ethernetCsmacd",
		},
		IfAdminStatus: map[int]int{101: 1, 102: 1},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	for _, ifIndex := range []int{101, 102} {
		info, ok := got[ifIndex]
		if !ok {
			t.Fatalf("ifIndex %d missing", ifIndex)
		}
		if !info.Enabled || !info.BridgePortPresent {
			t.Errorf("ifIndex %d: Enabled=%v BridgePortPresent=%v",
				ifIndex, info.Enabled, info.BridgePortPresent)
		}
	}
}

func TestExtractGeneric_TrunkAllWildcard(t *testing.T) {
	bp := map[int]int{1: 1001}
	rows := GenericRows{
		BasePortToIfIndex: bp,
		PortPvid:          map[int]int{1001: 1},
		VlanEgressPorts:   map[int][]byte{},
		VlanUntaggedPorts: map[int][]byte{},
		IfAdminStatus:     map[int]int{1001: 1},
		IfTypes:           map[int]string{1001: "ethernetCsmacd"},
	}
	for vid := 1; vid <= 4094; vid++ {
		// Each VID has port 1 in its egress set (so port 1 is in all VLANs).
		rows.VlanEgressPorts[vid] = []byte{0x80}
		if vid != 1 {
			// All VLANs except native have it tagged on the port.
			rows.VlanUntaggedPorts[vid] = []byte{0x00}
		} else {
			rows.VlanUntaggedPorts[vid] = []byte{0x80}
		}
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	info := got[1001]
	if !info.AllowedVlans.IsWildcard {
		t.Errorf("expected wildcard, got %+v", info.AllowedVlans)
	}
}

func TestExtractGeneric_RoutedPort(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 201}, // 201 IS in bridge table
		PortPvid:          map[int]int{},       // but has no PVID -> not bridged
		VlanEgressPorts:   map[int][]byte{},
		VlanUntaggedPorts: map[int][]byte{},
		IfAdminStatus:     map[int]int{201: 1},
		IfTypes:           map[int]string{201: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	info := got[201]
	if info.OperMode != OperRouted {
		t.Errorf("expected OperRouted, got %v", info.OperMode)
	}
}

func TestExtractGeneric_MissingTranslationTable(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{}, // empty
		VlanEgressPorts:   map[int][]byte{10: {0xFF}},
	}
	if _, err := ExtractGeneric(rows); err == nil {
		t.Fatal("want error, got nil")
	}
}

func TestExtractGeneric_PvidOnlyClassifiesAsAccess(t *testing.T) {
	// Simulates Arista EOS: dot1qPvid is populated but
	// dot1qVlanStaticEgressPorts/UntaggedPorts are absent entirely.
	// The PVID alone is sufficient signal to classify as access.
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101},
		PortPvid:          map[int]int{101: 10},
		VlanEgressPorts:   map[int][]byte{}, // no membership masks
		VlanUntaggedPorts: map[int][]byte{},
		IfAdminStatus:     map[int]int{101: 1},
		IfTypes:           map[int]string{101: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	info, ok := got[101]
	if !ok {
		t.Fatal("ifIndex 101 missing from result")
	}
	if info.AdminMode != AdminAccess {
		t.Errorf("AdminMode: got %v, want AdminAccess", info.AdminMode)
	}
	if info.AccessVlan == nil || *info.AccessVlan != 10 {
		t.Errorf("AccessVlan: got %v, want 10", info.AccessVlan)
	}
}

// TestExtractGeneric_MultipleBridgePortsPerIfIndex regression-tests the
// case where BRIDGE-MIB returns multiple bridge ports for the same
// ifIndex (rare but permitted, e.g. on switches where the same logical
// interface participates in multiple bridges or LAG sub-port mappings).
// The pre-fix reverse map was 1:1 and overwrote earlier bridge ports
// in random map-iteration order; only the last-seen port's membership
// was checked. The fix aggregates all bridge ports per ifIndex and
// unions membership across them.
func TestExtractGeneric_MultipleBridgePortsPerIfIndex(t *testing.T) {
	// Bridge ports 1 AND 2 both map to ifIndex 101.
	// VLAN 50 has port 1 in egress (untagged); port 2 is NOT.
	// VLAN 60 has port 2 in egress (tagged); port 1 is NOT.
	// Expected: ifIndex 101's allowed VIDs cover both 50 and 60
	// regardless of which bridge port survives map iteration.
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101, 2: 101},
		PortPvid:          map[int]int{101: 50},
		VlanEgressPorts: map[int][]byte{
			50: {0x80}, // bit 7 set — bridge port 1
			60: {0x40}, // bit 6 set — bridge port 2
		},
		VlanUntaggedPorts: map[int][]byte{
			50: {0x80}, // bridge port 1 untagged on VLAN 50
		},
		IfTypes:       map[int]string{101: "ethernetCsmacd"},
		IfAdminStatus: map[int]int{101: 1},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	info := got[101]
	if info == nil {
		t.Fatal("ifIndex 101 missing")
	}
	if len(info.AllowedVlans.Vids) != 2 {
		t.Errorf("AllowedVlans.Vids: got %v, want [50 60]", info.AllowedVlans.Vids)
	}
	if info.NativeVlan == nil || *info.NativeVlan != 50 {
		t.Errorf("NativeVlan: got %v, want 50", info.NativeVlan)
	}
}
