package qbridge

import (
	"reflect"
	"testing"
)

// genericAccess returns what the standard Q-BRIDGE path produces on a CISCOSB
// switch: a bridge port whose PVID reads 1 because the device answers 1 for
// every port, with no membership masks to correct it.
func genericAccess(pvid int) *SwitchportInfo {
	return &SwitchportInfo{
		Enabled:           true,
		BridgePortPresent: true,
		AdminMode:         AdminAccess,
		AccessVlan:        intPtr(pvid),
		NativeVlan:        intPtr(pvid),
	}
}

// genericTrunk returns what the generic pass produces for a working trunk, so
// tests can prove the overlay does not demote it.
func genericTrunk(native int, tagged ...int) *SwitchportInfo {
	return &SwitchportInfo{
		Enabled:           true,
		BridgePortPresent: true,
		AdminMode:         AdminTrunk,
		NativeVlan:        intPtr(native),
		AccessVlan:        intPtr(native),
		AllowedVlans:      AllowedVlans{Vids: tagged},
	}
}

func TestApplyCiscoSBCorrectsWrongStandardPvid(t *testing.T) {
	// Issue #482: dot1qPvid answers 1 for a port really on VLAN 2137.
	infos := map[int]*SwitchportInfo{2: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{AccessVlan: map[int]int{2: 2137}})
	got := Classify(*infos[2])
	if got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 2137 {
		t.Fatalf("got mode=%v untagged=%v want access/2137", got.Mode, deref(got.Untagged))
	}
}

func TestApplyCiscoSBDoesNotDemoteATrunk(t *testing.T) {
	// The access column says which VLAN is untagged, not whether the port is a
	// trunk. Deriving mode from it would drop the port's tagged VLANs.
	infos := map[int]*SwitchportInfo{5: genericTrunk(1, 1, 10, 20)}
	ApplyCiscoSB(infos, CiscoSBRows{AccessVlan: map[int]int{5: 10}})
	got := Classify(*infos[5])
	if got.Mode != ModeTrunk {
		t.Fatalf("got mode=%v want trunk", got.Mode)
	}
	if got.Untagged == nil || *got.Untagged != 10 {
		t.Fatalf("got untagged=%v want 10", deref(got.Untagged))
	}
	if want := []int{1, 20}; !reflect.DeepEqual(got.Tagged, want) {
		t.Fatalf("got tagged=%v want %v", got.Tagged, want)
	}
}

func TestApplyCiscoSBLeavesGenericResultWhenNoEvidence(t *testing.T) {
	// Non-CISCOSB Cisco gear is walked for these OIDs too, so absent or zeroed
	// columns must not disturb the generic classification.
	for _, tc := range []struct {
		name string
		rows CiscoSBRows
	}{
		{"no rows", CiscoSBRows{}},
		{"zero access vlan", CiscoSBRows{AccessVlan: map[int]int{9: 0}}},
		{"zero native vlan", CiscoSBRows{NativeVlan: map[int]int{9: 0}}},
		{"out-of-range access vlan", CiscoSBRows{AccessVlan: map[int]int{9: 4095}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			infos := map[int]*SwitchportInfo{9: genericAccess(50)}
			ApplyCiscoSB(infos, tc.rows)
			got := Classify(*infos[9])
			if got.Untagged == nil || *got.Untagged != 50 {
				t.Fatalf("got untagged=%v want the generic 50", deref(got.Untagged))
			}
		})
	}
}

func TestApplyCiscoSBIgnoresUnknownIfIndex(t *testing.T) {
	// A row for an ifIndex the generic pass never produced must not create one.
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{AccessVlan: map[int]int{999: 2137}})
	if len(infos) != 1 {
		t.Fatalf("got %d infos want 1", len(infos))
	}
}

func TestApplyCiscoSBFactoryDefaultNativeVlanIsNotEvidence(t *testing.T) {
	// vlanTrunkPortModeNativeVlanId reads 1 on an unconfigured port, which is
	// indistinguishable from unset, so on an access port it must not overwrite
	// the VLAN the generic pass found.
	infos := map[int]*SwitchportInfo{11: genericAccess(50)}
	ApplyCiscoSB(infos, CiscoSBRows{NativeVlan: map[int]int{11: 1}})
	if got := Classify(*infos[11]); got.Untagged == nil || *got.Untagged != 50 {
		t.Fatalf("got untagged=%v want the generic 50", deref(got.Untagged))
	}

	// On a port already known to be a trunk it is meaningful.
	trunk := map[int]*SwitchportInfo{12: genericTrunk(7, 7, 8)}
	ApplyCiscoSB(trunk, CiscoSBRows{NativeVlan: map[int]int{12: 1}})
	if got := Classify(*trunk[12]); got.Untagged == nil || *got.Untagged != 1 {
		t.Fatalf("got untagged=%v want 1 on a trunk", deref(got.Untagged))
	}
}

func TestApplyCiscoSBAccessColumnOutranksNativeColumn(t *testing.T) {
	// Both columns can be populated at once (the reporter's port 2 had 2137 in
	// each after trying both configurations). The access column wins.
	infos := map[int]*SwitchportInfo{3: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		AccessVlan: map[int]int{3: 2137},
		NativeVlan: map[int]int{3: 999},
	})
	if got := Classify(*infos[3]); got.Untagged == nil || *got.Untagged != 2137 {
		t.Fatalf("got untagged=%v want 2137", deref(got.Untagged))
	}
}

func TestApplyCiscoSBHasData(t *testing.T) {
	if (CiscoSBRows{}).HasData() {
		t.Error("empty rows must not report data")
	}
	if !(CiscoSBRows{AccessVlan: map[int]int{1: 10}}).HasData() {
		t.Error("access-VLAN rows must report data")
	}
	if !(CiscoSBRows{NativeVlan: map[int]int{1: 10}}).HasData() {
		t.Error("native-VLAN rows must report data")
	}
}
