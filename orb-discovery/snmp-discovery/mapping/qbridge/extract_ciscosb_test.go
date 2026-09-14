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

// TestApplyCiscoSB_SuppliesTheModeOnADeviceWithNoCatalog is the interaction
// between the two halves, which neither alone covers.
//
// These switches answer 1 for dot1qPvid on every port whatever it is
// configured for, and most publish no VLAN catalog, so the generic extractor
// now refuses that PVID and leaves the port with no mode. The private columns
// are the only real evidence such a port has, and a VLAN without a mode never
// reaches NetBox — so the overlay has to supply both.
func TestApplyCiscoSB_SuppliesTheModeOnADeviceWithNoCatalog(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex:  map[int]int{1: 101},
		PortPvid:           map[int]int{101: 1},
		VlanEgressPorts:    map[int][]byte{},
		VlanUntaggedPorts:  map[int][]byte{},
		IfAdminStatus:      map[int]int{101: 1},
		IfTypes:            map[int]string{101: "ethernetCsmacd"},
		VlanCatalogPresent: false,
	}
	infos, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if infos[101].AdminMode != AdminUnknown {
		t.Fatalf("precondition: the default PVID should have been refused, got %v", infos[101].AdminMode)
	}

	ApplyCiscoSB(infos, CiscoSBRows{AccessVlan: map[int]int{101: 20}})

	if c := Classify(*infos[101]); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 20 {
		t.Errorf("got %+v, want access on VLAN 20", c)
	}
}

// The trunk-native column is not access evidence and must not supply a mode.
func TestApplyCiscoSB_TheNativeColumnAloneSuppliesNoMode(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		101: {Enabled: true, BridgePortPresent: true, AdminMode: AdminUnknown},
	}
	ApplyCiscoSB(infos, CiscoSBRows{NativeVlan: map[int]int{101: 30}})

	if infos[101].AdminMode == AdminAccess {
		t.Error("a trunk native VLAN does not make a port access")
	}
}

// A port already read as a trunk keeps that: the overlay fills a vacuum, it
// does not overrule membership evidence.
func TestApplyCiscoSB_DoesNotDemoteATrunk(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		101: {
			Enabled: true, BridgePortPresent: true, AdminMode: AdminTrunk,
			AllowedVlans: AllowedVlans{Vids: []int{10, 20}},
		},
	}
	ApplyCiscoSB(infos, CiscoSBRows{AccessVlan: map[int]int{101: 20}})

	if infos[101].AdminMode != AdminTrunk {
		t.Errorf("AdminMode: got %v, want AdminTrunk", infos[101].AdminMode)
	}
	if c := Classify(*infos[101]); c.Mode != ModeTrunk || len(c.Tagged) != 1 || c.Tagged[0] != 10 {
		t.Errorf("the trunk must keep its tagged VLANs, got %+v", c)
	}
}

// The overlay names the untagged VLAN. Where the generic pass had read a
// different one out of an untagged mask, that VLAN is not a tagged VLAN and
// must not be published as one: the device said the port egresses it untagged.
func TestApplyCiscoSB_DoesNotPublishADisplacedUntaggedVlanAsTagged(t *testing.T) {
	info := genericTrunk(1, 1, 2, 3)
	info.NativeUntaggedByMask = true
	infos := map[int]*SwitchportInfo{10: info}
	ApplyCiscoSB(infos, CiscoSBRows{AccessVlan: map[int]int{10: 4}})
	got := Classify(*infos[10])
	if got.Untagged == nil || *got.Untagged != 4 {
		t.Fatalf("got untagged=%v want 4", deref(got.Untagged))
	}
	for _, v := range got.Tagged {
		if v == 1 {
			t.Fatalf("VLAN 1 is egressed untagged and cannot be tagged: got %v", got.Tagged)
		}
	}
	if want := []int{2, 3}; !reflect.DeepEqual(got.Tagged, want) {
		t.Fatalf("got tagged=%v want %v", got.Tagged, want)
	}
}
