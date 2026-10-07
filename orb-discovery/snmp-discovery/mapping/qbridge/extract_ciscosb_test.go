package qbridge

import (
	"fmt"
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

// The generic extractor infers routed from a missing dot1qPvid row. These
// switches answer that column for every port, but it is walked separately, so
// a failed or truncated walk leaves every port looking routed. The access
// column names the port an access port, which is positive evidence it is
// bridged, and Classify answers routed before it reads the mode.
func TestApplyCiscoSB_OverridesTheRoutedInference(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		7: {Enabled: true, BridgePortPresent: true, OperMode: OperRouted},
	}
	ApplyCiscoSB(infos, CiscoSBRows{AccessVlan: map[int]int{7: 42}})
	got := Classify(*infos[7])
	if got.Mode != ModeAccess {
		t.Fatalf("got mode=%v want access", got.Mode)
	}
	if got.Untagged == nil || *got.Untagged != 42 {
		t.Fatalf("got untagged=%v want 42", deref(got.Untagged))
	}

	// The trunk-native column is not access evidence, so it does not override
	// the inference: a port whose only CISCOSB value is a trunk native VLAN
	// still ends up with no mode and no VLAN.
	infos = map[int]*SwitchportInfo{
		7: {Enabled: true, BridgePortPresent: true, OperMode: OperRouted},
	}
	ApplyCiscoSB(infos, CiscoSBRows{NativeVlan: map[int]int{7: 42}})
	if got := Classify(*infos[7]); got.Mode != ModeRouted {
		t.Fatalf("got mode=%v want routed", got.Mode)
	}
}

// trunkLists builds the four vlanTrunkModeList columns naming vids: list n
// covers VLANs n*1024+1 onwards, the most significant bit of each octet first.
func trunkLists(vids ...int) map[int][]byte {
	lists := map[int][]byte{}
	for n := 0; n < 4; n++ {
		lists[n] = make([]byte, 128)
	}
	for _, vid := range vids {
		bit := (vid - 1) % 1024
		lists[(vid-1)/1024][bit/8] |= 0x80 >> (bit % 8)
	}
	return lists
}

// everyVlan is a trunk list allowing all of 1-4094, as "allowed vlan all" sets
// it, padding bits included.
func everyVlan() map[int][]byte {
	lists := map[int][]byte{}
	for n := 0; n < 4; n++ {
		lists[n] = make([]byte, 128)
		for i := range lists[n] {
			lists[n][i] = 0xff
		}
	}
	return lists
}

func catalog(vids ...int) map[int]struct{} {
	out := map[int]struct{}{}
	for _, vid := range vids {
		out[vid] = struct{}{}
	}
	return out
}

// A trunk keeps an access VLAN setting from when it was last an access port.
// The native column names its untagged VLAN and its member lists the tagged
// ones; the access column says nothing about it.
func TestApplyCiscoSB_TrunkTakesItsNativeAndMemberVlans(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		AccessVlan: map[int]int{1: 30},
		NativeVlan: map[int]int{1: 20},
		TrunkLists: map[int]map[int][]byte{1: trunkLists(10, 20, 40)},
		Vlans:      catalog(10, 20, 30, 40),
	})
	got := Classify(*infos[1])
	if got.Mode != ModeTrunk || got.Untagged == nil || *got.Untagged != 20 {
		t.Fatalf("got mode=%v untagged=%v want trunk/20", got.Mode, deref(got.Untagged))
	}
	if want := []int{10, 40}; !reflect.DeepEqual(got.Tagged, want) {
		t.Fatalf("got tagged=%v want %v", got.Tagged, want)
	}
}

// The member lists can name VLANs that were never created. The switch carries
// only those it has, so only those are tagged.
func TestApplyCiscoSB_TrunkTagsOnlyVlansTheDeviceHas(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 10},
		TrunkLists: map[int]map[int][]byte{1: trunkLists(10, 20, 99)},
		Vlans:      catalog(10, 20),
	})
	if got := Classify(*infos[1]); !reflect.DeepEqual(got.Tagged, []int{20}) {
		t.Fatalf("got tagged=%v want [20]", got.Tagged)
	}
}

// A native VLAN the port is not a member of is not carried, so the trunk has
// no untagged VLAN.
func TestApplyCiscoSB_NativeVlanOutsideTheListIsNotUntagged(t *testing.T) {
	infos := map[int]*SwitchportInfo{1000: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1000: 12},
		NativeVlan: map[int]int{1000: 1},
		TrunkLists: map[int]map[int][]byte{1000: trunkLists(10, 20)},
		Vlans:      catalog(1, 10, 20),
	})
	got := Classify(*infos[1000])
	if got.Mode != ModeTrunk || got.Untagged != nil {
		t.Fatalf("got mode=%v untagged=%v want trunk with no untagged VLAN", got.Mode, deref(got.Untagged))
	}
	if want := []int{10, 20}; !reflect.DeepEqual(got.Tagged, want) {
		t.Fatalf("got tagged=%v want %v", got.Tagged, want)
	}
}

// The native VLAN is a single VLAN the operator set, so like the access VLAN it
// is not held to the catalog; only the member lists can name VLANs in bulk.
func TestApplyCiscoSB_NativeVlanIsNotHeldToTheCatalog(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 50},
		TrunkLists: map[int]map[int][]byte{1: trunkLists(10, 50)},
		Vlans:      catalog(10),
	})
	if got := Classify(*infos[1]); got.Untagged == nil || *got.Untagged != 50 {
		t.Fatalf("got untagged=%v want 50", deref(got.Untagged))
	}
}

func TestApplyCiscoSB_TrunkAllowingEveryVlanIsTaggedAll(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 1},
		TrunkLists: map[int]map[int][]byte{1: everyVlan()},
		Vlans:      catalog(1, 10),
	})
	got := Classify(*infos[1])
	if got.Mode != ModeTrunkAll || got.Untagged == nil || *got.Untagged != 1 {
		t.Fatalf("got mode=%v untagged=%v want trunk-all/1", got.Mode, deref(got.Untagged))
	}
}

// Every VLAN means 1-4094: the padding bits after 4094 neither make a list
// complete nor are needed for it.
func TestApplyCiscoSB_EveryVlanIsJudgedOverOneTo4094(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lists map[int][]byte
		want  Mode
	}{
		{"padding clear", func() map[int][]byte {
			l := everyVlan()
			l[3][127] = 0xfc // VLANs 4089-4094; the last two bits are 4095 and 4096
			return l
		}(), ModeTrunkAll},
		{"4094 missing", func() map[int][]byte {
			l := everyVlan()
			l[3][127] = 0xfb
			return l
		}(), ModeTrunk},
		{"1 missing", func() map[int][]byte {
			l := everyVlan()
			l[0][0] = 0x7f
			return l
		}(), ModeTrunk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			infos := map[int]*SwitchportInfo{1: genericAccess(1)}
			ApplyCiscoSB(infos, CiscoSBRows{
				PortMode:   map[int]int{1: 12},
				NativeVlan: map[int]int{1: 0},
				TrunkLists: map[int]map[int][]byte{1: tc.lists},
				Vlans:      catalog(10),
			})
			if got := Classify(*infos[1]); got.Mode != tc.want {
				t.Fatalf("got mode=%v want %v", got.Mode, tc.want)
			}
		})
	}
}

// Each list covers its own 1024 VLANs, the first VLAN in the most significant
// bit. The VLANs either side of every boundary land in the right list.
func TestApplyCiscoSB_ReadsEachMemberListAtItsOwnOffset(t *testing.T) {
	vids := []int{1, 8, 9, 1024, 1025, 2048, 2049, 3072, 3073, 4094}
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 0},
		TrunkLists: map[int]map[int][]byte{1: trunkLists(vids...)},
		Vlans:      catalog(vids...),
	})
	if got := Classify(*infos[1]); !reflect.DeepEqual(got.Tagged, vids) {
		t.Fatalf("got tagged=%v want %v", got.Tagged, vids)
	}
}

// A list shorter than its 128 octets names no VLAN past its end.
func TestApplyCiscoSB_ShortMemberListEndsWhereItEnds(t *testing.T) {
	lists := trunkLists(10, 900)
	lists[0] = lists[0][:2] // VLANs 1-16 only
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 0},
		TrunkLists: map[int]map[int][]byte{1: lists},
		Vlans:      catalog(10, 900),
	})
	if got := Classify(*infos[1]); !reflect.DeepEqual(got.Tagged, []int{10}) {
		t.Fatalf("got tagged=%v want [10]", got.Tagged)
	}
}

// The member lists replace whatever membership the standard tables gave.
func TestApplyCiscoSB_TrunkReplacesTheGenericMembership(t *testing.T) {
	generic := genericTrunk(5, 5, 6, 7)
	generic.NativeUntaggedByMask = true
	infos := map[int]*SwitchportInfo{1: generic}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 10},
		TrunkLists: map[int]map[int][]byte{1: trunkLists(10, 20)},
		Vlans:      catalog(5, 6, 7, 10, 20),
	})
	got := Classify(*infos[1])
	if got.Untagged == nil || *got.Untagged != 10 || !reflect.DeepEqual(got.Tagged, []int{20}) {
		t.Fatalf("got untagged=%v tagged=%v want 10 and [20]", deref(got.Untagged), got.Tagged)
	}
}

// An access port keeps a trunk's default member lists and native VLAN. The
// access column alone describes it.
func TestApplyCiscoSB_AccessPortTakesItsAccessVlan(t *testing.T) {
	infos := map[int]*SwitchportInfo{5: genericTrunk(1, 1, 10, 20)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{5: 11},
		AccessVlan: map[int]int{5: 30},
		NativeVlan: map[int]int{5: 1},
		TrunkLists: map[int]map[int][]byte{5: everyVlan()},
		Vlans:      catalog(1, 10, 20, 30),
	})
	got := Classify(*infos[5])
	if got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 30 {
		t.Fatalf("got mode=%v untagged=%v want access/30", got.Mode, deref(got.Untagged))
	}
}

// On an access port, VLAN 1 in the access column is the VLAN the port is on.
func TestApplyCiscoSB_AccessPortOnVlanOne(t *testing.T) {
	infos := map[int]*SwitchportInfo{5: genericAccess(50)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{5: 11},
		AccessVlan: map[int]int{5: 1},
	})
	if got := Classify(*infos[5]); got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 1 {
		t.Fatalf("got mode=%v untagged=%v want access/1", got.Mode, deref(got.Untagged))
	}
}

// A port the device calls access or trunk is not classified from the standard
// tables when the columns for its mode are missing: those tables are what this
// platform gets wrong, and leaving the port out keeps what NetBox holds.
func TestApplyCiscoSB_StatedModeWithoutItsColumnsIsLeftOut(t *testing.T) {
	type tcase struct {
		name string
		rows CiscoSBRows
	}
	cases := []tcase{
		{"trunk without member lists", CiscoSBRows{
			PortMode:   map[int]int{1: 12},
			AccessVlan: map[int]int{1: 30},
			NativeVlan: map[int]int{1: 20},
		}},
	}
	for n := 0; n < 4; n++ {
		partial := trunkLists(10)
		delete(partial, n)
		cases = append(cases, tcase{fmt.Sprintf("trunk missing member list %d", n), CiscoSBRows{
			PortMode:   map[int]int{1: 12},
			NativeVlan: map[int]int{1: 10},
			TrunkLists: map[int]map[int][]byte{1: partial},
			Vlans:      catalog(10),
		}})
	}
	for _, tc := range append(cases, []tcase{
		{"trunk without a native VLAN row", CiscoSBRows{
			PortMode:   map[int]int{1: 12},
			TrunkLists: map[int]map[int][]byte{1: trunkLists(10, 20)},
			Vlans:      catalog(10, 20),
		}},
		{"access without an access VLAN", CiscoSBRows{
			PortMode:   map[int]int{1: 11},
			NativeVlan: map[int]int{1: 20},
		}},
		{"access VLAN out of range", CiscoSBRows{
			PortMode:   map[int]int{1: 11},
			AccessVlan: map[int]int{1: 0},
		}},
	}...) {
		t.Run(tc.name, func(t *testing.T) {
			// An operational reading is withdrawn along with the configured one.
			generic := genericAccess(1)
			generic.OperMode = OperAccess
			infos := map[int]*SwitchportInfo{1: generic}
			ApplyCiscoSB(infos, tc.rows)
			if got := Classify(*infos[1]); got.Mode != ModeUnknown || got.Untagged != nil {
				t.Fatalf("got mode=%v untagged=%v want unknown with no VLAN", got.Mode, deref(got.Untagged))
			}
		})
	}
}

// The routed inference from a missing dot1qPvid row gives way to a mode the
// device states.
func TestApplyCiscoSB_StatedModeOverridesTheRoutedInference(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows CiscoSBRows
		want Mode
	}{
		{"access", CiscoSBRows{PortMode: map[int]int{7: 11}, AccessVlan: map[int]int{7: 42}}, ModeAccess},
		{"trunk", CiscoSBRows{
			PortMode:   map[int]int{7: 12},
			NativeVlan: map[int]int{7: 0},
			TrunkLists: map[int]map[int][]byte{7: trunkLists(42)},
			Vlans:      catalog(42),
		}, ModeTrunk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			infos := map[int]*SwitchportInfo{
				7: {Enabled: true, BridgePortPresent: true, OperMode: OperRouted},
			}
			ApplyCiscoSB(infos, tc.rows)
			if got := Classify(*infos[7]); got.Mode != tc.want {
				t.Fatalf("got mode=%v want %v", got.Mode, tc.want)
			}
		})
	}
}

// A mode value other than access or trunk keeps the untagged-VLAN correction
// a port with no mode row gets: the access column, then the native column.
func TestApplyCiscoSB_OtherModeKeepsTheUntaggedCorrection(t *testing.T) {
	infos := map[int]*SwitchportInfo{3: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{3: 10},
		AccessVlan: map[int]int{3: 30},
		NativeVlan: map[int]int{3: 20},
		TrunkLists: map[int]map[int][]byte{3: trunkLists(20, 40)},
		Vlans:      catalog(20, 30, 40),
	})
	got := Classify(*infos[3])
	if got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 30 {
		t.Fatalf("got mode=%v untagged=%v want access/30", got.Mode, deref(got.Untagged))
	}
}

// Mode and member-list rows are CISCOSB data like the VLAN columns, and name
// ports like them.
func TestApplyCiscoSB_ModeAndListRowsCountAsData(t *testing.T) {
	if !(CiscoSBRows{PortMode: map[int]int{1: 12}}).HasData() {
		t.Error("mode rows must report data")
	}
	if !(CiscoSBRows{TrunkLists: map[int]map[int][]byte{1: trunkLists(10)}}).HasData() {
		t.Error("member-list rows must report data")
	}
	if (CiscoSBRows{Vlans: catalog(10)}).HasData() {
		t.Error("a catalog alone is not CISCOSB data")
	}
	rows := CiscoSBRows{
		PortMode:   map[int]int{3: 11},
		TrunkLists: map[int]map[int][]byte{2: trunkLists(10)},
		AccessVlan: map[int]int{1: 10},
	}
	if got := rows.IfIndexes(); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Fatalf("got %v want [1 2 3]", got)
	}
}

func TestApplyCiscoSB_StatedModeIgnoresUnknownIfIndex(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{999: 12},
		TrunkLists: map[int]map[int][]byte{999: trunkLists(10)},
	})
	if len(infos) != 1 {
		t.Fatalf("got %d infos want 1", len(infos))
	}
	if !reflect.DeepEqual(infos[1], genericAccess(1)) {
		t.Fatalf("port 1 changed: %+v", infos[1])
	}
}

// A native row reading 0, the column's default, says the trunk has no native
// VLAN; that is not a missing row.
func TestApplyCiscoSB_TrunkWithNativeZeroHasNoUntaggedVlan(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 0},
		TrunkLists: map[int]map[int][]byte{1: trunkLists(10, 20)},
		Vlans:      catalog(10, 20),
	})
	got := Classify(*infos[1])
	if got.Mode != ModeTrunk || got.Untagged != nil || !reflect.DeepEqual(got.Tagged, []int{10, 20}) {
		t.Fatalf("got %+v want trunk, no untagged, tagged [10 20]", got)
	}
}

// Without a VLAN catalog no member can be confirmed, so the trunk carries its
// native VLAN and no tagged VLANs.
func TestApplyCiscoSB_TrunkWithoutACatalogTagsNothing(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{1: 12},
		NativeVlan: map[int]int{1: 20},
		TrunkLists: map[int]map[int][]byte{1: trunkLists(10, 20)},
	})
	got := Classify(*infos[1])
	if got.Mode != ModeTrunk || got.Untagged == nil || *got.Untagged != 20 || len(got.Tagged) != 0 {
		t.Fatalf("got %+v want trunk, untagged 20, nothing tagged", got)
	}
}

// A switch that answers the mode column for its other ports has lost this
// port's row, so the port is left out rather than guessed at.
func TestApplyCiscoSB_PortMissingFromAnsweredModeColumnIsLeftOut(t *testing.T) {
	infos := map[int]*SwitchportInfo{1: genericAccess(1), 2: genericAccess(1)}
	ApplyCiscoSB(infos, CiscoSBRows{
		PortMode:   map[int]int{2: 11},
		AccessVlan: map[int]int{1: 30, 2: 40},
	})
	if got := Classify(*infos[1]); got.Mode != ModeUnknown {
		t.Fatalf("port 1: got mode=%v want unknown", got.Mode)
	}
	if got := Classify(*infos[2]); got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 40 {
		t.Fatalf("port 2: got mode=%v untagged=%v want access/40", got.Mode, deref(got.Untagged))
	}
}

func TestCiscoSBRows_OtherModes(t *testing.T) {
	rows := CiscoSBRows{PortMode: map[int]int{1: 11, 2: 12, 3: 10, 4: 10, 5: 15, 6: 1, 7: 20, 8: 13}}
	if got := rows.OtherModes(); !reflect.DeepEqual(got, []int{1, 10, 13, 15, 20}) {
		t.Fatalf("got %v want [1 10 13 15 20]", got)
	}
	if got := (CiscoSBRows{PortMode: map[int]int{1: 11, 2: 12}}).OtherModes(); len(got) != 0 {
		t.Fatalf("got %v want none", got)
	}
}
