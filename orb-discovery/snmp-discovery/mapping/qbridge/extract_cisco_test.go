package qbridge

import "testing"

func TestApplyCisco_VoiceStatic(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		101: {Enabled: true, BridgePortPresent: true, AdminMode: AdminAccess, AccessVlan: intPtr(10)},
	}
	rows := CiscoRows{
		VoiceVlanByIfIndex: map[int]int{101: 100},
	}
	ApplyCisco(infos, rows)
	if infos[101].VoiceVlan == nil || *infos[101].VoiceVlan != 100 {
		t.Errorf("VoiceVlan: got %v, want 100", infos[101].VoiceVlan)
	}
}

func TestApplyCisco_VoiceSentinels(t *testing.T) {
	tests := []struct {
		name     string
		sentinel int
		wantSet  bool
	}{
		{"none-0", 0, false},
		{"dot1p-only-4095", 4095, false},
		{"untagged-4096", 4096, false},
		{"valid-100", 100, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infos := map[int]*SwitchportInfo{
				101: {Enabled: true, BridgePortPresent: true, AdminMode: AdminAccess, AccessVlan: intPtr(10)},
			}
			rows := CiscoRows{
				VoiceVlanByIfIndex: map[int]int{101: tt.sentinel},
			}
			ApplyCisco(infos, rows)
			set := infos[101].VoiceVlan != nil
			if set != tt.wantSet {
				t.Errorf("voice set: got %v, want %v", set, tt.wantSet)
			}
		})
	}
}

func TestApplyCisco_AccessVlanOverlay(t *testing.T) {
	// vmMembershipTable says access VLAN is 50; generic had derived 10.
	// Cisco overlay wins on non-trunk ports.
	infos := map[int]*SwitchportInfo{
		101: {Enabled: true, BridgePortPresent: true, AdminMode: AdminAccess, AccessVlan: intPtr(10)},
	}
	rows := CiscoRows{
		MembershipAccessVlan: map[int]int{101: 50},
	}
	ApplyCisco(infos, rows)
	if infos[101].AccessVlan == nil || *infos[101].AccessVlan != 50 {
		t.Errorf("AccessVlan: got %v, want 50", infos[101].AccessVlan)
	}
}

func TestApplyCisco_DoesNotTouchTrunkPorts(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		101: {
			Enabled:           true,
			BridgePortPresent: true,
			AdminMode:         AdminTrunk,
			NativeVlan:        intPtr(1),
			AllowedVlans:      AllowedVlans{Vids: []int{1, 10, 20}},
		},
	}
	rows := CiscoRows{
		MembershipAccessVlan: map[int]int{101: 99}, // would mis-set if applied
	}
	ApplyCisco(infos, rows)
	if infos[101].AccessVlan != nil {
		t.Errorf("trunk port should not have AccessVlan set, got %v", infos[101].AccessVlan)
	}
}

func TestApplyCisco_PromotesUnknownToAccess(t *testing.T) {
	// Simulates classic Cisco IOS (e.g. 2960X): extract_generic saw no PVID
	// and an L3-capable ifType, so it set OperRouted / AdminUnknown.
	// vmVlan from CISCO-VLAN-MEMBERSHIP-MIB should override both.
	infos := map[int]*SwitchportInfo{
		201: {
			Enabled:           true,
			BridgePortPresent: true,
			AdminMode:         AdminUnknown,
			OperMode:          OperRouted,
		},
	}
	rows := CiscoRows{
		MembershipAccessVlan: map[int]int{201: 30},
	}
	ApplyCisco(infos, rows)
	info := infos[201]
	if info.AdminMode != AdminAccess {
		t.Errorf("AdminMode: got %v, want AdminAccess", info.AdminMode)
	}
	if info.OperMode != OperAccess {
		t.Errorf("OperMode: got %v, want OperAccess", info.OperMode)
	}
	if info.AccessVlan == nil || *info.AccessVlan != 30 {
		t.Errorf("AccessVlan: got %v, want 30", info.AccessVlan)
	}
}

// A trunk read from one tagged VLAN and nothing else is the weakest
// inference the generic extractor makes; a Cisco access row for that port
// is stronger, and turns it into an access port on the row's VLAN. A trunk
// seen in several VLANs is not touched, as before.
func TestApplyCisco_AccessRowOverridesATrunkInferredFromOneTaggedVlan(t *testing.T) {
	weak := &SwitchportInfo{Enabled: true, BridgePortPresent: true, AdminMode: AdminTrunk, TrunkFromOneTaggedVlan: true, AllowedVlans: AllowedVlans{Vids: []int{10}}}
	strong := &SwitchportInfo{Enabled: true, BridgePortPresent: true, AdminMode: AdminTrunk, AllowedVlans: AllowedVlans{Vids: []int{10, 20}}}
	infos := map[int]*SwitchportInfo{101: weak, 102: strong}
	ApplyCisco(infos, CiscoRows{MembershipAccessVlan: map[int]int{101: 10, 102: 10}})
	if c := Classify(*weak); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 10 {
		t.Errorf("weak trunk with an access row: got %+v, want access untagged 10", c)
	}
	if c := Classify(*strong); c.Mode != ModeTrunk || len(c.Tagged) != 2 {
		t.Errorf("trunk in two VLANs with an access row: got %+v, want trunk tagged [10 20]", c)
	}
}

// Cisco keeps a BRIDGE-MIB instance per VLAN, so the default context lists only
// the ports in VLAN 1. vmMembershipTable is indexed by ifIndex and needs no
// bridge port, so an access port in another VLAN still classifies from its row
// once the trunk table confirms it does not trunk.
func TestApplyCisco_AddsAnAccessPortTheBridgeTableOmits(t *testing.T) {
	infos := map[int]*SwitchportInfo{}
	rows := CiscoRows{
		MembershipAccessVlan: map[int]int{436207616: 300},
		TrunkEncapsulation:   map[int]int{436207616: encapNotApplicable},
		IfAdminStatus:        map[int]int{436207616: 1},
	}
	ApplyCisco(infos, rows)

	info, ok := infos[436207616]
	if !ok {
		t.Fatal("no entry for the port the bridge table omits")
	}
	got := Classify(*info)
	if got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 300 {
		t.Errorf("Classify: got %+v, want access on 300", got)
	}
}

// NX-OS publishes vmMembershipTable rows for trunk ports too, so a trunk that
// does not carry VLAN 1 is missing from the bridge table and still has a row.
// The trunk table says it trunks, and it is not added.
func TestApplyCisco_OmittedPortThatTrunksIsNotAdded(t *testing.T) {
	for name, rows := range map[string]CiscoRows{
		"encapsulation dot1Q":     {TrunkEncapsulation: map[int]int{436207616: 4}},
		"encapsulation negotiate": {TrunkEncapsulation: map[int]int{436207616: 5}},
		"encapsulation isl":       {TrunkEncapsulation: map[int]int{436207616: 1}},
		"dynamic status":          {TrunkStatus: map[int]int{436207616: trunkStatusTrunking}},
	} {
		rows.MembershipAccessVlan = map[int]int{436207616: 1}
		rows.IfAdminStatus = map[int]int{436207616: 1}
		infos := map[int]*SwitchportInfo{}
		ApplyCisco(infos, rows)
		if _, ok := infos[436207616]; ok {
			t.Errorf("%s: added a trunk as an access port", name)
		}
	}
}

// Without the trunk table an omitted port cannot be told from a trunk that
// does not carry VLAN 1, so it is left alone as before.
func TestApplyCisco_OmittedPortWithoutTrunkStateIsNotAdded(t *testing.T) {
	infos := map[int]*SwitchportInfo{}
	ApplyCisco(infos, CiscoRows{
		MembershipAccessVlan: map[int]int{436207616: 300},
		IfAdminStatus:        map[int]int{436207616: 1},
	})
	if _, ok := infos[436207616]; ok {
		t.Error("added a port the device said nothing about trunking for")
	}
}

// The dynamic status is the device's own verdict; a trunking port-channel
// member can still report its encapsulation as not applicable.
func TestApplyCisco_DynamicStatusWinsOverEncapsulation(t *testing.T) {
	infos := map[int]*SwitchportInfo{}
	ApplyCisco(infos, CiscoRows{
		MembershipAccessVlan: map[int]int{5: 30, 6: 40},
		TrunkStatus:          map[int]int{5: trunkStatusTrunking, 6: trunkStatusNotTrunking},
		TrunkEncapsulation:   map[int]int{5: encapNotApplicable, 6: 4},
		IfAdminStatus:        map[int]int{5: 1, 6: 1},
	})
	if _, ok := infos[5]; ok {
		t.Error("ifIndex 5 trunks by its dynamic status but was added")
	}
	if _, ok := infos[6]; !ok {
		t.Error("ifIndex 6 does not trunk by its dynamic status but was not added")
	}
}

// A bridged port the trunk table says trunks keeps what the generic pass made
// of it: its vmVlan row is the configured access VLAN, not what it carries.
func TestApplyCisco_BridgedPortThatTrunksIsNotMadeAccess(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		201: {Enabled: true, BridgePortPresent: true, AdminMode: AdminUnknown, OperMode: OperRouted},
	}
	ApplyCisco(infos, CiscoRows{
		MembershipAccessVlan: map[int]int{201: 30},
		TrunkStatus:          map[int]int{201: trunkStatusTrunking},
	})
	if infos[201].AccessVlan != nil || infos[201].AdminMode != AdminUnknown {
		t.Errorf("trunking port made access: %+v", infos[201])
	}
}

// An omitted port follows the rule bridged ports follow: administratively
// down, it is not classified.
func TestApplyCisco_OmittedPortThatIsDownIsNotClassified(t *testing.T) {
	infos := map[int]*SwitchportInfo{}
	rows := CiscoRows{
		MembershipAccessVlan: map[int]int{436207616: 300},
		TrunkEncapsulation:   map[int]int{436207616: encapNotApplicable},
		IfAdminStatus:        map[int]int{436207616: 2},
	}
	ApplyCisco(infos, rows)

	if info, ok := infos[436207616]; ok {
		if got := Classify(*info); got.Mode != ModeUnknown {
			t.Errorf("Classify: got %+v, want unknown for a port that is down", got)
		}
	}
}

// A row naming no valid VLAN is no evidence, so it adds no port.
func TestApplyCisco_OmittedPortWithoutAValidVlanIsNotAdded(t *testing.T) {
	for _, vid := range []int{0, 4095, 5000} {
		infos := map[int]*SwitchportInfo{}
		ApplyCisco(infos, CiscoRows{
			MembershipAccessVlan: map[int]int{436207616: vid},
			TrunkEncapsulation:   map[int]int{436207616: encapNotApplicable},
			IfAdminStatus:        map[int]int{436207616: 1},
		})
		if _, ok := infos[436207616]; ok {
			t.Errorf("vid %d: added a port from a row naming no VLAN", vid)
		}
	}
}

// The voice VLAN applies to a port added from its access row, as it does to
// a bridged one.
func TestApplyCisco_VoiceVlanOnAnOmittedAccessPort(t *testing.T) {
	infos := map[int]*SwitchportInfo{}
	ApplyCisco(infos, CiscoRows{
		MembershipAccessVlan: map[int]int{436207616: 30},
		VoiceVlanByIfIndex:   map[int]int{436207616: 100},
		TrunkEncapsulation:   map[int]int{436207616: encapNotApplicable},
		IfAdminStatus:        map[int]int{436207616: 1},
	})

	info, ok := infos[436207616]
	if !ok {
		t.Fatal("no entry for the port the bridge table omits")
	}
	got := Classify(*info)
	if got.Mode != ModeTrunk || got.Untagged == nil || *got.Untagged != 30 || len(got.Tagged) != 1 || got.Tagged[0] != 100 {
		t.Errorf("Classify: got %+v, want untagged 30 tagged [100]", got)
	}
}

// A voice row alone says nothing about the port's access VLAN, so it adds no
// port.
func TestApplyCisco_VoiceRowAloneAddsNoPort(t *testing.T) {
	infos := map[int]*SwitchportInfo{}
	ApplyCisco(infos, CiscoRows{
		VoiceVlanByIfIndex: map[int]int{436207616: 100},
		TrunkEncapsulation: map[int]int{436207616: encapNotApplicable},
		IfAdminStatus:      map[int]int{436207616: 1},
	})
	if _, ok := infos[436207616]; ok {
		t.Error("added a port from a voice row alone")
	}
}
