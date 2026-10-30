package qbridge

import (
	"log/slog"
	"reflect"
	"testing"
)

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

// Either column saying the port trunks is enough to skip it. The dynamic status
// is operational, so a configured trunk that is down reads notTrunking while
// NX-OS keeps its encapsulation at dot1Q; and a trunking port-channel member can
// report its encapsulation as not applicable while its dynamic status trunks.
func TestApplyCisco_EitherColumnSayingTrunkingWins(t *testing.T) {
	infos := map[int]*SwitchportInfo{}
	ApplyCisco(infos, CiscoRows{
		MembershipAccessVlan: map[int]int{5: 30, 6: 40, 7: 50, 8: 60},
		TrunkStatus: map[int]int{
			5: trunkStatusTrunking, 6: trunkStatusNotTrunking,
			7: trunkStatusNotTrunking, 8: trunkStatusNotTrunking,
		},
		TrunkEncapsulation: map[int]int{5: encapNotApplicable, 6: 4, 7: encapNotApplicable},
		IfAdminStatus:      map[int]int{5: 1, 6: 1, 7: 1, 8: 1},
	})
	for ifIndex, want := range map[int]bool{5: false, 6: false, 7: true, 8: true} {
		if _, got := infos[ifIndex]; got != want {
			t.Errorf("ifIndex %d: added=%v, want %v", ifIndex, got, want)
		}
	}
}

// The dynamic state is the configured mode. A port configured as a trunk
// (on, or onNoNegotiate) trunks whatever its link is doing: down, it reads
// notTrunking and, on a device following the MIB, notApplicable as well.
func TestApplyCisco_ConfiguredTrunkThatIsDownIsNotAdded(t *testing.T) {
	for _, state := range []int{trunkStateOn, trunkStateOnNoNegotiate} {
		infos := map[int]*SwitchportInfo{}
		ApplyCisco(infos, CiscoRows{
			MembershipAccessVlan: map[int]int{436207616: 300},
			TrunkDynamicState:    map[int]int{436207616: state},
			TrunkStatus:          map[int]int{436207616: trunkStatusNotTrunking},
			TrunkEncapsulation:   map[int]int{436207616: encapNotApplicable},
			IfAdminStatus:        map[int]int{436207616: 1},
		})
		if _, ok := infos[436207616]; ok {
			t.Errorf("state %d: added a configured trunk as an access port", state)
		}
	}
}

// Configured access, or a negotiating mode that is not trunking, is added as
// before.
func TestApplyCisco_PortNotConfiguredAsATrunkIsAdded(t *testing.T) {
	for _, state := range []int{2, 3, 4} {
		infos := map[int]*SwitchportInfo{}
		ApplyCisco(infos, CiscoRows{
			MembershipAccessVlan: map[int]int{436207616: 300},
			TrunkDynamicState:    map[int]int{436207616: state},
			TrunkStatus:          map[int]int{436207616: trunkStatusNotTrunking},
			TrunkEncapsulation:   map[int]int{436207616: encapNotApplicable},
			IfAdminStatus:        map[int]int{436207616: 1},
		})
		if _, ok := infos[436207616]; !ok {
			t.Errorf("state %d: port not configured as a trunk was not added", state)
		}
	}
}

// A dynamic status that is neither trunking nor notTrunking says nothing, so
// without an encapsulation row the port is not added.
func TestApplyCisco_UnexpectedDynamicStatusIsNoAnswer(t *testing.T) {
	for _, status := range []int{0, 3} {
		infos := map[int]*SwitchportInfo{}
		ApplyCisco(infos, CiscoRows{
			MembershipAccessVlan: map[int]int{436207616: 300},
			TrunkStatus:          map[int]int{436207616: status},
			IfAdminStatus:        map[int]int{436207616: 1},
		})
		if _, ok := infos[436207616]; ok {
			t.Errorf("status %d: added a port the trunk table gave no verdict on", status)
		}
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

// ciscoTestBitmap encodes VLAN IDs using Cisco's MSB-first bitmap layout.
// It is test-only and independent of the production decoder.
func ciscoTestBitmap(offset int, vids ...int) []byte {
	var bitmap []byte
	for _, vid := range vids {
		position := vid - offset
		if position < 0 || position >= 2048 {
			panic("VLAN outside bitmap range")
		}
		byteIndex := position / 8
		for len(bitmap) <= byteIndex {
			bitmap = append(bitmap, 0)
		}
		bitmap[byteIndex] |= byte(0x80 >> uint(position%8))
	}
	return bitmap
}

func TestDecodeCiscoActiveVlans(t *testing.T) {
	tests := []struct {
		name      string
		first     []byte
		second    []byte
		hasFirst  bool
		hasSecond bool
		want      []int
		wantOK    bool
	}{
		{
			name:  "Nexus Ethernet1/48 active VLANs",
			first: ciscoTestBitmap(0, 110, 120),
			second: ciscoTestBitmap(2048,
				3440, 3458, 3461, 3500, 3504, 3533, 3560, 3640, 3747, 3854, 3871, 3879, 3901),
			hasFirst:  true,
			hasSecond: true,
			want: []int{
				110, 120, 3440, 3458, 3461, 3500, 3504, 3533, 3560, 3640, 3747, 3854, 3871, 3879, 3901,
			},
			wantOK: true,
		},
		{
			name:      "bitmap boundaries",
			first:     ciscoTestBitmap(0, 1, 7, 8, 2047),
			second:    ciscoTestBitmap(2048, 2048, 2055, 2056, 4094),
			hasFirst:  true,
			hasSecond: true,
			want:      []int{1, 7, 8, 2047, 2048, 2055, 2056, 4094},
			wantOK:    true,
		},
		{
			name:      "reserved VLAN IDs excluded",
			first:     ciscoTestBitmap(0, 0, 1),
			second:    ciscoTestBitmap(2048, 4094, 4095),
			hasFirst:  true,
			hasSecond: true,
			want:      []int{1, 4094},
			wantOK:    true,
		},
		{
			name:      "present empty bitmaps",
			first:     []byte{},
			second:    []byte{},
			hasFirst:  true,
			hasSecond: true,
			want:      []int{},
			wantOK:    true,
		},
		{
			name:      "missing first row",
			second:    ciscoTestBitmap(2048, 3500),
			hasSecond: true,
			wantOK:    false,
		},
		{
			name:     "missing second row",
			first:    ciscoTestBitmap(0, 110),
			hasFirst: true,
			wantOK:   false,
		},
		{
			name:      "oversized first bitmap",
			first:     make([]byte, 257),
			second:    []byte{},
			hasFirst:  true,
			hasSecond: true,
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := decodeCiscoActiveVlans(
				tt.first, tt.second, tt.hasFirst, tt.hasSecond,
			)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VLANs = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecodeCiscoConfiguredVlans verifies all four 1024-bit segments,
// including boundary IDs and incomplete SNMP snapshots.
func TestDecodeCiscoConfiguredVlans(t *testing.T) {
	makeRows := func() CiscoRows {
		return CiscoRows{
			ConfiguredVlans: [4]map[int][]byte{
				{100: ciscoTestBitmap(0, 1, 110, 1023)},
				{100: ciscoTestBitmap(1024, 1024, 2047)},
				{100: ciscoTestBitmap(2048, 2048, 2500, 3071)},
				{100: ciscoTestBitmap(3072, 3072, 3500, 4094)},
			},
		}
	}

	t.Run("all four segments", func(t *testing.T) {
		got, ok := decodeCiscoConfiguredVlans(makeRows(), 100)
		want := []int{1, 110, 1023, 1024, 2047, 2048, 2500, 3071, 3072, 3500, 4094}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, ok %v; want %v", got, ok, want)
		}
	})

	t.Run("missing segment", func(t *testing.T) {
		rows := makeRows()
		delete(rows.ConfiguredVlans[2], 100)
		if _, ok := decodeCiscoConfiguredVlans(rows, 100); ok {
			t.Fatal("accepted incomplete configured VLAN snapshot")
		}
	})

	t.Run("oversized segment", func(t *testing.T) {
		rows := makeRows()
		rows.ConfiguredVlans[3][100] = make([]byte, 129)
		if _, ok := decodeCiscoConfiguredVlans(rows, 100); ok {
			t.Fatal("accepted oversized configured VLAN bitmap")
		}
	})
}

// TestCiscoTrunkMembership verifies configured/active intersection and
// tagged-all detection independently of switchport classification.
func TestCiscoTrunkMembership(t *testing.T) {
	t.Run("configured intersect active", func(t *testing.T) {
		configured := []int{110, 120, 130, 2500, 3500}
		active := []int{110, 120, 3500}

		carried, taggedAll := ciscoTrunkMembership(configured, active)
		if taggedAll {
			t.Fatal("unexpected tagged-all")
		}
		if !reflect.DeepEqual(carried, []int{110, 120, 3500}) {
			t.Fatalf("carried = %v", carried)
		}
	})

	t.Run("all VLANs configured", func(t *testing.T) {
		configured := make([]int, 4094)
		for i := range configured {
			configured[i] = i + 1
		}

		carried, taggedAll := ciscoTrunkMembership(configured, []int{1, 110})
		if !taggedAll {
			t.Fatal("expected tagged-all")
		}
		if !reflect.DeepEqual(carried, []int{1, 110}) {
			t.Fatalf("carried = %v", carried)
		}
	})

	t.Run("one VLAN missing is not tagged-all", func(t *testing.T) {
		configured := make([]int, 4093)
		for i := range configured {
			configured[i] = i + 1
		}

		_, taggedAll := ciscoTrunkMembership(configured, []int{1})
		if taggedAll {
			t.Fatal("incorrect tagged-all classification")
		}
	})
}

func TestApplyCiscoTrunks(t *testing.T) {
	t.Run("complete trunk with native VLAN", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{}
		rows := CiscoRows{
			TrunkDynamicState: map[int]int{100: 5},
			IfAdminStatus:     map[int]int{100: 1},
			NativeVlan:        map[int]int{100: 1},
			ConfiguredVlans: [4]map[int][]byte{
				{100: ciscoTestBitmap(0, 1, 110, 120)},
				{100: []byte{}},
				{100: []byte{}},
				{100: ciscoTestBitmap(3072, 3500)},
			},
			ActiveFirst2k:  map[int][]byte{100: ciscoTestBitmap(0, 1, 110, 120)},
			ActiveSecond2k: map[int][]byte{100: ciscoTestBitmap(2048, 3500)},
		}

		ApplyCiscoTrunks(infos, rows, slog.Default())
		got := Classify(*infos[100])

		if got.Mode != ModeTrunk {
			t.Fatalf("mode = %v, want trunk", got.Mode)
		}
		if !reflect.DeepEqual(got.Tagged, []int{110, 120, 3500}) {
			t.Errorf("tagged = %v", got.Tagged)
		}
		if got.Untagged == nil || *got.Untagged != 1 {
			t.Errorf("native = %v, want 1", got.Untagged)
		}
	})

	t.Run("disjoint configured and active VLANs leave port unchanged", func(t *testing.T) {
		info := &SwitchportInfo{
			Enabled:           true,
			BridgePortPresent: true,
			AdminMode:         AdminTrunk,
			AllowedVlans:      AllowedVlans{Vids: []int{50, 60}},
		}
		infos := map[int]*SwitchportInfo{100: info}
		rows := CiscoRows{
			TrunkDynamicState: map[int]int{100: 5},
			ConfiguredVlans: [4]map[int][]byte{
				{100: ciscoTestBitmap(0, 10, 20)},
				{100: {}},
				{100: {}},
				{100: {}},
			},
			ActiveFirst2k:  map[int][]byte{100: ciscoTestBitmap(0, 30, 40)},
			ActiveSecond2k: map[int][]byte{100: {}},
		}

		accepted := ApplyCiscoTrunks(infos, rows, slog.Default())

		if len(accepted) != 0 {
			t.Fatalf("disjoint trunk was accepted: %v", accepted)
		}
		if infos[100] != info {
			t.Fatal("existing switchport was replaced")
		}
		if info.AdminMode != AdminTrunk ||
			!reflect.DeepEqual(info.AllowedVlans.Vids, []int{50, 60}) {
			t.Fatalf("existing classification changed: %+v", info)
		}
	})

	t.Run("incomplete bitmap preserves generic trunk", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{
			100: {
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminTrunk,
				AllowedVlans:      AllowedVlans{Vids: []int{48, 791}},
			},
		}
		rows := CiscoRows{
			TrunkDynamicState: map[int]int{100: 5},
			ActiveFirst2k:     map[int][]byte{100: ciscoTestBitmap(0, 110)},
		}

		ApplyCiscoTrunks(infos, rows, slog.Default())

		if !reflect.DeepEqual(infos[100].AllowedVlans.Vids, []int{48, 791}) {
			t.Errorf("generic membership overwritten: %v", infos[100].AllowedVlans.Vids)
		}
	})

	t.Run("access port unchanged", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{
			100: {
				Enabled:           true,
				BridgePortPresent: true,
				AdminMode:         AdminAccess,
				AccessVlan:        intPtr(3500),
			},
		}
		rows := CiscoRows{
			TrunkStatus:    map[int]int{100: 2},
			ActiveFirst2k:  map[int][]byte{100: ciscoTestBitmap(0, 110)},
			ActiveSecond2k: map[int][]byte{100: ciscoTestBitmap(2048, 3500)},
			ConfiguredVlans: [4]map[int][]byte{
				{100: ciscoTestBitmap(0, 110)},
				{100: {}},
				{100: ciscoTestBitmap(2048, 3500)},
				{100: {}},
			},
		}

		ApplyCiscoTrunks(infos, rows, slog.Default())
		got := Classify(*infos[100])

		if got.Mode != ModeAccess || got.Untagged == nil || *got.Untagged != 3500 {
			t.Errorf("access classification changed: %+v", got)
		}
	})

	t.Run("missing IF-MIB state does not create port", func(t *testing.T) {
		infos := map[int]*SwitchportInfo{}
		rows := CiscoRows{
			TrunkDynamicState: map[int]int{100: 5},
			ActiveFirst2k:     map[int][]byte{100: ciscoTestBitmap(0, 110)},
			ActiveSecond2k:    map[int][]byte{100: ciscoTestBitmap(2048, 3500)},
			ConfiguredVlans: [4]map[int][]byte{
				{100: ciscoTestBitmap(0, 110)},
				{100: {}},
				{100: ciscoTestBitmap(2048, 3500)},
				{100: {}},
			},
		}

		ApplyCiscoTrunks(infos, rows, slog.Default())
		if _, exists := infos[100]; exists {
			t.Fatal("created port without IF-MIB administrative state")
		}
	})
}

// An inactive trunk must not overwrite an existing generic classification,
// even when its configured allowed VLANs are present.
func TestApplyCiscoTrunksEmptyActivePreservesExisting(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		100: {
			Enabled:           true,
			BridgePortPresent: true,
			AdminMode:         AdminTrunk,
			AllowedVlans:      AllowedVlans{Vids: []int{9, 41, 431}},
			NativeVlan:        intPtr(41),
		},
	}
	before := *infos[100]

	rows := CiscoRows{
		TrunkDynamicState: map[int]int{100: 5},
		NativeVlan:        map[int]int{100: 1},
		ActiveFirst2k:     map[int][]byte{100: {}},
		ActiveSecond2k:    map[int][]byte{100: {}},
		ConfiguredVlans: [4]map[int][]byte{
			{100: ciscoTestBitmap(0, 9, 41, 431)},
			{100: {}},
			{100: {}},
			{100: {}},
		},
	}

	ApplyCiscoTrunks(infos, rows, slog.Default())

	if !reflect.DeepEqual(*infos[100], before) {
		t.Fatalf("empty active bitmap changed switchport:\n got %+v\nwant %+v",
			*infos[100], before)
	}
}

// A trunk allowing every valid VLAN is tagged-all, regardless of how many
// VLANs are currently active.
func TestApplyCiscoTrunksTaggedAll(t *testing.T) {
	var configured [4]map[int][]byte
	for segment := range configured {
		bitmap := make([]byte, 128)
		for vid := 1; vid <= 4094; vid++ {
			if vid/1024 != segment {
				continue
			}
			position := vid - segment*1024
			bitmap[position/8] |= 0x80 >> uint(position%8)
		}
		configured[segment] = map[int][]byte{100: bitmap}
	}

	infos := map[int]*SwitchportInfo{}
	rows := CiscoRows{
		TrunkDynamicState: map[int]int{100: 5},
		IfAdminStatus:     map[int]int{100: 1},
		NativeVlan:        map[int]int{100: 1},
		ConfiguredVlans:   configured,
		ActiveFirst2k:     map[int][]byte{100: ciscoTestBitmap(0, 1, 110)},
		ActiveSecond2k:    map[int][]byte{100: ciscoTestBitmap(2048, 3500)},
	}

	ApplyCiscoTrunks(infos, rows, slog.Default())

	info := infos[100]
	if info == nil {
		t.Fatal("trunk not created")
	}
	if !info.AllowedVlans.IsWildcard {
		t.Fatal("expected wildcard allowed VLANs")
	}

	got := Classify(*info)
	if got.Mode != ModeTrunkAll {
		t.Fatalf("mode = %v, want tagged-all", got.Mode)
	}
	if got.Untagged == nil || *got.Untagged != 1 {
		t.Fatalf("native = %v, want VLAN 1", got.Untagged)
	}
}

// Cisco may report native VLAN 1 even when the trunk does not carry it.
// A positive Cisco trunk overlay must clear a stale generic native VLAN.
func TestApplyCiscoTrunksPhantomNativeVlan(t *testing.T) {
	infos := map[int]*SwitchportInfo{
		100: {
			Enabled:           true,
			BridgePortPresent: true,
			AdminMode:         AdminTrunk,
			NativeVlan:        intPtr(1),
		},
	}

	rows := CiscoRows{
		TrunkDynamicState: map[int]int{100: 5},
		NativeVlan:        map[int]int{100: 1},
		ConfiguredVlans: [4]map[int][]byte{
			{100: ciscoTestBitmap(0, 110, 120, 130)},
			{100: {}},
			{100: {}},
			{100: ciscoTestBitmap(3072, 3500)},
		},
		ActiveFirst2k:  map[int][]byte{100: ciscoTestBitmap(0, 110, 120)},
		ActiveSecond2k: map[int][]byte{100: ciscoTestBitmap(2048, 3500)},
	}

	ApplyCiscoTrunks(infos, rows, slog.Default())

	got := Classify(*infos[100])
	if got.Mode != ModeTrunk {
		t.Fatalf("mode = %v, want trunk", got.Mode)
	}
	if got.Untagged != nil {
		t.Fatalf("phantom native VLAN: %v", *got.Untagged)
	}
	if !reflect.DeepEqual(got.Tagged, []int{110, 120, 3500}) {
		t.Fatalf("tagged = %v, want [110 120 3500]", got.Tagged)
	}
}
