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

// maskWithPorts builds a Q-BRIDGE port bitmap with the given bridge ports set,
// MSB-first within each byte, sized to the highest port.
func maskWithPorts(ports ...int) []byte {
	maxPort := 0
	for _, p := range ports {
		if p > maxPort {
			maxPort = p
		}
	}
	mask := make([]byte, (maxPort+7)/8)
	for _, p := range ports {
		mask[(p-1)/8] |= 1 << (7 - (p-1)%8)
	}
	return mask
}

// A port carrying one VLAN it is not untagged in, with a PVID of 0, is a
// trunk with that VLAN tagged: the count of VLANs says nothing about
// tagging, and reading one VLAN as access took its VLAN from a PVID of 0,
// which left the port access with no VLAN at all.
func TestExtractGeneric_SingleTaggedVlanWithPvidZeroIsTrunk(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{4771: 606},
		PortPvid:          map[int]int{606: 0},
		VlanEgressPorts:   map[int][]byte{665: maskWithPorts(4771)},
		VlanUntaggedPorts: map[int][]byte{665: {}},
		IfAdminStatus:     map[int]int{606: 1},
		IfTypes:           map[int]string{606: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	info, ok := got[606]
	if !ok {
		t.Fatal("ifIndex 606 missing from result")
	}
	if info.AdminMode != AdminTrunk {
		t.Errorf("AdminMode: got %v, want AdminTrunk", info.AdminMode)
	}
	if len(info.AllowedVlans.Vids) != 1 || info.AllowedVlans.Vids[0] != 665 {
		t.Errorf("AllowedVlans: got %v, want [665]", info.AllowedVlans.Vids)
	}
	if info.NativeVlan != nil || info.AccessVlan != nil {
		t.Errorf("a PVID of 0 is no VLAN: native=%v access=%v", info.NativeVlan, info.AccessVlan)
	}
	c := Classify(*info)
	if c.Mode != ModeTrunk || len(c.Tagged) != 1 || c.Tagged[0] != 665 || c.Untagged != nil {
		t.Errorf("Classify: got %+v, want trunk tagged [665] untagged nil", c)
	}
}

// A device that publishes no untagged table still reports an access port
// through its PVID: one VLAN, and a PVID naming it, is access on that VLAN.
func TestExtractGeneric_SingleVlanNamedByPvidWithoutUntaggedTableIsAccess(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{3: 103},
		PortPvid:          map[int]int{103: 30},
		VlanEgressPorts:   map[int][]byte{30: maskWithPorts(3)},
		VlanUntaggedPorts: map[int][]byte{},
		IfAdminStatus:     map[int]int{103: 1},
		IfTypes:           map[int]string{103: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	info := got[103]
	if info == nil || info.AdminMode != AdminAccess {
		t.Fatalf("AdminMode: got %+v, want AdminAccess", info)
	}
	if c := Classify(*info); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 30 {
		t.Errorf("Classify: got %+v, want access untagged 30", c)
	}
}

// A port untagged in one VLAN and tagged in others is a trunk with that
// VLAN native, whatever the PVID says.
func TestExtractGeneric_UntaggedInOneTaggedInOthersIsTrunkWithNative(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{5: 105},
		PortPvid:          map[int]int{105: 0},
		VlanEgressPorts:   map[int][]byte{10: maskWithPorts(5), 20: maskWithPorts(5)},
		VlanUntaggedPorts: map[int][]byte{10: maskWithPorts(5), 20: {}},
		IfAdminStatus:     map[int]int{105: 1},
		IfTypes:           map[int]string{105: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	c := Classify(*got[105])
	if c.Mode != ModeTrunk || c.Untagged == nil || *c.Untagged != 10 || len(c.Tagged) != 1 || c.Tagged[0] != 20 {
		t.Errorf("Classify: got %+v, want trunk native 10 tagged [20]", c)
	}
}

// Text port lists are read only where the rows say the vendor publishes
// them: a value of digit and comma bytes is a legal bitmap on any other
// platform, however it parses, so without the vendor's word it stays one.
func TestExtractGeneric_TextListsOnlyWhereTheVendorPublishesThem(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{4097: 513, 4099: 518},
		PortPvid:          map[int]int{513: 0, 518: 0},
		VlanEgressPorts:   map[int][]byte{23: []byte("0,4097,4099")},
		VlanUntaggedPorts: map[int][]byte{23: []byte("")},
		IfAdminStatus:     map[int]int{513: 1, 518: 1},
		IfTypes:           map[int]string{513: "ethernetCsmacd", 518: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if vids := got[513].AllowedVlans.Vids; len(vids) != 0 {
		t.Errorf("without the vendor's word the list is a bitmap naming no known port: got %v", vids)
	}
	rows.TextPortLists = true
	got, err = ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if vids := got[513].AllowedVlans.Vids; len(vids) != 1 || vids[0] != 23 {
		t.Errorf("with the vendor's word the list names the port: got %v", vids)
	}
}

// A PVID naming the port's one VLAN stands in for the untagged table only
// where the device publishes none for that VLAN: a row that exists and leaves
// the port out says the port is tagged there, and the PVID does not override it.
func TestExtractGeneric_UntaggedRowExcludingThePortOutranksThePvid(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{7: 107},
		PortPvid:          map[int]int{107: 40},
		VlanEgressPorts:   map[int][]byte{40: maskWithPorts(7)},
		VlanUntaggedPorts: map[int][]byte{40: {0x00}},
		IfAdminStatus:     map[int]int{107: 1},
		IfTypes:           map[int]string{107: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	c := Classify(*got[107])
	if c.Mode != ModeTrunk || len(c.Tagged) != 1 || c.Tagged[0] != 40 {
		t.Errorf("Classify: got %+v, want trunk tagged [40]", c)
	}
}

// A port with bridge membership is bridged, whatever the PVID table says: a
// device that publishes egress rows for a port but no PVID row does not make
// it routed. Membership in two VLANs is a trunk; only a port with no
// membership at all falls to the routed inference.
func TestExtractGeneric_MembershipOutranksTheRoutedInference(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101, 2: 102},
		PortPvid:          map[int]int{},
		VlanEgressPorts:   map[int][]byte{10: maskWithPorts(1), 20: maskWithPorts(1)},
		VlanUntaggedPorts: map[int][]byte{},
		IfAdminStatus:     map[int]int{101: 1, 102: 1},
		IfTypes:           map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	c := Classify(*got[101])
	if c.Mode != ModeTrunk || len(c.Tagged) != 2 {
		t.Errorf("port with membership: got %+v, want trunk tagged [10 20]", c)
	}
	if c := Classify(*got[102]); c.Mode != ModeRouted {
		t.Errorf("port with no membership and no PVID: got %+v, want routed", c)
	}
}

// The extractor marks a trunk it inferred from one tagged VLAN alone, so a
// vendor overlay with positive access evidence can override that inference
// and no other.
func TestExtractGeneric_MarksATrunkInferredFromOneTaggedVlan(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101, 2: 102},
		PortPvid:          map[int]int{101: 0, 102: 0},
		VlanEgressPorts:   map[int][]byte{10: maskWithPorts(1, 2), 20: maskWithPorts(2)},
		VlanUntaggedPorts: map[int][]byte{10: {}, 20: {}},
		IfAdminStatus:     map[int]int{101: 1, 102: 1},
		IfTypes:           map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got[101].TrunkFromOneTaggedVlan {
		t.Error("a trunk inferred from one tagged VLAN is marked")
	}
	if got[102].TrunkFromOneTaggedVlan {
		t.Error("a trunk seen in two VLANs is not marked")
	}
}

// A bridge with VLAN filtering off still answers dot1qPvid, because RFC 4363
// gives the object a DEFVAL of 1 and the agent must return something. On a
// device that names no VLAN of its own there is nothing to corroborate that
// against, so reading it as "access on VLAN 1" invents a VLAN the operator
// never configured and attaches every bridge port to it.
func TestExtractGeneric_DefaultPvidWithoutACatalogIsNotAnAccessVlan(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101, 2: 102},
		PortPvid:          map[int]int{101: 1, 102: 1},
		VlanEgressPorts:   map[int][]byte{},
		VlanUntaggedPorts: map[int][]byte{},
		IfAdminStatus:     map[int]int{101: 1, 102: 1},
		IfTypes:           map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
		// The device published no VLAN of its own.
		VlanCatalogPresent: false,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, ifIndex := range []int{101, 102} {
		info := got[ifIndex]
		if info == nil {
			t.Fatalf("ifIndex %d missing", ifIndex)
		}
		if info.AdminMode == AdminAccess {
			t.Errorf("ifIndex %d: the MIB default alone must not make an access port", ifIndex)
		}
		if c := Classify(*info); c.Mode != ModeUnknown || c.Untagged != nil {
			t.Errorf("ifIndex %d: got %+v, want unclassified with no VLAN", ifIndex, c)
		}
	}
}

// The same default PVID is real configuration once the device names a VLAN
// somewhere: that is the Arista EOS shape, which publishes a static name
// catalog while omitting the membership masks.
func TestExtractGeneric_DefaultPvidWithACatalogIsStillAccess(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex:  map[int]int{1: 101},
		PortPvid:           map[int]int{101: 1},
		VlanEgressPorts:    map[int][]byte{},
		VlanUntaggedPorts:  map[int][]byte{},
		IfAdminStatus:      map[int]int{101: 1},
		IfTypes:            map[int]string{101: "ethernetCsmacd"},
		VlanCatalogPresent: true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 1 {
		t.Errorf("got %+v, want access on VLAN 1", c)
	}
}

// A PVID the operator had to set is configuration whether or not the device
// publishes a catalog, so only the default is refused.
func TestExtractGeneric_NonDefaultPvidWithoutACatalogIsStillAccess(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex:  map[int]int{1: 101},
		PortPvid:           map[int]int{101: 200},
		VlanEgressPorts:    map[int][]byte{},
		VlanUntaggedPorts:  map[int][]byte{},
		IfAdminStatus:      map[int]int{101: 1},
		IfTypes:            map[int]string{101: "ethernetCsmacd"},
		VlanCatalogPresent: false,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 200 {
		t.Errorf("got %+v, want access on VLAN 200", c)
	}
}

// One port reporting a PVID the operator had to set says the column is
// maintained on that device, so a 1 on its neighbour is a report rather than
// the MIB's default. Silencing only the neighbour would leave one switch
// described two ways: its VLAN-200 ports classified and its VLAN-1 ports
// absent.
func TestExtractGeneric_ARealPvidAnywhereMakesTheDefaultMeaningful(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex:  map[int]int{1: 101, 2: 102},
		PortPvid:           map[int]int{101: 1, 102: 200},
		VlanEgressPorts:    map[int][]byte{},
		VlanUntaggedPorts:  map[int][]byte{},
		IfAdminStatus:      map[int]int{101: 1, 102: 1},
		IfTypes:            map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
		VlanCatalogPresent: false,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	for ifIndex, want := range map[int]int{101: 1, 102: 200} {
		c := Classify(*got[ifIndex])
		if c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != want {
			t.Errorf("ifIndex %d: got %+v, want access on VLAN %d", ifIndex, c, want)
		}
	}
}

// A PVID of 0 is the device saying "no untagged VLAN", not a configured one,
// so it does not make the defaults on its neighbours meaningful.
func TestExtractGeneric_AZeroPvidIsNotARealPvid(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex:  map[int]int{1: 101, 2: 102},
		PortPvid:           map[int]int{101: 1, 102: 0},
		VlanEgressPorts:    map[int][]byte{},
		VlanUntaggedPorts:  map[int][]byte{},
		IfAdminStatus:      map[int]int{101: 1, 102: 1},
		IfTypes:            map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
		VlanCatalogPresent: false,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Mode != ModeUnknown {
		t.Errorf("got %+v, want unclassified", c)
	}
}

// TestExtractGeneric_CurrentUntaggedAbsenceDoesNotWithdrawAPvid separates the
// two Q-BRIDGE untagged tables, which do not mean the same thing.
//
// RFC 4363 defines the static untagged mask as configuration, the ports
// "permanently assigned" to egress untagged, so a port's absence from it is a
// statement about that port. The current mask is operational, the ports
// actually "transmitting traffic as untagged frames", and a port that is
// administratively up but not forwarding is simply not in it while dot1qPvid
// still reports the VLAN it is configured for.
//
// Reading absence in the current table the same way withdrew the access VLAN
// from every such port: six of them on a recorded Arista walk, the platform
// the PVID-only branch itself cites.
func TestExtractGeneric_CurrentUntaggedAbsenceDoesNotWithdrawAPvid(t *testing.T) {
	// Two ports configured on VLAN 31; only port 1 is currently forwarding.
	rows := GenericRows{
		BasePortToIfIndex:       map[int]int{1: 101, 2: 102},
		PortPvid:                map[int]int{101: 31, 102: 31},
		VlanEgressPorts:         map[int][]byte{31: maskWithPorts(1)},
		VlanUntaggedPorts:       map[int][]byte{31: maskWithPorts(1)},
		VlanEgressFromCurrent:   map[int]struct{}{31: {}},
		VlanUntaggedFromCurrent: map[int]struct{}{31: {}},
		IfAdminStatus:           map[int]int{101: 1, 102: 1},
		IfTypes:                 map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
		VlanCatalogPresent:      true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[102]); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 31 {
		t.Errorf("a port absent from the OPERATIONAL untagged mask keeps its PVID: got %+v", c)
	}

	// The same shape from the static table is configuration, and absence there
	// does withdraw the PVID, exactly as before.
	rows.VlanEgressFromCurrent = map[int]struct{}{}
	rows.VlanUntaggedFromCurrent = map[int]struct{}{}
	got, err = ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[102]); c.Untagged != nil {
		t.Errorf("a port absent from the CONFIGURED untagged mask has no untagged VLAN: got %+v", c)
	}
}

// Whether a host publishes text port lists is judged on its static masks
// alone. Junos is the vendor that does, and it keys some platforms' static
// table internally, so its current rows sit under indices the rekey never
// touches and arrive as extra VLANs. One of those in binary would otherwise
// make the whole host read as binary and lose every static membership on it.
func TestExtractGeneric_OneBinaryCurrentMaskDoesNotUnmakeATextHost(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{100: 500, 101: 501},
		PortPvid:          map[int]int{500: 10, 501: 10},
		VlanEgressPorts: map[int][]byte{
			10:   []byte("100,101"),      // the static text list
			4000: maskWithPorts(1, 2, 3), // a current row, in binary
		},
		VlanUntaggedPorts:     map[int][]byte{10: []byte("100,101")},
		VlanEgressFromCurrent: map[int]struct{}{4000: {}},
		IfAdminStatus:         map[int]int{500: 1, 501: 1},
		IfTypes:               map[int]string{500: "ethernetCsmacd", 501: "ethernetCsmacd"},
		TextPortLists:         true,
		VlanCatalogPresent:    true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[500]); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 10 {
		t.Errorf("the text host must keep its static membership: got %+v", c)
	}
}

// A sentinel PVID names no VLAN, so it is not evidence that the column is
// maintained. Counting it would hand every neighbour back the access VLAN 1
// the refusal exists to withhold, on the strength of a value CoerceVid itself
// rejects.
func TestExtractGeneric_ASentinelPvidIsNotEvidenceOfConfiguration(t *testing.T) {
	for _, sentinel := range []int{4095, 4096, 0, -1, 65535} {
		rows := GenericRows{
			BasePortToIfIndex:  map[int]int{1: 101, 2: 102},
			PortPvid:           map[int]int{101: 1, 102: sentinel},
			VlanEgressPorts:    map[int][]byte{},
			VlanUntaggedPorts:  map[int][]byte{},
			IfAdminStatus:      map[int]int{101: 1, 102: 1},
			IfTypes:            map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
			VlanCatalogPresent: false,
		}
		got, err := ExtractGeneric(rows)
		if err != nil {
			t.Fatalf("sentinel %d: %v", sentinel, err)
		}
		if c := Classify(*got[101]); c.Mode != ModeUnknown || c.Untagged != nil {
			t.Errorf("sentinel %d: the neighbour must stay unclassified, got %+v", sentinel, c)
		}
	}

	// A value that does name a VLAN still is evidence.
	rows := GenericRows{
		BasePortToIfIndex:  map[int]int{1: 101, 2: 102},
		PortPvid:           map[int]int{101: 1, 102: 4094},
		VlanEgressPorts:    map[int][]byte{},
		VlanUntaggedPorts:  map[int][]byte{},
		IfAdminStatus:      map[int]int{101: 1, 102: 1},
		IfTypes:            map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
		VlanCatalogPresent: false,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Mode != ModeAccess || c.Untagged == nil || *c.Untagged != 1 {
		t.Errorf("4094 is a real VLAN id and makes the column meaningful, got %+v", c)
	}
}

// A genuine bitmap byte can parse as a text list — 0x30 sets bridge ports 3
// and 4 and reads as the list "0" — so a current-table mask must not go
// through the text decoder on a host whose static masks are text. Converting
// it turns real membership into the wrong ports, or none.
func TestExtractGeneric_ACurrentBitmapIsNotDecodedAsText(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{3: 103, 4: 104, 100: 500},
		PortPvid:          map[int]int{500: 10},
		VlanEgressPorts: map[int][]byte{
			10: []byte("100"), // the static text list
			77: {0x30},        // a current bitmap: ports 3 and 4, reads as "0"
		},
		VlanUntaggedPorts:     map[int][]byte{10: []byte("100")},
		VlanEgressFromCurrent: map[int]struct{}{77: {}},
		IfAdminStatus:         map[int]int{103: 1, 104: 1, 500: 1},
		IfTypes:               map[int]string{103: "ethernetCsmacd", 104: "ethernetCsmacd", 500: "ethernetCsmacd"},
		TextPortLists:         true,
		VlanCatalogPresent:    true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Ports 3 and 4 are members of VLAN 77 by that bitmap.
	for _, ifIndex := range []int{103, 104} {
		c := Classify(*got[ifIndex])
		if len(c.Tagged) == 0 && c.Untagged == nil {
			t.Errorf("ifIndex %d lost its current-table membership to the text decoder: %+v", ifIndex, c)
		}
	}
	// And the text host still reads its own static list.
	if c := Classify(*got[500]); c.Untagged == nil || *c.Untagged != 10 {
		t.Errorf("the static text list must still decode: %+v", c)
	}
}

// A port's untagged VLAN is configuration, and the current table is not. A
// recorded switch answers dot1qPvid 1000 on five ports while the current
// table's untagged mask still names them in VLAN 1: reading the mask as the
// answer moved every one of them onto a VLAN their own PVID contradicts.
func TestExtractGeneric_ACurrentUntaggedMaskDoesNotDisplaceAPvid(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex:       map[int]int{1: 101},
		PortPvid:                map[int]int{101: 1000},
		VlanEgressPorts:         map[int][]byte{1: maskWithPorts(1)},
		VlanUntaggedPorts:       map[int][]byte{1: maskWithPorts(1)},
		VlanEgressFromCurrent:   map[int]struct{}{1: {}},
		VlanUntaggedFromCurrent: map[int]struct{}{1: {}},
		IfAdminStatus:           map[int]int{101: 1},
		IfTypes:                 map[int]string{101: "ethernetCsmacd"},
		VlanCatalogPresent:      true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	c := Classify(*got[101])
	if c.Untagged == nil || *c.Untagged != 1000 {
		t.Errorf("the configured PVID is the untagged VLAN: got %+v", c)
	}
	if len(c.Tagged) != 0 {
		t.Errorf("the VLAN the port egresses untagged is not a tagged VLAN: got %+v", c)
	}

	// The same masks from the static table are configuration too, and there is
	// then nothing to prefer the PVID over: the row wins as it always has.
	rows.VlanEgressFromCurrent = map[int]struct{}{}
	rows.VlanUntaggedFromCurrent = map[int]struct{}{}
	got, err = ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Untagged == nil || *c.Untagged != 1 {
		t.Errorf("a configured untagged row still outranks the PVID: got %+v", c)
	}
}

// The default PVID is distrusted for the reason the rest of this file
// distrusts it: not because it reads 1, but because no port on the device
// reports anything else. Where a neighbour does, a 1 is a report and displaces
// an operational mask like any other value.
func TestExtractGeneric_ACorroboratedDefaultPvidStillDisplaces(t *testing.T) {
	// One port answers a VLAN the operator had to set. That is the device
	// saying its PVID column is maintained.
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101, 2: 102},
		PortPvid:          map[int]int{101: 1, 102: 88},
		VlanEgressPorts: map[int][]byte{
			1: maskWithPorts(1), 88: maskWithPorts(2), 101: maskWithPorts(1),
		},
		VlanUntaggedPorts: map[int][]byte{
			1: maskWithPorts(1), 88: maskWithPorts(2), 101: maskWithPorts(1),
		},
		VlanEgressFromCurrent:   map[int]struct{}{1: {}, 88: {}, 101: {}},
		VlanUntaggedFromCurrent: map[int]struct{}{1: {}, 88: {}, 101: {}},
		IfAdminStatus:           map[int]int{101: 1, 102: 1},
		IfTypes:                 map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
		VlanCatalogPresent:      true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Untagged == nil || *c.Untagged != 1 {
		t.Errorf("a PVID of 1 on a device that maintains the column is a report: got %+v", c)
	}

	// Take the neighbour's real PVID away and nothing on the device says the
	// column means anything. The operational mask stands again.
	rows.PortPvid = map[int]int{101: 1, 102: 1}
	got, err = ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Untagged == nil || *c.Untagged != 101 {
		t.Errorf("an uncorroborated default PVID displaces nothing: got %+v", c)
	}
}

// An operational untagged row not trusted to name the port's untagged VLAN is
// not trusted to delete a configured membership either. Provenance is per
// column, so a VLAN can have a static egress mask and a current untagged one.
func TestExtractGeneric_AnOperationalUntaggedRowDoesNotDeleteConfiguredMembership(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101},
		PortPvid:          map[int]int{101: 20},
		VlanEgressPorts:   map[int][]byte{20: maskWithPorts(1), 30: maskWithPorts(1)},
		VlanUntaggedPorts: map[int][]byte{20: maskWithPorts(1), 30: maskWithPorts(1)},
		// VLAN 30's membership is configured; only its untagged row is not.
		VlanEgressFromCurrent:   map[int]struct{}{},
		VlanUntaggedFromCurrent: map[int]struct{}{30: {}},
		IfAdminStatus:           map[int]int{101: 1},
		IfTypes:                 map[int]string{101: "ethernetCsmacd"},
		VlanCatalogPresent:      true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	c := Classify(*got[101])
	if c.Untagged == nil || *c.Untagged != 20 {
		t.Errorf("the PVID names the untagged VLAN: got %+v", c)
	}
	if len(c.Tagged) != 1 || c.Tagged[0] != 30 {
		t.Errorf("configured membership survives as a tagged VLAN: got %+v", c)
	}

	// With the untagged row configured too, the device has said the port
	// egresses untagged there, and it is dropped rather than called tagged.
	rows.VlanUntaggedFromCurrent = map[int]struct{}{}
	got, err = ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); len(c.Tagged) != 0 {
		t.Errorf("a configured untagged row rules the VLAN out as tagged: got %+v", c)
	}
}

// Where no port on the device reports anything but the default, the PVID
// column says nothing and does not displace a VLAN the device reported the
// port untagged in.
func TestExtractGeneric_TheDefaultPvidDisplacesNothing(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex:       map[int]int{1: 101},
		PortPvid:                map[int]int{101: 1},
		VlanEgressPorts:         map[int][]byte{20: maskWithPorts(1)},
		VlanUntaggedPorts:       map[int][]byte{20: maskWithPorts(1)},
		VlanEgressFromCurrent:   map[int]struct{}{20: {}},
		VlanUntaggedFromCurrent: map[int]struct{}{20: {}},
		IfAdminStatus:           map[int]int{101: 1},
		IfTypes:                 map[int]string{101: "ethernetCsmacd"},
		VlanCatalogPresent:      true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Untagged == nil || *c.Untagged != 20 {
		t.Errorf("the reported untagged VLAN stands against a default PVID: got %+v", c)
	}
}

// One VLAN can be the untagged one. When several operational masks name the
// port, a PVID worth trusting settles which, and the rest are dropped rather
// than reported as tagged -- those masks are the device saying they are the
// VLANs it does not tag. Configured masks are not displaced this way: there
// the highest wins, which no test here should be read as endorsing.
func TestExtractGeneric_UntaggedInSeveralCurrentVlansKeepsOnlyThePvidsOwn(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{4: 104},
		PortPvid:          map[int]int{104: 10},
		VlanEgressPorts: map[int][]byte{
			1: maskWithPorts(4), 10: maskWithPorts(4), 99: maskWithPorts(4),
		},
		VlanUntaggedPorts: map[int][]byte{
			1: maskWithPorts(4), 10: maskWithPorts(4), 99: maskWithPorts(4),
		},
		VlanEgressFromCurrent:   map[int]struct{}{1: {}, 10: {}, 99: {}},
		VlanUntaggedFromCurrent: map[int]struct{}{1: {}, 10: {}, 99: {}},
		IfAdminStatus:           map[int]int{104: 1},
		IfTypes:                 map[int]string{104: "ethernetCsmacd"},
		VlanCatalogPresent:      true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	c := Classify(*got[104])
	if c.Untagged == nil || *c.Untagged != 10 {
		t.Errorf("the PVID picks which of them is untagged: got %+v", c)
	}
	if len(c.Tagged) != 0 {
		t.Errorf("no VLAN the port egresses untagged may be reported tagged: got %+v", c)
	}
}

// A VLAN the port is only in the egress mask of is genuinely tagged, and
// dropping the untagged ones must not take it with them.
func TestExtractGeneric_TaggedMembershipSurvivesTheUntaggedDrop(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101},
		PortPvid:          map[int]int{101: 312},
		VlanEgressPorts: map[int][]byte{
			1: maskWithPorts(1), 304: maskWithPorts(1), 312: maskWithPorts(1),
		},
		VlanUntaggedPorts: map[int][]byte{
			1: maskWithPorts(1), 312: maskWithPorts(1),
		},
		IfAdminStatus:      map[int]int{101: 1},
		IfTypes:            map[int]string{101: "ethernetCsmacd"},
		VlanCatalogPresent: true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	c := Classify(*got[101])
	if c.Mode != ModeTrunk || c.Untagged == nil || *c.Untagged != 312 {
		t.Errorf("the highest untagged VLAN is still the native one: got %+v", c)
	}
	if len(c.Tagged) != 1 || c.Tagged[0] != 304 {
		t.Errorf("only VLAN 1, which the port egresses untagged, is dropped: got %+v", c)
	}
}

// A maintained PVID column is a fact about the device; it does not make every
// value in it true of every port. Where the device CONFIGURES the PVID's VLAN
// and leaves this port out of it, the port is not in that VLAN whatever the
// column says, and a default PVID does not displace what the masks report.
//
// The withdrawal branch already refuses to read the same evidence the other
// way round. This is what makes the two branches agree.
func TestExtractGeneric_ADefaultPvidTheMasksContradictDisplacesNothing(t *testing.T) {
	rows := GenericRows{
		BasePortToIfIndex: map[int]int{1: 101, 2: 102},
		PortPvid:          map[int]int{101: 1, 102: 7},
		VlanEgressPorts: map[int][]byte{
			1: maskWithPorts(2), 7: maskWithPorts(2), 16: maskWithPorts(1),
		},
		VlanUntaggedPorts: map[int][]byte{
			1: maskWithPorts(2), 7: maskWithPorts(2), 16: maskWithPorts(1),
		},
		// VLAN 1 is configured and excludes this port; the port is untagged in
		// VLAN 16 operationally.
		VlanEgressFromCurrent:   map[int]struct{}{16: {}},
		VlanUntaggedFromCurrent: map[int]struct{}{16: {}},
		IfAdminStatus:           map[int]int{101: 1, 102: 1},
		IfTypes:                 map[int]string{101: "ethernetCsmacd", 102: "ethernetCsmacd"},
		VlanCatalogPresent:      true,
	}
	got, err := ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Untagged == nil || *c.Untagged != 16 {
		t.Errorf("a configured row excluding the port outranks its default PVID: got %+v", c)
	}

	// A PVID the operator had to set is not asked this question: a port parked
	// on a VLAN it is not a member of is a configuration, and the PVID is the
	// only record of it.
	rows.PortPvid = map[int]int{101: 999, 102: 7}
	rows.VlanEgressPorts[999] = maskWithPorts(2)
	rows.VlanUntaggedPorts[999] = maskWithPorts(2)
	got, err = ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Untagged == nil || *c.Untagged != 999 {
		t.Errorf("a non-default PVID stands even where a row excludes the port: got %+v", c)
	}

	// Publishing no row at all for the PVID's VLAN is not a contradiction. The
	// device has said nothing about that VLAN, so there is nothing to weigh the
	// PVID against and it stands, as it does wherever it is the only evidence.
	rows.PortPvid = map[int]int{101: 1, 102: 7}
	delete(rows.VlanEgressPorts, 1)
	delete(rows.VlanUntaggedPorts, 1)
	got, err = ExtractGeneric(rows)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c := Classify(*got[101]); c.Untagged == nil || *c.Untagged != 1 {
		t.Errorf("an unpublished VLAN contradicts nothing: got %+v", c)
	}
}

// masksContradictPvid is the port-level half of the default-PVID test. Which
// table it reads, in which order, and whose rows count are what it means.
func TestMasksContradictPvid(t *testing.T) {
	const pvid = 1
	ports := []int{1}
	in, out := maskWithPorts(1), maskWithPorts(2)
	configured := GenericRows{
		VlanEgressFromCurrent:   map[int]struct{}{},
		VlanUntaggedFromCurrent: map[int]struct{}{},
	}
	operational := GenericRows{
		VlanEgressFromCurrent:   map[int]struct{}{pvid: {}},
		VlanUntaggedFromCurrent: map[int]struct{}{pvid: {}},
	}
	cases := []struct {
		name             string
		rows             GenericRows
		egress, untagged map[int][]byte
		want             bool
	}{
		{"no row at all", configured, nil, nil, false},
		{"untagged excludes the port", configured, nil, map[int][]byte{pvid: out}, true},
		{"untagged names the port", configured, nil, map[int][]byte{pvid: in}, false},
		{"untagged row with no member", configured, nil, map[int][]byte{pvid: {}}, true},
		// In the egress mask but not the untagged one is a TAGGED member, which
		// refutes a PVID naming that VLAN as the port's untagged one.
		{
			"tagged member of its own PVID's VLAN", configured,
			map[int][]byte{pvid: in},
			map[int][]byte{pvid: out},
			true,
		},
		{
			"no untagged row, egress excludes", configured,
			map[int][]byte{pvid: out},
			nil, true,
		},
		{
			"no untagged row, egress names it", configured,
			map[int][]byte{pvid: in},
			nil, false,
		},
		// Operational absence is not configuration.
		{
			"current untagged excludes the port", operational,
			nil,
			map[int][]byte{pvid: out},
			false,
		},
		{
			"current egress excludes the port", operational,
			map[int][]byte{pvid: out},
			nil, false,
		},
	}
	for _, c := range cases {
		if got := masksContradictPvid(c.rows, c.egress, c.untagged, pvid, ports); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
