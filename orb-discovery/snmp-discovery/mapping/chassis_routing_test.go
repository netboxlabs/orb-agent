package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
)

func TestRouteIfIndex_AliasTable_DirectChassis(t *testing.T) {
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()
	// Port directly on chassis row 1 (entPhysicalIndex=1).
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1.0"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10101"}
	// Port on a card under chassis row 1000 (entPhysicalIndex=1050 -> contained=1000).
	oids[".1.3.6.1.2.1.47.1.1.1.1.4.1050"] = Value{Value: "1000"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.5.1050"] = Value{Value: "9"} // module
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1050.0"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10201"}

	inv := extractInventory(oids, logger)
	r := newChassisRouter(inv, oids, logger)

	id, ok := r.routeIfIndex(10101)
	assert.True(t, ok)
	assert.Equal(t, 1, id)

	id, ok = r.routeIfIndex(10201)
	assert.True(t, ok)
	assert.Equal(t, 2, id)
}

func TestRouteIfIndex_AliasMissing_ReturnsFalse(t *testing.T) {
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack() // no alias entries
	inv := extractInventory(oids, logger)
	r := newChassisRouter(inv, oids, logger)
	_, ok := r.routeIfIndex(10101)
	assert.False(t, ok)
}

func TestRouteIfIndex_AliasValueWithoutLeadingDot(t *testing.T) {
	// Some gosnmp ObjectIdentifier renderings omit the leading dot.
	// Routing must still succeed.
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1.0"] = Value{Value: "1.3.6.1.2.1.2.2.1.1.10101"} // no leading dot
	inv := extractInventory(oids, logger)
	r := newChassisRouter(inv, oids, logger)
	id, ok := r.routeIfIndex(10101)
	assert.True(t, ok)
	assert.Equal(t, 1, id)
}

func TestRouteIfIndex_NonIfIndexAliasValueIgnored(t *testing.T) {
	// Non-ifIndex VariablePointer values (e.g. pointing at ifAlias)
	// must be skipped without crashing.
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1.0"] = Value{Value: ".1.3.6.1.2.1.31.1.1.1.18.10101"} // ifAlias
	inv := extractInventory(oids, logger)
	r := newChassisRouter(inv, oids, logger)
	_, ok := r.routeIfIndex(10101)
	assert.False(t, ok, "non-ifIndex alias values are not usable for routing")
}

func TestRouteIfIndex_ChainTerminatesAtRoot_ReturnsFalse(t *testing.T) {
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()
	// entPhysicalIndex 999 contained directly in root (0) — not a chassis.
	oids[".1.3.6.1.2.1.47.1.1.1.1.4.999"] = Value{Value: "0"}
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.999.0"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.42"}

	inv := extractInventory(oids, logger)
	r := newChassisRouter(inv, oids, logger)
	_, ok := r.routeIfIndex(42)
	assert.False(t, ok)
}

func TestRouteIfIndex_AliasToDroppedChassisReturnsDroppedID(t *testing.T) {
	logger := slog.Default()
	// Build inventory with member id=2 dropped via duplicate serial.
	// entPhysicalIndex 1 → member id 1 (survivor), index 1000 → member id 2 (dropped).
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":     {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":     {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":     {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: "SHARED-SERIAL"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "SHARED-SERIAL"}, // dup → id 2 dropped
		// alias: entPhysicalIndex 1000 aliases ifIndex 99
		".1.3.6.1.2.1.47.1.3.2.1.2.1000.0": {Value: ".1.3.6.1.2.1.2.2.1.1.99"},
	}
	inv := extractInventory(oids, logger)
	r := newChassisRouter(inv, oids, logger)

	// Precondition: member id=2 must be in DroppedIDs.
	assert.Contains(t, inv.DroppedIDs, 2, "member id=2 must be dropped (dup serial)")

	// routeIfIndex must return ok=true and the dropped id so the caller
	// can trigger the skip-with-warn path rather than falling through to
	// ParseMemberID which might mis-route to master.
	id, ok := r.routeIfIndex(99)
	assert.True(t, ok, "alias-table hit on dropped chassis row must return ok=true")
	assert.Equal(t, 2, id, "must return the dropped member id so caller can skip-with-warn")
}

// TestRouteIfIndex_DuplicateIfIndexDeterministicResolution guards
// finding #15: when multiple entAliasMappingTable rows resolve to the
// SAME ifIndex via different (entPhysicalIndex, entAliasLogicalIndexOrZero)
// pairs — possible for ports that participate in multiple logical
// entities (VRFs, contexts) or LAG ifIndexes exposed against multiple
// physical members — the resolution must be deterministic regardless
// of Go's randomized `oids` iteration order.
//
// Precedence (newChassisRouter):
//  1. Prefer rows with entAliasLogicalIndexOrZero != 0 (RFC 6933
//     per-logical-entity mapping) over the zero-indexed default.
//  2. Among non-zero rows, prefer the lowest logical index.
//  3. Final tiebreaker: lowest entPhysicalIndex.
func TestRouteIfIndex_DuplicateIfIndexDeterministicResolution(t *testing.T) {
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()

	// Both rows resolve to ifIndex 10301. The first is the default
	// mapping (logical=0) for entPhysicalIndex 1 (chassis 1 / member 1);
	// the second is a non-zero logical mapping (logical=5) for
	// entPhysicalIndex 1000 (chassis 2 / member 2). Per the resolution
	// rule, the non-zero row must win → ent 1000 → member id 2.
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1.0"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10301"}
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1000.5"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10301"}

	inv := extractInventory(oids, logger)
	// Repeat the build several times to surface any non-determinism
	// surviving the sort (Go map iteration order changes per run, but
	// even within a process it is randomized per range statement).
	for i := 0; i < 25; i++ {
		r := newChassisRouter(inv, oids, logger)
		id, ok := r.routeIfIndex(10301)
		assert.True(t, ok, "iter %d: routeIfIndex must resolve duplicate-row ifIndex", i)
		assert.Equal(t, 2, id, "iter %d: non-zero logical row (ent 1000, member 2) must win over logical=0 row", i)
	}
}

// TestRouteIfIndex_DuplicateNonZeroLogicalLowestLogicalWins covers
// the second precedence rung: two non-zero logical rows competing
// for the same ifIndex. The row with the lower logical index wins.
func TestRouteIfIndex_DuplicateNonZeroLogicalLowestLogicalWins(t *testing.T) {
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()

	// logical=2 on chassis 1000 (member 2), logical=7 on chassis 1
	// (member 1). Lower logical index (2) wins → member 2.
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1000.2"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10501"}
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1.7"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10501"}

	inv := extractInventory(oids, logger)
	for i := 0; i < 25; i++ {
		r := newChassisRouter(inv, oids, logger)
		id, ok := r.routeIfIndex(10501)
		assert.True(t, ok, "iter %d", i)
		assert.Equal(t, 2, id, "iter %d: lowest logical-index (2) wins → member 2", i)
	}
}

// TestRouteIfIndex_DuplicateLogicalZeroLowestEntWins covers the
// tiebreaker rung: two alias rows for the same ifIndex BOTH carry
// entAliasLogicalIndexOrZero == 0 (no per-logical-entity context).
// The lower entPhysicalIndex must win, matching the lowest-id master
// pinning convention used elsewhere.
func TestRouteIfIndex_DuplicateLogicalZeroLowestEntWins(t *testing.T) {
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()

	// Two logical=0 rows both pointing at ifIndex 10401 — one on
	// chassis 1 (member 1), one on chassis 1000 (member 2). The lower
	// entPhysicalIndex (1) must win.
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1000.0"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10401"}
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1.0"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10401"}

	inv := extractInventory(oids, logger)
	for i := 0; i < 25; i++ {
		r := newChassisRouter(inv, oids, logger)
		id, ok := r.routeIfIndex(10401)
		assert.True(t, ok, "iter %d", i)
		assert.Equal(t, 1, id, "iter %d: lower entPhysicalIndex (chassis 1, member 1) wins", i)
	}
}

func TestParseMemberID(t *testing.T) {
	cases := []struct {
		ifName string
		wantID int
		wantOK bool
	}{
		// Cisco IOS/IOS-XE stack 3-tuple.
		{"GigabitEthernet1/0/1", 1, true},
		{"Gi1/0/1", 1, true},
		{"Gi2/0/24", 2, true},
		{"TenGigE2/0/24", 2, true},
		{"TenGigabitEthernet3/0/1", 3, true},
		{"FortyGigabitEthernet1/1/1", 1, true},
		{"HundredGigE1/0/1", 1, true},
		{"mGig3/0/1", 3, true}, // multi-gig prefix
		{"TwoGigabitEthernet1/0/2", 1, true},
		{"FiveGigabitEthernet1/0/3", 1, true},

		// Junos FPC.
		{"xe-0/0/0", 0, true},
		{"ge-2/0/1", 2, true},
		{"et-3/0/0", 3, true},

		// Aruba CX 1/1/1.
		{"1/1/1", 1, true},
		{"2/1/24", 2, true},

		// HP/H3C Comware.
		{"GigabitEthernet1/0/1", 1, true},
		{"Ten-GigabitEthernet2/0/1", 2, true},

		// No member id (route to master).
		{"Vlan10", 0, false},
		{"Loopback0", 0, false},
		{"Port-channel1", 0, false},
		{"Po1", 0, false},
		{"mgmt0", 0, false},
		{"Tunnel1", 0, false},
		{"BVI100", 0, false},
		{"Bundle-Ether1", 0, false},
		{"Null0", 0, false},
		{"", 0, false},

		// Negative cases for non-stack 2-tuple naming conventions —
		// must NOT false-positive into a stack member id.
		{"Gi1/1", 0, false},              // Cisco 2-tuple (non-stack chassis)
		{"GigabitEthernet1/1", 0, false}, // Cisco 2-tuple long form
		{"Ethernet1/1", 0, false},        // NX-OS 2-tuple (VPC is not VC)
		{"ether1", 0, false},             // MikroTik (no stack convention)
		{"ether10", 0, false},
		{"1:1", 0, false},          // Extreme EXOS (unsupported in batch 1)
		{"sfp-sfpplus1", 0, false}, // MikroTik SFP+ port

		// Cisco short-form prefixes (Te, Fo, Hu, Tw, Fi, Twe).
		{"Te1/0/1", 1, true},
		{"Te2/0/24", 2, true},
		{"Fo1/0/1", 1, true},
		{"Hu1/0/1", 1, true},
		{"Tw2/0/1", 2, true},
		{"Fi1/0/1", 1, true},
		{"Twe1/0/1", 1, true},

		// FastEthernet stack 3-tuple — rare but real on older Cisco
		// gear (e.g. some Catalyst stacks). Must NOT be swallowed by a
		// "FastEthernet0/0" master-only prefix entry.
		{"FastEthernet0/0/0", 0, true},
		{"Fa0/0/0", 0, true},
		{"FastEthernet1/0/24", 1, true},
		{"Fa2/0/1", 2, true},
		// Non-stack 2-tuple FastEthernet0/0 (e.g. Cisco router mgmt
		// port) — must fail to parse a member id; routeInterface
		// fallback then routes it to master.
		{"FastEthernet0/0", 0, false},
		{"Fa0/0", 0, false},

		// Subinterfaces — must parse the parent-port member id, not fall through.
		{"GigabitEthernet2/0/1.100", 2, true},
		{"Gi2/0/1.100", 2, true},
		{"xe-2/0/0.0", 2, true},
		{"ge-3/1/0.500", 3, true},
		{"2/1/24.100", 2, true},
		// Non-digit suffix → leave name alone, then no match (Vlan10.foo, etc.).
		{"Vlan10.foo", 0, false},
		// Edge: trailing dot with no digits, should not strip.
		{"foo.", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.ifName, func(t *testing.T) {
			id, ok := ParseMemberID(tc.ifName)
			assert.Equal(t, tc.wantOK, ok, "ok mismatch")
			if tc.wantOK {
				assert.Equal(t, tc.wantID, id, "id mismatch")
			}
		})
	}
}

// TestRouteInterface_AliasTablePathPrecedesEmptyName guards the
// invariant that the alias-table lookup runs BEFORE the empty-name
// short-circuit. On devices where some interfaces lack
// ifDescr/ifName, the alias-table can still deterministically route
// them to the owning member; falling straight to master would
// silently mis-attribute member-owned ports.
func TestRouteInterface_AliasTablePathPrecedesEmptyName(t *testing.T) {
	logger := slog.Default()
	oids := fixtureCisco3850TwoMemberStack()
	// Port on a card under chassis row 1000 (member 2) — alias table
	// resolves ifIndex 10201 to that member.
	oids[".1.3.6.1.2.1.47.1.1.1.1.4.1050"] = Value{Value: "1000"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.5.1050"] = Value{Value: "9"} // module
	oids[".1.3.6.1.2.1.47.1.3.2.1.2.1050.0"] = Value{Value: ".1.3.6.1.2.1.2.2.1.1.10201"}

	inv := extractInventory(oids, logger)
	router := newChassisRouter(inv, oids, logger)

	master := &diode.Device{Name: strPtr("3850-stack")}
	member := &diode.Device{Name: strPtr("3850-stack-2")}
	memberByID := map[int]*diode.Device{1: master, 2: member}

	// Interface with NO Name but with a known ifIndex → alias table
	// must still resolve it to member 2, not fall through to master.
	ifaceNoName := &diode.Interface{Name: nil}
	ifIndexByIface := map[*diode.Interface]int{ifaceNoName: 10201}

	got := routeInterface(ifaceNoName, ifIndexByIface, router, inv, memberByID, logger)
	assert.Equal(t, 2, got, "alias-table should route nameless iface to member 2, not master")

	// Empty string Name path — same behavior.
	ifaceEmpty := &diode.Interface{Name: strPtr("")}
	ifIndexByIface[ifaceEmpty] = 10201
	got = routeInterface(ifaceEmpty, ifIndexByIface, router, inv, memberByID, logger)
	assert.Equal(t, 2, got, "alias-table should route empty-name iface to member 2")
}
