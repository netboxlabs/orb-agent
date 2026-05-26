// Copyright 2026 NetBox Labs, Inc.

package mapping

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCapturingLogger builds an slog.Logger whose output lands in buf so
// individual tests can assert on warn-line presence.
func newCapturingLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestAssignMemberID_StandaloneAllZero — when chassisInv is nil the
// device is standalone; every module / sub-module / empty-bay entry must
// land on member id 0 so downstream translation emits them under master.
func TestAssignMemberID_StandaloneAllZero(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newCapturingLogger(buf)

	inv := newModuleInventory()
	inv.Modules = []ModuleEntry{
		{EntIndex: "101", Type: ModuleTypeSupervisor},
		{EntIndex: "201", Type: ModuleTypeLinecard},
	}
	inv.SubModules["201"] = []ModuleEntry{
		{EntIndex: "203", Type: ModuleTypeTransceiver, ParentEntIdx: "201"},
	}
	inv.EmptyBays = []ModuleEntry{
		{EntIndex: "300", Type: ModuleTypeUnknown},
	}

	assignMemberID(&inv, nil, ObjectIDValueMap{}, logger)

	for _, m := range inv.Modules {
		assert.Equalf(t, 0, m.MemberID, "module %s must be MemberID=0 in standalone", m.EntIndex)
	}
	for _, list := range inv.SubModules {
		for _, m := range list {
			assert.Equalf(t, 0, m.MemberID, "submodule %s must be MemberID=0 in standalone", m.EntIndex)
		}
	}
	for _, m := range inv.EmptyBays {
		assert.Equalf(t, 0, m.MemberID, "empty bay %s must be MemberID=0 in standalone", m.EntIndex)
	}
}

// TestAssignMemberID_VCMapsToMemberByChassisAncestor — module EntIndex
// "201" sits under class=5 "200" which sits under class=3 "1000". The
// chassis row "1000" belongs to member id 2 (per chassisInv.Members).
// assignMemberID must walk the containedIn chain to "1000" and stamp
// MemberID=2 on the module entry.
func TestAssignMemberID_VCMapsToMemberByChassisAncestor(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newCapturingLogger(buf)

	inv := newModuleInventory()
	inv.Modules = []ModuleEntry{
		{EntIndex: "201", Type: ModuleTypeLinecard},
	}

	chassisInv := &ChassisInventory{
		Members: []ChassisMember{
			{ID: 1, EntPhysicalIndex: "1"},
			{ID: 2, EntPhysicalIndex: "1000"},
		},
	}

	// containedIn chain: 201 -> 200 (class=5) -> 1000 (class=3).
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.201":  Value{Value: "200"},
		".1.3.6.1.2.1.47.1.1.1.1.5.201":  Value{Value: "9"},
		".1.3.6.1.2.1.47.1.1.1.1.4.200":  Value{Value: "1000"},
		".1.3.6.1.2.1.47.1.1.1.1.5.200":  Value{Value: "5"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1000": Value{Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000": Value{Value: "3"},
	}

	assignMemberID(&inv, chassisInv, oids, logger)

	require.Len(t, inv.Modules, 1)
	assert.Equal(t, 2, inv.Modules[0].MemberID,
		"module 201 chain terminates at chassis 1000 -> member 2")
}

// TestAssignMemberID_OrphanMember_DroppedOrLogged — a module whose
// chassis ancestor is NOT in chassisInv.Members must be left with the
// sentinel MemberID=-1 (translation step skips MemberID<0) and a warn
// log must fire so operators can spot the orphan.
func TestAssignMemberID_OrphanMember_DroppedOrLogged(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newCapturingLogger(buf)

	inv := newModuleInventory()
	inv.Modules = []ModuleEntry{
		{EntIndex: "401", Type: ModuleTypeLinecard},
	}

	chassisInv := &ChassisInventory{
		Members: []ChassisMember{
			{ID: 1, EntPhysicalIndex: "1"},
			{ID: 2, EntPhysicalIndex: "1000"},
		},
	}

	// 401 -> 400 (class=5) -> 9999 (class=3). 9999 is not in chassisInv.
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.401":  Value{Value: "400"},
		".1.3.6.1.2.1.47.1.1.1.1.5.401":  Value{Value: "9"},
		".1.3.6.1.2.1.47.1.1.1.1.4.400":  Value{Value: "9999"},
		".1.3.6.1.2.1.47.1.1.1.1.5.400":  Value{Value: "5"},
		".1.3.6.1.2.1.47.1.1.1.1.4.9999": Value{Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.9999": Value{Value: "3"},
	}

	assignMemberID(&inv, chassisInv, oids, logger)

	require.Len(t, inv.Modules, 1)
	assert.Equal(t, -1, inv.Modules[0].MemberID,
		"orphan module must carry MemberID=-1 sentinel for the skip path")
	assert.Contains(t, buf.String(), "orphan",
		"orphan module must produce a warn log")
}

// TestAssignMemberID_VCMasterKeyedByLowestMemberID — modules under the
// master chassis (entPhysicalIndex == Members[0].EntPhysicalIndex) must
// carry the lowest member id (Members[0].ID == 1), NOT 0. The "0 means
// standalone" rule applies only when chassisInv is nil/empty.
func TestAssignMemberID_VCMasterKeyedByLowestMemberID(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := newCapturingLogger(buf)

	inv := newModuleInventory()
	inv.Modules = []ModuleEntry{
		{EntIndex: "101", Type: ModuleTypeLinecard},
	}

	chassisInv := &ChassisInventory{
		Members: []ChassisMember{
			{ID: 1, EntPhysicalIndex: "1"},
			{ID: 2, EntPhysicalIndex: "1000"},
		},
	}

	// 101 -> 100 (class=5) -> 1 (class=3, master).
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.101": Value{Value: "100"},
		".1.3.6.1.2.1.47.1.1.1.1.5.101": Value{Value: "9"},
		".1.3.6.1.2.1.47.1.1.1.1.4.100": Value{Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.5.100": Value{Value: "5"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1":   Value{Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":   Value{Value: "3"},
	}

	assignMemberID(&inv, chassisInv, oids, logger)

	require.Len(t, inv.Modules, 1)
	assert.Equal(t, 1, inv.Modules[0].MemberID,
		"module under master chassis must carry the lowest member id (1), not 0")
}

// --- buildIfaceModuleMap tests ---

// TestBuildIfaceModuleMap_HappyPath — transceiver EntIndex "203" resolves
// through aliasMap to ifIndex "10101". The emitted Module at
// emittedModules["203"] must appear keyed by ifIndex "10101" in the
// result so the runner can later set Interface.Module via the
// ifIndexByIface lookup.
func TestBuildIfaceModuleMap_HappyPath(t *testing.T) {
	inv := newModuleInventory()
	inv.SubModules["201"] = []ModuleEntry{
		{EntIndex: "203", Type: ModuleTypeTransceiver, ParentEntIdx: "201"},
	}
	aliasMap := map[string]string{"203": "10101"}
	mod := &diode.Module{}
	emitted := map[string]*diode.Module{"203": mod}

	got := buildIfaceModuleMap(inv, aliasMap, emitted)

	require.Contains(t, got, "10101")
	assert.Same(t, mod, got["10101"], "result must point at the emittedModules entry")
	assert.Len(t, got, 1, "only the transceiver routes; no extra keys")
}

// TestBuildIfaceModuleMap_TransceiverWithoutAliasSkipped — a transceiver
// missing from aliasMap is silently skipped (no ifIndex to bind to).
func TestBuildIfaceModuleMap_TransceiverWithoutAliasSkipped(t *testing.T) {
	inv := newModuleInventory()
	inv.SubModules["201"] = []ModuleEntry{
		{EntIndex: "203", Type: ModuleTypeTransceiver, ParentEntIdx: "201"},
	}
	emitted := map[string]*diode.Module{"203": {}}

	got := buildIfaceModuleMap(inv, map[string]string{}, emitted)

	assert.Empty(t, got, "no aliasMap entry -> transceiver not in result")
}

// TestBuildIfaceModuleMap_VCMembersWithSameIfNameDoNotCollide — codex P1
// regression: on Juniper VC and some Aruba stacks each member uses a
// local ifName scope, so two distinct interfaces on two members canonicalize
// to the same string (e.g. "Gi1/0/1"). Keying by ifName collapses both
// transceivers onto one map entry and the runner attaches the wrong
// member's module. ifIndex is globally unique in the SNMP walk space —
// keying by it preserves both entries.
func TestBuildIfaceModuleMap_VCMembersWithSameIfNameDoNotCollide(t *testing.T) {
	mod1 := &diode.Module{Serial: strPtr("XCVR-MEMBER-1")}
	mod2 := &diode.Module{Serial: strPtr("XCVR-MEMBER-2")}
	inv := ModuleInventory{
		SubModules: map[string][]ModuleEntry{
			"201": {{EntIndex: "203", Type: ModuleTypeTransceiver}}, // member 1 linecard
			"401": {{EntIndex: "403", Type: ModuleTypeTransceiver}}, // member 2 linecard
		},
	}
	aliasMap := map[string]string{
		"203": "10101", // member 1 ifIndex
		"403": "20101", // member 2 ifIndex — DISTINCT
	}
	emittedModules := map[string]*diode.Module{
		"203": mod1,
		"403": mod2,
	}
	out := buildIfaceModuleMap(inv, aliasMap, emittedModules)

	require.Equal(t, mod1, out["10101"], "member 1 transceiver routes to ifIndex 10101")
	require.Equal(t, mod2, out["20101"], "member 2 transceiver routes to ifIndex 20101")
	require.Len(t, out, 2, "no collapse — distinct ifIndexes preserve distinct modules")
}

// --- Exported helper tests (runner wire-up) ---

// TestAliasMapFromOIDs_ParsesEntAliasMappingRows — confirms the flat
// entPhysicalIndex -> ifIndex shape: happy path, malformed suffix
// dropped, non-ifIndex value dropped, unrelated OID ignored.
func TestAliasMapFromOIDs_ParsesEntAliasMappingRows(t *testing.T) {
	oids := ObjectIDValueMap{
		// entAliasMappingIdent.<entPhysicalIndex>.<logicalIdx> -> ifEntry.ifIndex.<ifIdx>
		".1.3.6.1.2.1.47.1.3.2.1.2.203.0": Value{Value: ".1.3.6.1.2.1.2.2.1.1.10101"},
		".1.3.6.1.2.1.47.1.3.2.1.2.301.0": Value{Value: ".1.3.6.1.2.1.2.2.1.1.10201"},
		// Malformed — single-segment suffix, must be skipped.
		".1.3.6.1.2.1.47.1.3.2.1.2.999": Value{Value: ".1.3.6.1.2.1.2.2.1.1.99999"},
		// Non-ifIndex value (ifAlias), must be skipped.
		".1.3.6.1.2.1.47.1.3.2.1.2.404.0": Value{Value: ".1.3.6.1.2.1.31.1.1.1.18.10101"},
		// Unrelated OID, must be ignored.
		".1.3.6.1.2.1.2.2.1.2.10101": Value{Value: "GigabitEthernet1/0/1"},
	}
	m := AliasMapFromOIDs(oids)
	assert.Equal(t, "10101", m["203"])
	assert.Equal(t, "10201", m["301"])
	assert.NotContains(t, m, "999", "malformed row dropped")
	assert.NotContains(t, m, "404", "non-ifIndex value dropped")
	assert.Len(t, m, 2)
}

// TestAliasMapFromOIDs_DeterministicWhenMultipleAliasRowsShareEntIndex —
// when multiple entAliasMappingTable rows resolve to the same
// entPhysicalIndex, AliasMapFromOIDs must pick deterministically.
// Under the RFC 6933 precedence rule, a non-zero logical-index row wins
// over the .0 wildcard, so here logical=1 (ifIndex 10101) beats
// logical=0 (ifIndex 10201). Running 50x confirms map-iteration order
// can't flip it.
func TestAliasMapFromOIDs_DeterministicWhenMultipleAliasRowsShareEntIndex(t *testing.T) {
	oids := ObjectIDValueMap{
		// Two rows for entPhysicalIndex 203 — different logical idx,
		// different ifIndex. Non-zero logical-index row must win.
		".1.3.6.1.2.1.47.1.3.2.1.2.203.0": Value{Value: ".1.3.6.1.2.1.2.2.1.1.10201"},
		".1.3.6.1.2.1.47.1.3.2.1.2.203.1": Value{Value: ".1.3.6.1.2.1.2.2.1.1.10101"},
	}
	for i := 0; i < 50; i++ {
		m := AliasMapFromOIDs(oids)
		require.Equal(t, "10101", m["203"],
			"AliasMapFromOIDs must deterministically pick the non-zero logical-index row")
	}
}

// TestAliasMapFromOIDs_NonZeroLogicalIndexBeatsWildcard — RFC 6933
// entAliasMappingTable is keyed by (entPhysicalIndex,
// entAliasLogicalIndexOrZero). Non-zero logical-index rows carry
// per-logical-entity context and MUST take precedence over the .0
// "default mapping in the absence of any logical entity" row,
// regardless of which target ifIndex is numerically smaller. This
// mirrors chassis_routing.go's logical-index precedence rule.
func TestAliasMapFromOIDs_NonZeroLogicalIndexBeatsWildcard(t *testing.T) {
	// entPhysicalIndex 203 has TWO alias rows: a .0 wildcard pointing at
	// ifIndex 10101 (lower) AND a non-zero logical row pointing at
	// ifIndex 20201 (higher). Per RFC 6933, the non-zero logical-index
	// row wins regardless of which ifIndex is smaller.
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.3.2.1.2.203.0": Value{Value: ".1.3.6.1.2.1.2.2.1.1.10101"},
		".1.3.6.1.2.1.47.1.3.2.1.2.203.5": Value{Value: ".1.3.6.1.2.1.2.2.1.1.20201"},
	}
	m := AliasMapFromOIDs(oids)
	require.Equal(t, "20201", m["203"],
		"non-zero logical-index row must win over .0 wildcard")
}

// TestAliasMapFromOIDs_LowestLogicalIndexAmongNonZero — among multiple
// non-zero logical-index rows the lowest logical index is the
// deterministic tiebreaker. Mirrors chassis_routing.go's secondary sort.
func TestAliasMapFromOIDs_LowestLogicalIndexAmongNonZero(t *testing.T) {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.3.2.1.2.203.5": Value{Value: ".1.3.6.1.2.1.2.2.1.1.50505"},
		".1.3.6.1.2.1.47.1.3.2.1.2.203.2": Value{Value: ".1.3.6.1.2.1.2.2.1.1.20202"},
	}
	m := AliasMapFromOIDs(oids)
	require.Equal(t, "20202", m["203"],
		"lowest non-zero logical-index wins among non-zero candidates")
}

// TestMemberDevicesFromEntities_VCKeyedByLowestMemberID — the master
// Device (VcPosition == nil) must be keyed by Members[0].ID — the lowest
// logical member id — to mirror TranslateAsStack's memberByID convention
// (chassis.go:432). Non-master members are keyed by *VcPosition.
func TestMemberDevicesFromEntities_VCKeyedByLowestMemberID(t *testing.T) {
	master := &diode.Device{Name: strPtr("vc-master")} // VcPosition == nil
	pos2 := int64(2)
	pos3 := int64(3)
	m2 := &diode.Device{Name: strPtr("member-2"), VcPosition: &pos2}
	m3 := &diode.Device{Name: strPtr("member-3"), VcPosition: &pos3}
	entities := []diode.Entity{master, m2, m3}
	inv := &ChassisInventory{Members: []ChassisMember{{ID: 1}, {ID: 2}, {ID: 3}}}

	out := MemberDevicesFromEntities(entities, inv)

	assert.Equal(t, master, out[1], "master keyed by Members[0].ID (lowest), not 0")
	assert.Equal(t, m2, out[2])
	assert.Equal(t, m3, out[3])
	assert.NotContains(t, out, 0, "master must NOT be keyed by 0 in VC")
	assert.Len(t, out, 3)
}

// TestMemberDevicesFromEntities_StandaloneKeyedByZero — when there is no
// ChassisInventory the master falls back to the standalone key 0.
func TestMemberDevicesFromEntities_StandaloneKeyedByZero(t *testing.T) {
	dev := &diode.Device{Name: strPtr("standalone")} // VcPosition == nil
	out := MemberDevicesFromEntities([]diode.Entity{dev}, nil)
	assert.Equal(t, dev, out[0], "standalone master keyed by 0 when no ChassisInventory")
	assert.Len(t, out, 1)
}

// TestChassisInventoryFromOIDs_WrapsExtractInventory — single-chassis
// fixture produces at least one Member and the master member id is the
// parentRelPos from the fixture (1).
func TestChassisInventoryFromOIDs_WrapsExtractInventory(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	// Minimal stack fixture: one chassis row (class=3).
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  Value{Value: "3"},           // entPhysicalClass=chassis
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  Value{Value: "0"},           // contained in nothing
		".1.3.6.1.2.1.47.1.1.1.1.7.1":  Value{Value: "Stack-1"},     // entPhysicalName
		".1.3.6.1.2.1.47.1.1.1.1.11.1": Value{Value: "FOC2401L0K0"}, // serial
		".1.3.6.1.2.1.47.1.1.1.1.13.1": Value{Value: "C9300-48UXM"}, // modelName
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  Value{Value: "1"},           // parentRelPos
	}
	inv := ChassisInventoryFromOIDs(oids, logger)
	require.NotNil(t, inv)
	require.GreaterOrEqual(t, len(inv.Members), 1,
		"single-chassis fixture must produce at least one Member")
	assert.Equal(t, 1, inv.Members[0].ID,
		"master member ID is lowest present in fixture (parentRelPos=1)")
}

// --- AttachIfaceModules tests ---

// TestAttachIfaceModules_TopLevelInterface — sanity: the existing happy
// path (an *diode.Interface directly in the slice) still attaches the
// module. Guards against regression after the helper extraction.
func TestAttachIfaceModules_TopLevelInterface(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("GigabitEthernet1/0/1")}
	mod := &diode.Module{Serial: strPtr("XCVR-TOP")}
	entities := []diode.Entity{iface}
	ifaceModuleMap := map[string]*diode.Module{"10101": mod}
	ifIndexByIface := map[*diode.Interface]int{iface: 10101}

	AttachIfaceModules(entities, ifaceModuleMap, ifIndexByIface)

	require.NotNil(t, iface.Module, "top-level Interface must get its Module set")
	assert.Equal(t, "XCVR-TOP", *iface.Module.Serial)
}

// TestAttachIfaceModules_NestedInterfaceInIPAddress — codex P2
// regression. MapObjectIDsToEntity drops interfaces referenced by
// IPAddress.AssignedObject from the top-level entity slice (the L3
// routed-port case in mapping.go's getAssignedInterfaces filter). The
// runner's previous attach loop only iterated *diode.Interface entries
// and silently missed these, leaving Interface.Module nil. The helper
// must reach through IPAddress.AssignedObject.
func TestAttachIfaceModules_NestedInterfaceInIPAddress(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("TenGigabitEthernet2/0/1"), Module: nil}
	ip := &diode.IPAddress{
		Address:        strPtr("10.0.0.1/24"),
		AssignedObject: iface,
	}
	mod := &diode.Module{Serial: strPtr("FNS00000001")}
	// Note: ONLY the IPAddress sits in entities — the routed iface has
	// no standalone counterpart in the slice (the very case this fix
	// addresses).
	entities := []diode.Entity{ip}
	ifaceModuleMap := map[string]*diode.Module{"10101": mod}
	ifIndexByIface := map[*diode.Interface]int{iface: 10101}

	AttachIfaceModules(entities, ifaceModuleMap, ifIndexByIface)

	require.NotNil(t, iface.Module,
		"Interface inside IPAddress.AssignedObject must get its Module set")
	assert.Equal(t, "FNS00000001", *iface.Module.Serial)
}

// TestAttachIfaceModules_NestedInterfaceInMACAddress — mirror of the
// IPAddress case. MACAddress.AssignedObject carries an *diode.Interface
// on this codebase (chassis.go:484 walks it during member-rerouting).
// The helper must reach through that shape too so an interface visible
// ONLY via a MAC ref still gets its module attached.
func TestAttachIfaceModules_NestedInterfaceInMACAddress(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("TenGigabitEthernet2/0/2"), Module: nil}
	mac := &diode.MACAddress{
		MacAddress:     strPtr("00:11:22:33:44:55"),
		AssignedObject: iface,
	}
	mod := &diode.Module{Serial: strPtr("FNS00000002")}
	entities := []diode.Entity{mac}
	ifaceModuleMap := map[string]*diode.Module{"10102": mod}
	ifIndexByIface := map[*diode.Interface]int{iface: 10102}

	AttachIfaceModules(entities, ifaceModuleMap, ifIndexByIface)

	require.NotNil(t, iface.Module,
		"Interface inside MACAddress.AssignedObject must get its Module set")
	assert.Equal(t, "FNS00000002", *iface.Module.Serial)
}

// TestAttachIfaceModules_MissIfIndexLeavesModuleNil — when an interface
// pointer is not present in ifIndexByIface (e.g. came in via a path the
// registry didn't track) the helper skips it silently. Interface.Module
// remains nil — no panic, no fabricated lookup.
func TestAttachIfaceModules_MissIfIndexLeavesModuleNil(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("unknown")}
	entities := []diode.Entity{iface}
	ifaceModuleMap := map[string]*diode.Module{"10101": {Serial: strPtr("X")}}
	ifIndexByIface := map[*diode.Interface]int{} // iface missing

	AttachIfaceModules(entities, ifaceModuleMap, ifIndexByIface)

	assert.Nil(t, iface.Module, "interface absent from ifIndexByIface stays untouched")
}

// TestAttachIfaceModules_EmptyMapsAreNoOp — defensive: nil/empty inputs
// must not panic and must not mutate entities. The runner can call this
// unconditionally without guarding on map size.
func TestAttachIfaceModules_EmptyMapsAreNoOp(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("Gi1/0/1")}
	entities := []diode.Entity{iface}

	AttachIfaceModules(entities, nil, nil)
	assert.Nil(t, iface.Module)

	AttachIfaceModules(entities, map[string]*diode.Module{}, map[*diode.Interface]int{})
	assert.Nil(t, iface.Module)
}
