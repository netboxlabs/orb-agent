package mapping

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// TestChassisInventoryMapper_IsNoOp confirms the mapper accepts
// chassis_inventory PDUs without producing entities. Inventory data
// is consumed by TranslateAsStack later, not by this Map call.
func TestChassisInventoryMapper_IsNoOp(t *testing.T) {
	logger := slog.Default()
	registry := NewEntityRegistry(logger)
	mapper := &ChassisInventoryMapper{logger: logger}

	entry := &Entry{
		Entity: string(ChassisInventoryEntityType),
		Field:  "_id",
	}
	// Synthesize one entPhysicalSerialNum row.
	values := map[ObjectIDIndex]*ObjectIDValue{
		"11.1": {
			OID:    ".1.3.6.1.2.1.47.1.1.1.1.11.1",
			Index:  "11.1",
			Parent: ".1.3.6.1.2.1.47.1.1.1.1.11",
			Value:  "FCW123",
		},
	}

	result := mapper.Map(values, entry, registry, &config.Defaults{})
	assert.Nil(t, result, "ChassisInventoryMapper must not emit entities directly")
}

func TestExtractInventory_TwoMemberStack(t *testing.T) {
	logger := slog.Default()
	inv := extractInventory(fixtureCisco3850TwoMemberStack(), logger)

	assert.Len(t, inv.Members, 2)
	assert.Equal(t, 1, inv.Members[0].ID)
	assert.Equal(t, "FCW2147L0K3", inv.Members[0].Serial)
	assert.Equal(t, "WS-C3850-48P", inv.Members[0].Model)
	assert.Equal(t, "Switch 1", inv.Members[0].EntName)
	assert.Equal(t, "1", inv.Members[0].EntPhysicalIndex)

	assert.Equal(t, 2, inv.Members[1].ID)
	assert.Equal(t, "FCW2147L0K4", inv.Members[1].Serial)
	assert.Equal(t, "1000", inv.Members[1].EntPhysicalIndex)
}

// TestExtractInventory_WrappedStackContainer covers the Cisco
// StackWise Virtual (and similar) topology where the physical
// chassis(3) rows are NOT at the ENTITY-MIB root but nested inside a
// class=11 (stack) container. extractInventory must traverse
// entPhysicalContainedIn so wrapped chassis still qualify as members.
func TestExtractInventory_WrappedStackContainer(t *testing.T) {
	logger := slog.Default()
	inv := extractInventory(fixtureCiscoCat9400xStackWiseVirtual(), logger)

	assert.Len(t, inv.Members, 2)
	assert.True(t, inv.IsStack())

	// Switch 1 — entPhysicalIndex 2, parentRelPos=1 → derived ID 1.
	assert.Equal(t, 1, inv.Members[0].ID)
	assert.Equal(t, "FXS2238Q0WZ", inv.Members[0].Serial)
	assert.Equal(t, "C9407R", inv.Members[0].Model)
	assert.Equal(t, "Switch 1 Chassis", inv.Members[0].EntName)
	assert.Equal(t, "2", inv.Members[0].EntPhysicalIndex)

	// Switch 2 — entPhysicalIndex 500, parentRelPos=2 → derived ID 2.
	assert.Equal(t, 2, inv.Members[1].ID)
	assert.Equal(t, "FXS2238Q0WG", inv.Members[1].Serial)
	assert.Equal(t, "500", inv.Members[1].EntPhysicalIndex)
}

// TestExtractInventory_ChassisInsideNonStackParentRejected guards the
// wrapped-stack relaxation: a chassis(3) whose parent is anything
// other than class=11 (stack) — e.g. an arbitrary chassis nested in
// another chassis, or a chassis in a container(5) for some vendor
// quirk — must NOT be treated as a stack member. This keeps the
// flat-vs-wrapped distinction explicit.
func TestExtractInventory_ChassisInsideNonStackParentRejected(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		// Parent is class=5 (container), not class=11 (stack).
		".1.3.6.1.2.1.47.1.1.1.1.4.1": {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1": {Value: "5"},
		// Chassis nested inside the container — must be rejected.
		".1.3.6.1.2.1.47.1.1.1.1.4.2":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.5.2":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.2": {Value: "NESTED-CHASSIS"},
	}
	inv := extractInventory(oids, logger)
	assert.Empty(t, inv.Members)
}

// TestExtractInventory_PartialRowDoesNotPanic guards the property
// that a chassis(3) row whose companion columns (containedIn, serial,
// parentRelPos, modelName, entPhysicalName) are missing from `oids`
// is safely skipped rather than panicking. ObjectIDValueMap is
// `map[string]Value` (struct value, not pointer), so a missing key
// returns the zero `Value{}` and `.Value` is the empty string —
// trimSNMPString returns "" and the row falls through the
// containedIn / empty-serial guards without entering the dereference
// path. This is the partial / ACL-filtered SNMP walk scenario flagged
// by the reviewer.
func TestExtractInventory_PartialRowDoesNotPanic(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		// Only entPhysicalClass=3 present for index 7 — all other
		// columns (containedIn, parentRel, name, serial, model) are
		// absent. extractInventory must not panic and must drop this
		// row (no containedIn → not "0", not a stack container).
		".1.3.6.1.2.1.47.1.1.1.1.5.7": {Value: "3"},
		// A second row with class=3 + containedIn but no serial —
		// must hit the "empty serial" drop path, not panic.
		".1.3.6.1.2.1.47.1.1.1.1.5.8": {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.4.8": {Value: "0"},
		// A third row class=3 + containedIn pointing at a class=11
		// parent that is NOT in oids — isStackContainerParent must
		// return false safely and the row must be dropped.
		".1.3.6.1.2.1.47.1.1.1.1.5.9":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.4.9":  {Value: "42"}, // parent index 42 not present
		".1.3.6.1.2.1.47.1.1.1.1.11.9": {Value: "VALID-SERIAL"},
	}
	// Should not panic and should produce an empty inventory.
	assert.NotPanics(t, func() {
		inv := extractInventory(oids, logger)
		assert.Empty(t, inv.Members, "all three partial/orphan rows must be dropped")
	})
}

func TestExtractInventory_StandaloneSingleChassis(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC1234ABCD"},
		".1.3.6.1.2.1.47.1.1.1.1.13.1": {Value: "ISR4321"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 1)
	assert.Equal(t, 1, inv.Members[0].ID)
	assert.Equal(t, "FOC1234ABCD", inv.Members[0].Serial)
}

func TestExtractInventory_NonChassisRowsIgnored(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		// Module (class=9) — must NOT show up as a member.
		".1.3.6.1.2.1.47.1.1.1.1.4.5":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.5.5":  {Value: "9"},
		".1.3.6.1.2.1.47.1.1.1.1.11.5": {Value: "MOD-SERIAL"},
		// True chassis (class=3, containedIn=0).
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "REAL-CHASSIS"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 1)
	assert.Equal(t, "REAL-CHASSIS", inv.Members[0].Serial)
}

func TestExtractInventory_EmptySerialDropped(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":     {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":     {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: ""},
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "VALID"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 1)
	assert.Equal(t, "VALID", inv.Members[0].Serial)
}

// TestExtractInventory_NULPaddedStringsTrimmed guards the regression
// flagged by Codex/Copilot PR review: ENTITY-MIB DisplayStrings are
// often NUL-padded by vendor agents, but strings.TrimSpace doesn't
// strip \x00, so a NUL-padded "FOC1234\x00" would compare unequal to
// "FOC1234" returned by another agent — breaking dedup and stable
// matching against NetBox across runs.
func TestExtractInventory_NULPaddedStringsTrimmed(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		// Two chassis rows; serial #2 is NUL-padded but identical to #1
		// after trim — dedup must collapse them via duplicate-serial.
		".1.3.6.1.2.1.47.1.1.1.1.4.1":     {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":     {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":     {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1":     {Value: "Switch 1\x00"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: "FOC1234"},
		".1.3.6.1.2.1.47.1.1.1.1.13.1":    {Value: "WS-C3850-48P\x00"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "FOC1234\x00"},
	}
	inv := extractInventory(oids, logger)
	// One survivor (dup-serial collapses two members).
	assert.Len(t, inv.Members, 1)
	m := inv.Members[0]
	assert.Equal(t, "FOC1234", m.Serial, "serial must be NUL-stripped, not \"FOC1234\\x00\"")
	assert.Equal(t, "Switch 1", m.EntName, "entName must be NUL-stripped")
	assert.Equal(t, "WS-C3850-48P", m.Model, "model must be NUL-stripped")
}

// TestExtractInventory_NULOnlySerialDropped guards the edge case where
// a vendor returns a serial consisting only of NUL bytes — must be
// dropped just like an empty-string serial.
func TestExtractInventory_NULOnlySerialDropped(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":     {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":     {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: "\x00\x00\x00"}, // NUL-only
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "VALID"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 1)
	assert.Equal(t, "VALID", inv.Members[0].Serial)
}

// TestTrimSNMPString pins the contract: surrounding whitespace AND every
// NUL byte (including interior ones) are removed. NetBox/PostgreSQL rejects
// NUL anywhere in a text field, so a trailing-only trim is not enough.
func TestTrimSNMPString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"clean passthrough", "GigabitEthernet0/1", "GigabitEthernet0/1"},
		{"trailing nul pad", "Video\x00", "Video"},
		{"trailing nul run", "FOC1234\x00\x00\x00", "FOC1234"},
		{"leading and trailing space", "  Eng  ", "Eng"},
		{"interior nul", "Video\x00Backup", "VideoBackup"},
		{"interior nul plus pad", "A\x00B\x00", "AB"},
		{"nul only", "\x00\x00", ""},
		{"empty", "", ""},
		{"surrounding ws and interior nul", " a\x00b \t", "ab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, trimSNMPString(tc.in))
		})
	}
}

func TestDeriveMemberID_ParentRelPosWins(t *testing.T) {
	m := ChassisMember{ParentRelPos: 5, EntName: "Switch 9"}
	assert.Equal(t, 5, deriveMemberID(m, 0))
}

func TestDeriveMemberID_NameTrailingIntFallback(t *testing.T) {
	cases := []struct {
		entName string
		want    int
	}{
		{"Switch 1", 1},
		{"Switch 2", 2},
		{"FPC 0", 0},
		{"Member 7", 7},
		{"Virtual Chassis Member 3", 3},
		{"Chassis 12", 12},
	}
	for _, tc := range cases {
		t.Run(tc.entName, func(t *testing.T) {
			m := ChassisMember{ParentRelPos: 0, EntName: tc.entName}
			assert.Equal(t, tc.want, deriveMemberID(m, 99))
		})
	}
}

func TestDeriveMemberID_FinalIndexFallback(t *testing.T) {
	// parentRelPos=0, EntName has no trailing int → use ordinal fallback.
	m := ChassisMember{ParentRelPos: 0, EntName: "Chassis"}
	assert.Equal(t, 4, deriveMemberID(m, 4))
}

func TestExtractInventory_JunosFPC_TrailingIntFromName(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		// 3 FPC members with parentRelPos=0 (Junos doesn't populate it).
		// IDs must come from "FPC 0", "FPC 1", "FPC 2" trailing-int parse.
		".1.3.6.1.2.1.47.1.1.1.1.4.10":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.10":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.7.10":  {Value: "FPC 0"},
		".1.3.6.1.2.1.47.1.1.1.1.11.10": {Value: "BR0001"},
		".1.3.6.1.2.1.47.1.1.1.1.4.20":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.20":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.7.20":  {Value: "FPC 1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.20": {Value: "BR0002"},
		".1.3.6.1.2.1.47.1.1.1.1.4.30":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.30":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.7.30":  {Value: "FPC 2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.30": {Value: "BR0003"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 3)
	assert.Equal(t, 0, inv.Members[0].ID, "FPC 0 -> id 0")
	assert.Equal(t, 1, inv.Members[1].ID, "FPC 1 -> id 1")
	assert.Equal(t, 2, inv.Members[2].ID, "FPC 2 -> id 2")
}

func TestExtractInventory_DuplicateID_DifferentSerials_RefusesEmission(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":     {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":     {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":     {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: "SERIAL-A"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "1"}, // same id, different serial
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "SERIAL-B"},
	}
	inv := extractInventory(oids, logger)
	// Ambiguous: BOTH members dropped, IDs tracked for routing warns.
	assert.Empty(t, inv.Members)
	assert.Contains(t, inv.DroppedIDs, 1)
}

func TestExtractInventory_DuplicateSerial_HigherIDDropped(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":     {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":     {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":     {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: "DUP-SERIAL"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "DUP-SERIAL"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 1)
	assert.Equal(t, 1, inv.Members[0].ID)
	assert.Contains(t, inv.DroppedIDs, 2)
}

func TestExtractInventory_DuplicateSerial_SameID_SurvivorNotDropped(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		// Two rows reporting the same serial AND the same parentRelPos.
		".1.3.6.1.2.1.47.1.1.1.1.4.1":     {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":     {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":     {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: "SAME-SERIAL"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "SAME-SERIAL"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 1)
	assert.Equal(t, 1, inv.Members[0].ID)
	// The surviving member's id must NOT be in DroppedIDs — otherwise
	// routing would silently skip its interfaces.
	_, isDropped := inv.DroppedIDs[1]
	assert.False(t, isDropped, "surviving member id must not be in DroppedIDs")
}

func TestExtractInventory_IsStack(t *testing.T) {
	logger := slog.Default()
	assert.False(t, ChassisInventory{}.IsStack(), "empty -> standalone")
	assert.False(t, extractInventory(ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "S"},
	}, logger).IsStack(), "1 member -> standalone")
	assert.True(t, extractInventory(fixtureCisco3850TwoMemberStack(), logger).IsStack())
}

func TestBuildMasterRef_CarriesAllMatcherFields(t *testing.T) {
	master := &diode.Device{
		Name:     strPtr("3850-stack"),
		Serial:   strPtr("FCW2147L0K3"),
		AssetTag: strPtr("ASSET-1"),
		Site:     &diode.Site{Name: strPtr("dc1")},
		Tenant:   &diode.Tenant{Name: strPtr("acme")},
		Role:     &diode.DeviceRole{Name: strPtr("access")},
		DeviceType: &diode.DeviceType{
			Model:        strPtr("WS-C3850-48P"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
		PrimaryIp4: &diode.IPAddress{
			Address: strPtr("10.0.0.1/24"),
			// AssignedObject populated on rich master — MUST be stripped on ref.
			AssignedObject: &diode.Interface{Name: strPtr("Vlan1")},
		},
		// source_match value shape matches policy.setDeviceSourceMatch:
		// the value is a nested diode.Metadata with "netbox_id".
		Metadata: diode.Metadata{"source_match": diode.Metadata{"netbox_id": 42}},
	}

	ref := buildMasterRef(master)

	assert.Equal(t, "3850-stack", *ref.Name)
	assert.Equal(t, "FCW2147L0K3", *ref.Serial)
	assert.Equal(t, "ASSET-1", *ref.AssetTag)
	assert.Equal(t, "dc1", *ref.Site.Name)
	assert.Equal(t, "acme", *ref.Tenant.Name)
	assert.Equal(t, "access", *ref.Role.Name)
	assert.Equal(t, "WS-C3850-48P", *ref.DeviceType.Model)
	assert.NotNil(t, ref.PrimaryIp4)
	assert.Equal(t, "10.0.0.1/24", *ref.PrimaryIp4.Address)
	assert.Nil(t, ref.PrimaryIp4.AssignedObject,
		"primary_ip4.AssignedObject must be nil — breaks IP->Iface->Device cycle")
	assert.Nil(t, ref.VirtualChassis, "non-recursion")
	assert.Nil(t, ref.VcPosition, "VcPosition would only feed unreachable matcher #8")
	assert.Equal(t, diode.Metadata{"netbox_id": 42}, ref.Metadata["source_match"])
}

func TestBuildMasterRef_NilMasterReturnsNil(t *testing.T) {
	assert.Nil(t, buildMasterRef(nil))
}

func TestBuildMasterRef_OmitsUnsetFields(t *testing.T) {
	master := &diode.Device{Name: strPtr("x"), Serial: strPtr("y")}
	ref := buildMasterRef(master)
	assert.Nil(t, ref.AssetTag)
	assert.Nil(t, ref.PrimaryIp4)
	assert.Nil(t, ref.PrimaryIp6)
	assert.Nil(t, ref.Site)
}

func TestBuildMemberDevice_CarriesVcPositionAndMatcherBlock(t *testing.T) {
	master := &diode.Device{
		Name:     strPtr("3850-stack"),
		Site:     &diode.Site{Name: strPtr("dc1")},
		Tenant:   &diode.Tenant{Name: strPtr("acme")},
		Role:     &diode.DeviceRole{Name: strPtr("access")},
		Platform: &diode.Platform{Name: strPtr("ios-xe")},
		AssetTag: strPtr("MASTER-ASSET"),
		DeviceType: &diode.DeviceType{
			Model:        strPtr("WS-C3850-48P"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	masterRef := buildMasterRef(master)
	member := ChassisMember{ID: 2, Serial: "FCW2147L0K4", Model: "WS-C3850-12X"}

	dev := buildMemberDevice(master, member, masterRef, "3850-stack")

	assert.Equal(t, "3850-stack-2", *dev.Name)
	assert.Equal(t, "FCW2147L0K4", *dev.Serial)
	assert.Nil(t, dev.AssetTag, "AssetTag must be CLEARED on members")
	assert.Equal(t, int64(2), *dev.VcPosition)
	assert.NotNil(t, dev.VirtualChassis)
	assert.Equal(t, "3850-stack", *dev.VirtualChassis.Name)
	assert.NotNil(t, dev.VirtualChassis.Master)
	assert.Equal(t, "3850-stack", *dev.VirtualChassis.Master.Name)
	assert.Nil(t, dev.VirtualChassis.Master.VirtualChassis, "non-recursion")

	assert.Equal(t, "dc1", *dev.Site.Name)
	assert.Equal(t, "acme", *dev.Tenant.Name)
	assert.Equal(t, "access", *dev.Role.Name)
	assert.Equal(t, "ios-xe", *dev.Platform.Name)

	// Per-member DeviceType from entPhysicalModelName, not master's.
	assert.Equal(t, "WS-C3850-12X", *dev.DeviceType.Model)
}

// TestBuildMemberDevice_InheritsMasterLocation guards finding #16:
// when DeviceMapper.applyDefaults attaches `defaults.location` to the
// master Device (which happens BEFORE TranslateAsStack builds the
// non-master member devices), every member must also carry that
// Location. Without this propagation, members would be ingested into
// NetBox without the operator-configured location while the master /
// standalone case has it — silently splitting one logical stack
// across multiple NetBox locations.
func TestBuildMemberDevice_InheritsMasterLocation(t *testing.T) {
	site := &diode.Site{Name: strPtr("dc1")}
	loc := &diode.Location{Name: strPtr("rack-42"), Site: site}
	master := &diode.Device{
		Name:     strPtr("stack"),
		Site:     site,
		Location: loc,
	}
	masterRef := buildMasterRef(master)
	member := ChassisMember{ID: 2, Serial: "X", Model: "ModelB"}

	dev := buildMemberDevice(master, member, masterRef, "stack")

	require.NotNil(t, dev.Location, "members must inherit master.Location")
	assert.Same(t, loc, dev.Location,
		"Location is pointer-shared with master (mirrors Site/Tenant/Role/Platform sharing)")
	assert.Equal(t, "rack-42", *dev.Location.Name)
}

func TestBuildMemberDevice_FallsBackToMasterDeviceTypeWhenModelEmpty(t *testing.T) {
	master := &diode.Device{
		Name: strPtr("stack"),
		DeviceType: &diode.DeviceType{
			Model:        strPtr("ModelA"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("VendorA")},
		},
	}
	masterRef := buildMasterRef(master)
	member := ChassisMember{ID: 2, Serial: "X", Model: ""}

	dev := buildMemberDevice(master, member, masterRef, "stack")
	assert.Equal(t, "ModelA", *dev.DeviceType.Model,
		"member device_type falls back to master when entPhysicalModelName is empty")
}

func TestTranslateAsStack_StandaloneSetsSerialAndReturnsUnchangedShape(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("standalone")}
	iface := &diode.Interface{Name: strPtr("Gi0/0/0"), Device: master}
	entities := []diode.Entity{master, iface}
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC0001"},
	}

	out := TranslateAsStack(entities, oids, nil, nil, logger)

	assert.Len(t, out, 2, "shape unchanged on standalone")
	assert.Equal(t, "FOC0001", *master.Serial)
}

func TestTranslateAsStack_TwoMemberStackEmitsVCAndMember(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{
		Name: strPtr("3850-stack.example"),
		Site: &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{
			Model:        strPtr("WS-C3850-48P"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	ifaceM1 := &diode.Interface{Name: strPtr("GigabitEthernet1/0/1"), Device: master}
	ifaceM2 := &diode.Interface{Name: strPtr("GigabitEthernet2/0/1"), Device: master}
	entities := []diode.Entity{master, ifaceM1, ifaceM2}
	// No alias-table coverage in this fixture — ifName parsing drives routing.
	ifIndexByIface := map[*diode.Interface]int{}

	out := TranslateAsStack(entities, fixtureCisco3850TwoMemberStack(), ifIndexByIface, nil, logger)

	// master + VC + 1 member + 2 interfaces = 5
	var vc *diode.VirtualChassis
	var members []*diode.Device
	for _, e := range out {
		switch v := e.(type) {
		case *diode.VirtualChassis:
			vc = v
		case *diode.Device:
			if v != master {
				members = append(members, v)
			}
		}
	}
	assert.NotNil(t, vc)
	assert.Equal(t, "3850-stack.example", *vc.Name)
	assert.Len(t, members, 1)
	assert.Equal(t, "FCW2147L0K4", *members[0].Serial)
	assert.Equal(t, int64(2), *members[0].VcPosition)

	// Master remains plain (no VcPosition, no VirtualChassis).
	assert.Nil(t, master.VcPosition)
	assert.Nil(t, master.VirtualChassis)
	assert.Equal(t, "FCW2147L0K3", *master.Serial,
		"master Serial set from chassis row 1")

	// Interface routing: Gi1/0/1 -> master; Gi2/0/1 -> member.
	assert.Equal(t, master, ifaceM1.Device, "Gi1/0/1 stays on master")
	assert.Equal(t, "3850-stack.example-2", *ifaceM2.Device.Name,
		"Gi2/0/1 routes to member 2")
}

// TestTranslateAsStack_CiscoStackWiseVirtual_EmitsVCAndMember
// validates the end-to-end wrapped-stack path against a real Cisco
// Catalyst 9400X-SVL recording shape: two chassis(3) rows nested
// inside a class=11 (stack) container. Without the wrapped-stack
// relaxation in extractInventory, this test reproduces the bug
// observed in orb-test-lab where TranslateAsStack falls through to
// the single-Device path on real StackWise Virtual hardware.
func TestTranslateAsStack_CiscoStackWiseVirtual_EmitsVCAndMember(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{
		Name: strPtr("c9400x-svl.example"),
		Site: &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{
			Model:        strPtr("C9407R"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	ifaceM1 := &diode.Interface{Name: strPtr("HundredGigE1/0/1"), Device: master}
	ifaceM2 := &diode.Interface{Name: strPtr("HundredGigE2/0/1"), Device: master}
	entities := []diode.Entity{master, ifaceM1, ifaceM2}
	ifIndexByIface := map[*diode.Interface]int{}

	out := TranslateAsStack(entities, fixtureCiscoCat9400xStackWiseVirtual(), ifIndexByIface, nil, logger)

	var vc *diode.VirtualChassis
	var members []*diode.Device
	for _, e := range out {
		switch v := e.(type) {
		case *diode.VirtualChassis:
			vc = v
		case *diode.Device:
			if v != master {
				members = append(members, v)
			}
		}
	}
	assert.NotNil(t, vc, "StackWise Virtual must emit a VirtualChassis")
	assert.Equal(t, "c9400x-svl.example", *vc.Name)
	assert.Len(t, members, 1)
	assert.Equal(t, "FXS2238Q0WG", *members[0].Serial,
		"member device serial comes from the second chassis row")
	assert.Equal(t, int64(2), *members[0].VcPosition)

	// Master gets the lowest-id chassis serial; remains plain (no VC ref).
	assert.Nil(t, master.VcPosition)
	assert.Nil(t, master.VirtualChassis)
	assert.Equal(t, "FXS2238Q0WZ", *master.Serial)

	// Interface routing via ifName parsing.
	assert.Equal(t, master, ifaceM1.Device, "HundredGigE1/0/1 stays on master")
	assert.Equal(t, "c9400x-svl.example-2", *ifaceM2.Device.Name,
		"HundredGigE2/0/1 routes to member 2")
}

func TestTranslateAsStack_DroppedMemberIfaceSkippedWithWarn(t *testing.T) {
	// 3-row inventory with member 2 dropped via duplicate id; an
	// interface named Gi2/0/1 must be EXCLUDED from the output
	// (not silently routed to master).
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("stack"), DeviceType: &diode.DeviceType{Model: strPtr("X")}}
	orphan := &diode.Interface{Name: strPtr("Gi2/0/1"), Device: master}
	memberIface := &diode.Interface{Name: strPtr("Gi3/0/1"), Device: master}
	entities := []diode.Entity{master, orphan, memberIface}

	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "S1"},
		// Two rows both claiming id=2 -> dropped as ambiguous.
		".1.3.6.1.2.1.47.1.1.1.1.4.20":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.20":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.20":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.20": {Value: "S2-A"},
		".1.3.6.1.2.1.47.1.1.1.1.4.30":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.30":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.30":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.30": {Value: "S2-B"},
		// Surviving member 3.
		".1.3.6.1.2.1.47.1.1.1.1.4.40":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.40":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.40":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.40": {Value: "S3"},
	}

	out := TranslateAsStack(entities, oids, nil, nil, logger)

	// Orphan (Gi2/0/1) is excluded.
	for _, e := range out {
		if iface, ok := e.(*diode.Interface); ok {
			assert.NotEqual(t, "Gi2/0/1", *iface.Name,
				"orphaned member-2 port must be skipped, not routed to master")
		}
	}
	// Member-3 port survives.
	found := false
	for _, e := range out {
		if iface, ok := e.(*diode.Interface); ok && *iface.Name == "Gi3/0/1" {
			found = true
		}
	}
	assert.True(t, found, "member-3 port must remain in the output")
}

// TestTranslateAsStack_IPRoutedToMemberViaAssignedObject guards
// finding #12: MapObjectIDsToEntity drops IP-assigned interfaces from
// top-level emission, so member-owned interfaces visible only through
// IP.AssignedObject must still be rerouted from master to member.
func TestTranslateAsStack_IPRoutedToMemberViaAssignedObject(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{
		Name: strPtr("3850-stack.example"),
		DeviceType: &diode.DeviceType{
			Model:        strPtr("WS-C3850-48P"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	// Member-2 iface present only via IP.AssignedObject — NOT as a
	// top-level Interface entity. Today's pipeline strips it from
	// top-level when an IP references it.
	memberIface := &diode.Interface{Name: strPtr("GigabitEthernet2/0/24"), Device: master}
	memberIP := &diode.IPAddress{
		Address:        strPtr("10.0.2.24/24"),
		AssignedObject: memberIface,
	}
	entities := []diode.Entity{master, memberIP}

	out := TranslateAsStack(entities, fixtureCisco3850TwoMemberStack(), nil, nil, logger)

	// The IP survived and its nested Interface.Device now points at member-2.
	var seenIP *diode.IPAddress
	for _, e := range out {
		if ip, ok := e.(*diode.IPAddress); ok {
			seenIP = ip
		}
	}
	assert.NotNil(t, seenIP)
	iface, _ := seenIP.AssignedObject.(*diode.Interface)
	assert.Equal(t, "3850-stack.example-2", *iface.Device.Name,
		"IP.AssignedObject.Interface.Device must be re-pointed to member-2")
}

// TestTranslateAsStack_OrphanIPFiltered guards finding #12: an IP
// assigned to an interface that was skipped (parsed to a dropped
// member id) must NOT be ingested — otherwise NetBox sees an IP
// with a dangling AssignedObject.
func TestTranslateAsStack_OrphanIPFiltered(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("stack"), DeviceType: &diode.DeviceType{Model: strPtr("X")}}
	orphanIface := &diode.Interface{Name: strPtr("Gi2/0/1"), Device: master}
	orphanIP := &diode.IPAddress{
		Address:        strPtr("10.0.0.99/24"),
		AssignedObject: orphanIface,
	}
	entities := []diode.Entity{master, orphanIface, orphanIP}

	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "S1"},
		// Member 2 duplicated -> dropped as ambiguous.
		".1.3.6.1.2.1.47.1.1.1.1.4.20":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.20":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.20":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.20": {Value: "S2-A"},
		".1.3.6.1.2.1.47.1.1.1.1.4.30":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.30":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.30":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.30": {Value: "S2-B"},
		// Real member 3.
		".1.3.6.1.2.1.47.1.1.1.1.4.40":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.40":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.40":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.40": {Value: "S3"},
	}

	out := TranslateAsStack(entities, oids, nil, nil, logger)

	for _, e := range out {
		_, isIP := e.(*diode.IPAddress)
		assert.False(t, isIP, "IP assigned to a skipped (orphan) interface must be filtered")
	}
}

func TestTranslateAsStack_ArubaCX_2MemberVSF(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{
		Name: strPtr("aruba-cx-stack"),
		Site: &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{
			Model:        strPtr("Aruba-6300M-48G"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("HPE Aruba")},
		},
	}
	memberIface := &diode.Interface{Name: strPtr("2/1/24"), Device: master}
	entities := []diode.Entity{master, memberIface}

	out := TranslateAsStack(entities, fixtureArubaCX2MemberVSF(), nil, nil, logger)

	var members []*diode.Device
	for _, e := range out {
		if d, ok := e.(*diode.Device); ok && d != master {
			members = append(members, d)
		}
	}
	assert.Len(t, members, 1)
	assert.Equal(t, "SG12346", *members[0].Serial)
	assert.Equal(t, "aruba-cx-stack-2", *memberIface.Device.Name)
}

func TestTranslateAsStack_JunosQFX_4MemberVC(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{
		Name: strPtr("vc-edge-01"),
		Site: &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{
			Model:        strPtr("EX4300-48T"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Juniper")},
		},
	}
	fpc2Iface := &diode.Interface{Name: strPtr("xe-2/0/0"), Device: master}
	entities := []diode.Entity{master, fpc2Iface}

	out := TranslateAsStack(entities, fixtureJunosQFX4MemberVC(), nil, nil, logger)

	var members []*diode.Device
	for _, e := range out {
		if d, ok := e.(*diode.Device); ok && d != master {
			members = append(members, d)
		}
	}
	assert.Len(t, members, 3, "4-member VC -> master + 3 member Devices")

	// Master pinned to lowest id (FPC 0).
	assert.Equal(t, "BR0000000001", *master.Serial)

	// xe-2/0/0 routes to FPC 2 member.
	assert.Equal(t, "vc-edge-01-2", *fpc2Iface.Device.Name)
}

func TestExtractInventory_CarriesAssetTag(t *testing.T) {
	logger := slog.Default()
	oids := ObjectIDValueMap{
		// Row 1: tag present (with NUL padding to prove trimming).
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "SER-1"},
		".1.3.6.1.2.1.47.1.1.1.1.15.1": {Value: "ASSET-001 \x00\x00"},
		// Row 2: no .15 column at all -> empty tag.
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "SER-2"},
	}
	inv := extractInventory(oids, logger)
	assert.Len(t, inv.Members, 2)
	assert.Equal(t, "ASSET-001", inv.Members[0].AssetTag, "NUL/whitespace padding trimmed")
	assert.Equal(t, "", inv.Members[1].AssetTag, "absent column -> empty tag")
}

func TestAssetTagWalkGating(t *testing.T) {
	mappings := []config.MappingEntry{
		{OID: "1.3.6.1.2.1.47.1.1.1.1.15", Entity: "chassis_asset", Field: "assetID"},
		{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
	}
	logger := slog.Default()

	off, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{})
	require.NoError(t, err)
	_, walked := off.GenericObjectIDs()["1.3.6.1.2.1.47.1.1.1.1.15"]
	assert.False(t, walked, "asset tag column must not be walked with discover_asset_tags off")

	enabled := true
	on, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{DiscoverAssetTags: &enabled})
	require.NoError(t, err)
	_, walked = on.GenericObjectIDs()["1.3.6.1.2.1.47.1.1.1.1.15"]
	assert.True(t, walked, "asset tag column must be walked with discover_asset_tags on")
}

// TestAssetTagWalkGating_ChildEntry mirrors TestAssetTagWalkGating but uses the
// production child-entry shape: the chassis_asset column (.15) is a child of
// a chassis_inventory parent block (parent OID 1.3.6.1.2.1.47.1.1.1), which
// is the path exercised by objectIDsForVendor when MappingEntries are present.
//
// Assertions:
//   - with Options{} (off): .15 is ABSENT, sibling .11 (serial) IS present
//   - with DiscoverAssetTags: &true: .15 IS present
func TestAssetTagWalkGating_ChildEntry(t *testing.T) {
	const (
		parentOID   = "1.3.6.1.2.1.47.1.1.1"
		serialOID   = ".1.3.6.1.2.1.47.1.1.1.1.11"
		assetTagOID = ".1.3.6.1.2.1.47.1.1.1.1.15"
	)

	// Mirror the chassis_inventory parent + child block from policy/mapping.yaml.
	mappings := []config.MappingEntry{
		{
			OID: parentOID, Entity: "chassis_inventory", Field: "_id", IdentifierSize: 2,
			MappingEntries: []config.MappingEntry{
				{OID: serialOID, Entity: "chassis_inventory", Field: "serialNumber"},
				{OID: assetTagOID, Entity: "chassis_asset", Field: "assetID"},
			},
		},
	}
	logger := slog.Default()

	// Case 1: discover_asset_tags off (default Options{}).
	off, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{})
	require.NoError(t, err)
	gen := off.GenericObjectIDs()
	_, hasAsset := gen[assetTagOID]
	assert.False(t, hasAsset,
		"asset tag child column must not be walked with discover_asset_tags off")
	_, hasSerial := gen[serialOID]
	assert.True(t, hasSerial,
		"sibling chassis_inventory serial column must remain present when asset tag is off")

	// Case 2: discover_asset_tags on.
	enabled := true
	on, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{DiscoverAssetTags: &enabled})
	require.NoError(t, err)
	gen = on.GenericObjectIDs()
	_, hasAsset = gen[assetTagOID]
	assert.True(t, hasAsset,
		"asset tag child column must be walked with discover_asset_tags on")
}

// TestAssetTagWalkGating_VendorEntry tests the vendor-scoped path through
// objectIDsForVendor: a chassis_asset child entry under a vendor-scoped
// parent must be excluded from VendorObjectIDs when discover_asset_tags is
// off, and included when the option is on.
func TestAssetTagWalkGating_VendorEntry(t *testing.T) {
	const (
		vendor      = "cisco"
		parentOID   = "1.3.6.1.2.1.47.1.1.1"
		serialOID   = ".1.3.6.1.2.1.47.1.1.1.1.11"
		assetTagOID = ".1.3.6.1.2.1.47.1.1.1.1.15"
	)

	// Vendor-scoped chassis_inventory parent with a chassis_asset child.
	mappings := []config.MappingEntry{
		{
			OID: parentOID, Entity: "chassis_inventory", Field: "_id", IdentifierSize: 2,
			Vendor: vendor,
			MappingEntries: []config.MappingEntry{
				{OID: serialOID, Entity: "chassis_inventory", Field: "serialNumber"},
				{OID: assetTagOID, Entity: "chassis_asset", Field: "assetID"},
			},
		},
	}
	logger := slog.Default()

	// Case 1: discover_asset_tags off (default Options{}).
	off, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{})
	require.NoError(t, err)
	vend := off.VendorObjectIDs(vendor)
	_, hasAsset := vend[assetTagOID]
	assert.False(t, hasAsset,
		"vendor asset tag child column must not be walked with discover_asset_tags off")
	_, hasSerial := vend[serialOID]
	assert.True(t, hasSerial,
		"sibling chassis_inventory serial column must remain present when asset tag is off")

	// Case 2: discover_asset_tags on.
	enabled := true
	on, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{DiscoverAssetTags: &enabled})
	require.NoError(t, err)
	vend = on.VendorObjectIDs(vendor)
	_, hasAsset = vend[assetTagOID]
	assert.True(t, hasAsset,
		"vendor asset tag child column must be walked with discover_asset_tags on")
}

// stubManufacturers and stubDeviceLookup satisfy the data.ManufacturerRetriever
// and data.DeviceRetriever interfaces with harmless no-op implementations so
// that chassis tests can run through the full DeviceMapper code path without
// loading the real data files.
type stubManufacturers struct{}

func (stubManufacturers) GetManufacturer(_ string) (string, error) { return "Unknown", nil }

type stubDeviceLookup struct{}

func (stubDeviceLookup) GetDevice(_ string) (string, error) { return "", nil }
func (stubDeviceLookup) GetDeviceModel(_ string, _ map[string]string) (string, error) {
	return "", nil
}

// newTestMappingConfig reads the production mapping.yaml and builds a
// *Config using the same call path as the runner.
func newTestMappingConfig(t *testing.T, logger *slog.Logger) *Config {
	t.Helper()
	data, err := os.ReadFile("../policy/mapping.yaml")
	require.NoError(t, err, "read ../policy/mapping.yaml")
	var mc config.Mapping
	require.NoError(t, yaml.Unmarshal(data, &mc), "unmarshal mapping.yaml")
	cfg, err := NewConfig(mc.Entries, logger, stubManufacturers{}, stubDeviceLookup{}, &config.Defaults{}, config.Options{})
	require.NoError(t, err, "NewConfig from production mapping.yaml")
	return cfg
}

// TestTranslateAsStack_Idempotent_ThroughFullMapperPipeline runs the full
// MapObjectIDsToEntity → TranslateAsStack pipeline twice on identical OID
// input and asserts that both runs produce byte-equivalent proto output.
// This catches nondeterminism in either stage (Go-map iteration,
// pointer reuse, etc.).
func TestTranslateAsStack_Idempotent_ThroughFullMapperPipeline(t *testing.T) {
	logger := slog.Default()

	// Build a complete OID map: chassis inventory + ifTable rows so
	// MapObjectIDsToEntity emits Devices and Interfaces, then
	// TranslateAsStack rewrites them.
	//
	// IdentifierSize must match what the real walker sets: the runner
	// calls mappingConfig.GenericObjectIDs() which returns identifierSize=1
	// for every OID (child entries with IdentifierSize==0 default to 1).
	// Without this the scalar device OIDs and the ifTable OIDs all group
	// into the same index bucket (index=""), causing nondeterministic entity
	// count depending on which mapping entry wins the bucket.
	build := func() ObjectIDValueMap {
		oids := fixtureCisco3850TwoMemberStack()
		// Patch sysName and sysObjectID (from the base fixture) to use
		// IdentifierSize=1 so they group under index "0" (device bucket).
		for k, v := range oids {
			switch k {
			case ".1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.2.0":
				v.IdentifierSize = 1
				oids[k] = v
			}
		}
		// Minimal ifTable: ifIndex 10101 = Gi1/0/1, 10201 = Gi2/0/1.
		// IdentifierSize=1 groups each by trailing ifIndex.
		oids[".1.3.6.1.2.1.2.2.1.2.10101"] = Value{Value: "GigabitEthernet1/0/1", IdentifierSize: 1}
		oids[".1.3.6.1.2.1.2.2.1.3.10101"] = Value{Value: "6", IdentifierSize: 1}
		oids[".1.3.6.1.2.1.2.2.1.2.10201"] = Value{Value: "GigabitEthernet2/0/1", IdentifierSize: 1}
		oids[".1.3.6.1.2.1.2.2.1.3.10201"] = Value{Value: "6", IdentifierSize: 1}
		return oids
	}

	run := func() []diode.Entity {
		cfg := newTestMappingConfig(t, logger)
		mapper := NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")
		oids := build()
		ents := mapper.MapObjectIDsToEntity(oids)
		ifIdx := mapper.InterfacesByIfIndex()
		return TranslateAsStack(ents, oids, ifIdx, nil, logger)
	}

	a := run()
	b := run()

	assert.Equal(t, len(a), len(b), "entity count must be deterministic")
	for i := range a {
		if i >= len(b) {
			break
		}
		assert.IsType(t, a[i], b[i], "entity %d type mismatch", i)
	}
	marshalOpts := proto.MarshalOptions{Deterministic: true}
	for i := range a {
		if i >= len(b) {
			break
		}
		ab, err := marshalOpts.Marshal(a[i].ConvertToProtoMessage())
		require.NoError(t, err, "marshal a[%d]", i)
		bb, err := marshalOpts.Marshal(b[i].ConvertToProtoMessage())
		require.NoError(t, err, "marshal b[%d]", i)
		assert.Equal(t, ab, bb,
			"entity %d proto bytes differ — nondeterminism somewhere in MapObjectIDsToEntity or TranslateAsStack", i)
	}
}

// TestTranslateAsStack_AliasTableDroppedMemberSkipsWithWarn exercises the
// full path: entAliasMappingTable entry → dropped chassis row →
// skip-with-warn (interface excluded from output rather than mis-routed
// to master). Driven by the scenario from Fix 2 where a duplicate-serial
// drop removes the chassis row from memberByEntIdx but the alias table
// still points at its entPhysicalIndex.
func TestTranslateAsStack_AliasTableDroppedMemberSkipsWithWarn(t *testing.T) {
	// 3-member OID inventory: members 1 and 3 survive; member 2 is
	// dropped via duplicate serial. An alias entry maps ifIndex 99 to
	// the dropped entPhysicalIndex 1000 (member 2); another maps
	// ifIndex 10 to surviving entPhysicalIndex 1 (member 1).
	// This exercises the full path: alias-table → dropped chassis →
	// skip-with-warn, rather than mis-routing to master.
	master := &diode.Device{
		Name:       strPtr("dup-serial-stack"),
		DeviceType: &diode.DeviceType{Model: strPtr("WS-C3850-48P")},
	}
	droppedIface := &diode.Interface{Name: strPtr("Gi2/0/24"), Device: master}
	survivorIface := &diode.Interface{Name: strPtr("Gi1/0/1"), Device: master}
	entities := []diode.Entity{master, droppedIface, survivorIface}

	oids := ObjectIDValueMap{
		// Member 1 (entPhysicalIndex=1) — survivor.
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "SERIAL-A"},
		// Member 2 (entPhysicalIndex=1000) — dropped (dup serial of member 1).
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "SERIAL-A"}, // dup → member 2 dropped
		// Member 3 (entPhysicalIndex=2000) — survivor (distinct serial).
		".1.3.6.1.2.1.47.1.1.1.1.4.2000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.2000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.2000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.2000": {Value: "SERIAL-C"},
		// Alias: dropped entPhysicalIndex 1000 → ifIndex 99.
		".1.3.6.1.2.1.47.1.3.2.1.2.1000.0": {Value: ".1.3.6.1.2.1.2.2.1.1.99"},
		// Alias: surviving entPhysicalIndex 1 → ifIndex 10.
		".1.3.6.1.2.1.47.1.3.2.1.2.1.0": {Value: ".1.3.6.1.2.1.2.2.1.1.10"},
	}

	// Build ifIndexByIface map so alias routing is exercised.
	ifIndexByIface := map[*diode.Interface]int{
		droppedIface:  99,
		survivorIface: 10,
	}

	warnLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	out := TranslateAsStack(entities, oids, ifIndexByIface, nil, warnLogger)

	// droppedIface (Gi2/0/24, ifIndex 99 → dropped member 2) must be absent.
	for _, e := range out {
		if iface, ok := e.(*diode.Interface); ok {
			assert.NotEqual(t, "Gi2/0/24", strDeref(iface.Name),
				"interface aliased to dropped chassis row must be skipped, not routed to master")
		}
	}

	// survivorIface (Gi1/0/1, ifIndex 10 → surviving member 1 = master) must be present.
	var found bool
	for _, e := range out {
		if iface, ok := e.(*diode.Interface); ok && strDeref(iface.Name) == "Gi1/0/1" {
			found = true
		}
	}
	assert.True(t, found, "interface aliased to surviving chassis row must remain in output")
}

func TestResolveAssetTags_HappyPathAndValidation(t *testing.T) {
	logger := slog.Default()
	long := strings.Repeat("x", 51)
	members := []ChassisMember{
		{ID: 1, AssetTag: "ASSET-001"},
		{ID: 2, AssetTag: ""},   // empty -> absent from result
		{ID: 3, AssetTag: long}, // >50 runes -> warn + skip
	}
	tags := resolveAssetTags(members, "", logger)
	assert.Equal(t, map[int]string{1: "ASSET-001"}, tags)
}

func TestResolveAssetTags_DuplicatesSuppressedEverywhere(t *testing.T) {
	logger := slog.Default()
	members := []ChassisMember{
		{ID: 1, AssetTag: "DUP"},
		{ID: 2, AssetTag: "DUP"},
		{ID: 3, AssetTag: "UNIQUE"},
	}
	tags := resolveAssetTags(members, "", logger)
	assert.Equal(t, map[int]string{3: "UNIQUE"}, tags,
		"a tag shared by two chassis rows must be dropped from both")
}

func TestResolveAssetTags_DefaultsCollisionSuppressed(t *testing.T) {
	logger := slog.Default()
	members := []ChassisMember{
		{ID: 1, AssetTag: "FROM-DEFAULTS"},
		{ID: 2, AssetTag: "OK"},
	}
	tags := resolveAssetTags(members, "FROM-DEFAULTS", logger)
	assert.Equal(t, map[int]string{2: "OK"}, tags,
		"a row tag equal to the operator-supplied defaults tag must be dropped")
}

func TestResolveAssetTags_GarbageValuesSuppressed(t *testing.T) {
	logger := slog.Default()
	members := []ChassisMember{
		{ID: 1, AssetTag: "ASSET\x07001"},                  // embedded control byte
		{ID: 2, AssetTag: string([]byte{0xff, 0xfe, 'A'})}, // invalid UTF-8
		{ID: 3, AssetTag: "ASSET-OK"},
	}
	tags := resolveAssetTags(members, "", logger)
	assert.Equal(t, map[int]string{3: "ASSET-OK"}, tags,
		"control bytes and invalid UTF-8 must be suppressed")
}

func TestResolveAssetTags_PlaceholderValuesSuppressed(t *testing.T) {
	logger := slog.Default()
	members := []ChassisMember{
		{ID: 1, AssetTag: "UNKNOWN"},
		{ID: 2, AssetTag: "n/a"},
		{ID: 3, AssetTag: "None"},
		{ID: 4, AssetTag: "0"},
		{ID: 5, AssetTag: "Not Specified"},
		{ID: 6, AssetTag: "ASSET-REAL"},
	}
	tags := resolveAssetTags(members, "", logger)
	assert.Equal(t, map[int]string{6: "ASSET-REAL"}, tags,
		"well-known placeholder values must never become asset tags")
}

func TestResolveAssetTags_PlaceholderPrefixNotSuppressed(t *testing.T) {
	logger := slog.Default()
	members := []ChassisMember{
		{ID: 1, AssetTag: "NA1234"},      // starts like a placeholder but isn't one
		{ID: 2, AssetTag: "UNKNOWN-007"}, // exact match only
	}
	tags := resolveAssetTags(members, "", logger)
	assert.Equal(t, map[int]string{1: "NA1234", 2: "UNKNOWN-007"}, tags,
		"placeholder matching must be exact, not prefix-based")
}

func TestTranslateAsStack_StandaloneSetsAssetTag(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("standalone")}
	entities := []diode.Entity{master}
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC0001"},
		".1.3.6.1.2.1.47.1.1.1.1.15.1": {Value: "ASSET-STANDALONE"},
	}

	TranslateAsStack(entities, oids, nil, nil, logger)

	require.NotNil(t, master.AssetTag)
	assert.Equal(t, "ASSET-STANDALONE", *master.AssetTag)
}

func TestTranslateAsStack_StandaloneDefaultsAssetTagWins(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("standalone"), AssetTag: strPtr("OPERATOR-TAG")}
	entities := []diode.Entity{master}
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC0001"},
		".1.3.6.1.2.1.47.1.1.1.1.15.1": {Value: "WIRE-TAG"},
	}

	TranslateAsStack(entities, oids, nil, nil, logger)

	assert.Equal(t, "OPERATOR-TAG", *master.AssetTag,
		"defaults.asset_tag must not be overwritten by entPhysicalAssetID")
}

func TestTranslateAsStack_StandaloneEmptyAssetTagLeavesUnset(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("standalone")}
	entities := []diode.Entity{master}
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC0001"},
		".1.3.6.1.2.1.47.1.1.1.1.15.1": {Value: "\x00\x00"},
	}

	TranslateAsStack(entities, oids, nil, nil, logger)

	assert.Nil(t, master.AssetTag, "NUL-only entPhysicalAssetID must leave AssetTag unset")
}

func TestTranslateAsStack_StackPerMemberAssetTags(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{
		Name: strPtr("3850-stack.example"),
		DeviceType: &diode.DeviceType{
			Model:        strPtr("WS-C3850-48P"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	entities := []diode.Entity{master}
	oids := fixtureCisco3850TwoMemberStack()
	// Per-row tags layered onto the shared fixture (indices 1 and 1000).
	oids[".1.3.6.1.2.1.47.1.1.1.1.15.1"] = Value{Value: "ASSET-M1"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.15.1000"] = Value{Value: "ASSET-M2"}

	out := TranslateAsStack(entities, oids, map[*diode.Interface]int{}, nil, logger)

	var members []*diode.Device
	var vc *diode.VirtualChassis
	for _, e := range out {
		switch v := e.(type) {
		case *diode.VirtualChassis:
			vc = v
		case *diode.Device:
			if v != master {
				members = append(members, v)
			}
		}
	}
	require.NotNil(t, master.AssetTag)
	assert.Equal(t, "ASSET-M1", *master.AssetTag, "master gets its own chassis row's tag")
	require.NotNil(t, vc)
	require.NotNil(t, vc.Master)
	require.NotNil(t, vc.Master.AssetTag)
	assert.Equal(t, "ASSET-M1", *vc.Master.AssetTag,
		"masterRef must carry the same matcher fields as the rich master")
	require.Len(t, members, 1)
	require.NotNil(t, members[0].AssetTag)
	assert.Equal(t, "ASSET-M2", *members[0].AssetTag, "member gets its own per-row tag")
}

func TestTranslateAsStack_StackDuplicateAssetTagsSuppressed(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("3850-stack.example")}
	entities := []diode.Entity{master}
	oids := fixtureCisco3850TwoMemberStack()
	oids[".1.3.6.1.2.1.47.1.1.1.1.15.1"] = Value{Value: "SAME"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.15.1000"] = Value{Value: "SAME"}

	out := TranslateAsStack(entities, oids, map[*diode.Interface]int{}, nil, logger)

	assert.Nil(t, master.AssetTag, "duplicate tag must be suppressed on master")
	for _, e := range out {
		if d, ok := e.(*diode.Device); ok && d != master {
			assert.Nil(t, d.AssetTag, "duplicate tag must be suppressed on members")
		}
	}
}

func TestTranslateAsStack_StackMemberTagCollidingWithDefaultsSuppressed(t *testing.T) {
	logger := slog.Default()
	master := &diode.Device{Name: strPtr("3850-stack.example"), AssetTag: strPtr("OPERATOR-TAG")}
	entities := []diode.Entity{master}
	oids := fixtureCisco3850TwoMemberStack()
	// Member 2's wire tag equals the operator-supplied defaults tag on
	// the master -> must be suppressed to avoid matcher collision.
	oids[".1.3.6.1.2.1.47.1.1.1.1.15.1000"] = Value{Value: "OPERATOR-TAG"}

	out := TranslateAsStack(entities, oids, map[*diode.Interface]int{}, nil, logger)

	assert.Equal(t, "OPERATOR-TAG", *master.AssetTag, "defaults tag preserved on master")
	for _, e := range out {
		if d, ok := e.(*diode.Device); ok && d != master {
			assert.Nil(t, d.AssetTag, "member tag equal to defaults tag must be suppressed")
		}
	}
}

// TestResolveAssetTags_MasterRowAgreementIsNotCollision: when
// members[0] (the master row, sorted by ID) carries the same tag as
// masterTag, that is agreement with the operator's configured default — not
// a collision. The tag must be absent from the result (it's already on the
// master), but the function must NOT warn-log it as "collides with defaults
// asset_tag". Other members sharing masterTag still get the suppression.
func TestResolveAssetTags_MasterRowAgreementIsNotCollision(t *testing.T) {
	logger := slog.Default()
	// members[0] (lowest ID) carries the same tag as masterTag — agreement.
	// members[1] carries a different tag — should survive.
	// members[2] also carries masterTag — that's a genuine collision.
	members := []ChassisMember{
		{ID: 1, AssetTag: "OPERATOR-TAG"},
		{ID: 2, AssetTag: "MEMBER-OWN"},
		{ID: 3, AssetTag: "OPERATOR-TAG"},
	}
	tags := resolveAssetTags(members, "OPERATOR-TAG", logger)
	// members[0] and members[2] are both suppressed; only members[1] survives.
	assert.Equal(t, map[int]string{2: "MEMBER-OWN"}, tags,
		"master-row agreement and non-master collision both remove the tag; unique member tag survives")
}

// TestResolveAssetTags_AllEmptyReturnsNil guards the Fix 3/5 early-return:
// when every member has an empty AssetTag, resolveAssetTags must return nil
// (not an empty map) so the caller can short-circuit without allocating.
func TestResolveAssetTags_AllEmptyReturnsNil(t *testing.T) {
	logger := slog.Default()
	members := []ChassisMember{
		{ID: 1, AssetTag: ""},
		{ID: 2, AssetTag: ""},
	}
	tags := resolveAssetTags(members, "", logger)
	assert.Nil(t, tags, "all-empty input must return nil, not an empty map")
}

// TestTranslateAsStack_StandaloneDefaultsTagAgreement guards Fix 2 at the
// TranslateAsStack level: when defaults.asset_tag == entPhysicalAssetID for
// the single chassis row, the master keeps the defaults tag and the function
// does not overwrite it with a duplicate.
func TestTranslateAsStack_StandaloneDefaultsTagAgreement(t *testing.T) {
	logger := slog.Default()
	// Operator already set OPERATOR-TAG via defaults. Wire returns the same value.
	master := &diode.Device{Name: strPtr("standalone"), AssetTag: strPtr("OPERATOR-TAG")}
	entities := []diode.Entity{master}
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC0001"},
		".1.3.6.1.2.1.47.1.1.1.1.15.1": {Value: "OPERATOR-TAG"},
	}

	TranslateAsStack(entities, oids, nil, nil, logger)

	require.NotNil(t, master.AssetTag)
	assert.Equal(t, "OPERATOR-TAG", *master.AssetTag,
		"defaults tag must survive when wire tag agrees; master.AssetTag != nil guards the if check")
}

// TestTranslateAsStack_ClaimRejectionSuppressesTag verifies that a
// claimAssetTag callback returning false suppresses the tag application
// without affecting other fields.
//
// Case 1: standalone device — valid wire tag, claimer always returns
// false → master.AssetTag must remain nil.
//
// Case 2: two-member stack — claimer rejects only the member tag
// "ASSET-M2" → master keeps its own tag, member emitted without one.
func TestTranslateAsStack_ClaimRejectionSuppressesTag(t *testing.T) {
	t.Run("standalone_claimer_rejects", func(t *testing.T) {
		logger := slog.Default()
		master := &diode.Device{Name: strPtr("standalone")}
		entities := []diode.Entity{master}
		oids := ObjectIDValueMap{
			".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
			".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
			".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC-STANDALONE"},
			".1.3.6.1.2.1.47.1.1.1.1.15.1": {Value: "ASSET-STANDALONE"},
		}
		alwaysReject := func(_ string) bool { return false }

		TranslateAsStack(entities, oids, nil, alwaysReject, logger)

		assert.Nil(t, master.AssetTag, "claimer returning false must suppress standalone tag")
	})

	t.Run("stack_member_tag_rejected", func(t *testing.T) {
		logger := slog.Default()
		master := &diode.Device{
			Name:       strPtr("stack.example"),
			DeviceType: &diode.DeviceType{Model: strPtr("WS-C3850-48P")},
		}
		entities := []diode.Entity{master}
		oids := ObjectIDValueMap{
			// Member 1 (master)
			".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
			".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
			".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "1"},
			".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "SERIAL-M1"},
			".1.3.6.1.2.1.47.1.1.1.1.15.1": {Value: "ASSET-M1"},
			// Member 2
			".1.3.6.1.2.1.47.1.1.1.1.4.2":  {Value: "0"},
			".1.3.6.1.2.1.47.1.1.1.1.5.2":  {Value: "3"},
			".1.3.6.1.2.1.47.1.1.1.1.6.2":  {Value: "2"},
			".1.3.6.1.2.1.47.1.1.1.1.11.2": {Value: "SERIAL-M2"},
			".1.3.6.1.2.1.47.1.1.1.1.15.2": {Value: "ASSET-M2"},
		}
		// Claimer allows ASSET-M1 but rejects ASSET-M2.
		rejectM2 := func(tag string) bool { return tag != "ASSET-M2" }

		out := TranslateAsStack(entities, oids, nil, rejectM2, logger)

		// master (lowest id = 1) must carry ASSET-M1.
		require.NotNil(t, master.AssetTag, "master tag must be set when claimer allows it")
		assert.Equal(t, "ASSET-M1", *master.AssetTag)

		// Member 2 Device must be present but without AssetTag.
		var member2 *diode.Device
		for _, e := range out {
			if d, ok := e.(*diode.Device); ok && d.VcPosition != nil && *d.VcPosition == 2 {
				member2 = d
				break
			}
		}
		require.NotNil(t, member2, "member 2 Device must be emitted")
		assert.Nil(t, member2.AssetTag, "member 2 tag must be suppressed by claimer")
	})
}

// TestTranslateAsStack_DefaultsTagRegisteredWithClaimer: an
// operator-supplied defaults tag on the master must be REGISTERED with
// the claimer even though it is never applied through the discovered
// path — otherwise a different target of the same policy whose wire
// entPhysicalAssetID equals the defaults value could claim it as a
// discovered tag and merge onto this device's NetBox record.
func TestTranslateAsStack_DefaultsTagRegisteredWithClaimer(t *testing.T) {
	logger := slog.Default()

	t.Run("registered_with_chassis_rows", func(t *testing.T) {
		master := &diode.Device{Name: strPtr("standalone"), AssetTag: strPtr("OPERATOR-TAG")}
		entities := []diode.Entity{master}
		oids := ObjectIDValueMap{
			".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
			".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
			".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC-STANDALONE"},
		}
		var claimed []string
		recorder := func(tag string) bool {
			claimed = append(claimed, tag)
			return true
		}

		TranslateAsStack(entities, oids, nil, recorder, logger)

		assert.Contains(t, claimed, "OPERATOR-TAG", "defaults tag must be registered with the claimer")
		assert.Equal(t, "OPERATOR-TAG", *master.AssetTag, "defaults tag stays on the device")
	})

	t.Run("registered_without_chassis_rows", func(t *testing.T) {
		master := &diode.Device{Name: strPtr("no-entity-mib"), AssetTag: strPtr("OPERATOR-TAG")}
		entities := []diode.Entity{master}
		var claimed []string
		recorder := func(tag string) bool {
			claimed = append(claimed, tag)
			return true
		}

		TranslateAsStack(entities, ObjectIDValueMap{}, nil, recorder, logger)

		assert.Contains(t, claimed, "OPERATOR-TAG",
			"defaults tag must be registered even when the device exposes no chassis rows")
	})

	t.Run("defaults_tag_sticks_when_claim_rejected", func(t *testing.T) {
		master := &diode.Device{Name: strPtr("standalone"), AssetTag: strPtr("OPERATOR-TAG")}
		entities := []diode.Entity{master}
		alwaysReject := func(_ string) bool { return false }

		TranslateAsStack(entities, ObjectIDValueMap{}, nil, alwaysReject, logger)

		assert.Equal(t, "OPERATOR-TAG", *master.AssetTag,
			"operator-supplied defaults tag is never stripped; the claimer's warn covers the conflict")
	})
}
