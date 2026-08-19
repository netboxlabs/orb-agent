package mapping

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// TestChassisModuleMapper_MapReturnsNil confirms the mapper accepts
// chassis_module PDUs without producing entities. Module data is
// consumed by TranslateModulesWithAlias later, not by this Map call.
func TestChassisModuleMapper_MapReturnsNil(t *testing.T) {
	logger := slog.Default()
	registry := NewEntityRegistry(logger)
	mapper := &ChassisModuleMapper{logger: logger}

	entry := &Entry{
		Entity: string(ChassisModuleEntityType),
		Field:  "_id",
	}
	// Synthesize one entPhysicalDescr row.
	values := map[ObjectIDIndex]*ObjectIDValue{
		"2.1": {
			OID:    ".1.3.6.1.2.1.47.1.1.1.1.2.1",
			Index:  "2.1",
			Parent: ".1.3.6.1.2.1.47.1.1.1.1.2",
			Value:  "Linecard-1",
		},
	}

	result := mapper.Map(values, entry, registry, &config.Defaults{})
	assert.Nil(t, result, "ChassisModuleMapper must not emit entities directly")
}

// TestNewModuleInventory_HasEmptyMaps asserts the constructor produces
// a usable zero-value: SubModules ready for keyed writes, Modules and
// EmptyBays untouched (nil slices append fine).
func TestNewModuleInventory_HasEmptyMaps(t *testing.T) {
	inv := newModuleInventory()
	assert.NotNil(t, inv.SubModules, "newModuleInventory must initialise the SubModules map")
	assert.Empty(t, inv.SubModules)
	assert.Empty(t, inv.Modules, "Modules starts as an empty/nil slice")
	assert.Nil(t, inv.EmptyBays, "EmptyBays is lazily initialised; nil is fine on construct")
}

// TestClassifyModule walks the decision matrix: parent-depth gates
// transceiver/supervisor, PID prefixes pick PSU/Fan, everything else
// falls through to linecard. Both empty inputs → unknown.
func TestClassifyModule(t *testing.T) {
	cases := []struct {
		name            string
		model           string
		vendorType      string
		hasModuleParent bool
		want            ModuleType
	}{
		// Transceiver: under a class=9 module parent AND optic PID.
		{"qsfp-100g-sr4 under linecard", "QSFP-100G-SR4", "", true, ModuleTypeTransceiver},
		{"sfp-10g-lr under linecard", "SFP-10G-LR", "", true, ModuleTypeTransceiver},
		{"x2-10g under linecard", "X2-10GB-SR", "", true, ModuleTypeTransceiver},

		// Supervisor: at chassis level AND SUP pattern.
		{"sup at chassis depth", "C9400-SUP-1", "", false, ModuleTypeSupervisor},
		{"sup2 at chassis depth", "VS-SUP2T-10G", "", false, ModuleTypeSupervisor},

		// Linecard defaults at chassis depth.
		{"linecard PID at chassis depth", "C9400-LC-48U", "", false, ModuleTypeLinecard},
		{"unknown PID at chassis depth", "FOO-BAR-9000", "", false, ModuleTypeLinecard},

		// PSU and Fan classified anywhere.
		{"psu pwr prefix", "PWR-C5-715WAC", "", false, ModuleTypePSU},
		{"psu psu prefix", "PSU-2KW-AC", "", false, ModuleTypePSU},
		{"fan prefix", "FAN-T2", "", false, ModuleTypeFan},

		// Model-prefixed Cisco fan PIDs — the `-FAN` token appears as a
		// suffix or middle token, not a prefix. Common on C9400 chassis.
		{"fan -FAN suffix", "C9400-FAN", "", false, ModuleTypeFan},
		{"fan -FAN middle token", "C9404R-FAN-2", "", false, ModuleTypeFan},

		// Negative: fanless linecard PID embeds the substring "-FAN" but
		// must not be misclassified as a fan tray.
		{"fanless_linecard_not_mismatched_as_fan", "C9400-FANTOM-LC", "", false, ModuleTypeLinecard},

		// Model-prefixed Cisco PSU PIDs — `-PWR-` / `-PSU-` as middle token.
		{"psu -PWR- middle token", "C9404R-PWR-2KW-AC", "", false, ModuleTypePSU},

		// Edge: under module parent but non-optic → linecard (depth alone insufficient).
		{"non-optic under module parent", "WS-X45-FOO", "", true, ModuleTypeLinecard},

		// An optic PID is sufficient on its own: a fixed-port chassis holds
		// its transceivers directly, with no intervening module.
		{"optic PID at chassis depth", "QSFP-100G-SR4", "", false, ModuleTypeTransceiver},

		// VendorType fallback when Model is blank.
		{"vendortype fallback optic", "", "QSFP-100G-LR4", true, ModuleTypeTransceiver},

		// Both blank → unknown.
		{"both blank", "", "", false, ModuleTypeUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyModule(c.model, c.vendorType, c.hasModuleParent)
			assert.Equal(t, c.want, got)
		})
	}
}

// TestExtractModuleInventory_HappyPath asserts top-level modules are
// classified correctly (supervisor + linecard) and the transceiver
// lives in SubModules under the linecard's EntIndex.
func TestExtractModuleInventory_HappyPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	oids := buildOIDs(chassis9404RWithTransceiversFixture())

	inv := extractModuleInventory(oids, logger)

	require.Len(t, inv.Modules, 2)
	var sup, lc *ModuleEntry
	for i := range inv.Modules {
		switch inv.Modules[i].Type {
		case ModuleTypeSupervisor:
			sup = &inv.Modules[i]
		case ModuleTypeLinecard:
			lc = &inv.Modules[i]
		}
	}
	require.NotNil(t, sup, "supervisor must be classified")
	require.NotNil(t, lc, "linecard must be classified")
	assert.Equal(t, "JAE24010ABC", sup.Serial)
	assert.Equal(t, "C9400-SUP-1", sup.Model)
	assert.Equal(t, "Slot 1", sup.BayName)
	assert.Equal(t, "JAE24010LC2", lc.Serial)
	assert.Equal(t, "Slot 2", lc.BayName)

	subs := inv.SubModules["201"]
	require.Len(t, subs, 1)
	assert.Equal(t, ModuleTypeTransceiver, subs[0].Type)
	assert.Equal(t, "FNS24010TR1", subs[0].Serial)
	assert.Equal(t, "TenGigabitEthernet2/0/1", subs[0].BayName)
}

// TestExtractModuleInventory_NoModulesReturnsEmpty — chassis-only
// fixture produces empty Modules and SubModules.
func TestExtractModuleInventory_NoModulesReturnsEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Switch", "FOO", "C9300", "Switch", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	assert.Empty(t, inv.Modules)
	assert.Empty(t, inv.SubModules)
}

// TestExtractModuleInventory_OrphanContainmentDropped — module whose
// containedIn points at an absent index is dropped.
func TestExtractModuleInventory_OrphanContainmentDropped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "C9404R", "Chassis", ""},
		{"99", "777", "9", "1", "Orphan", "ORPH1", "C9400-LC", "Orphan linecard", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	assert.Empty(t, inv.Modules, "orphan module must be dropped")
}

// TestExtractModuleInventory_UnclassifiableClassSkipped — class=1
// (other) and class=2 (unknown) rows are skipped; only class=9 counts.
func TestExtractModuleInventory_UnclassifiableClassSkipped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "C9300", "Chassis", ""},
		{"50", "1", "1", "1", "Unknown other", "", "", "", ""},
		{"51", "1", "2", "1", "Unknown unknown", "", "", "", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	assert.Empty(t, inv.Modules)
}

// TestExtractModuleInventory_DuplicateSerialDedup — two class=9 rows
// sharing a serial; first occurrence (sorted ascending by EntIndex)
// wins, second is dropped.
func TestExtractModuleInventory_DuplicateSerialDedup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "C9404R", "Chassis", ""},
		{"100", "1", "5", "1", "Slot 1", "", "", "Slot 1", ""},
		{"101", "100", "9", "1", "Linecard A", "DUPSERIAL01", "C9400-LC-48U", "", ""},
		{"200", "1", "5", "2", "Slot 2", "", "", "Slot 2", ""},
		{"201", "200", "9", "1", "Linecard B (dup)", "DUPSERIAL01", "C9400-LC-48U", "", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	require.Len(t, inv.Modules, 1, "duplicate-serial second occurrence must be dropped")
	assert.Equal(t, "101", inv.Modules[0].EntIndex,
		"first occurrence (sorted ascending by EntIndex) wins")
}

// TestExtractModuleInventory_NormalizesWhitespace — ENTITY-MIB strings
// can arrive with leading/trailing whitespace or trailing NUL bytes.
// Every entPhysical string field (Name, Serial, Model, Description,
// VendorType, plus the bay's Name/ParentRel) must be trimmed via
// trimSNMPString at extraction so dedup keys stay stable across runs
// and downstream Diode payloads are clean.
func TestExtractModuleInventory_NormalizesWhitespace(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "C9404R", "Chassis", ""},
		{"100", "1", "5", "1", "  Slot 1 \x00", "", "", "Slot 1", ""},
		{"101", "100", "9", "1", "  Linecard \x00", "  ABC123 \x00 ", "  C9400-LC-48U\x00", "  desc \x00", "  vt \x00"},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	require.Len(t, inv.Modules, 1)
	m := inv.Modules[0]
	assert.Equal(t, "ABC123", m.Serial, "trailing NUL + whitespace stripped from Serial")
	assert.Equal(t, "C9400-LC-48U", m.Model)
	assert.Equal(t, "Linecard", m.Name)
	assert.Equal(t, "desc", m.Description)
	assert.Equal(t, "vt", m.VendorType)
	assert.Equal(t, "Slot 1", m.BayName, "bay name pulled from parent must also be trimmed")
}

// TestExtractModuleInventory_PortContainerNotEmptyBay — a class=5
// container whose only children are class=10 ports is a port slot, not
// a module bay. Surfacing it as an empty bay produces spurious
// ModuleBay entries. The empty-bay scan must skip class=5 rows that
// have any class=10 children.
func TestExtractModuleInventory_PortContainerNotEmptyBay(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "C9300", "Chassis", ""},
		// Class=5 port container under chassis. No class=9 child.
		{"100", "1", "5", "1", "Port Container", "", "", "", ""},
		// Class=10 port under the container.
		{"101", "100", "10", "1", "Gi1/0/1", "", "", "", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	assert.Empty(t, inv.EmptyBays,
		"class=5 with class=10 children is a port container, not an empty module bay")
}

// TestExtractModuleInventory_EmptyBayHarvested — class=5 row under
// the chassis with no class=9 child surfaces in EmptyBays (Aruba CX
// quirk). Populated bays continue to emit a normal Module entry.
func TestExtractModuleInventory_EmptyBayHarvested(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "8400", "Chassis", ""},
		// Empty bay — class=5 under chassis, no class=9 child.
		{"700", "1", "5", "5", "Slot 5 (empty)", "", "", "Slot 5", ""},
		// Populated bay — confirms we only get the empty one in EmptyBays.
		{"100", "1", "5", "1", "Slot 1", "", "", "Slot 1", ""},
		{"101", "100", "9", "1", "Linecard", "JAE1", "8400-LC", "", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)

	require.Len(t, inv.EmptyBays, 1)
	assert.Equal(t, "700", inv.EmptyBays[0].EntIndex)
	assert.Equal(t, "Slot 5 (empty)", inv.EmptyBays[0].BayName)
	require.Len(t, inv.Modules, 1)
	assert.Equal(t, "101", inv.Modules[0].EntIndex)
}

// TestExtractModuleInventory_BayPositionFromBayRow — BayPosition must
// reflect the chassis slot number (the bay's own entPhysicalParentRelPos),
// NOT the module's parentRelPos within its bay (which is almost always
// "1" on real hardware). Real Cat 9404R reports module ParentRel=1 and
// bay ParentRel=<slot>; sourcing position from the module produced
// "Slot 1" for every linecard regardless of physical slot.
func TestExtractModuleInventory_BayPositionFromBayRow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "C9404R", "Chassis", ""},
		// Bay in slot 5 of the chassis — bay.ParentRel=5.
		{"200", "1", "5", "5", "Slot 5", "", "", "Slot 5", ""},
		// Module within the bay — module.ParentRel=1 (always "1" on real HW).
		{"201", "200", "9", "1", "Linecard 5", "JAE5", "C9400-LC-48U", "", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	require.Len(t, inv.Modules, 1)
	assert.Equal(t, "5", inv.Modules[0].BayPosition,
		"BayPosition must come from the bay row's ParentRel, not the module's")
}

// TestExtractModuleInventory_ChassisRootedModuleSurvives — some fixed-FRU
// switches report modules directly under the chassis with no class=5
// container in between. The previous "no class=5 ancestor -> drop"
// behaviour silently lost these. Synthesize a self-referential bay so
// the module is still emitted.
func TestExtractModuleInventory_ChassisRootedModuleSurvives(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Fixed Switch", "FOO", "C9300", "Chassis", ""},
		// Linecard sits directly under chassis (no class=5 bay row).
		{"100", "1", "9", "7", "Linecard 7", "JAE7", "C9300-LC", "", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	require.Len(t, inv.Modules, 1, "chassis-rooted module must survive")
	m := inv.Modules[0]
	assert.Equal(t, "100", m.EntIndex)
	assert.Equal(t, "100", m.BayEntIndex,
		"synthesized bay self-references the module")
	// Prefix "Slot " telegraphs synthetic nature so NetBox UI doesn't show
	// a bay and module sharing the identical "Linecard 7" label.
	assert.Equal(t, "Slot 7", m.BayName,
		"synthesized bay name uses Slot + ParentRel to differ from module name")
	assert.Equal(t, "7", m.BayPosition,
		"synthesized bay position falls back to module's ParentRel")
}

// TestExtractModuleInventory_DedupUsesNumericEntIndexOrder — ENTITY-MIB
// EntIndex values are numeric. A lexicographic sort on the string form
// orders "10" before "9", which would pick the wrong dedup winner under
// the "first occurrence wins" contract. The dedup pass must sort
// numerically so EntIndex 9 wins over EntIndex 10 when they share a
// serial.
func TestExtractModuleInventory_DedupUsesNumericEntIndexOrder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// fixtureRow order: EntIndex, ContainedIn, Class, ParentRel, Name,
	// Serial, Model, Descr, VendorType.
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "CHSER01", "C9404R", "Chassis", ""},
		{"100", "1", "5", "1", "Slot 1", "", "", "Slot 1", ""},
		{"200", "1", "5", "2", "Slot 2", "", "", "Slot 2", ""},
		// EntIndex 9 — should win in numeric order.
		{"9", "100", "9", "1", "Linecard 9", "DUPE-SER-01", "C9400-LC-48U", "First card", ""},
		// EntIndex 10 — same serial; should lose in numeric order.
		{"10", "200", "9", "1", "Linecard 10", "DUPE-SER-01", "C9400-LC-48U", "Second card", ""},
	}
	inv := extractModuleInventory(buildOIDs(rows), logger)
	require.Len(t, inv.Modules, 1, "duplicate serial collapsed")
	assert.Equal(t, "9", inv.Modules[0].EntIndex,
		"EntIndex 9 wins under numeric sort (lex would pick 10)")
}
