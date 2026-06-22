// Copyright 2026 NetBox Labs, Inc.

package mapping

import (
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modeOff / modeLinecards / modeFull return *config.Options with the
// matching discover_modules string set. Tiny helpers so each test reads
// like prose.
func modeOff() *config.Options {
	v := config.DiscoverModulesOff
	return &config.Options{DiscoverModules: &v}
}

func modeLinecards() *config.Options {
	v := config.DiscoverModulesLinecards
	return &config.Options{DiscoverModules: &v}
}

func modeFull() *config.Options {
	v := config.DiscoverModulesFull
	return &config.Options{DiscoverModules: &v}
}

// TestTranslateModules_OffMode_ReturnsNil — default (and explicit "off")
// must short-circuit before any extraction or emission so existing
// pipelines see zero behaviour change.
func TestTranslateModules_OffMode_ReturnsNil(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	oids := buildOIDs(chassis9404RWithTransceiversFixture())
	dev := &diode.Device{Name: strPtr("test")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, ifaceMap := TranslateModules(oids, nil, memberDevices, modeOff(), nil, logger)

	assert.Nil(t, entities, "off mode emits no entities")
	assert.Nil(t, ifaceMap, "off mode produces no iface attachment map")
}

// TestTranslateModules_LinecardsMode_StandaloneEmitsLinecardsAndSupervisorsNoTransceivers
// — linecards mode emits the chassis-slot modules (supervisor + linecard
// in the 9404R fixture) and their bays, but NOT the transceiver. The
// iface attachment map is nil/empty in linecards mode.
func TestTranslateModules_LinecardsMode_StandaloneEmitsLinecardsAndSupervisorsNoTransceivers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	oids := buildOIDs(chassis9404RWithTransceiversFixture())
	dev := &diode.Device{Name: strPtr("test-router")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, ifaceMap := TranslateModules(oids, nil, memberDevices, modeLinecards(), nil, logger)

	var bays []*diode.ModuleBay
	var modules []*diode.Module
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.ModuleBay:
			bays = append(bays, v)
		case *diode.Module:
			modules = append(modules, v)
		}
	}
	require.Len(t, bays, 2, "supervisor bay + linecard bay")
	require.Len(t, modules, 2, "supervisor + linecard; no transceiver in linecards mode")

	// iface map stays empty — transceiver routing is full-mode only.
	assert.Empty(t, ifaceMap)

	// No transceiver model leaks into the module list.
	for _, m := range modules {
		require.NotNil(t, m.ModuleType, "every emitted Module needs a ModuleType")
		require.NotNil(t, m.ModuleType.Model)
		assert.NotEqual(t, "SFP-10G-LR", *m.ModuleType.Model,
			"transceivers must not be emitted as modules in linecards mode")
	}

	// Every ModuleBay carries Device; every Module carries Device + ModuleBay.
	for _, b := range bays {
		require.NotNil(t, b.Device, "ModuleBay must have Device set")
	}
	for _, m := range modules {
		require.NotNil(t, m.Device, "Module must have Device set")
		require.NotNil(t, m.ModuleBay, "Module must have ModuleBay set")
	}
}

// TestTranslateModules_PSUAndFan_NotEmitted — PSUs and fans are
// classified for label-only purposes; they must NOT surface as Module
// entities even in full mode.
func TestTranslateModules_PSUAndFan_NotEmitted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "C9404R", "Chassis", ""},
		{"100", "1", "5", "1", "PowerSupply 1", "", "", "", ""},
		{"101", "100", "9", "1", "PSU 1", "PSUSER01", "PWR-C5-715WAC", "", ""},
		{"200", "1", "5", "1", "Fan Tray", "", "", "", ""},
		// Fan PID — uses "FAN-" prefix so the current classifier (which
		// matches HasPrefix(upper, "FAN")) recognises it. PR #419's
		// classifier additionally treats "C9400-FAN" via the -FAN suffix,
		// but that branch is unrelated to this filter test.
		{"201", "200", "9", "1", "Fan 1", "FANSER01", "FAN-T1-R", "", ""},
		{"300", "1", "5", "1", "Slot 3", "", "", "", ""},
		{"301", "300", "9", "1", "Linecard 3", "LCSER03", "C9400-LC-48U", "", ""},
	}
	dev := &diode.Device{Name: strPtr("test")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(buildOIDs(rows), nil, memberDevices, modeFull(), nil, logger)

	var modules []*diode.Module
	for _, e := range entities {
		if m, ok := e.(*diode.Module); ok {
			modules = append(modules, m)
		}
	}
	require.Len(t, modules, 1, "only the linecard — PSU + fan filtered out")
	require.NotNil(t, modules[0].ModuleType)
	require.NotNil(t, modules[0].ModuleType.Model)
	assert.Equal(t, "C9400-LC-48U", *modules[0].ModuleType.Model)
}

// TestTranslateModules_FullMode_EmitsTransceiversAsSubBayedModules — in
// full mode the 9404R fixture must emit the supervisor + linecard pair
// plus a transceiver nested in its own sub-bay, AND the iface attachment
// map must route Gi1/0/1 → that transceiver Module.
func TestTranslateModules_FullMode_EmitsTransceiversAsSubBayedModules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	oids := buildOIDs(chassis9404RWithTransceiversFixture())
	dev := &diode.Device{Name: strPtr("test-router")}
	memberDevices := map[int]*diode.Device{0: dev}

	// Transceiver EntIndex "203" sits behind ifIndex "10101"
	// per the fixture's alias wiring intent.
	aliasMap := map[string]string{"203": "10101"}

	entities, ifaceMap := TranslateModulesWithAlias(
		oids, nil, memberDevices, modeFull(), nil, logger,
		aliasMap,
	)

	var bays []*diode.ModuleBay
	var modules []*diode.Module
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.ModuleBay:
			bays = append(bays, v)
		case *diode.Module:
			modules = append(modules, v)
		}
	}
	// Supervisor bay + linecard bay + transceiver sub-bay = 3 bays;
	// supervisor + linecard + transceiver = 3 modules.
	require.Len(t, bays, 3, "supervisor bay + linecard bay + transceiver sub-bay")
	require.Len(t, modules, 3, "supervisor + linecard + transceiver")

	// Iface map points the physical port (keyed by ifIndex) at the
	// transceiver module.
	require.Len(t, ifaceMap, 1)
	require.Contains(t, ifaceMap, "10101")
	require.NotNil(t, ifaceMap["10101"].Serial)
	assert.Equal(t, "FNS24010TR1", *ifaceMap["10101"].Serial)
}

// TestTranslateModules_FullMode_SubBayDeviceRooted — pins the sub-bay
// reconciler workaround documented in the design spec under
// "Sub-bay emission workaround". The transceiver's sub-bay MUST carry
// Device (so Diode has a matching scope) and MUST NOT carry Module
// (linking the sub-bay to its parent linecard makes the Diode
// reconciler re-plan the parent inside the sub-bay's changeset and
// trip dcim_module_module_bay_id_key on apply).
func TestTranslateModules_FullMode_SubBayDeviceRooted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	oids := buildOIDs(chassis9404RWithTransceiversFixture())
	dev := &diode.Device{Name: strPtr("test-router")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModulesWithAlias(
		oids, nil, memberDevices, modeFull(), nil, logger, nil,
	)

	// The transceiver's bay carries the port-shaped name from the
	// fixture ("TenGigabitEthernet2/0/1"). Find it and assert the
	// workaround invariants.
	var subBay *diode.ModuleBay
	for _, e := range entities {
		b, ok := e.(*diode.ModuleBay)
		if !ok || b.Name == nil {
			continue
		}
		if *b.Name == "TenGigabitEthernet2/0/1" {
			subBay = b
			break
		}
	}
	require.NotNil(t, subBay, "transceiver sub-bay must be emitted")
	assert.NotNil(t, subBay.Device,
		"sub-bay must be device-rooted (workaround for Diode reconciler)")
	assert.Nil(t, subBay.Module,
		"sub-bay must NOT carry Module=parent_linecard — see spec §Sub-bay emission workaround")
}

// TestTranslateModules_FullMode_EmptyBayEmittedAsBareModuleBay —
// Aruba CX-style empty bays surface as bare ModuleBay entities (no
// Module installed) in full mode only.
func TestTranslateModules_FullMode_EmptyBayEmittedAsBareModuleBay(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FOO", "8400", "Chassis", ""},
		// Empty bay — class=5 under chassis, no class=9 child.
		{"700", "1", "5", "5", "Slot 5 (empty)", "", "", "Slot 5", ""},
	}
	dev := &diode.Device{Name: strPtr("test")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModulesWithAlias(
		buildOIDs(rows), nil, memberDevices, modeFull(), nil, logger, nil,
	)

	var bays []*diode.ModuleBay
	var modules []*diode.Module
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.ModuleBay:
			bays = append(bays, v)
		case *diode.Module:
			modules = append(modules, v)
		}
	}
	require.Len(t, bays, 1, "one bare ModuleBay for the empty slot")
	require.Empty(t, modules, "no Module entity for an empty bay")
	require.NotNil(t, bays[0].Name)
	assert.Equal(t, "Slot 5 (empty)", *bays[0].Name)
	assert.NotNil(t, bays[0].Device, "even bare bays carry Device")
}

// TestTranslateModules_SubBayWorkaround_NotLinkedToParentLinecard pins
// the Diode reconciler workaround (spec §Sub-bay emission workaround).
// Background: dcim_module_module_bay_id_key is a unique constraint; if
// we emit a transceiver sub-bay with Module=parent_linecard, the
// reconciler re-plans the parent linecard inside the sub-bay's
// changeset and the apply step trips the unique constraint. Until the
// upstream fix lands, every transceiver-shaped ModuleBay must be
// device-rooted (Device set, Module nil) and the transceiver's own
// Module.ModuleBay must in turn carry Device (so it has a matching
// scope).
func TestTranslateModules_SubBayWorkaround_NotLinkedToParentLinecard(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	oids := buildOIDs(chassis9404RWithTransceiversFixture())
	dev := &diode.Device{Name: strPtr("test-router")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModulesWithAlias(
		oids, nil, memberDevices, modeFull(), nil, logger, nil,
	)

	// Identify which bays are sub-bays (transceiver-shaped). The 9404R
	// fixture names its port container "TenGigabitEthernet2/0/1", so a
	// HasPrefix("TenGigabit") match is sufficient here.
	subBaysSeen := 0
	for _, e := range entities {
		b, ok := e.(*diode.ModuleBay)
		if !ok || b.Name == nil {
			continue
		}
		name := *b.Name
		if !startsWith(name, "TenGigabit") {
			continue
		}
		subBaysSeen++
		// Workaround invariants:
		assert.Nil(t, b.Module,
			"sub-bay %q must not link to parent linecard — see spec §Sub-bay emission workaround", name)
		assert.NotNil(t, b.Device,
			"sub-bay %q must be device-rooted (Device set)", name)
	}
	require.Equal(t, 1, subBaysSeen, "expected exactly one transceiver sub-bay")

	// The transceiver Module must reach Device through its own bay too
	// (the device-rooted bay carries Device).
	for _, e := range entities {
		m, ok := e.(*diode.Module)
		if !ok || m.ModuleType == nil || m.ModuleType.Model == nil {
			continue
		}
		if *m.ModuleType.Model != "SFP-10G-LR" {
			continue
		}
		require.NotNil(t, m.ModuleBay, "transceiver Module must carry ModuleBay")
		assert.NotNil(t, m.ModuleBay.Device,
			"transceiver Module.ModuleBay must carry Device (device-rooted workaround)")
	}
}

// startsWith is a tiny local helper to keep the regression test free of
// strings.HasPrefix imports leakage in case future test refactors drop
// strings entirely.
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// TestTranslateModules_FullMode_EmitsTransceiversNestedTwoLevelsDeep —
// Juniper-style hierarchy puts optics two module-levels below the
// chassis: Chassis -> FPC (class=9) -> PIC bay (class=5) -> PIC
// (class=9) -> port container (class=5) -> optic (class=9). The PIC
// is itself a sub-module under the FPC, so optics under the PIC live
// in inv.SubModules keyed by the PIC's EntIndex — not by any
// inv.Modules entry. The full-mode emitter must walk every key in
// inv.SubModules (recursive over the containment tree) so optics
// nested under sub-modules surface as Module entities.
func TestTranslateModules_FullMode_EmitsTransceiversNestedTwoLevelsDeep(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "JN1234", "MX480", "", ""},
		// FPC slot (class=5 bay) + FPC (class=9 module under it)
		{"10", "1", "5", "1", "FPC 0 Slot", "", "", "", ""},
		{"11", "10", "9", "1", "FPC 0", "AB123FPC", "MPC7E-MRATE", "", ""},
		// PIC bay (class=5) under the FPC + PIC (class=9 module) under it
		{"20", "11", "5", "1", "PIC 0 Bay", "", "", "", ""},
		{"21", "20", "9", "1", "PIC 0", "CD456PIC", "MIC-3D-10XGE-SFPP", "", ""},
		// Port container (class=5) under the PIC + optic (class=9) under it
		{"30", "21", "5", "1", "xe-0/0/0", "", "", "", ""},
		{"31", "30", "9", "1", "xe-0/0/0 Optic", "EF789OPT", "SFP-10G-LR", "", ""},
	}
	dev := &diode.Device{Name: strPtr("mx480")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModulesWithAlias(
		buildOIDs(rows), nil, memberDevices, modeFull(), nil, logger, nil,
	)

	var transceiverSeen bool
	for _, e := range entities {
		m, ok := e.(*diode.Module)
		if !ok || m.ModuleType == nil || m.ModuleType.Model == nil {
			continue
		}
		if *m.ModuleType.Model == "SFP-10G-LR" {
			transceiverSeen = true
			require.NotNil(t, m.Serial)
			assert.Equal(t, "EF789OPT", *m.Serial)
		}
	}
	assert.True(t, transceiverSeen,
		"optic nested under a sub-module (PIC) must be emitted in full mode")
}

// TestTranslateModules_ModuleTypeManufacturer_SourcedFromDevice pins the
// invariant that ModuleType.Manufacturer.Name and the metric `vendor`
// attribute always agree — both must read from the emitted Device's
// DeviceType.Manufacturer.Name, falling back to defaults only when the
// device has no manufacturer set. Regression: previously emitModule
// sourced from defaults so a device with a real Manufacturer but empty
// defaults produced ModuleType.Manufacturer="Unknown" while the metric
// label read the real vendor — labels diverged from emitted entities.
func TestTranslateModules_ModuleTypeManufacturer_SourcedFromDevice(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	oids := buildOIDs(chassis9404RWithTransceiversFixture())
	dev := &diode.Device{
		Name: strPtr("test-router"),
		DeviceType: &diode.DeviceType{
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	memberDevices := map[int]*diode.Device{0: dev}
	// defaults has an empty Manufacturer — the device value MUST win.
	defaults := &config.Defaults{}

	entities, _ := TranslateModules(oids, nil, memberDevices, modeLinecards(), defaults, logger)

	var modules []*diode.Module
	for _, e := range entities {
		if m, ok := e.(*diode.Module); ok {
			modules = append(modules, m)
		}
	}
	require.NotEmpty(t, modules, "fixture must emit at least one module")
	for _, m := range modules {
		require.NotNil(t, m.ModuleType, "every emitted Module needs a ModuleType")
		require.NotNil(t, m.ModuleType.Manufacturer, "ModuleType must carry Manufacturer")
		require.NotNil(t, m.ModuleType.Manufacturer.Name)
		assert.Equal(t, "Cisco", *m.ModuleType.Manufacturer.Name,
			"ModuleType.Manufacturer.Name must come from the emitted Device, not defaults")
	}
}

// TestTranslateModulesWithAlias_VCOfModular_DispatchesPerMember — pins
// that on a virtual-chassis of two modular boxes, each member's
// linecards are emitted under that member's *diode.Device. The walk
// chains module 101 → bay 100 → chassis 1 (member 1) and module 1001 →
// bay 1000 → chassis 1000 (member 2). MemberID is stamped by
// assignMemberID and the translator routes via memberDevices[MemberID].
func TestTranslateModulesWithAlias_VCOfModular_DispatchesPerMember(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// 2-member VC: each member chassis owns a slot + linecard.
	rows := []fixtureRow{
		// Member 1 chassis (EntPhysicalIndex "1")
		{"1", "0", "3", "1", "Switch1 Chassis", "FCW2401SW01", "C9410R", "", ""},
		{"100", "1", "5", "1", "Slot 1", "", "", "", ""},
		{"101", "100", "9", "1", "LC1", "JAE24010LC1", "C9400-LC-48U", "", ""},
		// Member 2 chassis (EntPhysicalIndex "1000")
		{"1000", "0", "3", "2", "Switch2 Chassis", "FCW2401SW02", "C9410R", "", ""},
		{"1100", "1000", "5", "1", "Slot 1", "", "", "", ""},
		{"1101", "1100", "9", "1", "LC2", "JAE24010LC2", "C9400-LC-48U", "", ""},
	}
	chassisInv := &ChassisInventory{
		Members: []ChassisMember{
			{ID: 1, EntPhysicalIndex: "1", Serial: "FCW2401SW01", Model: "C9410R"},
			{ID: 2, EntPhysicalIndex: "1000", Serial: "FCW2401SW02", Model: "C9410R"},
		},
	}

	master := &diode.Device{Name: strPtr("vc-master")}
	pos2 := int64(2)
	member2 := &diode.Device{Name: strPtr("vc-member-2"), VcPosition: &pos2}
	// Master is keyed by lowest member ID (Members[0].ID == 1) to match
	// chassis.go's memberByID[lowest.ID] = master convention.
	memberDevices := map[int]*diode.Device{1: master, 2: member2}

	entities, _ := TranslateModulesWithAlias(
		buildOIDs(rows), chassisInv, memberDevices,
		modeLinecards(), nil, logger, nil,
	)

	var modules []*diode.Module
	for _, e := range entities {
		if m, ok := e.(*diode.Module); ok {
			modules = append(modules, m)
		}
	}
	require.Len(t, modules, 2, "one linecard per VC member")

	var lc1Mod, lc2Mod *diode.Module
	for _, m := range modules {
		require.NotNil(t, m.Serial)
		switch *m.Serial {
		case "JAE24010LC1":
			lc1Mod = m
		case "JAE24010LC2":
			lc2Mod = m
		}
	}
	require.NotNil(t, lc1Mod, "linecard under chassis 1 must be emitted")
	require.NotNil(t, lc2Mod, "linecard under chassis 1000 must be emitted")
	assert.Same(t, master, lc1Mod.Device,
		"linecard under chassis 1 (member 1) routes to master device")
	assert.Same(t, member2, lc2Mod.Device,
		"linecard under chassis 1000 (member 2) routes to member-2 device")
}

// TestTranslateModulesWithAlias_ModulesPrecedeInterfacesAfterSplice pins
// the Diode ingest ordering contract honoured by the runner's
// SpliceModulesAfterDevices call: every *diode.Module / *diode.ModuleBay
// index must be < every *diode.Interface index in the merged slice.
func TestTranslateModulesWithAlias_ModulesPrecedeInterfacesAfterSplice(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dev := &diode.Device{Name: strPtr("test-router")}
	iface1 := &diode.Interface{Name: strPtr("Gi1/0/1"), Device: dev}
	iface2 := &diode.Interface{Name: strPtr("Gi1/0/2"), Device: dev}
	entitiesForTarget := []diode.Entity{dev, iface1, iface2}

	oids := buildOIDs(chassis9404RWithTransceiversFixture())
	memberDevices := map[int]*diode.Device{0: dev}

	moduleEntities, _ := TranslateModulesWithAlias(
		oids, nil, memberDevices, modeLinecards(), nil, logger, nil,
	)
	require.NotEmpty(t, moduleEntities)

	merged := SpliceModulesAfterDevices(entitiesForTarget, moduleEntities)

	firstIface := -1
	lastModule := -1
	for i, e := range merged {
		switch e.(type) {
		case *diode.Module, *diode.ModuleBay:
			lastModule = i
		case *diode.Interface:
			if firstIface == -1 {
				firstIface = i
			}
		}
	}
	require.GreaterOrEqual(t, firstIface, 0, "no Interface in merged slice")
	require.GreaterOrEqual(t, lastModule, 0, "no Module/ModuleBay in merged slice")
	assert.Less(t, lastModule, firstIface,
		"Module/ModuleBay must precede Interface — Diode ingest contract")
}

// TestSpliceModulesAfterDevices covers the helper's three core shapes:
// empty modules (no-op), all-Device prefix (append at end of head), and
// mixed Device+VC head with trailing Interfaces (insert at first
// non-head index).
func TestSpliceModulesAfterDevices(t *testing.T) {
	dev := &diode.Device{Name: strPtr("d")}
	vc := &diode.VirtualChassis{Name: strPtr("vc")}
	iface := &diode.Interface{Name: strPtr("Gi0/0"), Device: dev}
	bay := &diode.ModuleBay{Name: strPtr("Slot 1"), Device: dev}
	mod := &diode.Module{Device: dev, ModuleBay: bay}

	t.Run("empty modules returns input unchanged", func(t *testing.T) {
		in := []diode.Entity{dev, iface}
		out := SpliceModulesAfterDevices(in, nil)
		assert.Equal(t, in, out)
	})

	t.Run("all-Device prefix appends modules at the end", func(t *testing.T) {
		in := []diode.Entity{dev, vc}
		out := SpliceModulesAfterDevices(in, []diode.Entity{bay, mod})
		require.Len(t, out, 4)
		assert.Same(t, dev, out[0])
		assert.Same(t, vc, out[1])
		assert.Same(t, bay, out[2])
		assert.Same(t, mod, out[3])
	})

	t.Run("mixed head+tail splices before first non-head", func(t *testing.T) {
		in := []diode.Entity{dev, vc, iface}
		out := SpliceModulesAfterDevices(in, []diode.Entity{bay, mod})
		require.Len(t, out, 5)
		assert.Same(t, dev, out[0])
		assert.Same(t, vc, out[1])
		assert.Same(t, bay, out[2])
		assert.Same(t, mod, out[3])
		assert.Same(t, iface, out[4])
	})

	// Pins the splice=0 path: when the slice has no Device/VC head, modules
	// must be prepended so they precede the first Interface (Diode ingest
	// requires Modules before any Interface that references them).
	t.Run("non_device_headed_slice_modules_prepend", func(t *testing.T) {
		in := []diode.Entity{iface}
		out := SpliceModulesAfterDevices(in, []diode.Entity{bay, mod})
		require.Len(t, out, 3)
		assert.Same(t, bay, out[0])
		assert.Same(t, mod, out[1])
		assert.Same(t, iface, out[2])
	})
}

// TestTranslateModules_ModuleTypeModel_FallsBackToVendorTypeWhenModelBlank
// — Aruba CX populates entPhysicalVendorType instead of entPhysicalModelName.
// The emitted ModuleType.Model must mirror classifyModule's
// Model -> VendorType -> Unknown fallback so the type label matches the
// classification (and so NetBox doesn't see "Unknown" for valid hardware).
func TestTranslateModules_ModuleTypeModel_FallsBackToVendorTypeWhenModelBlank(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// fixtureRow order: EntIndex, ContainedIn, Class, ParentRel, Name,
	// Serial, Model, Descr, VendorType.
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FCAR2401", "ArubaCX-8400", "Aruba 8400 Chassis", "aruba-8400"},
		{"100", "1", "5", "1", "Slot 1", "", "", "Slot 1", ""},
		// Aruba CX shape: Model blank, VendorType populated.
		{"101", "100", "9", "1", "Linecard 1", "ARSER01", "", "Aruba line card", "aruba-jl363a"},
	}
	dev := &diode.Device{Name: strPtr("aruba")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(buildOIDs(rows), nil, memberDevices, modeLinecards(), nil, logger)

	var modules []*diode.Module
	for _, e := range entities {
		if m, ok := e.(*diode.Module); ok {
			modules = append(modules, m)
		}
	}
	require.Len(t, modules, 1)
	require.NotNil(t, modules[0].ModuleType)
	require.NotNil(t, modules[0].ModuleType.Model)
	assert.Equal(t, "aruba-jl363a", *modules[0].ModuleType.Model,
		"blank Model must fall back to VendorType, not Unknown")
}
