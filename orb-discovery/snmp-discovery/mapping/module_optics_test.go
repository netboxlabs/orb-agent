// Copyright 2026 NetBox Labs, Inc.

package mapping

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testOpticLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// TestOpticDiscovery_LaneRowsNotEmittedAsModules asserts the per-lane
// sub-entities published beneath each optic are not modules or submodules.
// Every class-9 row on this platform is such a lane; the optics themselves
// are the class-5 containers, covered separately by
// TestOpticDiscovery_ContainerShapeEmitted.
func TestOpticDiscovery_LaneRowsNotEmittedAsModules(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(fixedPortLaneShapeFixture()), testOpticLogger())

	laneIdxs := []string{"100301210", "100302210", "100303210"}
	for _, m := range inv.Modules {
		assert.NotContains(t, laneIdxs, m.EntIndex, "lane row emitted as a module")
	}
	for _, subs := range inv.SubModules {
		for _, m := range subs {
			assert.NotContains(t, laneIdxs, m.EntIndex, "lane row emitted as a submodule")
		}
	}
}

// TestOpticDiscovery_OpticRowsNeverHarvestedAsEmptyBays asserts an optic row
// is never emitted as a bare bay. It is inventory in its own right, and the
// harvest drops the model and serial while naming the bay from the optic's
// own position — which is identical across every port on these platforms.
// On both fixtures every cage and the slot container above it are populated,
// so the expected outcome is that the harvest produces nothing at all — a
// stronger statement than "the optic indices specifically are absent", which
// per-index checks below also confirm.
//
// This must hold on both shapes: one has a lane child beneath every optic,
// the other beneath almost none, and suppressing lanes is what exposes the
// first shape to the harvest in the first place.
func TestOpticDiscovery_OpticRowsNeverHarvestedAsEmptyBays(t *testing.T) {
	opticIdxs := []string{"100301100", "100302100", "100303100"}

	for name, fixture := range map[string][]fixtureRow{
		"lane shape":    fixedPortLaneShapeFixture(),
		"harvest shape": fixedPortHarvestShapeFixture(),
	} {
		t.Run(name, func(t *testing.T) {
			inv := extractModuleInventory(buildOIDs(fixture), testOpticLogger())
			assert.Empty(t, inv.EmptyBays,
				"every cage and its slot container are populated; the harvest should produce nothing")
			for _, b := range inv.EmptyBays {
				assert.NotContains(t, opticIdxs, b.EntIndex,
					"optic row %s emitted as an empty bay", b.EntIndex)
			}
		})
	}
}

// TestOpticDiscovery_ContainerOfContainersNotHarvestedAsEmptyBay asserts a
// class-5 container whose own children are themselves class-5 containers
// (the per-port cages, never a class-9/10 leaf directly) is not harvested
// as an empty bay when something beneath it was emitted. Without upward
// propagation, bayHasChild only marks the nearest bay — the cage — so the
// slot container that holds all three cages would look empty even though
// every cage beneath it holds a populated, serialed optic. Every cage on
// this fixture is populated, so the expected outcome is no empty bays at
// all, not merely the absence of the slot container specifically.
func TestOpticDiscovery_ContainerOfContainersNotHarvestedAsEmptyBay(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(fixedPortLaneShapeFixture()), testOpticLogger())

	assert.Empty(t, inv.EmptyBays,
		"every cage beneath the slot container is populated; the harvest should produce nothing")
	for _, b := range inv.EmptyBays {
		assert.NotEqual(t, "1100300000", b.EntIndex,
			"the populated slot container must not be harvested as an empty bay")
	}
}

// TestOpticDiscovery_ContainerShapeEmitted asserts a class-5 row carrying an
// optic PID is discovered as a transceiver rather than ignored.
func TestOpticDiscovery_ContainerShapeEmitted(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(fixedPortLaneShapeFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 3, "one module per optic")
	for _, m := range inv.Modules {
		assert.Equal(t, ModuleTypeTransceiver, m.Type)
		assert.Equal(t, "SFP-10GLR-31", m.Model)
		assert.NotEmpty(t, m.Serial, "the optic's own serial must survive")
	}
}

// TestOpticDiscovery_ModularPortShapeNestsUnderLinecard asserts a class-10
// optic inside a linecard nests as a submodule with the bay taken from its
// real cage. It must not become a device-rooted bay.
func TestOpticDiscovery_ModularPortShapeNestsUnderLinecard(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(modularPortOpticFixture()), testOpticLogger())

	subs := inv.SubModules["2000"]
	require.Len(t, subs, 1, "exactly one optic nests under the linecard")
	assert.Equal(t, ModuleTypeTransceiver, subs[0].Type)
	assert.Equal(t, "SFP-10G-AOC2M", subs[0].Model)
	assert.Equal(t, "Te2/0/1 Container", subs[0].BayName,
		"bay comes from the optic's real class-5 cage")

	// The prefix list does not match this PID even though it is a real
	// transceiver. Pinning it makes any future prefix change a visible
	// decision rather than a surprise.
	for _, m := range subs {
		assert.NotEqual(t, "ABCU-5710RZ-CS5", m.Model)
	}
	// The linecard itself is legitimately device-rooted; the optic must
	// not be — no transceiver belongs in the top-level list.
	for _, m := range inv.Modules {
		assert.NotEqual(t, ModuleTypeTransceiver, m.Type, "no optic here is device-rooted")
	}
}

// TestOpticDiscovery_NonOpticContainersStayIgnored is the discriminator for
// the widening: PID-less class-5 cages must not become modules.
func TestOpticDiscovery_NonOpticContainersStayIgnored(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(chassis9404RWithTransceiversFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 2, "supervisor and linecard only")
	for _, m := range inv.Modules {
		assert.NotEqual(t, "Slot 1", m.Name)
		assert.NotEqual(t, "Slot 2", m.Name)
		assert.NotEqual(t, "TenGigabitEthernet2/0/1", m.Name)
	}
}

// TestOpticDiscovery_BayNamedForServedInterface asserts a fixed-port optic's
// bay is named for the interface the row itself names. Without it the bay is
// the cage's bare position number, which does not identify the port.
func TestOpticDiscovery_BayNamedForServedInterface(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(fixedPortLaneShapeFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 3)
	bays := make(map[string]bool, 3)
	for _, m := range inv.Modules {
		bays[m.BayName] = true
	}
	for _, want := range []string{"Ethernet1", "Ethernet2", "Ethernet3"} {
		assert.True(t, bays[want], "expected a bay named %s", want)
	}
}

// TestOpticDiscovery_LaneDescrNeverNamesABay pins the anchoring. A lane row
// descr contains "Xcvr for Ethernet1" as a substring, and an unanchored
// match would emit one bay per lane for a single physical optic.
func TestOpticDiscovery_LaneDescrNeverNamesABay(t *testing.T) {
	assert.Equal(t, "Ethernet1", servedInterface("", "Xcvr for Ethernet1", ""))
	assert.Empty(t, servedInterface("", "Lane 0 for Xcvr for Ethernet1", ""))
	assert.Empty(t, servedInterface("", "Xcvr Slot 1", ""))
}

// TestOpticDiscovery_NonInterfaceNameRejected pins the digit requirement.
// One platform names every optic row with the literal token "port";
// accepting it would name every bay on the chassis identically and merge
// them into one object.
func TestOpticDiscovery_NonInterfaceNameRejected(t *testing.T) {
	assert.Empty(t, servedInterface("port", "", ""))
	assert.Empty(t, servedInterface("SFP cage", "", ""))
	assert.Equal(t, "Ethernet0", servedInterface("Ethernet0", "", ""))
}

// TestOpticDiscovery_NameEqualToOwnPIDRejected pins Fix 2: a name-derived
// candidate that is really the row's own transceiver part number, not an
// interface, must be rejected — compared case-insensitively, since vendors
// are not consistent about PID casing.
func TestOpticDiscovery_NameEqualToOwnPIDRejected(t *testing.T) {
	assert.Empty(t, servedInterface("SFP-10G-LR", "", "SFP-10G-LR"))
	assert.Empty(t, servedInterface("sfp-10g-lr", "", "SFP-10G-LR"), "case-insensitive")
	assert.Equal(t, "Ethernet1", servedInterface("Ethernet1", "", "SFP-10G-LR"),
		"a real interface name must still be accepted")
}

// TestOpticDiscovery_StackedMembersKeepDistinctBays asserts that when two
// stack members each report an optic at the same position, all four bays
// survive. They are distinct NetBox objects because each carries its own
// Device; the extractor must not collapse them, and the literal token
// "port" must never become a bay name.
func TestOpticDiscovery_StackedMembersKeepDistinctBays(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(stackedPortOpticFixture()), testOpticLogger())

	var count int
	for _, subs := range inv.SubModules {
		for _, m := range subs {
			count++
			assert.NotEqual(t, "port", m.BayName, "the literal token must never name a bay")
		}
	}
	assert.Equal(t, 4, count, "two optics on each of two members")
}

// TestOpticDiscovery_SerialFreeOpticsEmittedWithDistinctBays covers the shape
// a real capture publishes 25 times: class-10 optics directly under the
// chassis, no serial, relPos -1 on every row. A blank serial is no reason to
// drop them — dcim.module matches on its bay, not on serial. relPos would name
// every bay "Slot -1", but the bay-naming rule runs first and each row names
// its own interface, so the bays are distinct and nothing collides.
func TestOpticDiscovery_SerialFreeOpticsEmittedWithDistinctBays(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(serialFreePortOpticFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 3, "a blank serial must not cost an optic its module")

	seen := make(map[string]string, len(inv.Modules))
	for _, m := range inv.Modules {
		assert.Equal(t, ModuleTypeTransceiver, m.Type)
		assert.Empty(t, m.Serial, "the serial really is absent in this capture")
		assert.Equal(t, m.Name, m.BayName, "named for the interface the row names")
		assert.NotEqual(t, "Slot -1", m.BayName, "relPos must not name the bay here")
		if prev, dup := seen[m.BayName]; dup {
			t.Fatalf("bay %q shared by ent %s and ent %s", m.BayName, prev, m.EntIndex)
		}
		seen[m.BayName] = m.EntIndex
	}
	assert.Len(t, seen, 3, "three optics, three distinct bays")
}

// TestOpticDiscovery_SerialFreeCagedOpticClaimsItsCage asserts a class-5 optic
// with no serial is emitted and takes its cage with it. The cage holds a module
// once the optic is emitted, so it must not also surface as an empty bay — that
// would double-count one physical slot.
func TestOpticDiscovery_SerialFreeCagedOpticClaimsItsCage(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(serialFreeCagedOpticFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 1, "the serial-free optic is emitted")
	assert.Equal(t, ModuleTypeTransceiver, inv.Modules[0].Type)
	assert.Equal(t, "Ethernet1", inv.Modules[0].BayName, "named from the descr's served interface")
	assert.Empty(t, inv.Modules[0].Serial)
	assert.Empty(t, inv.EmptyBays, "the cage now holds a module, so it is not an empty bay")
}

// TestOpticDiscovery_SerialFreeCagedPortOpticEmitted covers the class-10-in-a-
// cage shape real captures show, with the serial blank. The optic is emitted and
// named for its interface. The cage produces no bay of its own, empty or
// otherwise, because containerHasPortChild suppresses a container whose child is
// a port row — that suppression is unrelated to the serial.
func TestOpticDiscovery_SerialFreeCagedPortOpticEmitted(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(serialFreeCagedPortOpticFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 1, "the serial-free optic is emitted")
	assert.Equal(t, ModuleTypeTransceiver, inv.Modules[0].Type)
	assert.Equal(t, "TenGigabitEthernet1/0/1", inv.Modules[0].BayName)
	assert.Empty(t, inv.Modules[0].Serial)
	assert.Empty(t, inv.EmptyBays, "containerHasPortChild suppresses the cage")
}

// TestOpticDiscovery_ClassNineSerialFreeOpticStillEmitted pins the oldest of
// the blank-serial shapes: a class-9 optic beneath a linecard, discoverable
// since before the container/port scan was widened. It asserts full emission
// rather than mere absence-of-drop — the transceiver surfaces as a submodule
// ModuleBay + Module with Serial left unset, which is what emitModule's
// tolerance of a blank Serial is for.
func TestOpticDiscovery_ClassNineSerialFreeOpticStillEmitted(t *testing.T) {
	logger := testOpticLogger()

	oids := buildOIDs(serialFreeModuleOpticFixture())
	dev := &diode.Device{Name: strPtr("test-router")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(oids, nil, memberDevices, modeFull(), nil, logger)

	var transceiverMod *diode.Module
	for _, e := range entities {
		m, ok := e.(*diode.Module)
		if !ok || m.ModuleType == nil || m.ModuleType.Model == nil {
			continue
		}
		if *m.ModuleType.Model == "GLC-LH-SMD" {
			transceiverMod = m
		}
	}
	require.NotNil(t, transceiverMod, "the class-9 serial-free optic must still be emitted")
	require.NotNil(t, transceiverMod.ModuleBay, "the transceiver must carry its submodule bay")
	assert.Nil(t, transceiverMod.Serial, "serial stays unset, matching emitModule's existing tolerance")
}

// TestOpticDiscovery_LinecardsModeEmitsNoFixedPortOptic asserts a fixed-port
// optic stays out of linecards mode. A modular optic is already excluded by
// the full-mode gate because it lives in SubModules; a fixed-port optic is a
// top-level module and needs its own exclusion.
func TestOpticDiscovery_LinecardsModeEmitsNoFixedPortOptic(t *testing.T) {
	oids := buildOIDs(fixedPortLaneShapeFixture())
	dev := &diode.Device{Name: strPtr("test-switch")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(oids, nil, memberDevices, modeLinecards(), nil, testOpticLogger())

	for _, e := range entities {
		mod, ok := e.(*diode.Module)
		if !ok || mod.ModuleType == nil || mod.ModuleType.Model == nil {
			continue
		}
		assert.NotEqual(t, "SFP-10GLR-31", *mod.ModuleType.Model,
			"linecards mode must not emit a transceiver")
	}
}

// TestOpticDiscovery_FullModeEmitsInterfaceNamedBays asserts the emitted
// payload carries exactly one bay per optic, named for the interface it
// serves, each with its own serial. Asserting the exact set — rather than
// each wanted name plus a denylist of broken values — pins the whole
// outcome in one assertion: no container bay, no bare-number bay, no
// "Unknown" placeholder, regardless of what position value the container
// happens to report.
func TestOpticDiscovery_FullModeEmitsInterfaceNamedBays(t *testing.T) {
	oids := buildOIDs(fixedPortLaneShapeFixture())
	dev := &diode.Device{Name: strPtr("test-switch")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(oids, nil, memberDevices, modeFull(), nil, testOpticLogger())

	var bayNames []string
	serials := make(map[string]bool)
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.ModuleBay:
			require.NotNil(t, v.Name)
			bayNames = append(bayNames, *v.Name)
		case *diode.Module:
			if v.Serial != nil && *v.Serial != "" {
				serials[*v.Serial] = true
			}
		}
	}

	assert.ElementsMatch(t, []string{"Ethernet1", "Ethernet2", "Ethernet3"}, bayNames,
		"expected exactly one bay per optic, named for its served interface")
	assert.Len(t, serials, 3, "each optic contributes its own serial")
}

// TestOpticDiscovery_DuplicateBayNameDropped asserts the defensive guard
// against two module bays merging on one device: dcim.modulebay matches on
// name+device, so two transceivers landing on the same member with the same
// effective bay name must not both be emitted. The second is skipped and
// warned about — never merged, and never given a fabricated disambiguated
// name, since inventing one would itself become a permanent wrong value.
func TestOpticDiscovery_DuplicateBayNameDropped(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	oids := buildOIDs(duplicateBayNameOpticFixture())
	dev := &diode.Device{Name: strPtr("test-switch")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(oids, nil, memberDevices, modeFull(), nil, logger)

	var bayNames []string
	var serials []string
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.ModuleBay:
			require.NotNil(t, v.Name)
			bayNames = append(bayNames, *v.Name)
		case *diode.Module:
			if v.Serial != nil {
				serials = append(serials, *v.Serial)
			}
		}
	}

	assert.Equal(t, []string{"Unknown"}, bayNames, "only the first-seen bay may survive")
	assert.Equal(t, []string{"SYNSER0001A"}, serials, "the colliding second optic must not be emitted")
	assert.Contains(t, buf.String(), "duplicate transceiver bay name dropped")
	assert.Contains(t, buf.String(), "bay=Unknown")
	assert.Contains(t, buf.String(), "ent=11")
	assert.Contains(t, buf.String(), "member=0")
	assert.Contains(t, buf.String(), "model=SFP-10G-LR")
	assert.Contains(t, buf.String(), "reason=dup_bay_name")
}

// TestOpticDiscovery_NoDeviceMemberNeverPoisonsBayNameGuard pins the guard
// ordering fix: the device lookup must run BEFORE the duplicate-bay-name
// guard, not after. Reuses duplicateBayNameOpticFixture's two same-member,
// same-effective-bay-name ("Unknown") optics, but with an empty
// memberDevices map so BOTH lack a device — neither can ever be emitted,
// with or without the fix, because dcim.modulebay's matcher is
// (device, bay name) and the guard's key is (member, bay): two entries
// can only collide in the map if they share a member, and sharing a
// member means they share the exact same memberDevices[member] lookup, so
// one cannot have a device while the other does not. What the ordering
// DOES change is which reason each entry is dropped for. With the guard
// running first (pre-fix), the first optic still claims the bay-name key
// before its own nil-device check drops it, so the second optic — which
// was always going to be dropped for lacking a device too — instead gets
// misreported as a "duplicate transceiver bay name dropped", burying the
// real cause and polluting the guard's map with an entry nothing was ever
// emitted under. With the device check first (post-fix), neither entry
// ever touches the map, and both are reported for their real, correct
// reason.
func TestOpticDiscovery_NoDeviceMemberNeverPoisonsBayNameGuard(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	oids := buildOIDs(duplicateBayNameOpticFixture())
	memberDevices := map[int]*diode.Device{} // member 0 has no device at all

	entities, _ := TranslateModules(oids, nil, memberDevices, modeFull(), nil, logger)

	assert.Empty(t, entities, "neither optic has a device to emit under")
	assert.NotContains(t, buf.String(), "duplicate transceiver bay name dropped",
		"an entry that will never be emitted must not claim the bay name and misreport the next one as a duplicate")
	assert.NotContains(t, buf.String(), "reason=dup_bay_name")
	// Both entries must be reported for the real reason instead.
	assert.Contains(t, buf.String(), "no device for member")
	assert.Contains(t, buf.String(), "ent=10")
	assert.Contains(t, buf.String(), "ent=11")
}

// TestOpticDiscovery_ModularDuplicateBayNameDropped asserts the
// duplicate-bay-name guard also covers the full-mode-only submodule loop:
// two modular optics under separate linecards whose port cages happen to
// share the same name must not both be emitted. Only the first-seen
// survives; the second is skipped and warned about, exactly like the
// top-level guard.
func TestOpticDiscovery_ModularDuplicateBayNameDropped(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	oids := buildOIDs(duplicateModularBayNameOpticFixture())
	dev := &diode.Device{Name: strPtr("test-switch")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(oids, nil, memberDevices, modeFull(), nil, logger)

	var bayNames []string
	var serials []string
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.ModuleBay:
			require.NotNil(t, v.Name)
			bayNames = append(bayNames, *v.Name)
		case *diode.Module:
			if v.Serial != nil {
				serials = append(serials, *v.Serial)
			}
		}
	}

	var collidingBayCount int
	for _, n := range bayNames {
		if n == "Te1/0/1 Container" {
			collidingBayCount++
		}
	}
	assert.Equal(t, 1, collidingBayCount, "only the first-seen colliding bay may survive")
	assert.Contains(t, serials, "SYNLCA0001", "linecard A must still be emitted")
	assert.Contains(t, serials, "SYNLCB0001", "linecard B must still be emitted")
	assert.Contains(t, serials, "SYNSERBAYA", "the first-seen optic must be emitted")
	assert.NotContains(t, serials, "SYNSERBAYB", "the colliding second optic must not be emitted")
	assert.Contains(t, buf.String(), "duplicate transceiver bay name dropped")
	assert.Contains(t, buf.String(), `bay="Te1/0/1 Container"`)
	assert.Contains(t, buf.String(), "ent=202")
	assert.Contains(t, buf.String(), "member=0")
	assert.Contains(t, buf.String(), "model=SFP-10G-LR")
	assert.Contains(t, buf.String(), "reason=dup_bay_name")
}

// TestOpticDiscovery_CrossTierDuplicateBayNameDropped is the design-point
// test: it only passes because the top-level and submodule loops share ONE
// seenTransceiverBays map. A top-level fixed-port optic's bay resolves to
// "Ethernet1" via servedInterface; a modular optic nested under a separate
// linecard sits in a port cage literally named "Ethernet1". A per-loop map
// would let both survive as two ModuleBay("Ethernet1") objects on the same
// device — the exact merge-in-NetBox scenario the guard exists to prevent.
func TestOpticDiscovery_CrossTierDuplicateBayNameDropped(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	oids := buildOIDs(crossTierDuplicateBayNameOpticFixture())
	dev := &diode.Device{Name: strPtr("test-switch")}
	memberDevices := map[int]*diode.Device{0: dev}

	entities, _ := TranslateModules(oids, nil, memberDevices, modeFull(), nil, logger)

	var bayNames []string
	var serials []string
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.ModuleBay:
			require.NotNil(t, v.Name)
			bayNames = append(bayNames, *v.Name)
		case *diode.Module:
			if v.Serial != nil {
				serials = append(serials, *v.Serial)
			}
		}
	}

	var collidingBayCount int
	for _, n := range bayNames {
		if n == "Ethernet1" {
			collidingBayCount++
		}
	}
	assert.Equal(t, 1, collidingBayCount,
		"only one Ethernet1 bay may survive across the top-level and submodule tiers")
	assert.Contains(t, serials, "SYNSERTOP1", "the top-level fixed-port optic must win (seen first)")
	assert.NotContains(t, serials, "SYNSERSUB1", "the colliding modular optic must not be emitted")
	assert.Contains(t, buf.String(), "duplicate transceiver bay name dropped")
	assert.Contains(t, buf.String(), "bay=Ethernet1")
	assert.Contains(t, buf.String(), "ent=202")
	assert.Contains(t, buf.String(), "member=0")
	assert.Contains(t, buf.String(), "model=SFP-10G-LR")
	assert.Contains(t, buf.String(), "reason=dup_bay_name")
}

// TestOpticDiscovery_NameEqualToOwnPIDFallsBackToCageName pins Fix 2 at the
// extraction level: entPhysicalName equal to the optic's own effective PID
// must not become an interface-shaped bay name. With the descr naming no
// interface either, the bay must fall back to the cage-derived name
// instead of adopting the PID.
func TestOpticDiscovery_NameEqualToOwnPIDFallsBackToCageName(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(opticNameEqualsOwnPIDOpticFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 1)
	assert.Equal(t, "Te1/0/1 Container", inv.Modules[0].BayName,
		"the bay must fall back to the cage-derived name")
	assert.NotEqual(t, "SFP-10G-LR", inv.Modules[0].BayName,
		"the optic's own PID must never become the bay name")
}

// TestOpticDiscovery_CagelessLinecardOpticsGetDistinctBays pins the boundary
// between an optic's own cage and its module's slot. walkParents takes the
// nearest container and the nearest module independently, so for an optic with
// no cage it returns the container above the module — the linecard's slot.
// Naming every optic on the card after that one slot collides with the
// linecard's own bay and loses all but the first to the duplicate-bay guard.
func TestOpticDiscovery_CagelessLinecardOpticsGetDistinctBays(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(cagelessLinecardOpticsFixture()), testOpticLogger())

	subs := inv.SubModules["2000"]
	require.Len(t, subs, 3, "all three cageless optics nest under the linecard")

	var lcBay string
	for _, m := range inv.Modules {
		if m.Type == ModuleTypeLinecard {
			lcBay = m.BayName
		}
	}
	require.Equal(t, "Slot 2", lcBay, "the linecard keeps its slot-derived bay")

	seen := make(map[string]string, len(subs))
	for _, m := range subs {
		assert.Equal(t, ModuleTypeTransceiver, m.Type)
		assert.Equal(t, m.Name, m.BayName,
			"a cageless optic is named for the interface its row names")
		assert.NotEqual(t, lcBay, m.BayName,
			"an optic must never borrow its linecard's bay")
		if prev, dup := seen[m.BayName]; dup {
			t.Fatalf("bay %q shared by ent %s and ent %s: the duplicate-bay guard would drop one",
				m.BayName, prev, m.EntIndex)
		}
		seen[m.BayName] = m.EntIndex
	}
	assert.Len(t, seen, 3, "three optics, three distinct bays")
}

// TestOpticDiscovery_PIDPrefixesMatchDeviceDiscovery pins the optic PID
// designators. The set is MSA/SFF standardized, so it is shared with
// device-discovery's _OPTIC_PREFIXES; an optic recognised by one backend and
// not the other would make a device's inventory depend on which backend
// discovered it. Asserting the set explicitly means widening or narrowing it
// is a deliberate edit here, not a silent drift from the other backend.
func TestOpticDiscovery_PIDPrefixesMatchDeviceDiscovery(t *testing.T) {
	want := []string{
		"SFP-", "SFP+", "SFP28-", "SFP56-",
		"QSFP-", "QSFP+", "QSFP28", "QSFP56-",
		"QDD-", "OSFP-",
		"GLC-", "X2-", "CFP-", "CFP2-", "XENPAK-", "XFP-", "CVR-",
	}
	assert.ElementsMatch(t, want, opticPIDPrefixes,
		"keep in step with device-discovery custom_napalm/_modules.py _OPTIC_PREFIXES; "+
			"QSFP-DD is intentionally absent because QSFP- subsumes it")
}

func TestOpticDiscovery_OpticPIDRecognition(t *testing.T) {
	optics := []string{
		// Transcribed from captures that the previous seven-prefix set missed:
		// iosxe_c9400x-svl and iosxe_c9500x-svl, the StackWise Virtual pairs
		// this discovery path exists to serve.
		"QDD-400G-CU1M",
		"CVR-QSFP-SFP10G",
		// One per newly added designator.
		"SFP+10G-LR", "SFP28-25G-SR", "SFP56-50G-SR",
		"QSFP+40G-SR4", "QSFP28-100G-LR4", "QSFP56-200G-SR4",
		"OSFP-800G-DR8", "CFP2-100G-LR4",
		// Already recognised before; kept so a reordering cannot lose them.
		"SFP-10G-LR", "QSFP-100G-SR4", "GLC-LH-SMD",
		"X2-10GB-LR", "CFP-100G-LR4", "XENPAK-10GB-LR", "XFP-10G-MM-SR",
	}
	for _, pid := range optics {
		assert.True(t, isOpticPID(pid, ""), "%s should be recognised as an optic", pid)
		// vendorType carries the PID when model is blank.
		assert.True(t, isOpticPID("", pid), "%s should be recognised via vendorType", pid)
		assert.True(t, isOpticPID(strings.ToLower(pid), ""), "%s should match case-insensitively", pid)
	}

	notOptics := []string{
		"C9400-LC-48UX", "C9400-SUP-1", "C9404R", "PWR-C4-950WAC-R",
		"FAN-T1-R", "OS6350-P24", "STACK-T1-50CM", "",
		// Near-misses: a shared leading substring must not be enough.
		"SFPX-99", "QSFPX-99", "GLCX-1", "CVRX-1",
	}
	for _, pid := range notOptics {
		assert.False(t, isOpticPID(pid, ""), "%q must not be taken for an optic", pid)
	}
}

// TestOpticDiscovery_ChassisRootedModuleOpticsGetDistinctBays covers the second
// cageless shape. An optic under a chassis-rooted module has no container above
// it, so its bay is synthesized from its own row and named for ParentRel.
// bayBelowModule answers true for that bay — but only because the optic is
// trivially beneath its own parent, not because a cage exists — so the interface
// name has to be applied on the strength of the bay being synthesized. Platforms
// that report a non-positional ParentRel for every child would otherwise give
// every optic the same bay name and lose all but one to the duplicate-bay guard.
func TestOpticDiscovery_ChassisRootedModuleOpticsGetDistinctBays(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(chassisRootedModuleOpticsFixture()), testOpticLogger())

	subs := inv.SubModules["1"]
	require.Len(t, subs, 3, "all three optics nest under the chassis-rooted module")

	seen := make(map[string]string, len(subs))
	for _, m := range subs {
		assert.Equal(t, ModuleTypeTransceiver, m.Type)
		assert.Equal(t, m.Name, m.BayName, "named for the interface the row names")
		assert.NotEqual(t, "Slot -1", m.BayName, "a non-positional ParentRel must not name the bay")
		if prev, dup := seen[m.BayName]; dup {
			t.Fatalf("bay %q shared by ent %s and ent %s: the duplicate-bay guard would drop one",
				m.BayName, prev, m.EntIndex)
		}
		seen[m.BayName] = m.EntIndex
	}
	assert.Len(t, seen, 3, "three optics, three distinct bays")
}
