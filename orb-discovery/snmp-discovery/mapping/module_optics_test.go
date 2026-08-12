// Copyright 2026 NetBox Labs, Inc.

package mapping

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

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
			for _, b := range inv.EmptyBays {
				assert.NotContains(t, opticIdxs, b.EntIndex,
					"optic row %s emitted as an empty bay", b.EntIndex)
			}
		})
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
	assert.Equal(t, "Ethernet1", servedInterface("", "Xcvr for Ethernet1"))
	assert.Empty(t, servedInterface("", "Lane 0 for Xcvr for Ethernet1"))
	assert.Empty(t, servedInterface("", "Xcvr Slot 1"))
}

// TestOpticDiscovery_NonInterfaceNameRejected pins the digit requirement.
// One platform names every optic row with the literal token "port";
// accepting it would name every bay on the chassis identically and merge
// them into one object.
func TestOpticDiscovery_NonInterfaceNameRejected(t *testing.T) {
	assert.Empty(t, servedInterface("port", ""))
	assert.Empty(t, servedInterface("SFP cage", ""))
	assert.Equal(t, "Ethernet0", servedInterface("Ethernet0", ""))
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

// TestOpticDiscovery_SerialFreeOpticsSkippedWithOneWarning asserts optics
// without a serial are not emitted and that the warning is aggregated: one
// captured platform publishes 25 such rows, and a line each would mean 25
// per poll.
func TestOpticDiscovery_SerialFreeOpticsSkippedWithOneWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	inv := extractModuleInventory(buildOIDs(serialFreePortOpticFixture()), logger)

	assert.Empty(t, inv.Modules, "an optic with no serial cannot be emitted")
	assert.Equal(t, 1, strings.Count(buf.String(), "optics skipped for missing serial"),
		"exactly one aggregated warning")
	assert.Contains(t, buf.String(), "count=3")
}
