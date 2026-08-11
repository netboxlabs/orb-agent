// Copyright 2026 NetBox Labs, Inc.

package mapping

import (
	"log/slog"
	"os"
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
