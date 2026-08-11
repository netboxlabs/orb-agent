// Copyright 2026 NetBox Labs, Inc.

package mapping

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testOpticLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// TestOpticDiscovery_LaneRowsNotEmittedAsModules asserts the per-lane
// sub-entities published beneath each optic are not modules. On this platform
// every class-9 row is a lane, so before this rule the device's entire module
// inventory was lanes.
func TestOpticDiscovery_LaneRowsNotEmittedAsModules(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(fixedPortLaneShapeFixture()), testOpticLogger())

	assert.Empty(t, inv.Modules, "lane rows must not be emitted as modules")
	assert.Empty(t, inv.SubModules)
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
