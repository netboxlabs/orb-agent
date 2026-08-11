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

// TestOpticDiscovery_LaneShapeCharacterization records what the extractor
// does with the lane shape BEFORE this plan's changes. Every class-9 row on
// that platform is a lane, so the lanes become the entire module inventory:
// typed linecard, no model, no serial, and all sharing the bay position the
// optic row reports.
func TestOpticDiscovery_LaneShapeCharacterization(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(fixedPortLaneShapeFixture()), testOpticLogger())

	require.Len(t, inv.Modules, 3, "the three lane rows are emitted as modules")
	for _, m := range inv.Modules {
		assert.Equal(t, ModuleTypeLinecard, m.Type, "lane misclassified as a linecard")
		assert.Empty(t, m.Model, "lane carries no model")
		assert.Empty(t, m.Serial, "lane carries no serial")
		assert.Empty(t, m.BayName, "bay is the optic row, whose Name is empty")
		assert.Equal(t, "1", m.BayPosition, "so every lane shares bay position 1")
		assert.NotEqual(t, "SFP-10GLR-31", m.Model, "the real optic is not discovered")
	}
	assert.Empty(t, inv.SubModules, "no transceiver is emitted anywhere")
}

// TestOpticDiscovery_HarvestShapeCharacterization records the second
// mechanism. An optic with no lane child reaches the empty-bay harvest, so
// it is emitted as a bare bay with its model and serial discarded, and all
// three share bay position "1".
func TestOpticDiscovery_HarvestShapeCharacterization(t *testing.T) {
	inv := extractModuleInventory(buildOIDs(fixedPortHarvestShapeFixture()), testOpticLogger())

	assert.Empty(t, inv.Modules, "no modules at all on this shape today")

	var optics []ModuleEntry
	for _, b := range inv.EmptyBays {
		switch b.EntIndex {
		case "100301100", "100302100", "100303100":
			optics = append(optics, b)
		}
	}
	require.Len(t, optics, 3, "all three optics are harvested as empty bays")
	for _, b := range optics {
		assert.Equal(t, ModuleTypeUnknown, b.Type)
		assert.Empty(t, b.Model, "the harvest discards the model")
		assert.Empty(t, b.Serial, "the harvest discards the serial")
		assert.Equal(t, "1", b.BayPosition, "all three share bay position 1")
	}
}
