package backend

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

func TestConvertToRunData_UpdatedAtPreservedWhenUnchanged(t *testing.T) {
	// When status, reason, and entity count are unchanged, UpdatedAt should be preserved
	existingUpdatedAt := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC) // Newer but should be ignored

	entityCount := int64(42)
	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: &entityCount,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   backendUpdatedAt,
		},
	}
	existingRuns := []policies.RunData{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: &entityCount,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   existingUpdatedAt,
		},
	}

	runs := convertToRunData(statusRuns, existingRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, existingUpdatedAt, runs[0].UpdatedAt, "UpdatedAt should be preserved when status, reason, entity count unchanged")
}

func TestConvertToRunData_UpdatedAtChangedWhenStatusChanges(t *testing.T) {
	existingUpdatedAt := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)

	entityCount := int64(42)
	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-1",
			Status:      "failed", // Changed from completed
			Reason:      "",
			EntityCount: &entityCount,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   backendUpdatedAt,
		},
	}
	existingRuns := []policies.RunData{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: &entityCount,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   existingUpdatedAt,
		},
	}

	runs := convertToRunData(statusRuns, existingRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, backendUpdatedAt, runs[0].UpdatedAt, "UpdatedAt should be updated when status changes")
}

func TestConvertToRunData_UpdatedAtChangedWhenReasonChanges(t *testing.T) {
	existingUpdatedAt := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)

	entityCount := int64(42)
	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "policy error", // Changed
			EntityCount: &entityCount,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   backendUpdatedAt,
		},
	}
	existingRuns := []policies.RunData{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: &entityCount,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   existingUpdatedAt,
		},
	}

	runs := convertToRunData(statusRuns, existingRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, backendUpdatedAt, runs[0].UpdatedAt, "UpdatedAt should be updated when reason changes")
}

func TestConvertToRunData_UpdatedAtChangedWhenEntityCountChanges(t *testing.T) {
	existingUpdatedAt := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)

	entityCountOld := int64(42)
	entityCountNew := int64(100)
	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: &entityCountNew, // Changed
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   backendUpdatedAt,
		},
	}
	existingRuns := []policies.RunData{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: &entityCountOld,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   existingUpdatedAt,
		},
	}

	runs := convertToRunData(statusRuns, existingRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, backendUpdatedAt, runs[0].UpdatedAt, "UpdatedAt should be updated when entity count changes")
}

func TestConvertToRunData_UpdatedAtFromBackendWhenNewRun(t *testing.T) {
	// When run doesn't exist in existing runs, use backend's UpdatedAt
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)

	statusRuns := []PolicyStatusRun{
		{
			ID:        "run-new",
			Status:    "completed",
			Reason:    "",
			CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt: backendUpdatedAt,
		},
	}
	existingRuns := []policies.RunData{} // No existing runs

	runs := convertToRunData(statusRuns, existingRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, backendUpdatedAt, runs[0].UpdatedAt, "UpdatedAt should come from backend for new run")
}

func TestConvertToRunData_UpdatedAtPreservedWithNilEntityCount(t *testing.T) {
	// Both nil entity counts should be considered equal
	existingUpdatedAt := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)

	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: nil,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   backendUpdatedAt,
		},
	}
	existingRuns := []policies.RunData{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: nil,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   existingUpdatedAt,
		},
	}

	runs := convertToRunData(statusRuns, existingRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, existingUpdatedAt, runs[0].UpdatedAt, "UpdatedAt should be preserved when both entity counts are nil")
}

func TestConvertToRunData_UpdatedAtChangedWhenEntityCountNilToValue(t *testing.T) {
	// Going from nil to a value is a change
	existingUpdatedAt := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)
	entityCount := int64(42)

	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: &entityCount,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   backendUpdatedAt,
		},
	}
	existingRuns := []policies.RunData{
		{
			ID:          "run-1",
			Status:      "completed",
			Reason:      "",
			EntityCount: nil,
			CreatedAt:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt:   existingUpdatedAt,
		},
	}

	runs := convertToRunData(statusRuns, existingRuns)

	require.Len(t, runs, 1)
	assert.Equal(t, backendUpdatedAt, runs[0].UpdatedAt, "UpdatedAt should be updated when entity count changes from nil to value")
}

func TestConvertToRunData_WithNilExistingRuns(t *testing.T) {
	// When existingRuns is nil, all runs should use backend's UpdatedAt
	backendUpdatedAt := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)

	statusRuns := []PolicyStatusRun{
		{
			ID:        "run-1",
			Status:    "completed",
			CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			UpdatedAt: backendUpdatedAt,
		},
	}

	runs := convertToRunData(statusRuns, nil)

	require.Len(t, runs, 1)
	assert.Equal(t, backendUpdatedAt, runs[0].UpdatedAt)
}
