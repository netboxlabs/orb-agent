package backend

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertToRunData_MapsAllFields(t *testing.T) {
	ts1 := time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 3, 20, 10, 5, 0, 0, time.UTC)
	ts3 := time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC)
	ts4 := time.Date(2026, 3, 21, 8, 30, 0, 0, time.UTC)
	entityCount := int64(42)

	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-completed",
			Status:      "completed",
			Reason:      "finished normally",
			EntityCount: entityCount,
			CreatedAt:   ts1,
			UpdatedAt:   ts2,
		},
		{
			ID:        "run-failed",
			Status:    "failed",
			Reason:    "timeout",
			CreatedAt: ts3,
			UpdatedAt: ts4,
		},
		{
			ID:     "run-running",
			Status: "running",
			// All optional fields left at zero values
		},
	}

	runs := convertToRunData(statusRuns)
	require.Len(t, runs, 3)

	// Completed run: every field populated
	r0 := runs[0]
	assert.Equal(t, "run-completed", r0.ID)
	assert.Equal(t, "completed", r0.Status)
	assert.Equal(t, "finished normally", r0.Reason)
	require.NotNil(t, r0.EntityCount)
	assert.Equal(t, int64(42), r0.EntityCount)
	assert.Equal(t, ts1, r0.CreatedAt)
	assert.Equal(t, ts2, r0.UpdatedAt)

	// Failed run: no entity count
	r1 := runs[1]
	assert.Equal(t, "run-failed", r1.ID)
	assert.Equal(t, "failed", r1.Status)
	assert.Equal(t, "timeout", r1.Reason)
	assert.Zero(t, r1.EntityCount)
	assert.Equal(t, ts3, r1.CreatedAt)
	assert.Equal(t, ts4, r1.UpdatedAt)

	// Running run: zero-value optionals pass through as-is
	r2 := runs[2]
	assert.Equal(t, "run-running", r2.ID)
	assert.Equal(t, "running", r2.Status)
	assert.Empty(t, r2.Reason)
	assert.Zero(t, r2.EntityCount)
	assert.True(t, r2.CreatedAt.IsZero(), "zero CreatedAt should pass through unchanged")
	assert.True(t, r2.UpdatedAt.IsZero(), "zero UpdatedAt should pass through unchanged")

	// PolicyID should never be set by the converter (repo owns that)
	for _, r := range runs {
		assert.Empty(t, r.PolicyID, "PolicyID must not be set by convertToRunData")
	}
}

func TestConvertToRunData_EmptyInput(t *testing.T) {
	runs := convertToRunData(nil)
	require.Len(t, runs, 0)
}
