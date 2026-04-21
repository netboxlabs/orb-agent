package backend

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertToRunData_MapsAllFields(t *testing.T) {
	// Nanosecond timestamps — matches the wire format all backends actually emit.
	ts1Ns := int64(1742464800000000000) // 2025-03-20T10:00:00Z in nanoseconds
	ts2Ns := int64(1742465100000000000) // 2025-03-20T10:05:00Z in nanoseconds
	ts3Ns := int64(1742551200000000000) // 2025-03-21T10:00:00Z in nanoseconds
	ts4Ns := int64(1742553000000000000) // 2025-03-21T10:30:00Z in nanoseconds

	ts1 := time.Unix(0, ts1Ns).UTC()
	ts2 := time.Unix(0, ts2Ns).UTC()
	ts3 := time.Unix(0, ts3Ns).UTC()
	ts4 := time.Unix(0, ts4Ns).UTC()

	entityCount := int64(42)

	statusRuns := []PolicyStatusRun{
		{
			ID:          "run-completed",
			Status:      "completed",
			Reason:      "finished normally",
			EntityCount: entityCount,
			CreatedAt:   ts1Ns,
			UpdatedAt:   ts2Ns,
		},
		{
			ID:        "run-failed",
			Status:    "failed",
			Reason:    "timeout",
			CreatedAt: ts3Ns,
			UpdatedAt: ts4Ns,
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

	// Running run: zero int64 timestamps (omitted/missing) become zero time.Time
	// so that UpdateRuns' IsZero() fallback fires correctly.
	r2 := runs[2]
	assert.Equal(t, "run-running", r2.ID)
	assert.Equal(t, "running", r2.Status)
	assert.Empty(t, r2.Reason)
	assert.Zero(t, r2.EntityCount)
	assert.True(t, r2.CreatedAt.IsZero(), "zero int64 should map to zero time.Time, not Unix epoch")
	assert.True(t, r2.UpdatedAt.IsZero(), "zero int64 should map to zero time.Time, not Unix epoch")

	// PolicyID should never be set by the converter (repo owns that)
	for _, r := range runs {
		assert.Empty(t, r.PolicyID, "PolicyID must not be set by convertToRunData")
	}
}

func TestNsToTime_ZeroIsZeroTime(t *testing.T) {
	// Zero ns must map to zero time.Time, not Unix epoch, so IsZero() guards work.
	assert.True(t, nsToTime(0).IsZero(), "nsToTime(0) must return zero time.Time")
}

func TestNsToTime_NonZeroConvertsCorrectly(t *testing.T) {
	ns := int64(1742464800000000000)
	expected := time.Unix(0, ns).UTC()
	assert.Equal(t, expected, nsToTime(ns))
}

func TestConvertToRunData_EmptyInput(t *testing.T) {
	runs := convertToRunData(nil)
	require.Len(t, runs, 0)
}

func TestPolicyStatusRun_TargetsOmittedWhenEmptyOnWire(t *testing.T) {
	// Incoming backend JSON with NO targets field must unmarshal cleanly and leave Targets nil.
	payload := []byte(`{"id":"run-1","status":"running","created_at":0,"updated_at":0}`)

	var r PolicyStatusRun
	require.NoError(t, json.Unmarshal(payload, &r))

	assert.Nil(t, r.Targets)
}

func TestPolicyStatusRun_TargetsUnmarshaledWhenPresent(t *testing.T) {
	payload := []byte(`{"id":"run-1","status":"completed","targets":["10.0.0.1","10.0.0.2"],"created_at":0,"updated_at":0}`)

	var r PolicyStatusRun
	require.NoError(t, json.Unmarshal(payload, &r))

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, r.Targets)
}

func TestPolicyStatusRun_TargetsMarshaledAsOmitempty(t *testing.T) {
	// Constructing a PolicyStatusRun with no Targets must omit the key entirely.
	r := PolicyStatusRun{ID: "run-1", Status: "running"}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	assert.NotContains(t, string(body), "targets")
}
