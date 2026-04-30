package messages

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentHeartbeatSchemaVersion_IsOneOne(t *testing.T) {
	assert.Equal(t, "1.1", CurrentHeartbeatSchemaVersion)
}

func TestRunStateInfo_TargetsOmittedWhenNil(t *testing.T) {
	r := RunStateInfo{ID: "run-1", PolicyID: "policy-1", Status: "running"}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	assert.NotContains(t, string(body), "targets")
}

func TestRunStateInfo_TargetsOmittedWhenEmptySlice(t *testing.T) {
	r := RunStateInfo{ID: "run-1", PolicyID: "policy-1", Status: "running", Targets: []string{}}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	// omitempty on a slice omits both nil AND empty — this is what the contract requires.
	assert.NotContains(t, string(body), "targets")
}

func TestRunStateInfo_TargetsIncludedWhenPresent(t *testing.T) {
	r := RunStateInfo{
		ID:       "run-1",
		PolicyID: "policy-1",
		Status:   "completed",
		Targets:  []string{"10.0.0.1", "10.0.0.2"},
	}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))

	targets, ok := decoded["targets"].([]any)
	require.True(t, ok, "expected targets to be a JSON array")
	require.Len(t, targets, 2)
	assert.Equal(t, "10.0.0.1", targets[0])
	assert.Equal(t, "10.0.0.2", targets[1])
}

func TestRunStateInfo_DriverOmittedWhenEmpty(t *testing.T) {
	r := RunStateInfo{ID: "run-1", PolicyID: "policy-1", Status: "running"}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	assert.NotContains(t, string(body), "driver")
}

func TestRunStateInfo_DriverIncludedWhenPresent(t *testing.T) {
	r := RunStateInfo{
		ID:       "run-1",
		PolicyID: "policy-1",
		Status:   "completed",
		Driver:   "junos",
	}

	body, err := json.Marshal(r)
	require.NoError(t, err)

	assert.Contains(t, string(body), `"driver":"junos"`)
}
