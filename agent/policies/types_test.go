package policies_test

import (
	"database/sql/driver"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

func TestPolicyStateString(t *testing.T) {
	testCases := []struct {
		state    policies.PolicyState
		expected string
	}{
		{policies.Unknown, "unknown"},
		{policies.Running, "running"},
		{policies.FailedToApply, "failed_to_apply"},
		{policies.Offline, "offline"},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.expected, tc.state.String())
	}
}

func TestPolicyStateScan(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected policies.PolicyState
	}{
		{[]byte("unknown"), policies.Unknown},
		{[]byte("running"), policies.Running},
		{[]byte("failed_to_apply"), policies.FailedToApply},
		{[]byte("offline"), policies.Offline},
	}

	for _, tc := range testCases {
		var state policies.PolicyState
		err := state.Scan(tc.input)

		assert.NoError(t, err)
		assert.Equal(t, tc.expected, state)
	}
}

func TestPolicyStateValue(t *testing.T) {
	testCases := []struct {
		state    policies.PolicyState
		expected driver.Value
	}{
		{policies.Unknown, "unknown"},
		{policies.Running, "running"},
		{policies.FailedToApply, "failed_to_apply"},
		{policies.Offline, "offline"},
	}

	for _, tc := range testCases {
		value, err := tc.state.Value()

		assert.NoError(t, err)
		assert.Equal(t, tc.expected, value)
	}
}

func TestGetDatasetIDs(t *testing.T) {
	testCases := []struct {
		datasets  map[string]bool
		expectedN int
	}{
		{map[string]bool{}, 0},
		{map[string]bool{"dataset1": true}, 1},
		{map[string]bool{"dataset1": true, "dataset2": true}, 2},
		{map[string]bool{"dataset1": true, "dataset2": true, "dataset3": true}, 3},
	}

	for _, tc := range testCases {
		pd := policies.PolicyData{
			Datasets: tc.datasets,
		}

		ids := pd.GetDatasetIDs()

		assert.Len(t, ids, tc.expectedN)

		// Verify all expected IDs are in the result
		for id := range tc.datasets {
			assert.Contains(t, ids, id)
		}
	}
}
