package policies_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

func TestUpdateRunsStampsThePolicyVersionARunStartedUnder(t *testing.T) {
	v1At := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	v2At := v1At.Add(time.Hour)
	applied := []policies.AppliedVersion{{Version: 1, At: v1At}, {Version: 2, At: v2At}}

	tests := []struct {
		name      string
		createdAt time.Time
		stored    *policies.RunData // the run as the record already holds it
		want      int32
	}{
		{
			// ASUR-1614: the run ended just before v2 was saved and is first
			// reported after v2 was applied.
			name:      "run created under v1 and first seen after v2 is v1",
			createdAt: v2At.Add(-time.Second),
			want:      1,
		},
		{name: "run created after v2 was applied is v2", createdAt: v2At.Add(time.Second), want: 2},
		{name: "run created at the instant v2 was applied is v2", createdAt: v2At, want: 2},
		{name: "run with no created_at stays 0", want: 0},
		{name: "run older than the first apply stays 0", createdAt: v1At.Add(-time.Second), want: 0},
		{
			name:      "existing run keeps its stored version",
			createdAt: v2At.Add(time.Second),
			stored:    &policies.RunData{ID: "run-1", Status: "running", PolicyVersion: 1},
			want:      1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo, err := policies.NewMemRepo()
			require.NoError(t, err)
			pd := policies.PolicyData{ID: "p-id", Name: "p", Version: 2, Applied: applied}
			if tc.stored != nil {
				pd.Runs = []policies.RunData{*tc.stored}
			}
			require.NoError(t, repo.Update(pd))

			require.NoError(t, repo.UpdateRuns("p", []policies.RunData{
				{ID: "run-1", Status: "completed", CreatedAt: tc.createdAt},
			}))

			got, err := repo.Get("p-id")
			require.NoError(t, err)
			require.Len(t, got.Runs, 1)
			assert.Equal(t, tc.want, got.Runs[0].PolicyVersion)
		})
	}
}

func TestRecordApplied(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	entries := func(versions ...int32) []policies.AppliedVersion {
		out := make([]policies.AppliedVersion, len(versions))
		for i, v := range versions {
			out[i] = policies.AppliedVersion{Version: v, At: at}
		}
		return out
	}

	tests := []struct {
		name    string
		applied []policies.AppliedVersion
		version int32
		want    []int32
	}{
		{name: "first version is added", version: 1, want: []int32{1}},
		{name: "new version is added last", applied: entries(1), version: 2, want: []int32{1, 2}},
		{name: "re-apply of the same version adds nothing", applied: entries(1, 2), version: 2, want: []int32{1, 2}},
		{name: "version 0 adds nothing", applied: entries(1), version: 0, want: []int32{1}},
		{name: "only the last five are kept", applied: entries(1, 2, 3, 4, 5), version: 6, want: []int32{2, 3, 4, 5, 6}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pd := policies.PolicyData{Applied: tc.applied}
			pd.RecordApplied(tc.version, at)

			got := make([]int32, len(pd.Applied))
			for i, a := range pd.Applied {
				got[i] = a.Version
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// A copy of the record read from the repo must not write into the stored
// record's list when it records a new version.
func TestRecordAppliedDoesNotShareTheStoredList(t *testing.T) {
	stored := make([]policies.AppliedVersion, 1, 4)
	stored[0] = policies.AppliedVersion{Version: 1}
	pd := policies.PolicyData{Applied: stored}

	pd.RecordApplied(2, time.Now())

	assert.Equal(t, int32(0), stored[:2][1].Version, "the stored list's spare room is untouched")
}
