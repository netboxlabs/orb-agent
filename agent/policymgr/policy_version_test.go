package policymgr_test

import (
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// ASUR-1614 end to end: a run that started under v1 and is first reported
// after v2 was applied is stamped v1. The new version replaces the record and
// drops its runs, so the list of applied versions must survive that write.
func TestARunFirstSeenAfterANewVersionGetsTheVersionItStartedUnder(t *testing.T) {
	be, mgr := newVersionTestManager(t, "version_survives_update")
	payload := config.PolicyPayload{Action: "manage", ID: "pv", Name: "pv", Backend: "version_survives_update", DatasetID: "ds", Version: 1, Data: map[string]any{}}

	var sentV2 time.Time
	be.On("ApplyPolicy", isPolicy("pv", 1), false).Return(nil).Once()
	mgr.ManagePolicy(payload)
	runUnderV1 := time.Now()
	be.On("ApplyPolicy", isPolicy("pv", 2), true).Run(func(mock.Arguments) { sentV2 = time.Now() }).Return(nil).Once()
	payload.Version = 2
	payload.DatasetID = ""
	mgr.ManagePolicy(payload)
	be.AssertExpectations(t)

	stored, err := mgr.GetRepo().Get("pv")
	require.NoError(t, err)
	require.Equal(t, []int32{1, 2}, appliedVersions(stored))
	assert.False(t, stored.Applied[1].At.After(sentV2), "the time is taken before the backend is called")

	require.NoError(t, mgr.GetRepo().UpdateRuns("pv", []policies.RunData{
		{ID: "old", Status: "completed", CreatedAt: runUnderV1},
		{ID: "new", Status: "running", CreatedAt: time.Now()},
	}))
	stored, err = mgr.GetRepo().Get("pv")
	require.NoError(t, err)
	require.Len(t, stored.Runs, 2)
	assert.Equal(t, int32(1), stored.Runs[0].PolicyVersion)
	assert.Equal(t, int32(2), stored.Runs[1].PolicyVersion)
}

// A version is recorded once, however many times it is applied, and not at
// all when the backend refused it before sending its process anything.
func TestAppliedVersionsRecordsEachVersionTheBackendWasSentOnce(t *testing.T) {
	tests := []struct {
		name      string
		firstErr  error
		wantAfter []int32 // after the first apply of v1
	}{
		{name: "backend failed after it was sent", firstErr: errors.New("timed out"), wantAfter: []int32{1}},
		{name: "backend refused before it was sent", firstErr: backend.NotSent(errors.New("bad name")), wantAfter: nil},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			beName := []string{"version_failed", "version_not_sent"}[i]
			be, mgr := newVersionTestManager(t, beName)
			payload := config.PolicyPayload{Action: "manage", ID: "pv", Name: "pv", Backend: beName, DatasetID: "ds", Version: 1, Data: map[string]any{}}

			be.On("ApplyPolicy", isPolicy("pv", 1), mock.Anything).Return(tc.firstErr).Once()
			mgr.ManagePolicy(payload)
			stored, err := mgr.GetRepo().Get("pv")
			require.NoError(t, err)
			require.Equal(t, policies.FailedToApply, stored.State)
			assert.Equal(t, tc.wantAfter, appliedVersions(stored))
			first := stored.Applied

			// The same version again, this time accepted.
			be.On("ApplyPolicy", isPolicy("pv", 1), mock.Anything).Return(nil).Once()
			mgr.ManagePolicy(payload)
			be.AssertExpectations(t)
			stored, err = mgr.GetRepo().Get("pv")
			require.NoError(t, err)
			require.Equal(t, policies.Running, stored.State)
			assert.Equal(t, []int32{1}, appliedVersions(stored))
			if len(first) > 0 {
				assert.True(t, first[0].At.Equal(stored.Applied[0].At), "the re-apply keeps the first entry as it was")
			}
		})
	}
}

func newVersionTestManager(t *testing.T, beName string) (*mockBackend, policymgr.PolicyManager) {
	t.Helper()
	be := &mockBackend{name: beName}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register(beName, be)
	mgr, err := policymgr.New(slog.New(slog.NewTextHandler(os.Stdout, nil)), &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	return be, mgr
}

func appliedVersions(pd policies.PolicyData) []int32 {
	var out []int32
	for _, a := range pd.Applied {
		out = append(out, a.Version)
	}
	return out
}
