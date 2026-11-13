package policymgr_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

func isPolicy(id string, version int32) any {
	return mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == id && pd.Version == version })
}

// A policy stored while its backend starts on demand reaches the backend
// first through the replay after the start. Nothing of it runs there yet, so
// the replay applies it fresh instead of as an update that removes it first:
// the backend would answer that removal with a 404. Once applied, an edit is
// an update again.
func TestReplayAppliesAPolicyNoApplyReachedYetWithoutRemovingIt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	be := &mockBackend{name: "first_apply_replay"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("first_apply_replay", be)
	mgr, err := policymgr.New(logger, &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	starter := &fakeStarter{state: policymgr.StartStarting}
	mgr.SetStarter(starter)
	payload := config.PolicyPayload{Action: "manage", ID: "fresh-1", Name: "fresh", Backend: "first_apply_replay", DatasetID: "ds", Version: 1, Data: map[string]any{}}

	mgr.ManagePolicy(payload)
	be.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)

	be.On("ApplyPolicy", isPolicy("fresh-1", 1), false).Return(nil).Once()
	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "first_apply_replay", be))
	be.AssertExpectations(t)
	stored, err := mgr.GetRepo().Get("fresh-1")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)

	starter.state = policymgr.StartRunning
	be.On("ApplyPolicy", isPolicy("fresh-1", 2), true).Return(nil).Once()
	edit := payload
	edit.Version = 2
	edit.DatasetID = ""
	mgr.ManagePolicy(edit)
	be.AssertExpectations(t)
}

// A manage that lands once the backend runs but before the replay reaches
// the policy stored while it started applies it directly. It is still the
// policy's first apply, so it is not an update either.
func TestManageAppliesAPolicyNoApplyReachedYetWithoutRemovingIt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	be := &mockBackend{name: "first_apply_manage"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("first_apply_manage", be)
	mgr, err := policymgr.New(logger, &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	starter := &fakeStarter{state: policymgr.StartStarting}
	mgr.SetStarter(starter)
	payload := config.PolicyPayload{Action: "manage", ID: "fresh-2", Name: "fresh", Backend: "first_apply_manage", DatasetID: "ds", Version: 1, Data: map[string]any{}}
	mgr.ManagePolicy(payload)

	starter.state = policymgr.StartRunning
	be.On("ApplyPolicy", isPolicy("fresh-2", 2), false).Return(nil).Once()
	edit := payload
	edit.Version = 2
	mgr.ManagePolicy(edit)

	be.AssertExpectations(t)
	stored, err := mgr.GetRepo().Get("fresh-2")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "first_apply_manage", be))
	be.AssertExpectations(t) // the replay skips the running record: a second apply would panic
}

// A policy whose first manage failed on its secrets never reached the
// backend: once its secrets resolve, the refresh applies it fresh.
func TestSecretsRefreshAppliesAPolicyNoApplyReachedYetWithoutRemovingIt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	be := &mockBackend{name: "first_apply_refresh"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("first_apply_refresh", be)
	// Unresolved keeps answering that the secret fails, so the manage does
	// not retry the apply itself.
	secretsMgr := &mockSecretsManager{}
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	payload := config.PolicyPayload{Action: "manage", ID: "fresh-3", Name: "fresh", Backend: "first_apply_refresh", DatasetID: "ds", Version: 1, Data: map[string]any{}}
	secretsMgr.On("SolvePolicySecrets", payload).Return(config.PolicyPayload{}, errors.New("secret not found")).Once()
	mgr.ManagePolicy(payload)
	be.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)

	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(payload, nil).Once()
	be.On("ApplyPolicy", isPolicy("fresh-3", 1), false).Return(nil).Once()
	secretsMgr.TriggerCallbacks(map[string]error{"fresh-3": nil})

	be.AssertExpectations(t)
	stored, err := mgr.GetRepo().Get("fresh-3")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
}

// A first apply the backend answered with an error may still have created
// the policy: one that timed out, or half succeeded, leaves that unknown. The
// next apply is therefore an update, which removes whatever the first one
// left before applying the new version, whether the first apply came from a
// manage or from the replay after an on-demand start.
func TestAFailedFirstApplyMakesTheNextApplyAnUpdate(t *testing.T) {
	timedOut := errors.New("Post \"http://127.0.0.1/api/v1/policies\": context deadline exceeded")
	for name, deferred := range map[string]bool{"manage": false, "replay": true} {
		t.Run(name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
			beName := "first_apply_failed_" + name
			be := &mockBackend{name: beName}
			be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
			backend.Register(beName, be)
			mgr, err := policymgr.New(logger, &mockSecretsManager{passthrough: true}, config.Config{})
			require.NoError(t, err)
			starter := &fakeStarter{state: policymgr.StartRunning}
			if deferred {
				starter.state = policymgr.StartStarting
			}
			mgr.SetStarter(starter)
			payload := config.PolicyPayload{Action: "manage", ID: "failed-1", Name: "failed", Backend: beName, DatasetID: "ds", Version: 1, Data: map[string]any{}}

			be.On("ApplyPolicy", isPolicy("failed-1", 1), false).Return(timedOut).Once()
			mgr.ManagePolicy(payload)
			if deferred {
				require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), beName, be))
			}
			stored, err := mgr.GetRepo().Get("failed-1")
			require.NoError(t, err)
			require.Equal(t, policies.FailedToApply, stored.State)

			starter.state = policymgr.StartRunning
			be.On("ApplyPolicy", isPolicy("failed-1", 2), true).Return(nil).Once()
			edit := payload
			edit.Version = 2
			mgr.ManagePolicy(edit)

			be.AssertExpectations(t)
		})
	}
}

// replayAfterRestartRemoval applies two policies to a backend, removes them
// for a restart whose removal returns removeErr, edits one while the restart
// is in flight, and replays them with the backend's process kept, as a
// restart whose configure failed does. It reports whether the replay
// applied each as an update.
func replayAfterRestartRemoval(t *testing.T, beName string, removeErr error) (keptUpdated, editedUpdated bool) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	be := &mockBackend{name: beName}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("RemovePolicy", mock.Anything).Return(removeErr).Times(2)
	backend.Register(beName, be)
	mgr, err := policymgr.New(logger, &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	for _, id := range []string{"kept", "edited"} {
		be.On("ApplyPolicy", isPolicy(id, 1), false).Return(nil).Once()
		mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: id, Name: id, Backend: beName, DatasetID: "ds", Version: 1, Data: map[string]any{}})
	}

	require.NoError(t, mgr.RemoveBackendPolicies(beName, be, false))
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "edited", Name: "edited", Backend: beName, Version: 2, Data: map[string]any{}})
	stored, err := mgr.GetRepo().Get("edited")
	require.NoError(t, err)
	require.Equal(t, policymgr.ReasonBackendStarting, stored.BackendErr, "the edit must wait for the replay")

	updated := map[string]bool{}
	be.On("ApplyPolicy", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		pd, _ := args.Get(0).(policies.PolicyData)
		updated[pd.ID], _ = args.Get(1).(bool)
	}).Return(nil).Times(2)
	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), beName, be))
	be.AssertExpectations(t)
	return updated["kept"], updated["edited"]
}

// A restart removes the backend's policies before it resets the backend. A
// removal the backend confirmed, or answered that it has no such policy,
// leaves nothing of the policy there: the replay applies it, and an edit of
// it that arrived during the restart, without removing it again, even when
// the restart kept the backend's process because its configure failed.
func TestReplayAfterAConfirmedRestartRemovalAppliesWithoutRemoving(t *testing.T) {
	for name, removeErr := range map[string]error{
		"removed":      nil,
		"already gone": &backend.HTTPError{StatusCode: 404, Message: "404 policy does not exists"},
	} {
		t.Run(name, func(t *testing.T) {
			kept, edited := replayAfterRestartRemoval(t, "restart_removal_confirmed_"+map[string]string{"removed": "a", "already gone": "b"}[name], removeErr)
			assert.False(t, kept, "the policy the restart removed is applied fresh")
			assert.False(t, edited, "the edit deferred during the restart is applied fresh")
		})
	}
}

// A removal that failed may have left the policy on the backend: the replay
// still applies it, and an edit of it deferred during the restart, as an
// update, which removes whatever is left before applying.
func TestReplayAfterAFailedRestartRemovalStillUpdates(t *testing.T) {
	kept, edited := replayAfterRestartRemoval(t, "restart_removal_failed", errors.New("connection refused"))
	assert.True(t, kept, "the policy the restart failed to remove is updated")
	assert.True(t, edited, "the edit deferred during the restart is updated")
}
