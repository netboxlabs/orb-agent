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

// A restart removes the backend's policies and replays them once the
// backend runs again. A policy an apply already reached is still replayed as
// an update, as is an edit of it that arrived during the restart: the
// backend may still hold the policy if the removal failed.
func TestReplayStillUpdatesAPolicyAnApplyReached(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	be := &mockBackend{name: "first_apply_restart"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("RemovePolicy", mock.Anything).Return(nil).Maybe()
	backend.Register("first_apply_restart", be)
	mgr, err := policymgr.New(logger, &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	for _, id := range []string{"kept", "edited"} {
		be.On("ApplyPolicy", isPolicy(id, 1), false).Return(nil).Once()
		mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: id, Name: id, Backend: "first_apply_restart", DatasetID: "ds", Version: 1, Data: map[string]any{}})
	}

	require.NoError(t, mgr.RemoveBackendPolicies("first_apply_restart", be, false))
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "edited", Name: "edited", Backend: "first_apply_restart", Version: 2, Data: map[string]any{}})
	stored, err := mgr.GetRepo().Get("edited")
	require.NoError(t, err)
	require.Equal(t, policymgr.ReasonBackendStarting, stored.BackendErr, "the edit must wait for the replay")

	be.On("ApplyPolicy", isPolicy("kept", 1), true).Return(nil).Once()
	be.On("ApplyPolicy", isPolicy("edited", 2), true).Return(nil).Once()
	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "first_apply_restart", be))

	be.AssertExpectations(t)
}
