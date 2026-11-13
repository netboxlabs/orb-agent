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

// newNotOnBackendFixture registers a running mock backend under name and
// returns it with a policy manager whose starter reports it starting, so a
// manage stores its policy without any apply reaching the backend.
func newNotOnBackendFixture(t *testing.T, name string) (*mockBackend, policymgr.PolicyManager, *fakeStarter) {
	t.Helper()
	be := &mockBackend{name: name}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("RemovePolicy", mock.Anything).Return(nil).Maybe()
	backend.Register(name, be)
	mgr, err := policymgr.New(slog.New(slog.NewTextHandler(os.Stdout, nil)), &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	starter := &fakeStarter{state: policymgr.StartStarting}
	mgr.SetStarter(starter)
	return be, mgr, starter
}

// A policy no apply has reached is not on its backend, so removing it,
// whichever way, removes it from the agent without asking the backend,
// which would answer with a not-found error.
func TestRemovingAPolicyNoApplyReachedDoesNotCallTheBackend(t *testing.T) {
	for name, remove := range map[string]func(mgr policymgr.PolicyManager, beName string, be backend.Backend){
		"remove": func(mgr policymgr.PolicyManager, beName string, _ backend.Backend) {
			require.NoError(t, mgr.RemovePolicy("unsent", "unsent", beName))
		},
		"remove action": func(mgr policymgr.PolicyManager, beName string, _ backend.Backend) {
			mgr.ManagePolicy(config.PolicyPayload{Action: "remove", ID: "unsent", Name: "unsent", Backend: beName})
		},
		"last dataset": func(mgr policymgr.PolicyManager, beName string, be backend.Backend) {
			mgr.RemovePolicyDataset("unsent", "ds", beName, be)
		},
		"backend, permanently": func(mgr policymgr.PolicyManager, beName string, be backend.Backend) {
			require.NoError(t, mgr.RemoveBackendPolicies(beName, be, true))
		},
	} {
		t.Run(name, func(t *testing.T) {
			beName := "unsent_removal_" + map[string]string{"remove": "a", "remove action": "b", "last dataset": "c", "backend, permanently": "d"}[name]
			be, mgr, _ := newNotOnBackendFixture(t, beName)
			mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "unsent", Name: "unsent", Backend: beName, DatasetID: "ds", Version: 1, Data: map[string]any{}})

			remove(mgr, beName, be)

			be.AssertNotCalled(t, "RemovePolicy", mock.Anything)
			assert.False(t, mgr.GetRepo().Exists("unsent"), "the policy is removed from the agent")
		})
	}
}

// A restart's removal does not ask the backend about a policy no apply has
// reached either; the policy is kept for the replay, which applies it fresh.
func TestARestartDoesNotRemoveAPolicyNoApplyReachedFromTheBackend(t *testing.T) {
	be, mgr, starter := newNotOnBackendFixture(t, "unsent_restart")
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "unsent", Name: "unsent", Backend: "unsent_restart", DatasetID: "ds", Version: 1, Data: map[string]any{}})
	starter.state = policymgr.StartRunning

	require.NoError(t, mgr.RemoveBackendPolicies("unsent_restart", be, false))
	be.AssertNotCalled(t, "RemovePolicy", mock.Anything)

	be.On("ApplyPolicy", isPolicy("unsent", 1), false).Return(nil).Once()
	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "unsent_restart", be))
	be.AssertExpectations(t)
}

// A policy stopped on its backend because a secret no longer resolves is no
// longer there: once the secret resolves again, it is applied fresh, not
// removed first. A stop the backend failed may have left it running, so the
// next apply removes it first.
func TestAPolicyStoppedForAnUnresolvedSecretIsReappliedFresh(t *testing.T) {
	for name, stopErr := range map[string]error{
		"stopped":        nil,
		"already gone":   &backend.HTTPError{StatusCode: 404, Message: "404 policy does not exists"},
		"failed to stop": errors.New("connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			beName := "unresolved_stop_" + map[string]string{"stopped": "a", "already gone": "b", "failed to stop": "c"}[name]
			be := &mockBackend{name: beName}
			be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
			backend.Register(beName, be)
			secretsMgr := &mockSecretsManager{passthrough: true, resolvedAgain: map[string]bool{}}
			mgr, err := policymgr.New(slog.New(slog.NewTextHandler(os.Stdout, nil)), secretsMgr, config.Config{})
			require.NoError(t, err)
			be.On("ApplyPolicy", isPolicy("stopped", 1), false).Return(nil).Once()
			mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "stopped", Name: "stopped", Backend: beName, DatasetID: "ds", Version: 1, Data: map[string]any{}})

			be.On("RemovePolicy", mock.Anything).Return(stopErr).Once()
			secretsMgr.TriggerCallbacks(map[string]error{"stopped": errStillUnresolved})
			stored, err := mgr.GetRepo().Get("stopped")
			require.NoError(t, err)
			require.Equal(t, policies.FailedToApply, stored.State)

			secretsMgr.mu.Lock()
			secretsMgr.resolvedAgain["stopped"] = true
			secretsMgr.mu.Unlock()
			be.On("ApplyPolicy", isPolicy("stopped", 1), name == "failed to stop").Return(nil).Once()
			secretsMgr.TriggerCallbacks(map[string]error{"stopped": nil})

			be.AssertExpectations(t)
		})
	}
}

// Stopping a policy whose secret no longer resolves does not ask the backend
// to remove it when no apply has reached the backend: here the agent refused
// the policy's name before applying it.
func TestAStopForAnUnresolvedSecretDoesNotCallTheBackendForAPolicyNoApplyReached(t *testing.T) {
	be := &mockBackend{name: "unresolved_unsent"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("RemovePolicy", mock.Anything).Return(nil).Maybe()
	backend.Register("unresolved_unsent", be)
	secretsMgr := &mockSecretsManager{passthrough: true, resolvedAgain: map[string]bool{}}
	mgr, err := policymgr.New(slog.New(slog.NewTextHandler(os.Stdout, nil)), secretsMgr, config.Config{})
	require.NoError(t, err)
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "unsent", Name: "never/reached", Backend: "unresolved_unsent", DatasetID: "ds", Version: 1, Data: map[string]any{}})

	secretsMgr.TriggerCallbacks(map[string]error{"unsent": errStillUnresolved})

	be.AssertNotCalled(t, "RemovePolicy", mock.Anything)
	stored, err := mgr.GetRepo().Get("unsent")
	require.NoError(t, err)
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Contains(t, stored.BackendErr, "failed to resolve policy secrets")
}

// A backend that refuses a policy before sending it to its process, as
// pktvisor refuses a name it cannot address, holds no more of the policy
// than before. A policy no apply had reached is then still applied fresh
// next time, and a policy the backend already ran is still updated.
func TestARefusalBeforeTheBackendSentThePolicyKeepsWhatTheAgentKnew(t *testing.T) {
	refused := backend.NotSent(errors.New("pktvisor policy name \"edge ping\" must match [a-zA-Z_][a-zA-Z0-9_-]*"))
	for name, appliedFirst := range map[string]bool{"first apply": false, "edit": true} {
		t.Run(name, func(t *testing.T) {
			beName := "not_sent_" + map[bool]string{false: "first", true: "edit"}[appliedFirst]
			be := &mockBackend{name: beName}
			be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
			backend.Register(beName, be)
			mgr, err := policymgr.New(slog.New(slog.NewTextHandler(os.Stdout, nil)), &mockSecretsManager{passthrough: true}, config.Config{})
			require.NoError(t, err)
			payload := config.PolicyPayload{Action: "manage", ID: "refused", Name: "refused", Backend: beName, DatasetID: "ds", Version: 1, Data: map[string]any{}}
			if appliedFirst {
				be.On("ApplyPolicy", isPolicy("refused", 1), false).Return(nil).Once()
				mgr.ManagePolicy(payload)
				payload.Version++
			}

			be.On("ApplyPolicy", isPolicy("refused", payload.Version), appliedFirst).Return(refused).Once()
			mgr.ManagePolicy(payload)
			stored, err := mgr.GetRepo().Get("refused")
			require.NoError(t, err)
			require.Equal(t, policies.FailedToApply, stored.State)

			payload.Version++
			be.On("ApplyPolicy", isPolicy("refused", payload.Version), appliedFirst).Return(nil).Once()
			mgr.ManagePolicy(payload)

			be.AssertExpectations(t)
		})
	}
}

// A backend restart removes the backend's policies, and once a new process
// has replaced the backend's, that process holds none of them: the replay
// applies each fresh, the policy the backend ran and an edit of it deferred
// during the restart alike. Another backend's policies are left as they are.
func TestReplayAfterTheBackendProcessIsReplacedAppliesWithoutRemoving(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	be := &mockBackend{name: "replaced_process"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("RemovePolicy", mock.Anything).Return(nil).Maybe()
	backend.Register("replaced_process", be)
	other := &mockBackend{name: "replaced_process_other"}
	other.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("replaced_process_other", other)
	mgr, err := policymgr.New(logger, &mockSecretsManager{passthrough: true}, config.Config{})
	require.NoError(t, err)
	for _, id := range []string{"kept", "edited"} {
		be.On("ApplyPolicy", isPolicy(id, 1), false).Return(nil).Once()
		mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: id, Name: id, Backend: "replaced_process", DatasetID: "ds", Version: 1, Data: map[string]any{}})
	}
	other.On("ApplyPolicy", isPolicy("elsewhere", 1), false).Return(nil).Once()
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "elsewhere", Name: "elsewhere", Backend: "replaced_process_other", DatasetID: "ds", Version: 1, Data: map[string]any{}})

	require.NoError(t, mgr.RemoveBackendPolicies("replaced_process", be, false))
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "edited", Name: "edited", Backend: "replaced_process", Version: 2, Data: map[string]any{}})
	mgr.BackendProcessReplaced("replaced_process")

	be.On("ApplyPolicy", isPolicy("kept", 1), false).Return(nil).Once()
	be.On("ApplyPolicy", isPolicy("edited", 2), false).Return(nil).Once()
	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "replaced_process", be))
	be.AssertExpectations(t)

	other.On("ApplyPolicy", isPolicy("elsewhere", 2), true).Return(nil).Once()
	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "elsewhere", Name: "elsewhere", Backend: "replaced_process_other", Version: 2, Data: map[string]any{}})
	other.AssertExpectations(t)
}
