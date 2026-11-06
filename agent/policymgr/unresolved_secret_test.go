package policymgr_test

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// errSecretGone is how Vault reports a reference whose path was deleted.
var errSecretGone = errors.New("secret not found: secrets/snmp/community (secrets/data/snmp)")

const unresolvedReason = "failed to resolve policy secrets: secret not found: secrets/snmp/community (secrets/data/snmp)"

func newUnresolvedSecretFixture(t *testing.T, beName string) (*mockBackend, *mockSecretsManager, policymgr.PolicyManager) {
	t.Helper()
	be := &mockBackend{name: beName}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register(beName, be)
	secretsMgr := new(mockSecretsManager)
	mgr, err := policymgr.New(slog.New(slog.NewTextHandler(io.Discard, nil)), secretsMgr, config.Config{})
	require.NoError(t, err)
	return be, secretsMgr, mgr
}

func storedPolicy(id, beName string, state policies.PolicyState) policies.PolicyData {
	return policies.PolicyData{
		ID:       id,
		Name:     id,
		Backend:  beName,
		Version:  3,
		Data:     map[string]any{"community": "${vault://secrets/snmp/community}"},
		Datasets: map[string]bool{"ds-1": true},
		State:    state,
	}
}

func byID(id string) any {
	return mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == id })
}

func payloadByID(id string) any {
	return mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == id })
}

// A policy whose secret no longer resolves on a scheduled read is stopped on
// its backend, since the secret may be revoked, but kept, failed with the
// read's error as its reason: Fleet shows why, and the policy can be applied
// again. Its secrets are not read again here; the read just failed.
func TestAPolicyWhoseSecretNoLongerResolvesIsStoppedAndKeptFailed(t *testing.T) {
	be, secretsMgr, mgr := newUnresolvedSecretFixture(t, "unresolved_stop")
	require.NoError(t, mgr.GetRepo().Update(storedPolicy("unresolved-1", "unresolved_stop", policies.Running)))
	be.On("RemovePolicy", byID("unresolved-1")).Return(nil).Once()

	secretsMgr.TriggerCallbacks(map[string]error{"unresolved-1": errSecretGone})

	stored, err := mgr.GetRepo().Get("unresolved-1")
	require.NoError(t, err, "the policy must stay stored")
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Equal(t, unresolvedReason, stored.BackendErr)
	assert.Equal(t, int32(3), stored.Version)
	assert.Equal(t, map[string]bool{"ds-1": true}, stored.Datasets)
	be.AssertExpectations(t)
	be.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	secretsMgr.AssertNotCalled(t, "SolvePolicySecrets", mock.Anything)
}

// A policy the backend does not run is not asked to stop: only its reason
// changes to the secret that no longer resolves.
func TestAnUnresolvedSecretDoesNotStopAPolicyTheBackendDoesNotRun(t *testing.T) {
	be, secretsMgr, mgr := newUnresolvedSecretFixture(t, "unresolved_not_running")
	failed := storedPolicy("unresolved-2", "unresolved_not_running", policies.FailedToApply)
	failed.BackendErr = "400 refused"
	require.NoError(t, mgr.GetRepo().Update(failed))

	secretsMgr.TriggerCallbacks(map[string]error{"unresolved-2": errSecretGone})

	stored, err := mgr.GetRepo().Get("unresolved-2")
	require.NoError(t, err)
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Equal(t, unresolvedReason, stored.BackendErr)
	be.AssertNotCalled(t, "RemovePolicy", mock.Anything)
}

// Once the secret resolves again, the secrets manager's report re-applies the
// policy it stopped, with no restart and no update.
func TestAPolicyStoppedForAnUnresolvedSecretIsReappliedWhenItResolves(t *testing.T) {
	be, secretsMgr, mgr := newUnresolvedSecretFixture(t, "unresolved_recover")
	require.NoError(t, mgr.GetRepo().Update(storedPolicy("unresolved-3", "unresolved_recover", policies.Running)))
	be.On("RemovePolicy", byID("unresolved-3")).Return(nil).Once()
	secretsMgr.TriggerCallbacks(map[string]error{"unresolved-3": errSecretGone})

	solved := config.PolicyPayload{ID: "unresolved-3", Data: map[string]any{"community": "public"}}
	secretsMgr.On("SolvePolicySecrets", payloadByID("unresolved-3")).Return(solved, nil).Once()
	be.On("ApplyPolicy", byID("unresolved-3"), true).Return(nil).Once()
	secretsMgr.TriggerCallbacks(map[string]error{"unresolved-3": nil})

	stored, err := mgr.GetRepo().Get("unresolved-3")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
	assert.Empty(t, stored.BackendErr)
	be.AssertExpectations(t)
}

// Fleet re-delivers a policy on an update without its dataset ID. A policy
// stopped for a secret that no longer resolves is still the agent's, so the
// re-delivery applies it rather than being skipped as unseen.
func TestAPolicyStoppedForAnUnresolvedSecretIsAppliedOnItsNextDelivery(t *testing.T) {
	be, secretsMgr, mgr := newUnresolvedSecretFixture(t, "unresolved_redeliver")
	require.NoError(t, mgr.GetRepo().Update(storedPolicy("unresolved-4", "unresolved_redeliver", policies.Running)))
	be.On("RemovePolicy", byID("unresolved-4")).Return(nil).Once()
	secretsMgr.TriggerCallbacks(map[string]error{"unresolved-4": errSecretGone})

	update := config.PolicyPayload{
		Action:  "manage",
		ID:      "unresolved-4",
		Name:    "unresolved-4",
		Backend: "unresolved_redeliver",
		Version: 4,
		Data:    map[string]any{"community": "${vault://secrets/snmp/community}"},
	}
	solved := update
	solved.Data = map[string]any{"community": "public"}
	secretsMgr.On("SolvePolicySecrets", payloadByID("unresolved-4")).Return(solved, nil).Once()
	be.On("ApplyPolicy", byID("unresolved-4"), true).Return(nil).Once()
	mgr.ManagePolicy(update)

	stored, err := mgr.GetRepo().Get("unresolved-4")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
	assert.Empty(t, stored.BackendErr)
	assert.Equal(t, int32(4), stored.Version)
	be.AssertExpectations(t)
}
