package policymgr_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Mock for the backend.Backend interface
type mockBackend struct {
	mock.Mock
	name string
}

func (m *mockBackend) GetName() string {
	return m.name
}

func (m *mockBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo, cfg map[string]any, commons config.BackendCommons, _ filesmgr.Manager) error {
	args := m.Called(logger, repo, cfg, commons)
	return args.Error(0)
}

func (m *mockBackend) Version() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	args := m.Called(ctx, cancelFunc)
	return args.Error(0)
}

func (m *mockBackend) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) FullReset(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) GetStartTime() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *mockBackend) GetCapabilities() (map[string]any, error) {
	args := m.Called()
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *mockBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus), args.String(1), args.Error(2)
}

func (m *mockBackend) GetInitialState() backend.RunningStatus {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus)
}

func (m *mockBackend) ApplyPolicy(policy policies.PolicyData, updatePolicy bool) error {
	args := m.Called(policy, updatePolicy)
	return args.Error(0)
}

func (m *mockBackend) RemovePolicy(policy policies.PolicyData) error {
	args := m.Called(policy)
	return args.Error(0)
}

// Mock for the secretsmgr.Manager interface
type mockSecretsManager struct {
	mock.Mock
	callbacks   []func(map[string]bool)
	passthrough bool
}

func (m *mockSecretsManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	if m.passthrough {
		return payload, nil
	}
	args := m.Called(payload)
	return args.Get(0).(config.PolicyPayload), args.Error(1)
}

func (m *mockSecretsManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	args := m.Called(backends, configManager)
	return args.Get(0).(map[string]any), args.Get(1).(config.ManagerConfig), args.Error(2)
}

func (m *mockSecretsManager) RegisterUpdatePoliciesCallback(callback func(map[string]bool)) {
	m.callbacks = append(m.callbacks, callback)
}

func (m *mockSecretsManager) Start(context.Context) error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockSecretsManager) TriggerCallbacks(policiesIDs map[string]bool) {
	for _, callback := range m.callbacks {
		callback(policiesIDs)
	}
}

func TestNew(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	// Verify the repo was properly initialized
	repo := mgr.GetRepo()
	require.NotNil(t, repo)
}

func TestManagePolicy_ManageAction_NewPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	// Configure mock backend
	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Set up expectations
	policyData := map[string]any{"key": "value"}
	payload := config.PolicyPayload{
		Action:       "manage",
		ID:           "policy1",
		Name:         "Test Policy",
		Backend:      "testbackend",
		Version:      1,
		Data:         policyData,
		DatasetID:    "dataset1",
		AgentGroupID: "group1",
	}

	solvedPayload := payload
	secretsMgr.On("SolvePolicySecrets", payload).Return(solvedPayload, nil)

	expectedPolicy := policies.PolicyData{
		ID:       "policy1",
		Name:     "Test Policy",
		Backend:  "testbackend",
		Version:  1,
		Data:     policyData,
		State:    policies.Running,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
	}

	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == expectedPolicy.ID && pd.Name == expectedPolicy.Name
	}), false).Return(nil)

	// Execute
	mgr.ManagePolicy(payload)

	// Validate
	mockBe.AssertExpectations(t)
	secretsMgr.AssertExpectations(t)

	// Verify policy is in repo with correct state
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, expectedPolicy.ID, state[0].ID)
	assert.Equal(t, expectedPolicy.Name, state[0].Name)
	assert.Equal(t, policies.Running, state[0].State)
	assert.Equal(t, expectedPolicy.Datasets, state[0].Datasets)
	assert.Equal(t, expectedPolicy.GroupIDs, state[0].GroupIDs)
}

func TestManagePolicy_ManageAction_UpdatePolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	// Configure mock backend
	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// First add a policy
	initialPayload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Test Policy",
		Backend:   "testbackend",
		Version:   1,
		Data:      map[string]any{"key": "value"},
		DatasetID: "dataset1",
	}

	secretsMgr.On("SolvePolicySecrets", initialPayload).Return(initialPayload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, false).Return(nil)

	// Initial setup
	mgr.ManagePolicy(initialPayload)

	// Now update the policy with a higher version
	updatePayload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Updated Policy", // Changed name
		Backend:   "testbackend",
		Version:   2, // Increased version
		Data:      map[string]any{"key": "updated"},
		DatasetID: "dataset2", // Additional dataset
	}

	secretsMgr.On("SolvePolicySecrets", updatePayload).Return(updatePayload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, true).Return(nil)

	// Execute the update
	mgr.ManagePolicy(updatePayload)

	// Validate state after update
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)

	// Check updated properties
	assert.Equal(t, "policy1", state[0].ID)
	assert.Equal(t, "Updated Policy", state[0].Name)
	assert.Equal(t, int32(2), state[0].Version)
	assert.Equal(t, policies.Running, state[0].State)

	// Check that both datasets are there
	assert.True(t, state[0].Datasets["dataset1"])
	assert.True(t, state[0].Datasets["dataset2"])

	// a successful apply consumes the pending rename: no residue persists
	assert.Nil(t, state[0].PreviousPolicyData)
}

func TestManagePolicy_BackendNotRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Unknown, "backend not running", nil)
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Test Policy",
		Backend:   "testbackend",
		Version:   1,
		Data:      map[string]any{"key": "value"},
		DatasetID: "dataset1",
	}

	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)

	mgr.ManagePolicy(payload)

	mockBe.AssertExpectations(t)
	mockBe.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	secretsMgr.AssertExpectations(t)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.FailedToApply, state[0].State)
	assert.Equal(t, "backend not running", state[0].BackendErr)
}

func TestManagePolicy_ManageAction_BackendUnavailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	// Don't register any backends

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Test Policy",
		Backend:   "unavailablebackend", // This backend doesn't exist
		Version:   1,
		Data:      map[string]any{"key": "value"},
		DatasetID: "dataset1",
	}

	// Execute
	mgr.ManagePolicy(payload)

	// Validate state - policy should be saved but marked as failed
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, "policy1", state[0].ID)
	assert.Equal(t, policies.FailedToApply, state[0].State)
	assert.Equal(t, "backend not available", state[0].BackendErr)
}

func TestManagePolicy_RemoveAction(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// First add a policy
	initialPayload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Test Policy",
		Backend:   "testbackend",
		Version:   1,
		Data:      map[string]any{"key": "value"},
		DatasetID: "dataset1",
	}

	secretsMgr.On("SolvePolicySecrets", initialPayload).Return(initialPayload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, false).Return(nil)

	// Initial setup
	mgr.ManagePolicy(initialPayload)

	// Now remove the policy
	removePayload := config.PolicyPayload{
		Action:  "remove",
		ID:      "policy1",
		Name:    "Test Policy",
		Backend: "testbackend",
	}

	mockBe.On("RemovePolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy1" && pd.Name == "Test Policy"
	})).Return(nil)

	// Execute remove
	mgr.ManagePolicy(removePayload)

	// Validate - policy should be removed
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestRemovePolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Add a policy to the repo first (we need to use ManagePolicy)
	addPayload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Test Policy",
		Backend:   "testbackend",
		Version:   1,
		Data:      map[string]any{},
		DatasetID: "dataset1",
	}
	secretsMgr.On("SolvePolicySecrets", addPayload).Return(addPayload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, false).Return(nil)
	mgr.ManagePolicy(addPayload)

	// Set up expectations for removal
	mockBe.On("RemovePolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy1" && pd.Name == "Test Policy"
	})).Return(nil)

	// Execute removal
	err = mgr.RemovePolicy("policy1", "Test Policy", "testbackend")
	require.NoError(t, err)

	// Verify policy is gone
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestRemoveBackendPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Add multiple policies
	for i := 1; i <= 3; i++ {
		payload := config.PolicyPayload{
			Action:    "manage",
			ID:        fmt.Sprintf("policy%d", i),
			Name:      fmt.Sprintf("Test Policy %d", i),
			Backend:   "testbackend",
			Version:   int32(i),
			Data:      map[string]any{},
			DatasetID: fmt.Sprintf("dataset%d", i),
		}
		secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)
		mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
			return pd.ID == payload.ID
		}), false).Return(nil)

		mgr.ManagePolicy(payload)
	}

	// Verify we have 3 policies
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Len(t, state, 3)

	// Set up expectations for removal - all policies should be removed
	mockBe.On("RemovePolicy", mock.Anything).Return(nil).Times(3)

	// Test non-permanent removal (only marks policies as unknown)
	err = mgr.RemoveBackendPolicies("testbackend", mockBe, false)
	require.NoError(t, err)

	// Verify policies are still there but with state Unknown
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Len(t, state, 3)
	for _, policy := range state {
		assert.Equal(t, policies.Unknown, policy.State)
	}

	// Test permanent removal
	mockBe.On("RemovePolicy", mock.Anything).Return(nil).Times(3)
	err = mgr.RemoveBackendPolicies("testbackend", mockBe, true)
	require.NoError(t, err)

	// Verify policies are gone
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

// A backend's policies are re-applied with their secrets solved the way a
// manage solves them, with updatePolicy true (the remove-then-apply form
// every backend implements, safe against a name already present), and the
// repo keeps the unsolved data. Another backend's policies are not touched.
func TestApplyBackendPoliciesAppliesOnlyThatBackendsPoliciesWithSolvedSecrets(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	mine := &mockBackend{name: "applier_mine"}
	mine.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	other := &mockBackend{name: "applier_other"}
	other.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	unsolved := map[string]any{"community": "${vault://snmp/community}"}
	require.NoError(t, repo.Update(policies.PolicyData{ID: "mine-1", Name: "Mine One", Backend: "applier_mine", Version: 1, Data: unsolved, State: policies.Unknown, PreviousPolicyData: &policies.PolicyData{Name: "Old Name"}}))
	require.NoError(t, repo.Update(policies.PolicyData{ID: "other-1", Name: "Other One", Backend: "applier_other", Version: 1, Data: map[string]any{}, State: policies.Unknown}))

	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "mine-1" && p.Backend == "applier_mine" })).
		Return(config.PolicyPayload{ID: "mine-1", Name: "Mine One", Backend: "applier_mine", Version: 1, Data: map[string]any{"community": "s3cr3t"}}, nil).Once()
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "other-1" })).
		Return(config.PolicyPayload{ID: "other-1", Name: "Other One", Backend: "applier_other", Version: 1, Data: map[string]any{}}, nil).Maybe()
	mine.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		data, _ := pd.Data.(map[string]any)
		return pd.ID == "mine-1" && data["community"] == "s3cr3t"
	}), true).Return(nil).Once()
	// registered after the specific expectation, so testify's first-match
	// rule still routes mine-1 to it; a wrong implementation then fails on
	// the assertions below instead of panicking inside testify
	mine.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe()

	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "applier_mine", mine))

	mine.AssertExpectations(t)
	secretsMgr.AssertExpectations(t)
	other.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	stored, err := repo.Get("mine-1")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
	assert.Empty(t, stored.BackendErr)
	assert.Equal(t, unsolved, stored.Data, "the repo keeps the unsolved references")
	assert.Nil(t, stored.PreviousPolicyData, "a successful apply clears a pending rename")
	otherStored, err := repo.Get("other-1")
	require.NoError(t, err)
	assert.Equal(t, policies.Unknown, otherStored.State)
}

// A backend that is not running at that moment cannot take an apply; the
// policies are left as they are for its next start rather than stamped
// failed, and the caller learns why.
func TestApplyBackendPoliciesLeavesPoliciesWhenTheBackendIsNotRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	flaky := &mockBackend{name: "applier_flaky"}
	flaky.On("GetRunningStatus").Return(backend.BackendError, "process running, REST API unavailable", nil)
	flaky.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe()
	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(config.PolicyPayload{}, nil).Maybe()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: "flaky-1", Name: "Flaky One", Backend: "applier_flaky", Version: 1, Data: map[string]any{}, State: policies.Unknown}))

	err = mgr.ApplyBackendPolicies(context.Background(), "applier_flaky", flaky)

	require.ErrorIs(t, err, policymgr.ErrBackendNotRunning)
	flaky.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	stored, err := mgr.GetRepo().Get("flaky-1")
	require.NoError(t, err)
	assert.Equal(t, policies.Unknown, stored.State, "untouched for the next start")
}

// A secret that cannot be solved fails that policy alone, with the operator
// facing reason, and the others still apply.
func TestApplyBackendPoliciesFailsOnlyThePolicyWhoseSecretsCannotBeSolved(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	be := &mockBackend{name: "applier_secrets"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	for _, id := range []string{"sec-good", "sec-bad"} {
		require.NoError(t, repo.Update(policies.PolicyData{ID: id, Name: id, Backend: "applier_secrets", Version: 1, Data: map[string]any{}, State: policies.Unknown}))
	}
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "sec-good" })).
		Return(config.PolicyPayload{ID: "sec-good", Name: "sec-good", Backend: "applier_secrets", Version: 1, Data: map[string]any{}}, nil).Once()
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "sec-bad" })).
		Return(config.PolicyPayload{}, errors.New("vault: permission denied")).Once()
	be.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "sec-good" }), true).Return(nil).Once()
	be.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe() // after the specific one, see the first test

	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "applier_secrets", be))

	be.AssertExpectations(t)
	secretsMgr.AssertExpectations(t)
	good, _ := repo.Get("sec-good")
	bad, _ := repo.Get("sec-bad")
	assert.Equal(t, policies.Running, good.State)
	assert.Equal(t, policies.FailedToApply, bad.State)
	assert.Contains(t, bad.BackendErr, "failed to resolve policy secrets: vault: permission denied")
}

// A backend that rejects one policy's apply fails that policy alone, with
// the backend's own error as the reason, and the others still apply.
func TestApplyBackendPoliciesFailsOnlyThePolicyTheBackendRejects(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	be := &mockBackend{name: "applier_backend_fail"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	for _, id := range []string{"be-good", "be-bad"} {
		require.NoError(t, repo.Update(policies.PolicyData{ID: id, Name: id, Backend: "applier_backend_fail", Version: 1, Data: map[string]any{}, State: policies.Unknown}))
	}
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "be-good" })).
		Return(config.PolicyPayload{ID: "be-good", Name: "be-good", Backend: "applier_backend_fail", Version: 1, Data: map[string]any{}}, nil).Once()
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "be-bad" })).
		Return(config.PolicyPayload{ID: "be-bad", Name: "be-bad", Backend: "applier_backend_fail", Version: 1, Data: map[string]any{}}, nil).Once()
	be.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "be-good" }), true).Return(nil).Once()
	be.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "be-bad" }), true).Return(errors.New("failed to apply")).Once()

	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "applier_backend_fail", be))

	be.AssertExpectations(t)
	secretsMgr.AssertExpectations(t)
	good, _ := repo.Get("be-good")
	bad, _ := repo.Get("be-bad")
	assert.Equal(t, policies.Running, good.State)
	assert.Equal(t, policies.FailedToApply, bad.State)
	assert.Equal(t, "failed to apply", bad.BackendErr)
}

// A context cancelled partway through the loop stops the replay before the
// next policy: the one already applied keeps its outcome, the one never
// reached stays unknown, and the call reports the cancellation so the caller
// knows the remaining policies were left untouched rather than applied.
func TestApplyBackendPoliciesStopsWhenTheContextIsCancelledMidLoop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := &mockBackend{name: "midloop_backend"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{ID: "first", Name: "first", Backend: "midloop_backend", Version: 1, Data: map[string]any{}, State: policies.Unknown}))
	require.NoError(t, repo.Update(policies.PolicyData{ID: "second", Name: "second", Backend: "midloop_backend", Version: 1, Data: map[string]any{}, State: policies.Unknown}))

	// GetAll iterates a map, so which record is applied first is not fixed;
	// whichever one is, its own ApplyPolicy call cancels the context, and the
	// assertions below check the outcome by state rather than by ID.
	ctx, cancel := context.WithCancel(context.Background())
	be.On("ApplyPolicy", mock.Anything, true).
		Run(func(_ mock.Arguments) { cancel() }).
		Return(nil).Once()

	err = mgr.ApplyBackendPolicies(ctx, "midloop_backend", be)

	require.ErrorIs(t, err, context.Canceled)
	be.AssertExpectations(t) // exactly one ApplyPolicy call: a second would panic on the exhausted expectation
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	var running, unknown int
	for _, pd := range state {
		switch pd.State {
		case policies.Running:
			running++
		case policies.Unknown:
			unknown++
		}
	}
	assert.Equal(t, 1, running, "the policy reached before the cancellation was applied")
	assert.Equal(t, 1, unknown, "the policy never reached stays as it was")
}

// A record already Running reflects the current process: every restart marks
// a backend's policies unknown before stopping it, and a manage during a
// restart is stored failed to apply rather than running, so a running record
// can only have been applied by this same process already. Skipping it is
// what lets the replay run more than once (the restart's second pass, after
// the mutex is released) without applying a policy twice.
func TestApplyBackendPoliciesSkipsPoliciesAlreadyRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := &mockBackend{name: "skip_running_backend"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{ID: "already-running", Name: "already-running", Backend: "skip_running_backend", Version: 1, Data: map[string]any{}, State: policies.Running}))
	require.NoError(t, repo.Update(policies.PolicyData{ID: "not-yet", Name: "not-yet", Backend: "skip_running_backend", Version: 1, Data: map[string]any{}, State: policies.Unknown}))

	be.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "not-yet" }), true).Return(nil).Once()

	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "skip_running_backend", be))

	be.AssertExpectations(t) // the running record calling ApplyPolicy again would panic on the exhausted expectation
	alreadyRunning, err := repo.Get("already-running")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, alreadyRunning.State)
	notYet, err := repo.Get("not-yet")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, notYet.State)
}

// The state monitor calls repo.UpdateRuns for a policy at any time and does
// not take the backend's apply mutex, so a run it writes while an apply's
// HTTP call to the backend is in flight must survive the write-back that
// follows the apply.
func TestApplyBackendPoliciesKeepsRunUpdatesWrittenDuringTheApply(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := &mockBackend{name: "applier_runs"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{ID: "runs-1", Name: "Runs One", Backend: "applier_runs", Version: 1, Data: map[string]any{}, State: policies.Unknown}))

	be.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "runs-1" }), true).
		Run(func(_ mock.Arguments) {
			require.NoError(t, repo.UpdateRuns("Runs One", []policies.RunData{{ID: "run-1", Status: "running"}}))
		}).
		Return(nil).Once()

	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), "applier_runs", be))

	be.AssertExpectations(t)
	stored, err := repo.Get("runs-1")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
	require.Len(t, stored.Runs, 1, "the run written during the apply must not be discarded by the write-back")
	assert.Equal(t, "run-1", stored.Runs[0].ID)
}

// Same as above, through the secrets-refresh path (refreshPolicyLocked)
// instead of the applier: a run written mid-apply must survive that
// write-back too.
func TestSecretsRefreshKeepsRunUpdatesWrittenDuringTheApply(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	be := &mockBackend{name: "refresher_runs"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("refresher_runs", be)

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{ID: "runs-2", Name: "Runs Two", Backend: "refresher_runs", Version: 1, Data: map[string]any{}, State: policies.Unknown}))

	solved := config.PolicyPayload{ID: "runs-2", Name: "Runs Two", Backend: "refresher_runs", Version: 1, Data: map[string]any{}}
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "runs-2" })).Return(solved, nil)
	be.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "runs-2" }), true).
		Run(func(_ mock.Arguments) {
			require.NoError(t, repo.UpdateRuns("Runs Two", []policies.RunData{{ID: "run-2", Status: "running"}}))
		}).
		Return(nil).Once()

	secretsMgr.TriggerCallbacks(map[string]bool{"runs-2": true})

	be.AssertExpectations(t)
	stored, err := repo.Get("runs-2")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
	require.Len(t, stored.Runs, 1, "the run written during the apply must not be discarded by the write-back")
	assert.Equal(t, "run-2", stored.Runs[0].ID)
}

// Same as TestApplyBackendPoliciesKeepsRunUpdatesWrittenDuringTheApply, for
// the non-permanent removal path: the write-back after RemovePolicy must
// carry forward any run the state monitor wrote while the backend call was
// in flight, not overwrite it with the pre-removal snapshot.
func TestRemoveBackendPoliciesKeepsRunUpdatesWrittenDuringTheRemoval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	be := &mockBackend{name: "remover_runs"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("remover_runs", be)

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{ID: "runs-3", Name: "Runs Three", Backend: "remover_runs", Version: 1, Data: map[string]any{}, State: policies.Running}))

	be.On("RemovePolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "runs-3" })).
		Run(func(_ mock.Arguments) {
			require.NoError(t, repo.UpdateRuns("Runs Three", []policies.RunData{{ID: "run-3", Status: "running"}}))
		}).
		Return(nil).Once()

	require.NoError(t, mgr.RemoveBackendPolicies("remover_runs", be, false))

	be.AssertExpectations(t)
	stored, err := repo.Get("runs-3")
	require.NoError(t, err)
	assert.Equal(t, policies.Unknown, stored.State)
	require.Len(t, stored.Runs, 1, "the run written during the removal must not be discarded by the write-back")
	assert.Equal(t, "run-3", stored.Runs[0].ID)
}

func TestPoliciesChanged(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// First add some policies
	for i := 1; i <= 3; i++ {
		payload := config.PolicyPayload{
			Action:    "manage",
			ID:        fmt.Sprintf("policy%d", i),
			Name:      fmt.Sprintf("Test Policy %d", i),
			Backend:   "testbackend",
			Version:   int32(i),
			Data:      map[string]any{"original": "data"},
			DatasetID: fmt.Sprintf("dataset%d", i),
		}
		secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(pd config.PolicyPayload) bool {
			return pd.ID == payload.ID
		})).Return(payload, nil)
		mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
			return pd.ID == payload.ID
		}), mock.Anything).Return(nil)

		mgr.ManagePolicy(payload)
	}

	// Set up for policy update callback
	// Scenario: policy1 unchanged, policy2 updated, policy3 removed
	policiesStatus := map[string]bool{
		"policy1": true,  // Valid - no change
		"policy2": true,  // Valid - will be updated
		"policy3": false, // Invalid - will be removed
	}
	// policy3 not included, meaning it should be removed

	// Setup expectations for policy2 update
	solvedPayload := config.PolicyPayload{
		ID:   "policy2",
		Name: "Test Policy 2",
		Data: map[string]any{"updated": "data"},
	}
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(payload config.PolicyPayload) bool {
		return payload.ID == "policy2"
	})).Return(solvedPayload, nil)

	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy2" && pd.Data.(map[string]any)["updated"] == "data"
	}), true).Return(nil)

	// Setup expectations for policy3 removal
	mockBe.On("RemovePolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy3"
	})).Return(nil)

	// Trigger the secret update callback
	secretsMgr.TriggerCallbacks(policiesStatus)

	// Verify final state
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)

	// We should have 2 policies left
	stateMap := make(map[string]policies.PolicyData)
	for _, p := range state {
		stateMap[p.ID] = p
	}

	assert.Len(t, stateMap, 2)
	assert.Contains(t, stateMap, "policy1")
	assert.Contains(t, stateMap, "policy2")
	assert.NotContains(t, stateMap, "policy3")

	// Verify policy2 was not updated in DB
	updatedPolicy := stateMap["policy2"]
	updatedData := updatedPolicy.Data.(map[string]any)
	assert.NotEqual(t, "data", updatedData["updated"])
}

func TestRemovePolicyDataset(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// First add a policy with multiple datasets
	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Test Policy",
		Backend:   "testbackend",
		Version:   1,
		Data:      map[string]any{},
		DatasetID: "dataset1",
	}
	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, false).Return(nil)
	mgr.ManagePolicy(payload)

	// Add another dataset to the policy
	payload2 := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1", // Same policy ID
		Name:      "Test Policy",
		Backend:   "testbackend",
		Version:   1,
		Data:      map[string]any{},
		DatasetID: "dataset2", // Different dataset
	}
	secretsMgr.On("SolvePolicySecrets", payload2).Return(payload2, nil)
	mockBe.On("ApplyPolicy", mock.Anything, true).Return(nil)
	mgr.ManagePolicy(payload2)

	// Verify policy has both datasets
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Len(t, state[0].Datasets, 2)
	assert.True(t, state[0].Datasets["dataset1"])
	assert.True(t, state[0].Datasets["dataset2"])

	// Test removing one dataset
	mgr.RemovePolicyDataset("policy1", "dataset1", "testbackend", mockBe)

	// Verify policy still exists but with only one dataset
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Len(t, state[0].Datasets, 1)
	assert.False(t, state[0].Datasets["dataset1"])
	assert.True(t, state[0].Datasets["dataset2"])

	// Test removing the last dataset - should remove the policy
	mockBe.On("RemovePolicy", mock.Anything).Return(nil)
	mgr.RemovePolicyDataset("policy1", "dataset2", "testbackend", mockBe)

	// Verify policy is gone
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestRemovePolicy_BackendRemoveError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_remove_err"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_remove_err", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Add a policy first
	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{
		ID:      "p1",
		Name:    "P1",
		Backend: "be_remove_err",
		State:   policies.Running,
	}))

	// RemovePolicy should still succeed even if backend errors
	mockBe.On("RemovePolicy", mock.Anything).Return(errors.New("backend error"))
	err = mgr.RemovePolicy("p1", "P1", "be_remove_err")
	assert.NoError(t, err)
}

func TestRemovePolicy_UnknownBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	err = mgr.RemovePolicy("p1", "P1", "nonexistent_backend_xyz")
	assert.Error(t, err)
}

func TestRemovePolicyDataset_GetError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_dataset_get_err"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_dataset_get_err", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Call RemovePolicyDataset on a policy that doesn't exist — should not panic
	mgr.RemovePolicyDataset("nonexistent_policy", "dataset1", "be_dataset_get_err", mockBe)
	mockBe.AssertNotCalled(t, "RemovePolicy")
}

func TestRemovePolicyDataset_RemovePolicyError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_dataset_rm_err"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_dataset_rm_err", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Add policy with single dataset
	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "p_ds_rm",
		Name:      "P DS RM",
		Backend:   "be_dataset_rm_err",
		Version:   1,
		DatasetID: "ds1",
		Data:      map[string]any{},
	}
	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(payload, nil)
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil)
	mockBe.On("ApplyPolicy", mock.Anything, false).Return(nil)
	mgr.ManagePolicy(payload)

	// RemovePolicy on backend errors — should still complete
	mockBe.On("RemovePolicy", mock.Anything).Return(errors.New("backend remove error"))
	mgr.RemovePolicyDataset("p_ds_rm", "ds1", "be_dataset_rm_err", mockBe)

	// Policy should be gone from repo
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

// A restart removes the policies of the backend being restarted and no
// other's: the repo holds every backend's policies, and removing them all
// left the agent with nothing applied until the next full list from fleet.
func TestRemoveBackendPoliciesLeavesOtherBackendsAlone(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	restarted := &mockBackend{name: "restarted_backend"}
	restarted.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	other := &mockBackend{name: "other_backend"}
	other.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("restarted_backend", restarted)
	backend.Register("other_backend", other)

	restarted.On("ApplyPolicy", mock.Anything, false).Return(nil)
	other.On("ApplyPolicy", mock.Anything, false).Return(nil)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	for _, be := range []string{"restarted_backend", "other_backend"} {
		payload := config.PolicyPayload{Action: "manage", ID: "policy-" + be, Name: "Policy " + be, Backend: be, Version: 1, Data: map[string]any{}, DatasetID: "ds-" + be}
		secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)
		mgr.ManagePolicy(payload)
	}
	restarted.On("RemovePolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "policy-restarted_backend" })).Return(nil).Once()

	require.NoError(t, mgr.RemoveBackendPolicies("restarted_backend", restarted, true))

	other.AssertNotCalled(t, "RemovePolicy", mock.Anything)
	restarted.AssertExpectations(t)
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, "policy-other_backend", state[0].ID)
}

func policyIDs(state []policies.PolicyData) []string {
	ids := make([]string, 0, len(state))
	for _, p := range state {
		ids = append(ids, p.ID)
	}
	return ids
}

// A remove for a backend the agent never started has no process to ask and
// no logger to log the call with, so the policy leaves the agent's repo
// without the call, as an expected condition rather than an error.
func TestRemovePolicyDoesNotCallABackendThatIsNotRunning(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	secretsMgr := new(mockSecretsManager)
	cold := &mockBackend{name: "cold_backend"}
	cold.On("GetRunningStatus").Return(backend.Unknown, "backend not started yet", nil)
	backend.Register("cold_backend", cold)

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	payload := config.PolicyPayload{Action: "manage", ID: "policy-cold", Name: "Cold Policy", Backend: "cold_backend", Version: 1, Data: map[string]any{}, DatasetID: "ds-cold"}
	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)
	mgr.ManagePolicy(payload)
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Contains(t, policyIDs(state), "policy-cold", "the policy is kept as failed to apply")

	require.NoError(t, mgr.RemovePolicy("policy-cold", "Cold Policy", "cold_backend"))

	cold.AssertNotCalled(t, "RemovePolicy", mock.Anything)
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	assert.NotContains(t, policyIDs(state), "policy-cold")
	assert.NotContains(t, logs.String(), "level=ERROR", "an expected condition is not an error")
	assert.Contains(t, logs.String(), "treating policy as already removed")

	// The dataset path removes through the same gate.
	mgr.ManagePolicy(payload)
	mgr.RemovePolicyDataset("policy-cold", "ds-cold", "cold_backend", cold)
	cold.AssertNotCalled(t, "RemovePolicy", mock.Anything)
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	assert.NotContains(t, policyIDs(state), "policy-cold")
}

// A backend that was started is asked whatever its state: a live process
// whose status probe timed out may still hold the policy, and skipping it
// would drop the agent's record while the policy kept running.
func TestRemovePolicyStillAsksABackendWhoseStatusProbeFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	flaky := &mockBackend{name: "flaky_backend"}
	flaky.On("GetRunningStatus").Return(backend.BackendError, "process running, REST API unavailable", errors.New("timeout"))
	backend.Register("flaky_backend", flaky)
	flaky.On("RemovePolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "policy-flaky" })).Return(nil).Once()

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	payload := config.PolicyPayload{Action: "manage", ID: "policy-flaky", Name: "Flaky Policy", Backend: "flaky_backend", Version: 1, Data: map[string]any{}, DatasetID: "ds-flaky"}
	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)
	mgr.ManagePolicy(payload)

	require.NoError(t, mgr.RemovePolicy("policy-flaky", "Flaky Policy", "flaky_backend"))

	flaky.AssertExpectations(t)
}

// A restart's removals go through the same gate as a single remove: a
// backend the agent never started is not asked, and its records still leave.
func TestRemoveBackendPoliciesDoesNotCallABackendThatWasNeverStarted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cold := &mockBackend{name: "cold_restart_backend"}
	cold.On("GetRunningStatus").Return(backend.Unknown, "backend not started yet", nil)
	backend.Register("cold_restart_backend", cold)

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	payload := config.PolicyPayload{Action: "manage", ID: "policy-cold-restart", Name: "Cold Restart Policy", Backend: "cold_restart_backend", Version: 1, Data: map[string]any{}, DatasetID: "ds-cold-restart"}
	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)
	mgr.ManagePolicy(payload)

	require.NoError(t, mgr.RemoveBackendPolicies("cold_restart_backend", cold, true))

	cold.AssertNotCalled(t, "RemovePolicy", mock.Anything)
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.NotContains(t, policyIDs(state), "policy-cold-restart")
}

func TestRemoveBackendPolicies_Permanently(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_perm_remove"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_perm_remove", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	repo := mgr.GetRepo()
	for i := 1; i <= 2; i++ {
		require.NoError(t, repo.Update(policies.PolicyData{
			ID:      fmt.Sprintf("perm%d", i),
			Name:    fmt.Sprintf("Perm %d", i),
			Backend: "be_perm_remove",
			State:   policies.Running,
		}))
	}

	mockBe.On("RemovePolicy", mock.Anything).Return(nil)

	err = mgr.RemoveBackendPolicies("be_perm_remove", mockBe, true)
	require.NoError(t, err)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestRemoveBackendPolicies_NotPermanently(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_nonperm_remove"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_nonperm_remove", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	repo := mgr.GetRepo()
	for i := 1; i <= 2; i++ {
		require.NoError(t, repo.Update(policies.PolicyData{
			ID:      fmt.Sprintf("nonperm%d", i),
			Name:    fmt.Sprintf("NonPerm %d", i),
			Backend: "be_nonperm_remove",
			State:   policies.Running,
		}))
	}

	mockBe.On("RemovePolicy", mock.Anything).Return(nil)

	err = mgr.RemoveBackendPolicies("be_nonperm_remove", mockBe, false)
	require.NoError(t, err)

	// Policies still exist but state is Unknown
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Len(t, state, 2)
	for _, p := range state {
		assert.Equal(t, policies.Unknown, p.State)
	}
}

func TestPoliciesChanged_BackendNotAvailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Add a policy with a backend that is not registered
	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{
		ID:      "p_no_be",
		Name:    "P No BE",
		Backend: "unregistered_backend_xyz",
		State:   policies.Running,
	}))

	// Trigger policiesChanged via secrets callback — backend not available path
	secretsMgr.TriggerCallbacks(map[string]bool{"p_no_be": true})

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.FailedToApply, state[0].State)
	assert.Equal(t, "backend not available", state[0].BackendErr)
}

func TestPoliciesChanged_SolveSecretsError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_secrets_err"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_secrets_err", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{
		ID:      "p_sec_err",
		Name:    "P Sec Err",
		Backend: "be_secrets_err",
		State:   policies.Running,
		Data:    map[string]any{},
	}))

	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(config.PolicyPayload{}, errors.New("secrets error"))

	// Should not panic, just log and continue
	secretsMgr.TriggerCallbacks(map[string]bool{"p_sec_err": true})
	mockBe.AssertNotCalled(t, "ApplyPolicy")
}

func TestApplyPolicy_BackendNotRunning_WithDetail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_not_running_detail"}
	// Backend returns non-running state with a detail string but no error
	mockBe.On("GetRunningStatus").Return(backend.Offline, "backend is offline", nil)
	backend.Register("be_not_running_detail", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "p_detail",
		Name:      "P Detail",
		Backend:   "be_not_running_detail",
		Version:   1,
		DatasetID: "ds1",
		Data:      map[string]any{},
	}
	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(payload, nil)
	mgr.ManagePolicy(payload)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.FailedToApply, state[0].State)
	assert.Equal(t, "backend is offline", state[0].BackendErr)
}

func TestManagePolicy_ExistingPolicy_WithAgentGroupID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_group_id"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_group_id", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// First apply — include AgentGroupID so GroupIDs map is initialized
	payload := config.PolicyPayload{
		Action:       "manage",
		ID:           "p_group",
		Name:         "P Group",
		Backend:      "be_group_id",
		Version:      1,
		DatasetID:    "ds1",
		AgentGroupID: "group1",
		Data:         map[string]any{},
	}
	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(payload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil)
	mgr.ManagePolicy(payload)

	// Update with AgentGroupID on existing policy
	payload2 := config.PolicyPayload{
		Action:       "manage",
		ID:           "p_group",
		Name:         "P Group",
		Backend:      "be_group_id",
		Version:      2,
		AgentGroupID: "group1",
		Data:         map[string]any{},
	}
	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(payload2, nil)
	mgr.ManagePolicy(payload2)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.True(t, state[0].GroupIDs["group1"])
}

func TestManagePolicy_ExistingPolicy_NameChange(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_rename"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_rename", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "p_rename",
		Name:      "Old Name",
		Backend:   "be_rename",
		Version:   1,
		DatasetID: "ds1",
		Data:      map[string]any{},
	}
	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(payload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil)
	mgr.ManagePolicy(payload)

	// Update with name change
	payload2 := config.PolicyPayload{
		Action:  "manage",
		ID:      "p_rename",
		Name:    "New Name",
		Backend: "be_rename",
		Version: 2,
		Data:    map[string]any{},
	}
	secretsMgr.On("SolvePolicySecrets", mock.Anything).Return(payload2, nil)
	mgr.ManagePolicy(payload2)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, "New Name", state[0].Name)
}

func TestManagePolicy_DefaultAction(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Unknown action — should just log and do nothing
	mgr.ManagePolicy(config.PolicyPayload{Action: "unknown", ID: "p1"})

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestManagePolicy_ManageAction_SecretsFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "secretsfailbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("secretsfailbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy-sf1",
		Name:      "Secrets Fail Policy",
		Backend:   "secretsfailbackend",
		Version:   1,
		Data:      map[string]any{"password": "${secret://vault/kv/password}"},
		DatasetID: "dataset-sf1",
	}
	secretsErr := errors.New("failed to get secret path kv/data/kv/password: secret not found")
	secretsMgr.On("SolvePolicySecrets", payload).Return(config.PolicyPayload{}, secretsErr)

	mgr.ManagePolicy(payload)

	// The policy must never reach the backend.
	mockBe.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	secretsMgr.AssertExpectations(t)

	// The failure is PERSISTED so the heartbeat's policy_state channel reports it.
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	pd := state[0]
	assert.Equal(t, policies.FailedToApply, pd.State)
	// Short reason: exact value, untruncated, no marker.
	assert.Equal(t, "failed to resolve policy secrets: "+secretsErr.Error(), pd.BackendErr)

	// A second failing manage (e.g. full-list re-delivery on reconnect) is
	// idempotent: still one policy, still failed.
	payload2 := payload
	payload2.Version = 2
	payload2.DatasetID = "" // updates usually do not carry a dataset id
	secretsMgr.On("SolvePolicySecrets", payload2).Return(config.PolicyPayload{}, secretsErr)
	mgr.ManagePolicy(payload2)

	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.FailedToApply, state[0].State)

	// Recovery: a manage with WORKING secrets applies normally and clears the error.
	payload3 := payload
	payload3.Version = 3
	payload3.DatasetID = ""
	secretsMgr.On("SolvePolicySecrets", payload3).Return(payload3, nil)
	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy-sf1" && pd.Version == 3
	}), true).Return(nil)
	mgr.ManagePolicy(payload3)

	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.Running, state[0].State)
	assert.Empty(t, state[0].BackendErr)
}

func TestPoliciesChanged_SecretsFailureAndRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "secretsreapplybackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("secretsreapplybackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	policyData := map[string]any{"key": "value"}
	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy-rc1",
		Name:      "Recheck Policy",
		Backend:   "secretsreapplybackend",
		Version:   1,
		Data:      policyData,
		DatasetID: "dataset-rc1",
	}
	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)
	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy-rc1"
	}), mock.Anything).Return(nil)
	mgr.ManagePolicy(payload)

	// The secrets-changed callback rebuilds the payload from the repo via
	// applyStoredPolicy. IMPORTANT: verify the matcher against the ACTUAL
	// payload construction in the re-apply loop (config.PolicyPayload{ID,
	// Name, Backend, Version, Data}) before finalizing.
	reapplyPayload := config.PolicyPayload{ID: "policy-rc1", Name: "Recheck Policy", Backend: "secretsreapplybackend", Version: 1, Data: policyData}
	secretsMgr.On("SolvePolicySecrets", reapplyPayload).Return(config.PolicyPayload{}, errors.New("vault sealed")).Once()
	secretsMgr.TriggerCallbacks(map[string]bool{"policy-rc1": true})

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.FailedToApply, state[0].State)
	assert.Contains(t, state[0].BackendErr, "failed to resolve policy secrets:")
	assert.Contains(t, state[0].BackendErr, "vault sealed")

	// Recovery through the callback: secrets resolve again -> Running, error cleared.
	secretsMgr.On("SolvePolicySecrets", reapplyPayload).Return(reapplyPayload, nil)
	secretsMgr.TriggerCallbacks(map[string]bool{"policy-rc1": true})

	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.Running, state[0].State)
	assert.Empty(t, state[0].BackendErr)
}

func TestManagePolicy_SecretsFailure_ReasonTruncated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "secretstruncbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("secretstruncbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy-tr1",
		Name:      "Trunc Policy",
		Backend:   "secretstruncbackend",
		Version:   1,
		Data:      map[string]any{"key": "value"},
		DatasetID: "dataset-tr1",
	}
	// Provider errors can embed unbounded HTTP response bodies.
	giant := errors.New(strings.Repeat("x", 5000))
	secretsMgr.On("SolvePolicySecrets", payload).Return(config.PolicyPayload{}, giant)
	mgr.ManagePolicy(payload)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.True(t, strings.HasPrefix(state[0].BackendErr, "failed to resolve policy secrets:"))
	// total length (marker included) must stay within the 1024-byte bound
	assert.LessOrEqual(t, len(state[0].BackendErr), 1024)
	assert.True(t, strings.HasSuffix(state[0].BackendErr, "... (truncated)"))
}

func TestRemoveBackendPolicies_BackendError_Permanently(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_perm_err"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("be_perm_err", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	repo := mgr.GetRepo()
	require.NoError(t, repo.Update(policies.PolicyData{
		ID:      "permerr1",
		Name:    "Perm Err 1",
		Backend: "be_perm_err",
		State:   policies.Running,
	}))

	// Backend errors on remove — should still proceed
	mockBe.On("RemovePolicy", mock.Anything).Return(errors.New("backend error"))

	err = mgr.RemoveBackendPolicies("be_perm_err", mockBe, true)
	require.NoError(t, err)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestManagePolicy_RenameSecretsFailure_CarriesPreviousPolicyData(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "secretsrenamebackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("secretsrenamebackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	policyData := map[string]any{"key": "value"}
	payloadV1 := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy-rn1",
		Name:      "Old Name",
		Backend:   "secretsrenamebackend",
		Version:   1,
		Data:      policyData,
		DatasetID: "dataset-rn1",
	}
	secretsMgr.On("SolvePolicySecrets", payloadV1).Return(payloadV1, nil)
	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy-rn1" && pd.Version == 1
	}), false).Return(nil)
	mgr.ManagePolicy(payloadV1)

	// v2 renames the policy AND fails secret resolution: the rename never
	// reaches the backend, but the pending rename chain must be persisted.
	payloadV2 := payloadV1
	payloadV2.Name = "New Name"
	payloadV2.Version = 2
	payloadV2.DatasetID = ""
	secretsMgr.On("SolvePolicySecrets", payloadV2).Return(config.PolicyPayload{}, errors.New("vault sealed"))
	mgr.ManagePolicy(payloadV2)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.FailedToApply, state[0].State)
	require.NotNil(t, state[0].PreviousPolicyData)
	assert.Equal(t, "Old Name", state[0].PreviousPolicyData.Name)

	// v3: same-name manage, still failing — the pending chain is carried, not lost.
	payloadV3 := payloadV2
	payloadV3.Version = 3
	secretsMgr.On("SolvePolicySecrets", payloadV3).Return(config.PolicyPayload{}, errors.New("vault sealed"))
	mgr.ManagePolicy(payloadV3)

	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	require.NotNil(t, state[0].PreviousPolicyData)
	assert.Equal(t, "Old Name", state[0].PreviousPolicyData.Name)

	// v4: a STACKED rename (to a third name) with recovered secrets. The PENDING
	// chain must win over the intermediate repo name ("New Name" never reached
	// the backend): the backend must be told to remove "Old Name".
	payloadV4 := payloadV3
	payloadV4.Name = "Third Name"
	payloadV4.Version = 4
	secretsMgr.On("SolvePolicySecrets", payloadV4).Return(payloadV4, nil)
	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy-rn1" && pd.Version == 4 && pd.Name == "Third Name" &&
			pd.PreviousPolicyData != nil && pd.PreviousPolicyData.Name == "Old Name"
	}), true).Return(nil)
	mgr.ManagePolicy(payloadV4)

	mockBe.AssertExpectations(t)

	// Invariant: after the successful apply, the pending rename is consumed —
	// the persisted PreviousPolicyData must be nil (persisted PPD == pending).
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.Running, state[0].State)
	assert.Nil(t, state[0].PreviousPolicyData)
}

func TestRemovePolicy_PendingRenameTargetsBackendName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "secretsremovebackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("secretsremovebackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	policyData := map[string]any{"key": "value"}
	payloadV1 := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy-rm1",
		Name:      "Live Name",
		Backend:   "secretsremovebackend",
		Version:   1,
		Data:      policyData,
		DatasetID: "dataset-rm1",
	}
	secretsMgr.On("SolvePolicySecrets", payloadV1).Return(payloadV1, nil)
	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy-rm1" && pd.Version == 1
	}), false).Return(nil)
	mgr.ManagePolicy(payloadV1)

	// Rename fails secrets: repo now says "Renamed Name" but the backend still
	// runs "Live Name" (pending rename persisted by Task 1).
	payloadV2 := payloadV1
	payloadV2.Name = "Renamed Name"
	payloadV2.Version = 2
	payloadV2.DatasetID = ""
	secretsMgr.On("SolvePolicySecrets", payloadV2).Return(config.PolicyPayload{}, errors.New("vault sealed"))
	mgr.ManagePolicy(payloadV2)

	// Removal must hand the backend the STORED record so its remove honors the
	// pending rename (all backends prefer PreviousPolicyData.Name for deletes).
	mockBe.On("RemovePolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy-rm1" &&
			pd.PreviousPolicyData != nil && pd.PreviousPolicyData.Name == "Live Name"
	})).Return(nil)
	require.NoError(t, mgr.RemovePolicy("policy-rm1", "Renamed Name", "secretsremovebackend"))

	mockBe.AssertExpectations(t)
}

func removePolicySetup(t *testing.T, beName string, removeErr error) (policymgr.PolicyManager, *strings.Builder) {
	t.Helper()
	logs := &strings.Builder{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	secretsMgr := new(mockSecretsManager)

	mockBe := &mockBackend{name: beName}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register(beName, mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)

	addPayload := config.PolicyPayload{
		Action:    "manage",
		ID:        "policy1",
		Name:      "Test Policy",
		Backend:   beName,
		Version:   1,
		Data:      map[string]any{},
		DatasetID: "dataset1",
	}
	secretsMgr.On("SolvePolicySecrets", addPayload).Return(addPayload, nil)
	mockBe.On("ApplyPolicy", mock.Anything, false).Return(nil)
	mgr.ManagePolicy(addPayload)

	mockBe.On("RemovePolicy", mock.Anything).Return(removeErr)
	return mgr, logs
}

func TestRemovePolicyBackend404IsNoOpNotError(t *testing.T) {
	notFound := &backend.HTTPError{StatusCode: 404, Message: "policy 'Test Policy' not found"}
	mgr, logs := removePolicySetup(t, "testbackend404", notFound)

	err := mgr.RemovePolicy("policy1", "Test Policy", "testbackend404")
	require.NoError(t, err)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state, "policy must still be removed from the local PolicyManager")

	assert.NotContains(t, logs.String(), "level=ERROR", "a 404 on removal is a no-op, not an error")
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "already removed")
}

func TestRemovePolicyBackendNon404StillLogsError(t *testing.T) {
	serverErr := &backend.HTTPError{StatusCode: 500, Message: "boom"}
	mgr, logs := removePolicySetup(t, "testbackend500", serverErr)

	err := mgr.RemovePolicy("policy1", "Test Policy", "testbackend500")
	require.NoError(t, err)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)

	assert.Contains(t, logs.String(), "level=ERROR", "non-404 backend failures must stay ERROR")
}

// TestManagePolicy_RefusesUnaddressableName pins that a policy the agent
// could never remove is not created in the first place.
//
// A slash cannot be carried inside one path segment of the backend's API
// URL, so RemovePolicy refuses such a name. Finding that out at removal
// would be too late: RemovePolicy discards the local record even when the
// backend refuses, so the policy would keep running on the backend with no
// state left to retry from. The apply is refused instead, and reported
// through the same FailedToApply path any other apply failure uses.
func TestManagePolicy_RefusesUnaddressableName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)

	payload := config.PolicyPayload{
		Action:       "manage",
		ID:           "policy1",
		Name:         "nightly/rollup",
		Backend:      "testbackend",
		Version:      1,
		Data:         map[string]any{"key": "value"},
		DatasetID:    "dataset1",
		AgentGroupID: "group1",
	}
	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil)

	mgr.ManagePolicy(payload)

	// No ApplyPolicy expectation is registered, so AssertExpectations would
	// not catch an unwanted call on its own; the mock would panic instead.
	// Assert the outcome the operator sees.
	mockBe.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)

	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Equal(t, policies.FailedToApply, state[0].State,
		"a name the agent cannot address must not be reported as running")
	assert.Contains(t, state[0].BackendErr, "slash",
		"the recorded error must say why, since the operator has to rename the policy")

	secretsMgr.AssertExpectations(t)
}

// blockingBackend is a backend whose ApplyPolicy blocks, for one policy
// version only, until released, so a test can hold the backend's apply
// mutex from an applier while another operation for the same backend is
// attempted. Every other apply goes straight through.
type blockingBackend struct {
	mockBackend
	blockID      string
	blockVersion int32
	entered      chan struct{}
	release      chan struct{}

	mu      sync.Mutex
	applied []policies.PolicyData
}

func newBlockingBackend(name, blockID string, blockVersion int32) *blockingBackend {
	b := &blockingBackend{
		mockBackend:  mockBackend{name: name},
		blockID:      blockID,
		blockVersion: blockVersion,
		entered:      make(chan struct{}, 4),
		release:      make(chan struct{}),
	}
	b.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	return b
}

func (b *blockingBackend) ApplyPolicy(pd policies.PolicyData, _ bool) error {
	if pd.ID == b.blockID && pd.Version == b.blockVersion {
		b.entered <- struct{}{}
		<-b.release
	}
	b.mu.Lock()
	b.applied = append(b.applied, pd)
	b.mu.Unlock()
	return nil
}

func (b *blockingBackend) RemovePolicy(_ policies.PolicyData) error { return nil }

func (b *blockingBackend) appliedVersions(id string) []int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	var versions []int32
	for _, pd := range b.applied {
		if pd.ID == id {
			versions = append(versions, pd.Version)
		}
	}
	return versions
}

// waitFor fails the test instead of hanging when a goroutine that should
// have reached a point never does (the re-entrancy deadlock this mutex must
// never introduce).
func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen within 5s; a goroutine is probably deadlocked on the apply mutex", what)
	}
}

// Every policy operation for one backend waits for any other in flight for
// that backend: a manage that arrives while the applier holds the backend's
// mutex is applied after it, not interleaved with it.
func TestManagePolicyWaitsForAnApplierHoldingTheBackendsMutex(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	be := newBlockingBackend("mutex_backend", "held", 1)
	backend.Register("mutex_backend", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: "held", Name: "Held", Backend: "mutex_backend", Version: 1, Data: map[string]any{}, State: policies.Unknown}))
	secretsMgr.On("SolvePolicySecrets", mock.MatchedBy(func(p config.PolicyPayload) bool { return p.ID == "held" })).
		Return(config.PolicyPayload{ID: "held", Name: "Held", Backend: "mutex_backend", Version: 1, Data: map[string]any{}}, nil).Maybe()
	incoming := config.PolicyPayload{Action: "manage", ID: "new", Name: "New", Backend: "mutex_backend", Version: 1, Data: map[string]any{}, DatasetID: "ds-new"}
	secretsMgr.On("SolvePolicySecrets", incoming).Return(incoming, nil).Maybe()

	applierDone := make(chan struct{})
	go func() { _ = mgr.ApplyBackendPolicies(context.Background(), "mutex_backend", be); close(applierDone) }()
	waitFor(t, be.entered, "the applier reaching the backend") // it now holds the mutex inside ApplyPolicy

	manageDone := make(chan struct{})
	go func() { mgr.ManagePolicy(incoming); close(manageDone) }()
	select {
	case <-manageDone:
		t.Fatal("the manage completed while the applier held the backend's mutex")
	case <-time.After(200 * time.Millisecond):
	}

	close(be.release)
	waitFor(t, applierDone, "the applier finishing after release")
	waitFor(t, manageDone, "the manage finishing after the applier released the mutex")
	assert.Equal(t, []int32{1}, be.appliedVersions("held"))
	assert.Equal(t, []int32{1}, be.appliedVersions("new"))
}

// Two operations on the same policy cannot interleave: a manage with a newer
// version that arrives while the applier is re-applying the older one runs
// after it, so the repo ends with the newer version and the applier's stale
// copy is never written back over it. This is the spec's "a policy
// persisted between the starter's decision and the applier's read is
// applied by exactly one of them", exercised here through the applier alone,
// since no starter exists yet.
func TestManageOfTheSamePolicyIsNotLostUnderAConcurrentApplier(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := newBlockingBackend("same_policy_backend", "same", 1)
	backend.Register("same_policy_backend", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: "same", Name: "Same", Backend: "same_policy_backend", Version: 1, Data: map[string]any{}, State: policies.Unknown, Datasets: map[string]bool{"ds": true}}))
	newer := config.PolicyPayload{Action: "manage", ID: "same", Name: "Same", Backend: "same_policy_backend", Version: 2, Data: map[string]any{}}

	applierDone := make(chan struct{})
	go func() {
		_ = mgr.ApplyBackendPolicies(context.Background(), "same_policy_backend", be)
		close(applierDone)
	}()
	waitFor(t, be.entered, "the applier reaching the backend")

	manageDone := make(chan struct{})
	go func() { mgr.ManagePolicy(newer); close(manageDone) }()
	select {
	case <-manageDone:
		t.Fatal("the manage completed while the applier held the backend's mutex")
	case <-time.After(200 * time.Millisecond):
	}

	close(be.release)
	waitFor(t, applierDone, "the applier finishing after release")
	waitFor(t, manageDone, "the manage finishing after the applier released the mutex")
	assert.Equal(t, []int32{1, 2}, be.appliedVersions("same"), "each version applied exactly once, in order")
	stored, err := mgr.GetRepo().Get("same")
	require.NoError(t, err)
	assert.Equal(t, int32(2), stored.Version, "the applier's stale copy was not written back over the manage")
	assert.Equal(t, policies.Running, stored.State)
}

// A manage whose payload names a different backend than the stored record
// is refused with the record untouched: the two backends have different
// mutexes, so a move would let the policy run on both with nothing left to
// remove the old copy.
func TestManagePolicyRefusesMovingAPolicyToAnotherBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	first := &mockBackend{name: "move_first"}
	first.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	first.On("RemovePolicy", mock.Anything).Return(nil).Maybe()
	second := &mockBackend{name: "move_second"}
	second.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	second.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe()
	backend.Register("move_first", first)
	backend.Register("move_second", second)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	stored := policies.PolicyData{ID: "mover", Name: "Mover", Backend: "move_first", Version: 1, Data: map[string]any{}, State: policies.Running, Datasets: map[string]bool{"ds": true}}
	require.NoError(t, mgr.GetRepo().Update(stored))

	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "mover", Name: "Mover", Backend: "move_second", Version: 2, Data: map[string]any{}})

	second.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	first.AssertNotCalled(t, "RemovePolicy", mock.Anything)
	after, err := mgr.GetRepo().Get("mover")
	require.NoError(t, err)
	assert.Equal(t, stored.Backend, after.Backend)
	assert.Equal(t, stored.Version, after.Version)
	assert.Equal(t, policies.Running, after.State)
}

// The secrets refresh removes a policy the provider no longer allows through
// the same removal the remove action uses; both run inside the backend's
// critical section without taking the mutex twice.
func TestRemovalsInsideTheCriticalSectionDoNotDeadlock(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	be := &mockBackend{name: "reentrant_backend"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("RemovePolicy", mock.Anything).Return(nil).Maybe()
	backend.Register("reentrant_backend", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	for _, id := range []string{"gone-1", "gone-2"} {
		require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: id, Name: id, Backend: "reentrant_backend", Version: 1, Data: map[string]any{}, State: policies.Running}))
	}

	done := make(chan struct{})
	go func() {
		secretsMgr.TriggerCallbacks(map[string]bool{"gone-1": false})
		mgr.ManagePolicy(config.PolicyPayload{Action: "remove", ID: "gone-2", Name: "gone-2", Backend: "reentrant_backend"})
		close(done)
	}()
	waitFor(t, done, "the two removals")
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, policyIDs(state))
}

// A policy removed while the secrets refresh was about to re-apply it is not
// resurrected: the refresh re-reads the record under the backend's mutex and
// finds it gone.
func TestPoliciesChangedDoesNotResurrectARemovedPolicy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := newBlockingBackend("resurrect_backend", "victim", 1) // its RemovePolicy override returns nil
	backend.Register("resurrect_backend", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: "victim", Name: "Victim", Backend: "resurrect_backend", Version: 1, Data: map[string]any{}, State: policies.Unknown}))

	// the applier holds the mutex; the refresh queues behind it having read
	// nothing yet, and a remove that also queues behind it lands first.
	// be is the hand-written blockingBackend, not a testify expectation, so
	// a lost sleep race here fails the appliedVersions assertion below
	// cleanly rather than panicking on an unregistered call.
	applierDone := make(chan struct{})
	go func() {
		_ = mgr.ApplyBackendPolicies(context.Background(), "resurrect_backend", be)
		close(applierDone)
	}()
	waitFor(t, be.entered, "the applier reaching the backend")
	removeDone := make(chan struct{})
	go func() { _ = mgr.RemovePolicy("victim", "Victim", "resurrect_backend"); close(removeDone) }()
	time.Sleep(50 * time.Millisecond) // let the remove queue on the mutex first
	refreshDone := make(chan struct{})
	go func() { secretsMgr.TriggerCallbacks(map[string]bool{"victim": true}); close(refreshDone) }()
	time.Sleep(50 * time.Millisecond)

	close(be.release)
	waitFor(t, applierDone, "the applier finishing")
	waitFor(t, removeDone, "the remove finishing")
	waitFor(t, refreshDone, "the refresh finishing")
	assert.False(t, mgr.GetRepo().Exists("victim"), "the refresh must not write a removed policy back")
	assert.Equal(t, []int32{1}, be.appliedVersions("victim"), "only the applier applied it")
}

// A policy moved to another backend while the secrets refresh was queued on
// the old backend's mutex is left untouched: refreshPolicyLocked re-reads the
// record under the lock it holds and, finding the record now names a
// different backend, skips rather than acting on it under the wrong mutex.
func TestRefreshPolicySkipsAPolicyMovedToAnotherBackendWhileQueued(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	from := newBlockingBackend("moved_from_backend", "blocker", 1)
	backend.Register("moved_from_backend", from)
	to := &mockBackend{name: "moved_to_backend"}
	to.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	// Permissive stub so a lost sleep race (the refresh reading the record
	// after the move instead of before) fails the AssertNotCalled assertion
	// below cleanly instead of panicking on an unregistered expectation.
	to.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe()
	backend.Register("moved_to_backend", to)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: "held", Name: "Held", Backend: "moved_from_backend", Version: 1, Data: map[string]any{}, State: policies.Running}))

	// a manage on an unrelated policy on the same backend holds the mutex,
	// without touching "held"'s record, so it can block without racing the
	// repo mutation below
	blockerDone := make(chan struct{})
	go func() {
		mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "blocker", Name: "Blocker", Backend: "moved_from_backend", Version: 1, Data: map[string]any{}, DatasetID: "ds-blocker"})
		close(blockerDone)
	}()
	waitFor(t, from.entered, "the blocking manage reaching the backend")

	refreshDone := make(chan struct{})
	go func() { secretsMgr.TriggerCallbacks(map[string]bool{"held": true}); close(refreshDone) }()
	time.Sleep(50 * time.Millisecond) // let the refresh read "held"'s current backend and queue on its mutex

	require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: "held", Name: "Held", Backend: "moved_to_backend", Version: 1, Data: map[string]any{}, State: policies.Running}))

	close(from.release)
	waitFor(t, blockerDone, "the blocking manage finishing")
	waitFor(t, refreshDone, "the refresh finishing")

	to.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	stored, err := mgr.GetRepo().Get("held")
	require.NoError(t, err)
	assert.Equal(t, "moved_to_backend", stored.Backend, "the refresh must not act on a policy that moved to another backend while queued")
}

// fakeStarter answers EnsureStarted with a fixed state or error and counts
// the calls under a mutex: EnsureStarted is called under a per-backend
// mutex, so two backends sharing one starter can reach it concurrently.
type fakeStarter struct {
	state policymgr.StartState
	err   error

	mu    sync.Mutex
	calls []string
}

func (f *fakeStarter) EnsureStarted(name string) (policymgr.StartState, error) {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	f.mu.Unlock()
	return f.state, f.err
}

// callsSeen returns a snapshot of the backend names EnsureStarted was
// called with, safe to read while other goroutines may still be calling it.
func (f *fakeStarter) callsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// A backend the starter reports as starting does not receive the policy
// yet: it is stored as failed to apply with "backend starting", the reason
// the supervisor's applier will replace once the backend is running.
func TestManagePolicyStoresAPolicyForABackendThatIsStarting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := &mockBackend{name: "starter_backend"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe()
	backend.Register("starter_backend", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	starter := &fakeStarter{state: policymgr.StartStarting}
	mgr.SetStarter(starter)
	payload := config.PolicyPayload{Action: "manage", ID: "starting-1", Name: "Starting", Backend: "starter_backend", Version: 1, Data: map[string]any{}, DatasetID: "ds"}

	mgr.ManagePolicy(payload)

	assert.Equal(t, []string{"starter_backend"}, starter.callsSeen())
	be.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	stored, err := mgr.GetRepo().Get("starting-1")
	require.NoError(t, err)
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Equal(t, "backend starting", stored.BackendErr)
	assert.Equal(t, map[string]bool{"ds": true}, stored.Datasets, "the dataset bookkeeping is persisted with the record")
}

// A starter that reports the backend running changes nothing: the policy is
// applied as it is today.
func TestManagePolicyAppliesWhenTheStarterReportsRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	be := &mockBackend{name: "starter_running"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("starter_running", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	mgr.SetStarter(&fakeStarter{state: policymgr.StartRunning})
	payload := config.PolicyPayload{Action: "manage", ID: "running-1", Name: "Running", Backend: "starter_running", Version: 1, Data: map[string]any{}, DatasetID: "ds"}
	secretsMgr.On("SolvePolicySecrets", payload).Return(payload, nil).Once()
	be.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool { return pd.ID == "running-1" }), false).Return(nil).Once()

	mgr.ManagePolicy(payload)

	be.AssertExpectations(t)
	stored, _ := mgr.GetRepo().Get("running-1")
	assert.Equal(t, policies.Running, stored.State)
}

// A starter that cannot start the backend fails the policy with its reason.
func TestManagePolicyStoresTheStartersError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := &mockBackend{name: "starter_failing"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe()
	backend.Register("starter_failing", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	mgr.SetStarter(&fakeStarter{err: errors.New("binary not found")})

	mgr.ManagePolicy(config.PolicyPayload{Action: "manage", ID: "failing-1", Name: "Failing", Backend: "starter_failing", Version: 1, Data: map[string]any{}, DatasetID: "ds"})

	be.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	stored, _ := mgr.GetRepo().Get("failing-1")
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Equal(t, "binary not found", stored.BackendErr)
}

// The secrets refresh consults the starter the same way.
func TestPoliciesChangedConsultsTheStarter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := &mockSecretsManager{passthrough: true}
	be := &mockBackend{name: "starter_refresh"}
	be.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	be.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil).Maybe()
	backend.Register("starter_refresh", be)
	mgr, err := policymgr.New(logger, secretsMgr, config.Config{})
	require.NoError(t, err)
	require.NoError(t, mgr.GetRepo().Update(policies.PolicyData{ID: "refresh-1", Name: "Refresh", Backend: "starter_refresh", Version: 1, Data: map[string]any{}, State: policies.Running}))
	starter := &fakeStarter{state: policymgr.StartStarting}
	mgr.SetStarter(starter)

	secretsMgr.TriggerCallbacks(map[string]bool{"refresh-1": true})

	assert.Equal(t, []string{"starter_refresh"}, starter.callsSeen())
	be.AssertNotCalled(t, "ApplyPolicy", mock.Anything, mock.Anything)
	stored, _ := mgr.GetRepo().Get("refresh-1")
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Equal(t, "backend starting", stored.BackendErr)
}
