package policymgr_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
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
	callbacks []func(map[string]bool)
}

func (m *mockSecretsManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
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
	err = mgr.RemoveBackendPolicies(mockBe, false)
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
	err = mgr.RemoveBackendPolicies(mockBe, true)
	require.NoError(t, err)

	// Verify policies are gone
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestApplyBackendPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	cfg := config.Config{}

	mockBe := &mockBackend{name: "testbackend"}
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	backend.Register("testbackend", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// First add policies but mark them as unknown (simulating a backend restart)
	repo := mgr.GetRepo()
	for i := 1; i <= 3; i++ {
		policy := policies.PolicyData{
			ID:       fmt.Sprintf("policy%d", i),
			Name:     fmt.Sprintf("Test Policy %d", i),
			Backend:  "testbackend",
			Version:  int32(i),
			Data:     map[string]any{},
			State:    policies.Unknown,
			Datasets: map[string]bool{fmt.Sprintf("dataset%d", i): true},
		}
		err := repo.Update(policy)
		require.NoError(t, err)
	}

	// Set up expectations for applying policies
	mockBe.On("ApplyPolicy", mock.Anything, false).Return(nil).Times(3)

	// Execute
	err = mgr.ApplyBackendPolicies(mockBe)
	require.NoError(t, err)

	// Verify policies are now running
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Len(t, state, 3)
	for _, policy := range state {
		assert.Equal(t, policies.Running, policy.State)
		assert.Empty(t, policy.BackendErr)
	}

	// Test error case - one policy fails to apply
	repo = mgr.GetRepo() // Get fresh repo
	for i := 1; i <= 3; i++ {
		policy := policies.PolicyData{
			ID:       fmt.Sprintf("policy%d", i),
			Name:     fmt.Sprintf("Test Policy %d", i),
			Backend:  "testbackend",
			Version:  int32(i),
			Data:     map[string]any{},
			State:    policies.Unknown,
			Datasets: map[string]bool{fmt.Sprintf("dataset%d", i): true},
		}
		err := repo.Update(policy)
		require.NoError(t, err)
	}

	// Make policy2 fail
	mockBe.ExpectedCalls = nil
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()
	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy1" || pd.ID == "policy3"
	}), false).Return(nil).Times(2)
	mockBe.On("ApplyPolicy", mock.MatchedBy(func(pd policies.PolicyData) bool {
		return pd.ID == "policy2"
	}), false).Return(errors.New("failed to apply")).Once()

	// Execute
	err = mgr.ApplyBackendPolicies(mockBe)
	require.NoError(t, err) // Function should not return error even if some policies fail

	// Verify status
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Len(t, state, 3)

	for _, policy := range state {
		if policy.ID == "policy2" {
			assert.Equal(t, policies.FailedToApply, policy.State)
			assert.Equal(t, "failed to apply", policy.BackendErr)
		} else {
			assert.Equal(t, policies.Running, policy.State)
			assert.Empty(t, policy.BackendErr)
		}
	}
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
	mgr.RemovePolicyDataset("policy1", "dataset1", mockBe)

	// Verify policy still exists but with only one dataset
	state, err = mgr.GetPolicyState()
	require.NoError(t, err)
	require.Len(t, state, 1)
	assert.Len(t, state[0].Datasets, 1)
	assert.False(t, state[0].Datasets["dataset1"])
	assert.True(t, state[0].Datasets["dataset2"])

	// Test removing the last dataset - should remove the policy
	mockBe.On("RemovePolicy", mock.Anything).Return(nil)
	mgr.RemovePolicyDataset("policy1", "dataset2", mockBe)

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
	backend.Register("be_dataset_get_err", mockBe)

	mgr, err := policymgr.New(logger, secretsMgr, cfg)
	require.NoError(t, err)

	// Call RemovePolicyDataset on a policy that doesn't exist — should not panic
	mgr.RemovePolicyDataset("nonexistent_policy", "dataset1", mockBe)
	mockBe.AssertNotCalled(t, "RemovePolicy")
}

func TestRemovePolicyDataset_RemovePolicyError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_dataset_rm_err"}
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
	mgr.RemovePolicyDataset("p_ds_rm", "ds1", mockBe)

	// Policy should be gone from repo
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	assert.Empty(t, state)
}

func TestRemoveBackendPolicies_Permanently(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secretsMgr := new(mockSecretsManager)
	secretsMgr.On("RegisterUpdatePoliciesCallback", mock.Anything).Return()
	cfg := config.Config{}

	mockBe := &mockBackend{name: "be_perm_remove"}
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

	err = mgr.RemoveBackendPolicies(mockBe, true)
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

	err = mgr.RemoveBackendPolicies(mockBe, false)
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

	// The secrets-changed callback rebuilds a minimal payload from the repo.
	// IMPORTANT: verify the matcher against the ACTUAL payload construction in
	// the re-apply loop (config.PolicyPayload{ID, Name, Data}) before finalizing.
	reapplyPayload := config.PolicyPayload{ID: "policy-rc1", Name: "Recheck Policy", Data: policyData}
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

	err = mgr.RemoveBackendPolicies(mockBe, true)
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
