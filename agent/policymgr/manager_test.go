package policymgr_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

func (m *mockBackend) ManagedBinaryName() string { return "" }

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

	// Check for PreviousPolicyData with original name
	require.NotNil(t, state[0].PreviousPolicyData)
	assert.Equal(t, "Test Policy", state[0].PreviousPolicyData.Name)
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
