package policies_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

func TestNewMemRepo(t *testing.T) {
	repo, err := policies.NewMemRepo()

	assert.NoError(t, err)
	assert.NotNil(t, repo)
}

func TestExists(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Non-existent policy
	exists := repo.Exists("non-existent-id")
	assert.False(t, exists)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Now it should exist
	exists = repo.Exists("test-id")
	assert.True(t, exists)
}

func TestGet(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Try to get a non-existent policy
	_, err = repo.Get("non-existent-id")
	assert.Error(t, err)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Get the policy
	retrievedPD, err := repo.Get("test-id")
	require.NoError(t, err)

	assert.Equal(t, pd.ID, retrievedPD.ID)
	assert.Equal(t, pd.Name, retrievedPD.Name)
	assert.Equal(t, pd.Backend, retrievedPD.Backend)
	assert.Equal(t, pd.Version, retrievedPD.Version)
	assert.Equal(t, pd.Datasets, retrievedPD.Datasets)
	assert.Equal(t, pd.GroupIDs, retrievedPD.GroupIDs)
	assert.Equal(t, pd.State, retrievedPD.State)
}

func TestGetByName(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Try to get a non-existent policy by name
	_, err = repo.GetByName("non-existent-name")
	assert.Error(t, err)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Get the policy by name
	retrievedPD, err := repo.GetByName("test-policy")
	require.NoError(t, err)

	assert.Equal(t, pd.ID, retrievedPD.ID)
	assert.Equal(t, pd.Name, retrievedPD.Name)
}

func TestUpdate(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Update the policy
	pd.Version = 2
	pd.State = policies.Running

	err = repo.Update(pd)
	require.NoError(t, err)

	// Get the updated policy
	retrievedPD, err := repo.Get("test-id")
	require.NoError(t, err)

	assert.Equal(t, int32(2), retrievedPD.Version)
	assert.Equal(t, policies.Running, retrievedPD.State)
}

func TestRemove(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Try to remove a non-existent policy
	err = repo.Remove("non-existent-id")
	assert.Error(t, err)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Remove the policy
	err = repo.Remove("test-id")
	assert.NoError(t, err)

	// Verify it's removed
	exists := repo.Exists("test-id")
	assert.False(t, exists)

	// Verify name mapping is also removed
	_, err = repo.GetByName("test-policy")
	assert.Error(t, err)
}

func TestGetAll(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Get all policies when none exist
	allPolicies, err := repo.GetAll()
	require.NoError(t, err)
	assert.Empty(t, allPolicies)

	// Create policies
	pd1 := policies.PolicyData{
		ID:       "test-id-1",
		Name:     "test-policy-1",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	pd2 := policies.PolicyData{
		ID:       "test-id-2",
		Name:     "test-policy-2",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset2": true},
		GroupIDs: map[string]bool{"group2": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Running,
	}

	err = repo.Update(pd1)
	require.NoError(t, err)

	err = repo.Update(pd2)
	require.NoError(t, err)

	// Get all policies
	allPolicies, err = repo.GetAll()
	require.NoError(t, err)

	assert.Len(t, allPolicies, 2)

	// Create a map of policies by ID for easier checking
	policiesMap := make(map[string]policies.PolicyData)
	for _, p := range allPolicies {
		policiesMap[p.ID] = p
	}

	// Verify both policies are returned
	assert.Contains(t, policiesMap, "test-id-1")
	assert.Contains(t, policiesMap, "test-id-2")
}

func TestEnsureDataset(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Try to ensure dataset for a non-existent policy
	err = repo.EnsureDataset("non-existent-id", "dataset2")
	assert.Error(t, err)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Ensure a new dataset
	err = repo.EnsureDataset("test-id", "dataset2")
	assert.NoError(t, err)

	// Verify the dataset is added
	retrievedPD, err := repo.Get("test-id")
	require.NoError(t, err)

	assert.True(t, retrievedPD.Datasets["dataset1"])
	assert.True(t, retrievedPD.Datasets["dataset2"])
}

func TestRemoveDataset(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Try to remove dataset from a non-existent policy
	_, err = repo.RemoveDataset("non-existent-id", "dataset1")
	assert.Error(t, err)

	// Create a policy with multiple datasets
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true, "dataset2": true, "dataset3": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Remove a dataset that doesn't affect policy removal
	removePolicy, err := repo.RemoveDataset("test-id", "dataset1")
	require.NoError(t, err)
	assert.False(t, removePolicy)

	// Verify the dataset is removed but policy still exists
	retrievedPD, err := repo.Get("test-id")
	require.NoError(t, err)
	assert.False(t, retrievedPD.Datasets["dataset1"])
	assert.True(t, retrievedPD.Datasets["dataset2"])
	assert.True(t, retrievedPD.Datasets["dataset3"])

	// Remove another dataset
	removePolicy, err = repo.RemoveDataset("test-id", "dataset2")
	require.NoError(t, err)
	assert.False(t, removePolicy)

	// Remove the last dataset which should trigger policy removal
	removePolicy, err = repo.RemoveDataset("test-id", "dataset3")
	require.NoError(t, err)
	assert.True(t, removePolicy)

	// Verify the datasets are all removed
	retrievedPD, err = repo.Get("test-id")
	require.NoError(t, err)
	assert.Empty(t, retrievedPD.Datasets)
}

func TestEnsureGroupID(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Try to ensure group ID for a non-existent policy
	err = repo.EnsureGroupID("non-existent-id", "group2")
	assert.Error(t, err)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Ensure a new group ID
	err = repo.EnsureGroupID("test-id", "group2")
	assert.NoError(t, err)

	// Verify the group ID is added
	retrievedPD, err := repo.Get("test-id")
	require.NoError(t, err)

	assert.True(t, retrievedPD.GroupIDs["group1"])
	assert.True(t, retrievedPD.GroupIDs["group2"])
}

func TestUpdateRenamingPolicy(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	// Create a policy
	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "old-name",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		Data:     map[string]any{"key": "value"},
		State:    policies.Unknown,
	}

	err = repo.Update(pd)
	require.NoError(t, err)

	// Verify we can get by old name
	_, err = repo.GetByName("old-name")
	require.NoError(t, err)

	// Update the policy with a new name
	pd.Name = "new-name"
	err = repo.Update(pd)
	require.NoError(t, err)

	// Verify we can get by new name
	retrievedPD, err := repo.GetByName("new-name")
	require.NoError(t, err)
	assert.Equal(t, "test-id", retrievedPD.ID)

	// Verify we cannot get by old name
	_, err = repo.GetByName("old-name")
	assert.Error(t, err)
}
