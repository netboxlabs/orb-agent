package policies_test

import (
	"testing"
	"time"

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

func TestUpdateRuns(t *testing.T) {
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

	// Update runs for the policy (new runs, no timestamps)
	runs := []policies.RunData{
		{
			ID:     "run-1",
			Status: "completed",
		},
		{
			ID:     "run-2",
			Status: "running",
		},
	}

	before := time.Now().UTC()
	err = repo.UpdateRuns("test-policy", runs)
	require.NoError(t, err)
	after := time.Now().UTC()

	// Verify runs are updated
	retrievedPD, err := repo.Get("test-id")
	require.NoError(t, err)
	assert.Len(t, retrievedPD.Runs, 2)
	assert.Equal(t, "run-1", retrievedPD.Runs[0].ID)
	assert.Equal(t, "completed", retrievedPD.Runs[0].Status)
	assert.Equal(t, "test-id", retrievedPD.Runs[0].PolicyID)
	assert.Equal(t, "run-2", retrievedPD.Runs[1].ID)
	assert.Equal(t, "running", retrievedPD.Runs[1].Status)
	assert.Equal(t, "test-id", retrievedPD.Runs[1].PolicyID)

	// Verify timestamps were set for new runs
	for _, r := range retrievedPD.Runs {
		assert.False(t, r.CreatedAt.IsZero(), "CreatedAt should be set for new run %s", r.ID)
		assert.False(t, r.UpdatedAt.IsZero(), "UpdatedAt should be set for new run %s", r.ID)
		assert.True(t, !r.CreatedAt.Before(before) && !r.CreatedAt.After(after))
		assert.True(t, !r.UpdatedAt.Before(before) && !r.UpdatedAt.After(after))
	}

	// Verify runs are also returned via GetByName
	retrievedPDByName, err := repo.GetByName("test-policy")
	require.NoError(t, err)
	assert.Len(t, retrievedPDByName.Runs, 2)
}

func TestUpdateRuns_InProgressRunAlwaysAdvancesUpdatedAt(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		State:    policies.Running,
	}
	err = repo.Update(pd)
	require.NoError(t, err)

	entityCount := int64(5)

	// First update: new run
	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "running", EntityCount: entityCount},
	})
	require.NoError(t, err)

	first, _ := repo.Get("test-id")
	createdAt := first.Runs[0].CreatedAt
	updatedAt := first.Runs[0].UpdatedAt

	time.Sleep(2 * time.Millisecond)

	// Second update: exact same data — UpdatedAt must still advance
	// because the run is in progress and UpdatedAt reflects elapsed time
	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "running", EntityCount: entityCount},
	})
	require.NoError(t, err)

	second, _ := repo.Get("test-id")
	assert.Equal(t, createdAt, second.Runs[0].CreatedAt, "CreatedAt must not change")
	assert.True(t, second.Runs[0].UpdatedAt.After(updatedAt), "UpdatedAt must advance on every poll while run is in progress")
}

func TestUpdateRuns_TerminalStatusFreezesUpdatedAt(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		State:    policies.Running,
	}
	err = repo.Update(pd)
	require.NoError(t, err)

	// First: run is running
	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "running"},
	})
	require.NoError(t, err)

	time.Sleep(2 * time.Millisecond)

	// Second: run completes — UpdatedAt should advance to mark completion
	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "completed"},
	})
	require.NoError(t, err)

	completed, _ := repo.Get("test-id")
	completedAt := completed.Runs[0].UpdatedAt
	createdAt := completed.Runs[0].CreatedAt
	assert.True(t, completedAt.After(createdAt), "UpdatedAt should be after CreatedAt for completed run")

	time.Sleep(2 * time.Millisecond)

	// Third: backend keeps reporting the same completed run — UpdatedAt must not change
	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "completed"},
	})
	require.NoError(t, err)

	frozen, _ := repo.Get("test-id")
	assert.Equal(t, completedAt, frozen.Runs[0].UpdatedAt, "UpdatedAt must be frozen after terminal status")
	assert.Equal(t, createdAt, frozen.Runs[0].CreatedAt, "CreatedAt must never change")
}

func TestUpdateRuns_FailedStatusFreezesUpdatedAt(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	pd := policies.PolicyData{
		ID:       "test-id",
		Name:     "test-policy",
		Backend:  "test-backend",
		Version:  1,
		Datasets: map[string]bool{"dataset1": true},
		GroupIDs: map[string]bool{"group1": true},
		State:    policies.Running,
	}
	err = repo.Update(pd)
	require.NoError(t, err)

	// Run fails
	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "failed", Reason: "timeout"},
	})
	require.NoError(t, err)

	failed, _ := repo.Get("test-id")
	failedAt := failed.Runs[0].UpdatedAt

	time.Sleep(2 * time.Millisecond)

	// Backend keeps reporting same failed run — timestamps frozen
	err = repo.UpdateRuns("test-policy", []policies.RunData{
		{ID: "run-1", Status: "failed", Reason: "timeout"},
	})
	require.NoError(t, err)

	frozen, _ := repo.Get("test-id")
	assert.Equal(t, failedAt, frozen.Runs[0].UpdatedAt, "UpdatedAt must be frozen after failed status")
}

func TestUpdateRuns_NonExistentPolicy(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	runs := []policies.RunData{
		{
			ID:     "run-1",
			Status: "completed",
		},
	}

	err = repo.UpdateRuns("non-existent-policy", runs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, policies.ErrPolicyNotFound)
}

func TestUpdateRuns_GetAllIncludesRuns(t *testing.T) {
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

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

	// Update runs for policy 1
	runs1 := []policies.RunData{
		{
			ID:     "run-1",
			Status: "completed",
		},
	}
	err = repo.UpdateRuns("test-policy-1", runs1)
	require.NoError(t, err)

	// Get all policies
	allPolicies, err := repo.GetAll()
	require.NoError(t, err)

	// Find policy 1 and verify runs
	var foundPolicy1 bool
	for _, p := range allPolicies {
		if p.ID == "test-id-1" {
			foundPolicy1 = true
			assert.Len(t, p.Runs, 1)
			assert.Equal(t, "run-1", p.Runs[0].ID)
			break
		}
	}
	assert.True(t, foundPolicy1, "Policy 1 should be found in GetAll()")

	// Verify policy 2 has no runs
	var foundPolicy2 bool
	for _, p := range allPolicies {
		if p.ID == "test-id-2" {
			foundPolicy2 = true
			assert.Empty(t, p.Runs)
			break
		}
	}
	assert.True(t, foundPolicy2, "Policy 2 should be found in GetAll()")
}
