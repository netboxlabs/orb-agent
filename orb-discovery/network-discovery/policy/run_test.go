package policy_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/netboxlabs/orb-discovery/network-discovery/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunStore_CreateRun(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"

	run := store.CreateRun(policyName)

	// Verify run properties
	assert.NotEmpty(t, run.ID)
	assert.Equal(t, policy.RunStatusRunning, run.Status)
	assert.Empty(t, run.Reason)
	assert.Equal(t, 0, run.EntityCount)
	assert.False(t, run.CreatedAt.IsZero())
	assert.False(t, run.UpdatedAt.IsZero())
	assert.Equal(t, run.CreatedAt, run.UpdatedAt)

	// Verify run is stored
	runs := store.GetRunsForPolicy(policyName)
	require.Len(t, runs, 1)
	assert.Equal(t, run.ID, runs[0].ID)
}

func TestRunStore_UpdateRun(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"

	run := store.CreateRun(policyName)
	runID := run.ID

	// Update to completed
	entityCount := 5
	store.UpdateRun(policyName, runID, policy.RunStatusCompleted, nil, entityCount)

	runs := store.GetRunsForPolicy(policyName)
	require.Len(t, runs, 1)
	assert.Equal(t, policy.RunStatusCompleted, runs[0].Status)
	assert.Empty(t, runs[0].Reason)
	assert.Equal(t, entityCount, runs[0].EntityCount)
	assert.True(t, runs[0].UpdatedAt.After(runs[0].CreatedAt))

	// Update to failed with error
	testError := errors.New("test error")
	entityCount = 10
	store.UpdateRun(policyName, runID, policy.RunStatusFailed, testError, entityCount)

	runs = store.GetRunsForPolicy(policyName)
	require.Len(t, runs, 1)
	assert.Equal(t, policy.RunStatusFailed, runs[0].Status)
	assert.Equal(t, testError.Error(), runs[0].Reason)
	assert.Equal(t, entityCount, runs[0].EntityCount)
}

func TestRunStore_MaxFiveRuns(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"

	// Create 7 runs
	var runIDs []string
	for i := 0; i < 7; i++ {
		run := store.CreateRun(policyName)
		runIDs = append(runIDs, run.ID)
		time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
	}

	// Verify only last 5 runs are retained
	runs := store.GetRunsForPolicy(policyName)
	require.Len(t, runs, 5)

	// Verify the last 5 runs are the ones retained
	expectedIDs := runIDs[2:] // Last 5 runs
	actualIDs := make([]string, len(runs))
	for i, run := range runs {
		actualIDs[i] = run.ID
	}
	assert.Equal(t, expectedIDs, actualIDs)
}

func TestRunStore_Concurrency(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"

	var wg sync.WaitGroup
	numGoroutines := 10
	runsPerGoroutine := 5

	// Create runs concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < runsPerGoroutine; j++ {
				store.CreateRun(policyName)
			}
		}()
	}

	wg.Wait()

	// Verify all runs were created (should have max 5 per policy)
	runs := store.GetRunsForPolicy(policyName)
	assert.LessOrEqual(t, len(runs), 5)

	// Test concurrent updates
	if len(runs) > 0 {
		runID := runs[0].ID
		entityCount := 3
		wg = sync.WaitGroup{}
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.UpdateRun(policyName, runID, policy.RunStatusCompleted, nil, entityCount)
			}()
		}
		wg.Wait()

		// Verify run was updated
		runs = store.GetRunsForPolicy(policyName)
		found := false
		for _, run := range runs {
			if run.ID == runID {
				assert.Equal(t, policy.RunStatusCompleted, run.Status)
				assert.Equal(t, entityCount, run.EntityCount)
				found = true
				break
			}
		}
		assert.True(t, found, "Run should be found after concurrent updates")
	}
}

func TestRunStore_GetAllPoliciesWithRuns(t *testing.T) {
	store := policy.NewRunStore()

	// Create runs for multiple policies
	policy1 := "policy-1"
	policy2 := "policy-2"

	store.CreateRun(policy1)
	store.CreateRun(policy1)
	store.CreateRun(policy2)

	allRuns := store.GetAllPoliciesWithRuns()

	assert.Len(t, allRuns, 2)
	assert.Len(t, allRuns[policy1], 2)
	assert.Len(t, allRuns[policy2], 1)
}

func TestRunStore_GetRunsForPolicy_Empty(t *testing.T) {
	store := policy.NewRunStore()

	runs := store.GetRunsForPolicy("non-existent-policy")
	assert.Empty(t, runs)
}

func TestRunStore_UpdateRun_NonExistent(t *testing.T) {
	store := policy.NewRunStore()

	// Update a run that doesn't exist - should not panic
	store.UpdateRun("non-existent-policy", "non-existent-id", policy.RunStatusFailed, errors.New("test"), 0)

	// Verify no runs were created
	runs := store.GetRunsForPolicy("non-existent-policy")
	assert.Empty(t, runs)
}
