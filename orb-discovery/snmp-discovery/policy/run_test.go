package policy_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunStore_CreateRun(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target := "192.168.1.10"
	port := uint16(161)
	parentTarget := "192.168.1.0/24"

	run := store.CreateRun(policyName, target, port, parentTarget)

	// Verify run properties
	assert.NotEmpty(t, run.ID)
	assert.Equal(t, policyName, run.PolicyID)
	assert.Equal(t, policy.RunStatusRunning, run.Status)
	assert.Empty(t, run.Reason)
	assert.Equal(t, 0, run.EntityCount)

	// Verify metadata
	assert.NotNil(t, run.Metadata)
	assert.Equal(t, target, run.Metadata["target"])
	assert.Equal(t, "161", run.Metadata["port"])
	assert.Equal(t, parentTarget, run.Metadata["parent_target"])

	assert.Greater(t, run.CreatedAt, int64(0))
	assert.Greater(t, run.UpdatedAt, int64(0))
	assert.Equal(t, run.CreatedAt, run.UpdatedAt)

	// Verify run is stored for target
	runs := store.GetRunsForTarget(policyName, target, port)
	require.Len(t, runs, 1)
	assert.Equal(t, run.ID, runs[0].ID)
}

func TestRunStore_CreateRun_NoParentTarget(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target := "192.168.1.10"
	port := uint16(161)

	run := store.CreateRun(policyName, target, port, "")

	// Verify metadata has target and port, but not parent_target
	assert.NotNil(t, run.Metadata)
	assert.Equal(t, target, run.Metadata["target"])
	assert.Equal(t, "161", run.Metadata["port"])
	assert.NotContains(t, run.Metadata, "parent_target")
}

func TestRunStore_UpdateRun(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target := "192.168.1.10"
	port := uint16(161)

	run := store.CreateRun(policyName, target, port, "")
	runID := run.ID

	// Update to completed
	entityCount := 5
	store.UpdateRun(policyName, target, port, runID, policy.RunStatusCompleted, nil, entityCount)

	runs := store.GetRunsForTarget(policyName, target, port)
	require.Len(t, runs, 1)
	assert.Equal(t, policy.RunStatusCompleted, runs[0].Status)
	assert.Empty(t, runs[0].Reason)
	assert.Equal(t, entityCount, runs[0].EntityCount)
	assert.Greater(t, runs[0].UpdatedAt, runs[0].CreatedAt)

	// Update to failed with error
	testError := errors.New("test error")
	entityCount = 10
	store.UpdateRun(policyName, target, port, runID, policy.RunStatusFailed, testError, entityCount)

	runs = store.GetRunsForTarget(policyName, target, port)
	require.Len(t, runs, 1)
	assert.Equal(t, policy.RunStatusFailed, runs[0].Status)
	assert.Equal(t, testError.Error(), runs[0].Reason)
	assert.Equal(t, entityCount, runs[0].EntityCount)
}

func TestRunStore_MaxThreeRunsPerTarget(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target := "192.168.1.10"
	port := uint16(161)

	// Create 5 runs for same target+port
	var runIDs []string
	for i := 0; i < 5; i++ {
		run := store.CreateRun(policyName, target, port, "")
		runIDs = append(runIDs, run.ID)
		time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
	}

	// Verify only last 3 runs are retained for this target+port
	runs := store.GetRunsForTarget(policyName, target, port)
	require.Len(t, runs, 3)

	// Verify the last 3 runs are the ones retained
	expectedIDs := runIDs[2:] // Last 3 runs
	actualIDs := make([]string, len(runs))
	for i, run := range runs {
		actualIDs[i] = run.ID
	}
	assert.Equal(t, expectedIDs, actualIDs)
}

func TestRunStore_MaxThreeRunsPerTarget_MultipleTargets(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target1 := "192.168.1.10"
	target2 := "192.168.1.11"
	port := uint16(161)
	parentTarget := "192.168.1.0/24"

	// Create 5 runs for target1
	for i := 0; i < 5; i++ {
		store.CreateRun(policyName, target1, port, parentTarget)
		time.Sleep(10 * time.Millisecond)
	}

	// Create 4 runs for target2
	for i := 0; i < 4; i++ {
		store.CreateRun(policyName, target2, port, parentTarget)
		time.Sleep(10 * time.Millisecond)
	}

	// Verify each target has max 3 runs
	runs1 := store.GetRunsForTarget(policyName, target1, port)
	require.Len(t, runs1, 3)

	runs2 := store.GetRunsForTarget(policyName, target2, port)
	require.Len(t, runs2, 3)

	// Verify runs have correct metadata
	for _, run := range runs1 {
		assert.Equal(t, target1, run.Metadata["target"])
		assert.Equal(t, "161", run.Metadata["port"])
		assert.Equal(t, parentTarget, run.Metadata["parent_target"])
	}
	for _, run := range runs2 {
		assert.Equal(t, target2, run.Metadata["target"])
		assert.Equal(t, "161", run.Metadata["port"])
		assert.Equal(t, parentTarget, run.Metadata["parent_target"])
	}

	// Verify GetRunsForPolicy returns all runs from both targets (flattened)
	allRuns := store.GetRunsForPolicy(policyName)
	assert.Len(t, allRuns, 6) // 3 from target1 + 3 from target2

	// Verify runs are sorted by CreatedAt descending (newest first)
	for i := 0; i < len(allRuns)-1; i++ {
		assert.GreaterOrEqual(t, allRuns[i].CreatedAt, allRuns[i+1].CreatedAt,
			"Runs should be sorted newest first")
	}
}

func TestRunStore_GetRunsForTarget(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target1 := "192.168.1.10"
	target2 := "192.168.1.11"
	port := uint16(161)

	store.CreateRun(policyName, target1, port, "")
	store.CreateRun(policyName, target1, port, "")
	store.CreateRun(policyName, target2, port, "")

	runs1 := store.GetRunsForTarget(policyName, target1, port)
	assert.Len(t, runs1, 2)

	runs2 := store.GetRunsForTarget(policyName, target2, port)
	assert.Len(t, runs2, 1)

	// Verify runs are for correct target
	for _, run := range runs1 {
		assert.Equal(t, target1, run.Metadata["target"])
		assert.Equal(t, "161", run.Metadata["port"])
	}
	for _, run := range runs2 {
		assert.Equal(t, target2, run.Metadata["target"])
		assert.Equal(t, "161", run.Metadata["port"])
	}
}

func TestRunStore_GetRunsForPolicy(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target1 := "192.168.1.10"
	target2 := "192.168.1.11"
	target3 := "192.168.1.12"
	port := uint16(161)

	// Create runs for different targets
	store.CreateRun(policyName, target1, port, "192.168.1.0/24")
	time.Sleep(10 * time.Millisecond)
	store.CreateRun(policyName, target2, port, "192.168.1.0/24")
	time.Sleep(10 * time.Millisecond)
	store.CreateRun(policyName, target3, port, "192.168.1.0/24")

	// Get all runs for policy (should be flattened)
	runs := store.GetRunsForPolicy(policyName)
	assert.Len(t, runs, 3)

	// Verify runs are sorted by CreatedAt descending
	assert.Greater(t, runs[0].CreatedAt, runs[1].CreatedAt)
	assert.Greater(t, runs[1].CreatedAt, runs[2].CreatedAt)

	// Verify each run has correct metadata
	targets := make(map[string]bool)
	for _, run := range runs {
		targets[run.Metadata["target"]] = true
		assert.Equal(t, "192.168.1.0/24", run.Metadata["parent_target"])
	}
	assert.Len(t, targets, 3)
}

func TestRunStore_GetRunsForPolicy_Empty(t *testing.T) {
	store := policy.NewRunStore()

	runs := store.GetRunsForPolicy("non-existent-policy")
	assert.Empty(t, runs)
	// Verify it returns empty slice, not nil, for consistent JSON serialization
	assert.NotNil(t, runs, "Should return empty slice, not nil")
}

func TestRunStore_GetRunsForTarget_Empty(t *testing.T) {
	store := policy.NewRunStore()

	runs := store.GetRunsForTarget("non-existent-policy", "192.168.1.10", 161)
	assert.Empty(t, runs)
	// Verify it returns empty slice, not nil, for consistent JSON serialization
	assert.NotNil(t, runs, "Should return empty slice, not nil")
}

func TestRunStore_Concurrency(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target := "192.168.1.10"
	port := uint16(161)

	var wg sync.WaitGroup
	numGoroutines := 10
	runsPerGoroutine := 5

	// Create runs concurrently for same target
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < runsPerGoroutine; j++ {
				store.CreateRun(policyName, target, port, "")
			}
		}()
	}

	wg.Wait()

	// Verify max 3 runs per target+port
	runs := store.GetRunsForTarget(policyName, target, port)
	assert.LessOrEqual(t, len(runs), 3)

	// Test concurrent updates
	if len(runs) > 0 {
		runID := runs[0].ID
		entityCount := 3
		wg = sync.WaitGroup{}
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.UpdateRun(policyName, target, port, runID, policy.RunStatusCompleted, nil, entityCount)
			}()
		}
		wg.Wait()

		// Verify run was updated
		runs = store.GetRunsForTarget(policyName, target, port)
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

func TestRunStore_Concurrency_MultipleTargets(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	targets := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"}
	port := uint16(161)

	var wg sync.WaitGroup

	// Create runs concurrently for multiple targets
	for _, target := range targets {
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				store.CreateRun(policyName, t, port, "192.168.1.0/24")
			}(target)
		}
	}

	wg.Wait()

	// Verify each target has max 3 runs
	for _, target := range targets {
		runs := store.GetRunsForTarget(policyName, target, port)
		assert.LessOrEqual(t, len(runs), 3)
	}

	// Verify total runs are correct
	allRuns := store.GetRunsForPolicy(policyName)
	assert.LessOrEqual(t, len(allRuns), 9) // max 3 per target+port × 3 targets
}

func TestRunStore_GetAllPoliciesWithRuns(t *testing.T) {
	store := policy.NewRunStore()

	// Create runs for multiple policies
	policy1 := "policy-1"
	policy2 := "policy-2"
	port := uint16(161)

	store.CreateRun(policy1, "192.168.1.10", port, "")
	store.CreateRun(policy1, "192.168.1.11", port, "")
	store.CreateRun(policy2, "192.168.2.10", port, "")

	allRuns := store.GetAllPoliciesWithRuns()

	assert.Len(t, allRuns, 2)
	assert.Len(t, allRuns[policy1], 2)
	assert.Len(t, allRuns[policy2], 1)

	// Verify runs are sorted within each policy
	for _, runs := range allRuns {
		for i := 0; i < len(runs)-1; i++ {
			assert.GreaterOrEqual(t, runs[i].CreatedAt, runs[i+1].CreatedAt)
		}
	}
}

func TestRunStore_UpdateRun_NonExistent(t *testing.T) {
	store := policy.NewRunStore()

	// Update a run that doesn't exist - should not panic
	store.UpdateRun("non-existent-policy", "192.168.1.10", 161, "non-existent-id", policy.RunStatusFailed, errors.New("test"), 0)

	// Verify no runs were created
	runs := store.GetRunsForPolicy("non-existent-policy")
	assert.Empty(t, runs)
}

func TestRunStore_TargetNormalization(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	port := uint16(161)

	// Create runs with different but distinct IPs
	target1 := "192.168.1.10"
	target2 := "192.168.1.11"

	run1 := store.CreateRun(policyName, target1, port, "")
	time.Sleep(10 * time.Millisecond)
	run2 := store.CreateRun(policyName, target2, port, "")

	// Should be stored under different normalized targets
	runs1 := store.GetRunsForTarget(policyName, target1, port)
	assert.Len(t, runs1, 1, "First target should have one run")

	runs2 := store.GetRunsForTarget(policyName, target2, port)
	assert.Len(t, runs2, 1, "Second target should have one run")

	// Verify metadata preserves original target strings
	assert.Equal(t, target1, run1.Metadata["target"])
	assert.Equal(t, "161", run1.Metadata["port"])
	assert.Equal(t, target2, run2.Metadata["target"])
	assert.Equal(t, "161", run2.Metadata["port"])

	// Test that same IP in different notation normalizes correctly
	target3 := "192.168.1.10" // Same as target1
	_ = store.CreateRun(policyName, target3, port, "")

	// Should be under same normalized target+port as target1
	runs1After := store.GetRunsForTarget(policyName, target1, port)
	assert.Len(t, runs1After, 2, "Same normalized target+port should have both runs")
}

func TestRunStore_ScanRunWithRange(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	scanTarget := "192.168.1.0/24"
	port := uint16(161)

	// Create scan run (no parent_target)
	scanRun := store.CreateRun(policyName, scanTarget, port, "")

	assert.Equal(t, scanTarget, scanRun.Metadata["target"])
	assert.Equal(t, "161", scanRun.Metadata["port"])
	assert.NotContains(t, scanRun.Metadata, "parent_target")

	// Create individual target runs from scan
	target1 := "192.168.1.10"
	target2 := "192.168.1.11"

	run1 := store.CreateRun(policyName, target1, port, scanTarget)
	run2 := store.CreateRun(policyName, target2, port, scanTarget)

	assert.Equal(t, target1, run1.Metadata["target"])
	assert.Equal(t, "161", run1.Metadata["port"])
	assert.Equal(t, scanTarget, run1.Metadata["parent_target"])

	assert.Equal(t, target2, run2.Metadata["target"])
	assert.Equal(t, "161", run2.Metadata["port"])
	assert.Equal(t, scanTarget, run2.Metadata["parent_target"])

	// Verify scan run is tracked separately (with its own port)
	scanRuns := store.GetRunsForTarget(policyName, scanTarget, port)
	assert.Len(t, scanRuns, 1)

	target1Runs := store.GetRunsForTarget(policyName, target1, port)
	assert.Len(t, target1Runs, 1)

	// Verify all runs are returned by GetRunsForPolicy
	allRuns := store.GetRunsForPolicy(policyName)
	assert.Len(t, allRuns, 3) // scan + 2 targets
}

func TestRunStore_SameHostDifferentPorts(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target := "192.168.1.10"
	port161 := uint16(161)
	port162 := uint16(162)

	// Create 5 runs for port 161
	var runIDsPort161 []string
	for i := 0; i < 5; i++ {
		run := store.CreateRun(policyName, target, port161, "")
		runIDsPort161 = append(runIDsPort161, run.ID)
		time.Sleep(10 * time.Millisecond)
	}

	// Create 5 runs for port 162
	var runIDsPort162 []string
	for i := 0; i < 5; i++ {
		run := store.CreateRun(policyName, target, port162, "")
		runIDsPort162 = append(runIDsPort162, run.ID)
		time.Sleep(10 * time.Millisecond)
	}

	// Verify port 161 has max 3 runs
	runsPort161 := store.GetRunsForTarget(policyName, target, port161)
	require.Len(t, runsPort161, 3, "Port 161 should have max 3 runs")

	// Verify port 162 has max 3 runs
	runsPort162 := store.GetRunsForTarget(policyName, target, port162)
	require.Len(t, runsPort162, 3, "Port 162 should have max 3 runs")

	// Verify the runs are tracked independently
	expectedIDsPort161 := runIDsPort161[2:] // Last 3 runs for port 161
	expectedIDsPort162 := runIDsPort162[2:] // Last 3 runs for port 162

	actualIDsPort161 := make([]string, len(runsPort161))
	for i, run := range runsPort161 {
		actualIDsPort161[i] = run.ID
	}

	actualIDsPort162 := make([]string, len(runsPort162))
	for i, run := range runsPort162 {
		actualIDsPort162[i] = run.ID
	}

	assert.Equal(t, expectedIDsPort161, actualIDsPort161, "Port 161 should have correct runs")
	assert.Equal(t, expectedIDsPort162, actualIDsPort162, "Port 162 should have correct runs")

	// Verify GetRunsForPolicy returns runs from both ports
	allRuns := store.GetRunsForPolicy(policyName)
	assert.Len(t, allRuns, 6, "Should have 3 runs from each port")

	// Verify metadata has correct port values
	for _, run := range runsPort161 {
		assert.Equal(t, "161", run.Metadata["port"], "Port 161 runs should have port=161 in metadata")
	}
	for _, run := range runsPort162 {
		assert.Equal(t, "162", run.Metadata["port"], "Port 162 runs should have port=162 in metadata")
	}
}

func TestRunStore_PortInMetadata(t *testing.T) {
	store := policy.NewRunStore()
	policyName := "test-policy"
	target := "192.168.1.10"
	port := uint16(162)

	// Create run with non-default port
	run := store.CreateRun(policyName, target, port, "")

	// Verify metadata contains port as separate field
	assert.NotNil(t, run.Metadata, "Metadata should not be nil")
	assert.Equal(t, target, run.Metadata["target"], "Metadata should have target field")
	assert.Equal(t, "162", run.Metadata["port"], "Metadata should have port as string")

	// Verify port is stored as string, not concatenated with target
	assert.NotContains(t, run.Metadata["target"], ":", "Target should not contain port")
	assert.NotContains(t, run.Metadata["target"], "162", "Target should not contain port number")
}

func TestRunStore_EmptyRunsJSONSerialization(t *testing.T) {
	store := policy.NewRunStore()

	// Test GetRunsForPolicy with non-existent policy
	runs := store.GetRunsForPolicy("non-existent")
	assert.NotNil(t, runs, "Should return empty slice, not nil")
	assert.Len(t, runs, 0, "Should be empty")

	// Test GetRunsForTarget with non-existent policy
	runs = store.GetRunsForTarget("non-existent", "192.168.1.1", 161)
	assert.NotNil(t, runs, "Should return empty slice, not nil")
	assert.Len(t, runs, 0, "Should be empty")

	// Test GetAllPoliciesWithRuns - empty policies should have empty arrays
	policyName := "empty-policy"
	store.CreateRun(policyName, "192.168.1.1", 161, "")

	// Clear all runs by getting and not adding any
	allRuns := store.GetAllPoliciesWithRuns()
	assert.Contains(t, allRuns, policyName)
	assert.NotNil(t, allRuns[policyName], "Policy runs should be empty slice, not nil")
}
