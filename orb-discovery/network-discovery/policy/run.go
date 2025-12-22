package policy

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// RunStatus represents the status of a run
type RunStatus string

const (
	// RunStatusRunning indicates the run is currently running
	RunStatusRunning RunStatus = "running"
	// RunStatusCompleted indicates the run completed successfully
	RunStatusCompleted RunStatus = "completed"
	// RunStatusFailed indicates the run failed with an error
	RunStatusFailed RunStatus = "failed"
)

// Run represents a single run execution
type Run struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	Status      RunStatus `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int       `json:"entity_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RunStore manages runs in memory
type RunStore struct {
	mu   sync.RWMutex
	runs map[string][]*Run // policyName -> runs (max 5)
}

const maxRunsPerPolicy = 5

// NewRunStore creates a new RunStore
func NewRunStore() *RunStore {
	return &RunStore{
		runs: make(map[string][]*Run),
	}
}

// CreateRun creates a new run for the given policy and returns it
func (rs *RunStore) CreateRun(policyName string) *Run {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()
	run := &Run{
		ID:        uuid.New().String(),
		PolicyID:  policyName,
		Status:    RunStatusRunning,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Add run to the policy's run list
	runs := rs.runs[policyName]
	runs = append(runs, run)

	// Keep only the last maxRunsPerPolicy runs
	if len(runs) > maxRunsPerPolicy {
		runs = runs[len(runs)-maxRunsPerPolicy:]
	}

	rs.runs[policyName] = runs
	return run
}

// UpdateRun updates the status of a run
func (rs *RunStore) UpdateRun(policyName, runID string, status RunStatus, err error, entityCount int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	runs := rs.runs[policyName]
	for _, run := range runs {
		if run.ID == runID {
			run.Status = status
			run.EntityCount = entityCount
			run.UpdatedAt = time.Now()
			if err != nil {
				run.Reason = err.Error()
			}
			return
		}
	}
}

// GetRunsForPolicy returns all runs for a given policy
func (rs *RunStore) GetRunsForPolicy(policyName string) []*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	runs := rs.runs[policyName]
	// Return a copy to avoid race conditions
	result := make([]*Run, len(runs))
	copy(result, runs)
	return result
}

// GetAllPoliciesWithRuns returns all policies with their runs
func (rs *RunStore) GetAllPoliciesWithRuns() map[string][]*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	result := make(map[string][]*Run)
	for policyName, runs := range rs.runs {
		// Return a copy to avoid race conditions
		runsCopy := make([]*Run, len(runs))
		copy(runsCopy, runs)
		result[policyName] = runsCopy
	}
	return result
}
