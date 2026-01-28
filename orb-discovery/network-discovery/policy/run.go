package policy

import (
	"encoding/json"
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
	ID          string            `json:"id"`
	PolicyID    string            `json:"policy_id"`
	Status      RunStatus         `json:"status"`
	Reason      string            `json:"reason,omitempty"`
	EntityCount int               `json:"entity_count"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   int64             `json:"created_at"`
	UpdatedAt   int64             `json:"updated_at"`
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
func (rs *RunStore) CreateRun(policyName string, targets []string) *Run {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()

	// Create metadata with targets if provided
	var metadata map[string]string
	if len(targets) > 0 {
		targetsJSON, err := json.Marshal(targets)
		if err == nil {
			metadata = make(map[string]string)
			metadata["targets"] = string(targetsJSON)
		}
	}

	run := &Run{
		ID:        uuid.New().String(),
		PolicyID:  policyName,
		Status:    RunStatusRunning,
		Metadata:  metadata,
		CreatedAt: now.UTC().UnixNano(),
		UpdatedAt: now.UTC().UnixNano(),
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
			run.UpdatedAt = time.Now().UTC().UnixNano()
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
