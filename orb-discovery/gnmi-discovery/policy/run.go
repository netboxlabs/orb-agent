package policy

import (
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RunStatus is the status of a run.
type RunStatus string

const (
	// RunStatusRunning indicates an in-progress flush run.
	RunStatusRunning RunStatus = "running"
	// RunStatusCompleted indicates a successfully finished flush run.
	RunStatusCompleted RunStatus = "completed"
	// RunStatusFailed indicates a flush run that ended with an error.
	RunStatusFailed RunStatus = "failed"
)

const maxRunsPerTarget = 3

// Run is a single flush execution (one reconciled-snapshot ingest).
type Run struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	Target      string    `json:"target"`
	Status      RunStatus `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int       `json:"entity_count"`
	CreatedAt   int64     `json:"created_at"`
	UpdatedAt   int64     `json:"updated_at"`
}

// RunStore keeps recent runs in memory, per policy and target.
type RunStore struct {
	mu   sync.RWMutex
	runs map[string]map[string][]*Run // policy -> host -> runs (last maxRunsPerTarget)
}

// NewRunStore returns an empty store.
func NewRunStore() *RunStore {
	return &RunStore{runs: make(map[string]map[string][]*Run)}
}

func copyRun(r *Run) *Run { c := *r; return &c }

// CreateRun records a new running run for policy/host and returns a copy.
func (rs *RunStore) CreateRun(policy, host string) *Run {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	now := time.Now().UTC().UnixNano()
	run := &Run{
		ID: uuid.New().String(), PolicyID: policy, Target: host,
		Status: RunStatusRunning, CreatedAt: now, UpdatedAt: now,
	}
	if rs.runs[policy] == nil {
		rs.runs[policy] = make(map[string][]*Run)
	}
	runs := append(rs.runs[policy][host], run)
	if len(runs) > maxRunsPerTarget {
		runs = runs[len(runs)-maxRunsPerTarget:]
	}
	rs.runs[policy][host] = runs
	return copyRun(run)
}

// UpdateRun updates the status and metadata of a run.
func (rs *RunStore) UpdateRun(policy, host, runID string, status RunStatus, err error, entityCount int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.runs[policy] == nil {
		return
	}
	for _, run := range rs.runs[policy][host] {
		if run.ID == runID {
			run.Status = status
			run.EntityCount = entityCount
			run.UpdatedAt = time.Now().UTC().UnixNano()
			if err != nil {
				run.Reason = err.Error()
			} else {
				run.Reason = ""
			}
			return
		}
	}
}

// GetRunsForPolicy returns all runs for a policy (flattened, newest first).
func (rs *RunStore) GetRunsForPolicy(policy string) []*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]*Run, 0)
	for _, targetRuns := range rs.runs[policy] {
		for _, r := range targetRuns {
			out = append(out, copyRun(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}
