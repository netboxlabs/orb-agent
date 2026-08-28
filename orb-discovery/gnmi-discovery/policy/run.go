package policy

import (
	"sort"
	"strings"
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

// maxRunsPerPolicy caps what /status reports for one policy. A /22 policy can
// hold three runs for each of a thousand targets, and the whole list is
// marshalled on every health check.
const maxRunsPerPolicy = 100

// Run is a single flush execution (one reconciled-snapshot ingest).
type Run struct {
	ID       string `json:"id"`
	PolicyID string `json:"policy_id"`
	Target   string `json:"target"`
	// Targets is what the agent actually reads: PolicyStatusRun decodes
	// `json:"targets"` and has no `target` field, so a run that carries only the
	// singular form reaches the fleet with no target at all.
	Targets     []string  `json:"targets,omitempty"`
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
		Targets: []string{host},
		Status:  RunStatusRunning, CreatedAt: now, UpdatedAt: now,
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

// sweepRunKey is the store key for a policy's sweep runs. A real host is never
// empty, so this cannot collide with a per-device run — including the case where
// the policy's only target is a single host that has runs of its own.
// device-discovery distinguishes the same two shapes the same way, with an empty
// parent_target.
const sweepRunKey = ""

// CreateSweepRun records the start of a target sweep. It is created at the
// start, not on completion, so a sweep that hangs or takes minutes against a
// large range is visible while it runs rather than only afterwards.
func (rs *RunStore) CreateSweepRun(policy string, originalTargets []string) *Run {
	run := rs.CreateRun(policy, sweepRunKey)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, r := range rs.runs[policy][sweepRunKey] {
		if r.ID == run.ID {
			// The operator's own host strings, so the run names the CIDR they
			// wrote rather than a synthesized pseudo-host.
			r.Targets = append([]string(nil), originalTargets...)
			r.Target = strings.Join(originalTargets, ",")
			return copyRun(r)
		}
	}
	return run
}

// FinishSweepRun closes a sweep run with a human-readable reason. UpdateRun
// fills Reason only from a non-nil error, and a successful sweep has no error
// to report while still having something worth saying.
func (rs *RunStore) FinishSweepRun(policy, runID string, status RunStatus, reason string, admitted int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, run := range rs.runs[policy][sweepRunKey] {
		if run.ID == runID {
			run.Status = status
			run.Reason = reason
			run.EntityCount = admitted
			run.UpdatedAt = time.Now().UTC().UnixNano()
			return
		}
	}
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

// GetRunsForPolicy returns a policy's most recently active runs.
//
// The result is capped. A policy sweeping a /22 holds up to maxRunsPerTarget
// runs for each of a thousand targets, and the agent polls /status every 10s
// with a 2s budget and restarts the backend when that times out — so an
// uncapped list turns a large policy into a restart loop.
//
// Sweep runs are exempt from the cap. They are the one record that describes the
// policy as a whole, and they are also the easiest to lose: a busy range
// produces device runs continuously, which would push the sweep off the end.
func (rs *RunStore) GetRunsForPolicy(policy string) []*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]*Run, 0)
	var sweeps []*Run
	for host, targetRuns := range rs.runs[policy] {
		for _, r := range targetRuns {
			if host == sweepRunKey {
				sweeps = append(sweeps, copyRun(r))
				continue
			}
			out = append(out, copyRun(r))
		}
	}
	sortByActivity(out)
	if room := maxRunsPerPolicy - len(sweeps); len(out) > room {
		out = out[:max(room, 0)]
	}
	out = append(out, sweeps...)
	sortByActivity(out)
	return out
}

// sortByActivity orders runs most-recently-active first.
//
// Not creation order: a sweep run is created before every run it starts, so
// sorting on CreatedAt would permanently bury it under the per-device runs it
// produced. Activity order is also the more useful one generally. The
// consequence for existing policies is that per-device runs order by activity
// rather than by creation.
func sortByActivity(runs []*Run) {
	sort.Slice(runs, func(i, j int) bool { return runs[i].UpdatedAt > runs[j].UpdatedAt })
}
