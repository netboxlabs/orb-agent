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

// GetRunsForPolicy returns a policy's runs, capped.
//
// The cap exists because a policy sweeping a /22 holds up to maxRunsPerTarget
// runs for each of a thousand targets, and the agent polls /status every 10s
// with a 2s budget and restarts the backend when that times out — so an uncapped
// list turns a large policy into a restart loop.
//
// What survives the cap is ordered by how much it explains, not by recency:
//
// Sweep runs first. They are the one record describing the policy as a whole,
// and the easiest to lose, since a busy range produces device runs continuously.
//
// Then runs still in flight, stalest first. These must never be dropped, and
// activity order drops them first: a run's UpdatedAt is stamped when it is
// created and not touched again until it finishes, so the longer one hangs the
// further it sinks. deriveStatus looks for RunStatusRunning in this result alone,
// so truncating an in-flight run makes a policy with a hung ingest report
// completed and hides the run that would explain it. Stalest first because if
// even these have to be trimmed, the most stuck ones are the ones worth seeing.
//
// Finished runs fill whatever budget is left, most recently active first.
func (rs *RunStore) GetRunsForPolicy(policy string) []*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	var sweeps, running, finished []*Run
	for host, targetRuns := range rs.runs[policy] {
		for _, r := range targetRuns {
			c := copyRun(r)
			switch {
			case host == sweepRunKey:
				sweeps = append(sweeps, c)
			case c.Status == RunStatusRunning:
				running = append(running, c)
			default:
				finished = append(finished, c)
			}
		}
	}

	sortByStalest(running)
	sortByActivity(finished)

	budget := max(maxRunsPerPolicy-len(sweeps), 0)
	if len(running) > budget {
		running = running[:budget]
	}
	budget -= len(running)
	if len(finished) > budget {
		finished = finished[:max(budget, 0)]
	}

	out := make([]*Run, 0, len(sweeps)+len(running)+len(finished))
	out = append(out, sweeps...)
	out = append(out, running...)
	out = append(out, finished...)
	sortByActivity(out)
	return out
}

// sortByStalest orders runs least-recently-active first.
func sortByStalest(runs []*Run) {
	sort.Slice(runs, func(i, j int) bool { return runs[i].UpdatedAt < runs[j].UpdatedAt })
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
