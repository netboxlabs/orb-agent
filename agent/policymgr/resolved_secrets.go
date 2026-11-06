package policymgr

import (
	"slices"
	"sync"
	"time"

	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

// removedGrace is how long a removed policy's values keep masking its
// backend's output: a line the backend printed about the policy before the
// removal can still be waiting to be relayed.
const removedGrace = time.Minute

// resolvedSecrets holds, by policy ID, the values the policy's secret
// references resolved to and the backend it runs on. The agent resolves a
// policy's secrets for each apply and stores only its unresolved data, but
// what the backend reports or prints about the policy afterwards can quote
// what it was given: a run's reason, a line of its process's output. Those
// are masked with the values kept here.
type resolvedSecrets struct {
	mu       sync.Mutex
	byPolicy map[string]policySecrets
	now      func() time.Time
}

type policySecrets struct {
	backend string
	// values are those of the policy's last resolution, previous those of
	// the one before it that differed: the backend goes on reporting a run
	// it ran with them after the policy changed or its secret was rotated.
	// Only two are kept, since each value is held in memory and masks every
	// line the backend prints.
	values, previous []resolvedValue
	// removed is when the policy was removed, or zero.
	removed time.Time
}

func newResolvedSecrets() *resolvedSecrets {
	return &resolvedSecrets{byPolicy: make(map[string]policySecrets), now: time.Now}
}

// remember records the values a policy's references resolved to for an apply
// to the named backend.
func (s *resolvedSecrets) remember(policyID, backendName string, resolved []resolvedValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, ok := s.byPolicy[policyID]
	if !ok && len(resolved) == 0 {
		return
	}
	ps.backend = backendName
	ps.removed = time.Time{}
	if !sameValues(ps.values, resolved) {
		ps.previous, ps.values = ps.values, slices.Clone(resolved)
	}
	s.byPolicy[policyID] = ps
}

// sameValues reports whether a and b hold the same values, in any order:
// resolvedValues walks maps, whose order changes from one call to the next.
func sameValues(a, b []resolvedValue) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !slices.Contains(b, r) {
			return false
		}
	}
	return true
}

// removed records that a policy was removed: its values are dropped
// removedGrace later.
func (s *resolvedSecrets) removed(policyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ps, ok := s.byPolicy[policyID]; ok {
		ps.removed = s.now()
		s.byPolicy[policyID] = ps
	}
}

// kept returns the policy's entry, dropping it when it was removed more than
// removedGrace ago. The caller holds s.mu.
func (s *resolvedSecrets) kept(policyID string) (policySecrets, bool) {
	ps, ok := s.byPolicy[policyID]
	if ok && !ps.removed.IsZero() && s.now().Sub(ps.removed) > removedGrace {
		delete(s.byPolicy, policyID)
		return policySecrets{}, false
	}
	return ps, ok
}

// of returns the values kept for a policy.
func (s *resolvedSecrets) of(policyID string) []resolvedValue {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, _ := s.kept(policyID)
	values := slices.Clone(ps.values)
	for _, r := range ps.previous {
		if !slices.Contains(values, r) {
			values = append(values, r)
		}
	}
	return values
}

// maskOutput masks, in a line a backend's process printed, the values of
// every policy the backend runs: a line names no policy.
func (s *resolvedSecrets) maskOutput(backendName, line string) string {
	var values []string
	s.mu.Lock()
	for id := range s.byPolicy {
		ps, ok := s.kept(id)
		if !ok || ps.backend != backendName {
			continue
		}
		values = appendNew(values, ps.values)
		values = appendNew(values, ps.previous)
	}
	s.mu.Unlock()
	if len(values) == 0 {
		return line
	}
	return redact.Values(line, values)
}

// appendNew appends to values those of resolved it does not hold yet.
func appendNew(values []string, resolved []resolvedValue) []string {
	for _, r := range resolved {
		if !slices.Contains(values, r.value) {
			values = append(values, r.value)
		}
	}
	return values
}

// maskingRepo is the repo the policy manager keeps its policies in and hands
// out to the backends and their state manager.
type maskingRepo struct {
	policies.PolicyRepo
	secrets *resolvedSecrets
}

// UpdateRuns masks the values the policy's secret references resolved to in
// the runs a backend reports before storing them: the runs ride every
// heartbeat to Fleet. A backend can put in a run's reason an exception's
// text that quotes what it was given, so the reason is masked, and kept to
// the bound a refusal is kept to, as a refusal is; and it can copy a target
// or its driver from the policy's scope.
func (r *maskingRepo) UpdateRuns(policyName string, runs []policies.RunData) error {
	var resolved []resolvedValue
	if pd, err := r.GetByName(policyName); err == nil {
		resolved = r.secrets.of(pd.ID)
	}
	values := appendNew(nil, resolved)
	for i := range runs {
		if runs[i].Reason != "" {
			_, runs[i].Reason = backendRefusal(runs[i].Reason, resolved)
		}
		if len(values) == 0 {
			continue
		}
		if runs[i].Targets != nil {
			targets := make([]string, len(runs[i].Targets))
			for j, target := range runs[i].Targets {
				targets[j] = redact.Values(target, values)
			}
			runs[i].Targets = targets
		}
		runs[i].Driver = redact.Values(runs[i].Driver, values)
	}
	return r.PolicyRepo.UpdateRuns(policyName, runs)
}

// Remove removes a policy; the values its secret references resolved to are
// dropped removedGrace later.
func (r *maskingRepo) Remove(policyID string) error {
	err := r.PolicyRepo.Remove(policyID)
	r.secrets.removed(policyID)
	return err
}
