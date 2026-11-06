package policymgr

import (
	"slices"
	"sync"

	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

// resolvedSecrets holds, by policy ID, the values the policy's secret
// references resolved to and the backend it runs on. The agent resolves a
// policy's secrets for each apply and stores only its unresolved data, but
// what the backend reports or prints about the policy afterwards can quote
// what it was given: a run's reason, a line of its process's output. Those
// are masked with the values kept here.
type resolvedSecrets struct {
	mu       sync.Mutex
	byPolicy map[string]policySecrets
}

type policySecrets struct {
	backend string
	values  []resolvedValue
}

func newResolvedSecrets() *resolvedSecrets {
	return &resolvedSecrets{byPolicy: make(map[string]policySecrets)}
}

// remember adds the values a policy's references resolved to for an apply to
// the named backend. The values of earlier applies are kept until the policy
// is removed: the backend goes on reporting a run it ran with them after the
// policy changed or its secret was rotated.
func (s *resolvedSecrets) remember(policyID, backendName string, resolved []resolvedValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, ok := s.byPolicy[policyID]
	if !ok && len(resolved) == 0 {
		return
	}
	ps.backend = backendName
	for _, r := range resolved {
		if !slices.Contains(ps.values, r) {
			ps.values = append(ps.values, r)
		}
	}
	s.byPolicy[policyID] = ps
}

// forget drops a removed policy's values.
func (s *resolvedSecrets) forget(policyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byPolicy, policyID)
}

// of returns the values kept for a policy.
func (s *resolvedSecrets) of(policyID string) []resolvedValue {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.byPolicy[policyID].values)
}

// maskOutput masks, in a line a backend's process printed, the values of
// every policy the backend runs: a line names no policy.
func (s *resolvedSecrets) maskOutput(backendName, line string) string {
	var values []string
	s.mu.Lock()
	for _, ps := range s.byPolicy {
		if ps.backend != backendName {
			continue
		}
		for _, r := range ps.values {
			if !slices.Contains(values, r.value) {
				values = append(values, r.value)
			}
		}
	}
	s.mu.Unlock()
	if len(values) == 0 {
		return line
	}
	return redact.Values(line, values)
}

// maskingRepo is the repo the policy manager keeps its policies in and hands
// out to the backends and their state manager.
type maskingRepo struct {
	policies.PolicyRepo
	secrets *resolvedSecrets
}

// UpdateRuns masks, in the reason of each run a backend reports, the values
// the policy's secret references resolved to, and keeps it to the bound a
// refusal is kept to, before storing the runs: the reasons ride every
// heartbeat to Fleet, and a backend can put in one an exception's text that
// quotes what it was given.
func (r *maskingRepo) UpdateRuns(policyName string, runs []policies.RunData) error {
	var resolved []resolvedValue
	if pd, err := r.GetByName(policyName); err == nil {
		resolved = r.secrets.of(pd.ID)
	}
	for i := range runs {
		if runs[i].Reason != "" {
			_, runs[i].Reason = backendRefusal(runs[i].Reason, resolved)
		}
	}
	return r.PolicyRepo.UpdateRuns(policyName, runs)
}

// Remove removes a policy and forgets the values its secret references
// resolved to.
func (r *maskingRepo) Remove(policyID string) error {
	err := r.PolicyRepo.Remove(policyID)
	r.secrets.forget(policyID)
	return err
}
