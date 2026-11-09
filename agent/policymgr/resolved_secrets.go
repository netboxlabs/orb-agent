package policymgr

import (
	"cmp"
	"slices"
	"sync"
	"time"

	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

// removedGrace is how long the values of a policy removed from a backend, or
// moved to another, keep masking the backend's output: a line the backend
// printed about the policy before can still be waiting to be relayed.
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
	// departed holds the values of the policies removed from a backend, or
	// moved to another, less than removedGrace ago.
	departed []departedSecrets
	// maskers holds, by backend, what masks its output, built from its
	// policies' values when a line needs it after they changed.
	maskers map[string]*redact.Masker
	now     func() time.Time
}

type policySecrets struct {
	backend string
	// values are those of the policy's last resolution, previous those of
	// the one before it that differed: the backend goes on reporting a run
	// it ran with them after the policy changed or its secret was rotated.
	// Only two are kept, since each value is held in memory and masks every
	// line the backend prints.
	values, previous []resolvedValue
	// masks masks the runs the backend reports for the policy, built from
	// both when one is first stored after they changed.
	masks *refusalMasks
}

// both returns the values of the policy's last two resolutions, each once.
func (ps policySecrets) both() []resolvedValue {
	both := slices.Clone(ps.values)
	for _, r := range ps.previous {
		if !slices.Contains(both, r) {
			both = append(both, r)
		}
	}
	return both
}

// noSecrets masks the runs of a policy the agent keeps no values for: it
// only keeps their reasons to the bound.
var noSecrets = newRefusalMasks(nil)

type departedSecrets struct {
	backend string
	values  []resolvedValue
	at      time.Time
}

func newResolvedSecrets() *resolvedSecrets {
	return &resolvedSecrets{
		byPolicy: make(map[string]policySecrets),
		maskers:  make(map[string]*redact.Masker),
		now:      time.Now,
	}
}

// remember records the values a policy's references resolved to for an apply
// to the named backend.
func (s *resolvedSecrets) remember(policyID, backendName string, resolved []resolvedValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	ps, ok := s.byPolicy[policyID]
	if !ok && len(resolved) == 0 {
		return
	}
	if ok && ps.backend != backendName {
		s.departLocked(ps)
		ps = policySecrets{}
	}
	ps.backend = backendName
	if !sameValues(ps.values, resolved) {
		ps.previous, ps.values = ps.values, slices.Clone(resolved)
		ps.masks = nil
		delete(s.maskers, backendName)
	}
	s.byPolicy[policyID] = ps
}

// sameValues reports whether a and b hold the same values, as many times
// each, in any order: resolvedValues walks maps, whose order changes from
// one call to the next.
func sameValues(a, b []resolvedValue) bool {
	if len(a) != len(b) {
		return false
	}
	byPathAndValue := func(x, y resolvedValue) int {
		return cmp.Or(cmp.Compare(x.path, y.path), cmp.Compare(x.value, y.value))
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, byPathAndValue)
	slices.SortFunc(b, byPathAndValue)
	return slices.Equal(a, b)
}

// removed records that a policy was removed. Its values keep masking its
// backend's output for removedGrace, and are dropped then.
func (s *resolvedSecrets) removed(policyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ps, ok := s.byPolicy[policyID]; ok {
		delete(s.byPolicy, policyID)
		s.departLocked(ps)
	}
}

// departLocked keeps a policy's values masking the output of the backend it
// ran on for removedGrace, and has them dropped then, whatever else happens
// before. The caller holds s.mu.
func (s *resolvedSecrets) departLocked(ps policySecrets) {
	s.departed = append(s.departed, departedSecrets{backend: ps.backend, values: ps.both(), at: s.now()})
	time.AfterFunc(removedGrace, s.prune)
}

func (s *resolvedSecrets) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
}

// pruneLocked drops the departed values older than removedGrace. The caller
// holds s.mu.
func (s *resolvedSecrets) pruneLocked() {
	now := s.now()
	s.departed = slices.DeleteFunc(s.departed, func(d departedSecrets) bool {
		if now.Sub(d.at) <= removedGrace {
			return false
		}
		delete(s.maskers, d.backend)
		return true
	})
}

// of returns the values kept for a policy the agent runs.
func (s *resolvedSecrets) of(policyID string) []resolvedValue {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byPolicy[policyID].both()
}

// masksOf returns what masks the runs a backend reports for a policy the
// agent runs.
func (s *resolvedSecrets) masksOf(policyID string) *refusalMasks {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, ok := s.byPolicy[policyID]
	if !ok {
		return noSecrets
	}
	if ps.masks == nil {
		ps.masks = newRefusalMasks(ps.both())
		s.byPolicy[policyID] = ps
	}
	return ps.masks
}

// maskOutput masks, in a line a backend's process printed, the values of
// every policy the backend runs, or ran less than removedGrace ago: a line
// names no policy.
func (s *resolvedSecrets) maskOutput(backendName, line string) string {
	s.mu.Lock()
	s.pruneLocked()
	m, ok := s.maskers[backendName]
	if !ok {
		var values []string
		for _, ps := range s.byPolicy {
			if ps.backend == backendName {
				values = appendNew(values, ps.both())
			}
		}
		for _, d := range s.departed {
			if d.backend == backendName {
				values = appendNew(values, d.values)
			}
		}
		m = redact.NewMasker(values)
		s.maskers[backendName] = m
	}
	s.mu.Unlock()
	return m.Mask(line)
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
// the bound a refusal is kept to, as a refusal is. It can also copy a target
// or its driver from the policy's scope, so one that is a value is masked
// whole; any other is kept as reported, since Fleet matches a target to a
// device by its exact name.
//
// The runs are masked with the values of the policy their name maps to when
// they are stored: the manager stores a policy it just applied once the
// backend accepted it, so a poll can report its runs before its record lands,
// or while it does. The store looks the name up and saves the runs under one
// lock, which the heartbeat and each export wait on, and masking a long reason
// with a large value takes long. So the runs are masked before, for the
// policy the name maps to then, and again under the lock, from what was
// reported, only when the name maps to another policy by then or that
// policy's values changed; a reason is then masked with the values of both.
func (r *maskingRepo) UpdateRuns(policyName string, runs []policies.RunData) error {
	reported := slices.Clone(runs)
	var maskedFor string
	var maskedWith *refusalMasks
	if pd, err := r.GetByName(policyName); err == nil {
		maskedFor, maskedWith = pd.ID, r.secrets.masksOf(pd.ID)
		maskedWith.maskRuns(runs)
	}
	return r.PolicyRepo.UpdateRunsWith(policyName, runs, func(policyID string, runs []policies.RunData) {
		masks := r.secrets.masksOf(policyID)
		if policyID == maskedFor && masks == maskedWith {
			return
		}
		copy(runs, reported)
		if maskedWith != nil {
			// The runs were reported for the policy looked up first, and can
			// quote its values whatever the name maps to by now.
			for i := range runs {
				runs[i].Reason = maskedWith.all.Mask(runs[i].Reason)
			}
		}
		masks.maskRuns(runs)
	})
}

// UpdateRunsWith masks the runs as UpdateRuns does once prepare has rewritten
// them, under the store's lock.
func (r *maskingRepo) UpdateRunsWith(policyName string, runs []policies.RunData, prepare func(policyID string, runs []policies.RunData)) error {
	return r.PolicyRepo.UpdateRunsWith(policyName, runs, func(policyID string, runs []policies.RunData) {
		if prepare != nil {
			prepare(policyID, runs)
		}
		r.secrets.masksOf(policyID).maskRuns(runs)
	})
}

// maskRuns masks, in runs a backend reported for the policy m was built for,
// the values its secret references resolved to.
func (m *refusalMasks) maskRuns(runs []policies.RunData) {
	isValue := func(v string) bool { return v != "" && slices.Contains(m.values, v) }
	for i := range runs {
		if runs[i].Reason != "" {
			_, runs[i].Reason = m.refusal("", runs[i].Reason)
		}
		if slices.ContainsFunc(runs[i].Targets, isValue) {
			targets := slices.Clone(runs[i].Targets)
			for j, target := range targets {
				if isValue(target) {
					targets[j] = redact.MaskedSecret
				}
			}
			runs[i].Targets = targets
		}
		if isValue(runs[i].Driver) {
			runs[i].Driver = redact.MaskedSecret
		}
	}
}

// Remove removes a policy; the values its secret references resolved to keep
// masking its backend's output for removedGrace.
func (r *maskingRepo) Remove(policyID string) error {
	err := r.PolicyRepo.Remove(policyID)
	r.secrets.removed(policyID)
	return err
}
