package policies

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrPolicyNotFound is returned when a policy cannot be found by name or ID.
var ErrPolicyNotFound = errors.New("policy not found")

// PolicyRepo is the interface for policy repositories
type PolicyRepo interface {
	Exists(policyID string) bool
	Get(policyID string) (PolicyData, error)
	Remove(policyID string) error
	Update(data PolicyData) error
	GetAll() ([]PolicyData, error)
	GetByName(policyName string) (PolicyData, error)
	EnsureDataset(policyID string, datasetID string) error
	RemoveDataset(policyID string, datasetID string) (bool, error)
	EnsureGroupID(policyID string, agentGroupID string) error
	UpdateRuns(policyName string, runs []RunData) error
}

type policyMemRepo struct {
	mu      sync.RWMutex
	db      map[string]PolicyData
	nameMap map[string]string
}

var _ PolicyRepo = (*policyMemRepo)(nil)

func (p *policyMemRepo) GetByName(policyName string) (PolicyData, error) {
	p.mu.RLock()
	id, ok := p.nameMap[policyName]
	p.mu.RUnlock()
	if ok {
		return p.Get(id)
	}
	return PolicyData{}, fmt.Errorf("%w: %s", ErrPolicyNotFound, policyName)
}

// NewMemRepo creates a new in-memory policy repository
func NewMemRepo() (PolicyRepo, error) {
	r := &policyMemRepo{
		db:      make(map[string]PolicyData),
		nameMap: make(map[string]string),
	}
	return r, nil
}

func (p *policyMemRepo) EnsureDataset(policyID string, datasetID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, ok := p.db[policyID]
	if !ok {
		return errors.New("unknown policy ID")
	}
	policy.Datasets[datasetID] = true
	p.db[policyID] = policy
	return nil
}

func (p *policyMemRepo) RemoveDataset(policyID string, datasetID string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, ok := p.db[policyID]
	if !ok {
		return false, errors.New("unknown policy ID")
	}
	if ok := policy.Datasets[datasetID]; ok {
		delete(policy.Datasets, datasetID)
	}
	p.db[policyID] = policy
	// If after remove the policy it doesn't have others datasets,
	// we can remove the policy from the agent
	if len(policy.Datasets) > 0 {
		return false, nil
	}
	return true, nil
}

func (p *policyMemRepo) Exists(policyID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.db[policyID]
	return ok
}

func (p *policyMemRepo) Get(policyID string) (PolicyData, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	policy, ok := p.db[policyID]
	if !ok {
		return PolicyData{}, errors.New("unknown policy ID")
	}
	return policy, nil
}

func (p *policyMemRepo) Remove(policyID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.db[policyID]
	if !ok {
		return errors.New("unknown policy ID")
	}
	delete(p.nameMap, v.Name)
	delete(p.db, policyID)
	return nil
}

func (p *policyMemRepo) Update(data PolicyData) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, ok := p.db[data.ID]
	if ok {
		// existed, clear old map
		delete(p.nameMap, policy.Name)
	}
	p.db[data.ID] = data
	p.nameMap[data.Name] = data.ID
	return nil
}

func (p *policyMemRepo) GetAll() (ret []PolicyData, err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ret = make([]PolicyData, len(p.db))
	i := 0
	for _, v := range p.db {
		ret[i] = v
		i++
	}
	err = nil
	return ret, err
}

func (p *policyMemRepo) EnsureGroupID(policyID string, agentGroupID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, ok := p.db[policyID]
	if !ok {
		return errors.New("unknown policy ID")
	}
	policy.GroupIDs[agentGroupID] = true
	p.db[policyID] = policy
	return nil
}

func (p *policyMemRepo) UpdateRuns(policyName string, runs []RunData) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	policyID, ok := p.nameMap[policyName]
	if !ok {
		return fmt.Errorf("%w: %s", ErrPolicyNotFound, policyName)
	}
	policy, ok := p.db[policyID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrPolicyNotFound, policyID)
	}

	// Index existing runs for change detection and timestamp preservation
	existingByID := make(map[string]RunData, len(policy.Runs))
	for _, r := range policy.Runs {
		existingByID[r.ID] = r
	}

	now := time.Now().UTC()
	for i := range runs {
		runs[i].PolicyID = policyID

		if existing, ok := existingByID[runs[i].ID]; ok {
			// Existing run: always preserve CreatedAt
			runs[i].CreatedAt = existing.CreatedAt

			if isTerminalStatus(existing.Status) {
				// Run already finished; freeze UpdatedAt so
				// UpdatedAt − CreatedAt reflects the final run duration.
				runs[i].UpdatedAt = existing.UpdatedAt
			} else {
				// Run is still in progress; always advance UpdatedAt so
				// UpdatedAt − CreatedAt reflects the current elapsed time.
				runs[i].UpdatedAt = now
			}
		} else {
			// New run: use the backend's CreatedAt if provided; fall back to now.
			if runs[i].CreatedAt.IsZero() {
				runs[i].CreatedAt = now
			}
			runs[i].UpdatedAt = now
		}
	}

	policy.Runs = runs
	p.db[policyID] = policy
	return nil
}

var _ PolicyRepo = (*policyMemRepo)(nil)
