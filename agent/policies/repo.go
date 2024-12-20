package policies

import (
	"errors"

	"go.uber.org/zap"
)

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
}

type policyMemRepo struct {
	logger *zap.Logger

	db      map[string]PolicyData
	nameMap map[string]string
}

var _ PolicyRepo = (*policyMemRepo)(nil)

func (p policyMemRepo) GetByName(policyName string) (PolicyData, error) {
	if id, ok := p.nameMap[policyName]; ok {
		return p.Get(id)
	}
	return PolicyData{}, errors.New("policy name not found")
}

// NewMemRepo creates a new in-memory policy repository
func NewMemRepo(logger *zap.Logger) (PolicyRepo, error) {
	r := &policyMemRepo{
		logger:  logger,
		db:      make(map[string]PolicyData),
		nameMap: make(map[string]string),
	}
	return r, nil
}

func (p policyMemRepo) EnsureDataset(policyID string, datasetID string) error {
	policy, ok := p.db[policyID]
	if !ok {
		return errors.New("unknown policy ID")
	}
	policy.Datasets[datasetID] = true
	return nil
}

func (p policyMemRepo) RemoveDataset(policyID string, datasetID string) (bool, error) {
	policy, ok := p.db[policyID]
	if !ok {
		return false, errors.New("unknown policy ID")
	}
	if ok := policy.Datasets[datasetID]; ok {
		delete(policy.Datasets, datasetID)
	}
	// If after remove the policy it doesn't have others datasets,
	// we can remove the policy from the agent
	if len(policy.Datasets) > 0 {
		return false, nil
	}
	return true, nil
}

func (p policyMemRepo) Exists(policyID string) bool {
	_, ok := p.db[policyID]
	return ok
}

func (p policyMemRepo) Get(policyID string) (PolicyData, error) {
	policy, ok := p.db[policyID]
	if !ok {
		return PolicyData{}, errors.New("unknown policy ID")
	}
	return policy, nil
}

func (p policyMemRepo) Remove(policyID string) error {
	v, err := p.Get(policyID)
	if err != nil {
		return err
	}
	delete(p.nameMap, v.Name)
	delete(p.db, policyID)
	return nil
}

func (p policyMemRepo) Update(data PolicyData) error {
	policy, ok := p.db[data.ID]
	if ok {
		// existed, clear old map
		delete(p.nameMap, policy.Name)
	}
	p.db[data.ID] = data
	p.nameMap[data.Name] = data.ID
	return nil
}

func (p policyMemRepo) GetAll() (ret []PolicyData, err error) {
	ret = make([]PolicyData, len(p.db))
	i := 0
	for _, v := range p.db {
		ret[i] = v
		i++
	}
	err = nil
	return ret, err
}

func (p policyMemRepo) EnsureGroupID(policyID string, agentGroupID string) error {
	policy, ok := p.db[policyID]
	if !ok {
		return errors.New("unknown policy ID")
	}
	policy.GroupIDs[agentGroupID] = true
	return nil
}

var _ PolicyRepo = (*policyMemRepo)(nil)
