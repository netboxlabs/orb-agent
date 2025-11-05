package policymgr

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
)

// PolicyManager is the interface for managing policies
type PolicyManager interface {
	ManagePolicy(payload config.PolicyPayload)
	RemovePolicyDataset(policyID string, datasetID string, be backend.Backend)
	GetPolicyState() ([]policies.PolicyData, error)
	GetRepo() policies.PolicyRepo
	ApplyBackendPolicies(be backend.Backend) error
	RemoveBackendPolicies(be backend.Backend, permanently bool) error
	RemovePolicy(policyID string, policyName string, beName string) error
}

var _ PolicyManager = (*policyManager)(nil)

type policyManager struct {
	logger *slog.Logger
	config config.Config

	repo    policies.PolicyRepo
	secrets secretsmgr.Manager
}

// New creates a new instance of PolicyManager
func New(logger *slog.Logger, secrets secretsmgr.Manager, c config.Config) (PolicyManager, error) {
	repo, err := policies.NewMemRepo()
	if err != nil {
		return nil, err
	}
	policyManager := &policyManager{logger: logger, config: c, repo: repo, secrets: secrets}
	policyManager.secrets.RegisterUpdatePoliciesCallback(policyManager.policiesChanged)
	return policyManager, nil
}

func (a *policyManager) GetRepo() policies.PolicyRepo {
	return a.repo
}

func (a *policyManager) GetPolicyState() ([]policies.PolicyData, error) {
	return a.repo.GetAll()
}

func (a *policyManager) ManagePolicy(payload config.PolicyPayload) {
	a.logger.Info("managing agent policy from core",
		"action", payload.Action,
		"name", payload.Name,
		"dataset", payload.DatasetID,
		"backend", payload.Backend,
		"id", payload.ID,
		"version", int(payload.Version))

	switch payload.Action {
	case "manage":
		pd := policies.PolicyData{
			ID:      payload.ID,
			Name:    payload.Name,
			Backend: payload.Backend,
			Version: payload.Version,
			Data:    payload.Data,
			State:   policies.Unknown,
		}
		var updatePolicy bool
		if a.repo.Exists(payload.ID) {
			// we have already processed this policy id before (it may be running or failed)
			// ensure we are associating this dataset with this policy, if one was specified
			// note the usual case is dataset id is NOT passed during policy updates
			if payload.DatasetID != "" {
				err := a.repo.EnsureDataset(payload.ID, payload.DatasetID)
				if err != nil {
					a.logger.Warn("policy failed to ensure dataset id", "policy_id", payload.ID,
						"policy_name", payload.Name, "dataset_id", payload.DatasetID, "error", err)
				}
			}

			if payload.AgentGroupID != "" {
				err := a.repo.EnsureGroupID(payload.ID, payload.AgentGroupID)
				if err != nil {
					a.logger.Warn("policy failed to ensure agent group id", "policy_id", payload.ID,
						"policy_name", payload.Name, "agent_group_id", payload.AgentGroupID, "error", err)
				}
			}

			// if policy already exist and has no version upgrade, has no need to apply it again
			currentPolicy, err := a.repo.Get(payload.ID)
			if err != nil {
				a.logger.Error("failed to retrieve policy", "policy_id", payload.ID, "error", err)
				return
			}
			if currentPolicy.Backend == pd.Backend && currentPolicy.Version >= pd.Version && currentPolicy.State == policies.Running {
				a.logger.Info("a better version of this policy has already been applied, skipping", "policy_id", pd.ID, "policy_name", pd.Name,
					"attempted_version", fmt.Sprint(pd.Version), "current_version", fmt.Sprint(currentPolicy.Version))
				return
			}
			updatePolicy = true
			if currentPolicy.Name != pd.Name {
				pd.PreviousPolicyData = &policies.PolicyData{Name: currentPolicy.Name}
			}
			pd.Datasets = currentPolicy.Datasets
			pd.GroupIDs = currentPolicy.GroupIDs
		} else {
			// new policy we have not seen before, associate with this dataset
			// on first time we see policy, we *require* dataset
			if payload.DatasetID == "" {
				a.logger.Error("policy RPC for unseen policy did not include dataset ID, skipping", "policy_id", payload.ID, "policy_name", payload.Name)
				return
			}
			pd.Datasets = map[string]bool{payload.DatasetID: true}

			if payload.AgentGroupID != "" {
				pd.GroupIDs = map[string]bool{payload.AgentGroupID: true}
			}

		}
		if !backend.HaveBackend(payload.Backend) {
			a.logger.Warn("policy failed to apply because backend is not available", "policy_id", payload.ID, "policy_name", payload.Name)
			pd.State = policies.FailedToApply
			pd.BackendErr = "backend not available"
		} else {
			// attempt to apply the policy to the backend. status of policy application (running/failed) is maintained there.
			be := backend.GetBackend(payload.Backend)
			newPayload, err := a.secrets.SolvePolicySecrets(payload)
			if err != nil {
				a.logger.Error("failed to solve secrets", "policy_id", payload.ID, "policy_name", payload.Name, "error", err)
				return
			}
			pd.Data = newPayload.Data
			a.applyPolicy(payload, be, &pd, updatePolicy)
			pd.Data = payload.Data
		}
		// save policy (with latest status) to local policy db
		err := a.repo.Update(pd)
		if err != nil {
			a.logger.Error("got error in update last status", "error", err)
			return
		}
		return
	case "remove":
		err := a.RemovePolicy(payload.ID, payload.Name, payload.Backend)
		if err != nil {
			a.logger.Error("policy failed to be removed", "policy_id", payload.ID, "policy_name", payload.Name, "error", err)
		}
		return
	default:
		a.logger.Error("unknown policy action, ignored", "action", payload.Action)
	}
}

func (a *policyManager) RemovePolicy(policyID string, policyName string, beName string) error {
	pd := policies.PolicyData{
		ID:   policyID,
		Name: policyName,
	}
	if !backend.HaveBackend(beName) {
		return errors.New("policy remove for a backend we do not have, ignoring")
	}
	be := backend.GetBackend(beName)
	err := be.RemovePolicy(pd)
	if err != nil {
		a.logger.Error("backend remove policy failed: will still remove from PolicyManager", "policy_id", policyID, "error", err)
	}
	// Remove policy from orb-agent local repo
	err = a.repo.Remove(pd.ID)
	if err != nil {
		return err
	}
	return nil
}

func (a *policyManager) RemovePolicyDataset(policyID string, datasetID string, be backend.Backend) {
	policyData, err := a.repo.Get(policyID)
	if err != nil {
		a.logger.Warn("failed to retrieve policy data", "policy_id", policyID, "policy_name", policyData.Name, "error", err)
		return
	}
	removePolicy, err := a.repo.RemoveDataset(policyID, datasetID)
	if err != nil {
		a.logger.Warn("failed to remove policy dataset", "dataset_id", datasetID, "policy_name", policyData.Name, "error", err)
		return
	}
	if removePolicy {
		// Remove policy via http request
		err := be.RemovePolicy(policyData)
		if err != nil {
			a.logger.Warn("policy failed to remove", "policy_id", policyID, "policy_name", policyData.Name, "error", err)
		}
		// Remove policy from orb-agent local repo
		err = a.repo.Remove(policyData.ID)
		if err != nil {
			a.logger.Warn("policy failed to remove local", "policy_id", policyData.ID, "policy_name", policyData.Name, "error", err)
		}
	}
}

func (a *policyManager) applyPolicy(payload config.PolicyPayload, be backend.Backend, pd *policies.PolicyData, updatePolicy bool) {
	state, detail, err := be.GetRunningStatus()
	if state != backend.Running || err != nil {
		pd.State = policies.FailedToApply
		switch {
		case err != nil:
			pd.BackendErr = err.Error()
		case detail != "":
			pd.BackendErr = detail
		default:
			pd.BackendErr = fmt.Sprintf("backend state: %s", state)
		}

		a.logger.Warn(
			"backend is not ready to apply policy",
			"backend", pd.Backend,
			"policy_id", payload.ID,
			"policy_name", payload.Name,
			"backend_state", state.String(),
			"detail", detail,
			"error", err,
		)
		return
	}

	err = be.ApplyPolicy(*pd, updatePolicy)
	if err != nil {
		a.logger.Warn("policy failed to apply", "policy_id", payload.ID, "policy_name", payload.Name,
			"backend", pd.Backend, "error", err)
		pd.State = policies.FailedToApply
		pd.BackendErr = err.Error()
	} else {
		a.logger.Info("policy applied successfully", "policy_id", payload.ID, "policy_name", payload.Name,
			"backend", pd.Backend)
		pd.State = policies.Running
		pd.BackendErr = ""
	}
}

func (a *policyManager) RemoveBackendPolicies(be backend.Backend, permanently bool) error {
	plcies, err := a.repo.GetAll()
	if err != nil {
		a.logger.Error("failed to retrieve list of policies", "error", err)
		return err
	}

	for _, plcy := range plcies {
		err := be.RemovePolicy(plcy)
		if err != nil {
			a.logger.Error("failed to remove policy from backend", "policy_id", plcy.ID, "policy_name", plcy.Name, "error", err)
			// note we continue here: even if the backend failed to remove, we update our policy repo to remove it
		}
		if permanently {
			err = a.repo.Remove(plcy.ID)
			if err != nil {
				return err
			}
		} else {
			plcy.State = policies.Unknown
			err = a.repo.Update(plcy)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *policyManager) ApplyBackendPolicies(be backend.Backend) error {
	plcies, err := a.repo.GetAll()
	if err != nil {
		a.logger.Error("failed to retrieve list of policies", "error", err)
		return err
	}

	for _, policy := range plcies {
		err := be.ApplyPolicy(policy, false)
		if err != nil {
			a.logger.Warn("policy failed to apply", "policy_id", policy.ID, "policy_name", policy.Name, "error", err)
			policy.State = policies.FailedToApply
			policy.BackendErr = err.Error()
		} else {
			a.logger.Info("policy applied successfully", "policy_id", policy.ID, "policy_name", policy.Name)
			policy.State = policies.Running
			policy.BackendErr = ""
		}
		err = a.repo.Update(policy)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *policyManager) policiesChanged(policiesIDs map[string]bool) {
	for id, valid := range policiesIDs {
		policy, err := a.repo.Get(id)
		if err != nil {
			a.logger.Error("failed to get policy", "error", err)
			continue
		}
		if !valid {
			if err := a.RemovePolicy(policy.ID, policy.Name, policy.Backend); err != nil {
				a.logger.Error("failed to remove policy", "error", err)
			}
			continue
		}
		if !backend.HaveBackend(policy.Backend) {
			a.logger.Warn("policy failed to apply because backend is not available", "policy_id", policy.ID, "policy_name", policy.Name)
			policy.State = policies.FailedToApply
			policy.BackendErr = "backend not available"
		} else {
			payload := config.PolicyPayload{
				ID:   policy.ID,
				Name: policy.Name,
				Data: policy.Data,
			}
			newPayload, err := a.secrets.SolvePolicySecrets(payload)
			if err != nil {
				a.logger.Error("failed to solve secrets", "policy_id", policy.ID, "policy_name", policy.Name, "error", err)
				continue
			}
			policy.Data = newPayload.Data
			be := backend.GetBackend(policy.Backend)
			a.applyPolicy(payload, be, &policy, true)
			policy.Data = payload.Data
		}

		if err = a.repo.Update(policy); err != nil {
			a.logger.Error("got error in update last status", "error", err)
		}
	}
}
