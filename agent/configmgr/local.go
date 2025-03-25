package configmgr

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
)

var _ Manager = (*localConfigManager)(nil)

type localConfigManager struct {
	logger  *zap.Logger
	pMgr    policymgr.PolicyManager
	sMgr    secretsmgr.Manager
	config  config.LocalManager
	version int32
}

func (lc *localConfigManager) policiesChanged(policiesIDs map[string]bool) {
	lc.version++
	for id, valid := range policiesIDs {
		policy, err := lc.pMgr.GetRepo().Get(id)
		if err != nil {
			lc.logger.Error("failed to get policy", zap.Error(err))
			continue
		}
		if !valid {
			if err := lc.pMgr.RemovePolicy(policy.ID, policy.Name, policy.Backend); err != nil {
				lc.logger.Error("failed to remove policy", zap.Error(err))
			}
			continue
		}
		payload := config.PolicyPayload{
			ID: policy.ID, Action: "manage",
			Name: policy.Name, DatasetID: uuid.NewString(), Backend: policy.Backend,
			Version: lc.version, Data: policy.Data,
		}
		payload, err = lc.sMgr.SolveSecrets(payload)
		if err != nil {
			lc.logger.Error("failed to solve secrets", zap.Error(err))
			continue
		}
		lc.pMgr.ManagePolicy(payload)
	}
}

func (lc *localConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	if cfg.OrbAgent.Policies == nil {
		return errors.New("no policies specified")
	}
	lc.version = 1
	lc.sMgr.RegisterUpdateCallback(lc.policiesChanged)

	for beName, policy := range cfg.OrbAgent.Policies {
		_, ok := backends[beName]
		if !ok {
			return errors.New("backend not found: " + beName)
		}
		for pName, data := range policy {
			policyID := uuid.NewSHA1(uuid.Nil, []byte(pName+beName)).String()
			id := uuid.NewString()
			payload := config.PolicyPayload{
				ID: policyID, Action: "manage",
				Name: pName, DatasetID: id, Backend: beName, Version: lc.version, Data: data,
			}
			var err error
			payload, err = lc.sMgr.SolveSecrets(payload)
			if err != nil {
				return err
			}
			lc.pMgr.ManagePolicy(payload)
		}

	}
	return nil
}

func (lc *localConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
