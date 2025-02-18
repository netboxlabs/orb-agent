package configmgr

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

var _ Manager = (*localConfigManager)(nil)

type localConfigManager struct {
	logger *zap.Logger
	pMgr   policymgr.PolicyManager
	config config.LocalManager
}

func (lc *localConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	if cfg.OrbAgent.Policies == nil {
		return errors.New("no policies specified")
	}

	for beName, policy := range cfg.OrbAgent.Policies {
		_, ok := backends[beName]
		if !ok {
			return errors.New("backend not found: " + beName)
		}
		for pName, data := range policy {
			policyID := uuid.NewSHA1(uuid.Nil, []byte(pName+beName)).String()
			id := uuid.NewString()
			payload := config.PolicyPayload{ID: policyID, Action: "manage",
				Name: pName, DatasetID: id, Backend: beName, Version: 1, Data: data}
			lc.pMgr.ManagePolicy(payload)
		}

	}
	return nil
}

func (lc *localConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
