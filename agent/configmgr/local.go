package configmgr

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

var _ Manager = (*localConfigManager)(nil)

type localConfigManager struct {
	logger *slog.Logger
	pMgr   policymgr.PolicyManager
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
		newPolicy, ok := policy.(map[string]any)
		if !ok {
			return errors.New("invalid policy format for backend: " + beName)
		}
		for pName, data := range newPolicy {
			policyID := uuid.NewSHA1(uuid.Nil, []byte(pName+beName)).String()
			id := uuid.NewString()
			payload := config.PolicyPayload{
				ID: policyID, Action: "manage",
				Name: pName, DatasetID: id, Backend: beName, Version: 1, Data: data,
			}
			lc.pMgr.ManagePolicy(payload)
		}

	}
	return nil
}

// GetContext returns a context for local config manager (no-op for now).
func (lc *localConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}

// Stop is a no-op for local config manager.
func (lc *localConfigManager) Stop(_ context.Context) error {
	return nil
}
