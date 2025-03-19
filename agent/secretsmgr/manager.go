package secretsmgr

import (
	"context"

	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// Manager is an interface for managing secrets
type Manager interface {
	Start(ctx context.Context) error
	SolveSecrets(payload config.PolicyPayload) (config.PolicyPayload, error)
}

// New creates a new instance of ConfigManager based on the configuration
func New(logger *zap.Logger, c config.ManagerSecrets) Manager {
	switch c.Active {
	case "vault":
		return &vaultManager{logger: logger, config: c.Sources.Vault}
	default:
		return &dummyManager{}
	}
}

var _ Manager = (*dummyManager)(nil)

type dummyManager struct{}

func (v *dummyManager) Start(_ context.Context) error {
	return nil
}

func (v *dummyManager) SolveSecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, nil
}
