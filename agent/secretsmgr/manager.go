package secretsmgr

import (
	"context"
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// Manager is an interface for managing secrets
type Manager interface {
	Start(ctx context.Context) error
	RegisterUpdateCallback(callback func(map[string]bool))
	SolveSecrets(payload config.PolicyPayload) (config.PolicyPayload, error)
}

// New creates a new instance of ConfigManager based on the configuration
func New(logger *slog.Logger, c config.ManagerSecrets) Manager {
	switch c.Active {
	case "vault":
		return &vaultManager{logger: logger, config: c.Sources.Vault}
	default:
		logger.Info("no secrets manager specified or invalid type, skipping")
		return &dummyManager{}
	}
}

var _ Manager = (*dummyManager)(nil)

type dummyManager struct{}

func (v *dummyManager) Start(_ context.Context) error {
	return nil
}

func (v *dummyManager) RegisterUpdateCallback(_ func(map[string]bool)) {
}

func (v *dummyManager) SolveSecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, nil
}
