package secretsmgr

import (
	"context"
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// Manager is an interface for managing secrets
type Manager interface {
	Start(ctx context.Context) error
	RegisterUpdatePoliciesCallback(callback func(map[string]bool))
	SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error)
	SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error)
}

// New creates a new instance of ConfigManager based on the configuration
func New(logger *slog.Logger, c config.ManagerSecrets) Manager {
	switch c.Active {
	case "vault":
		return &vaultManager{logger: logger, config: c.Sources.Vault}
	case "fleet":
		return NewFleetSecretsManager(logger, c.Sources.Fleet)
	case "delinea":
		return &delineaManager{logger: logger, config: c.Sources.Delinea}
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

func (v *dummyManager) RegisterUpdatePoliciesCallback(_ func(map[string]bool)) {
}

func (v *dummyManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, nil
}

func (v *dummyManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	return backends, configManager, nil
}
