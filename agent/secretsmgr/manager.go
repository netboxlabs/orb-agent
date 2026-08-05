package secretsmgr

import (
	"context"
	"fmt"
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

// New creates a secrets Manager from configuration. An empty active type is a
// no-op manager; a non-empty unrecognized type is a configuration error.
func New(logger *slog.Logger, c config.ManagerSecrets) (Manager, error) {
	switch c.Active {
	case "vault":
		return &vaultManager{preLogger: logger, config: c.Sources.Vault}, nil
	case "fleet":
		return NewFleetSecretsManager(logger, c.Sources.Fleet), nil
	case "delinea":
		return &delineaManager{preLogger: logger, config: c.Sources.Delinea}, nil
	case "doppler":
		return &dopplerManager{preLogger: logger, config: c.Sources.Doppler}, nil
	case "cyberark":
		return &cyberarkManager{preLogger: logger, config: c.Sources.CyberArk}, nil
	case "":
		logger.Info("no secrets manager specified, skipping")
		return &dummyManager{}, nil
	default:
		return nil, fmt.Errorf("unsupported secrets manager type %q (supported: vault, fleet, delinea, doppler, cyberark)", c.Active)
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
