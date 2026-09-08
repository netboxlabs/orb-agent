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
	case "dsv":
		return &dsvManager{preLogger: logger, config: c.Sources.DSV}, nil
	case "":
		logger.Info("no secrets manager specified, skipping")
		return &dummyManager{}, nil
	default:
		return nil, fmt.Errorf("unsupported secrets manager type %q (supported: vault, fleet, delinea, doppler, cyberark, dsv)", c.Active)
	}
}

var _ Manager = (*dummyManager)(nil)

type dummyManager struct{}

func (v *dummyManager) Start(_ context.Context) error {
	return nil
}

func (v *dummyManager) RegisterUpdatePoliciesCallback(_ func(map[string]bool)) {
}

// SolvePolicySecrets passes provider-specific placeholders through untouched
// (pre-existing behavior), but fails fast on a generic ${secret://…} reference:
// it explicitly asks for the active secrets manager, and there is none — better
// a clear error than the literal placeholder reaching the backend.
func (v *dummyManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	if _, err := processValue(payload.Data, genericScheme, payload.ID, rejectGenericRef); err != nil {
		return payload, err
	}
	return payload, nil
}

// SolveConfigSecrets applies the same fail-fast rule to config-level values.
func (v *dummyManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	if _, err := processValue(backends, genericScheme, "_backends", rejectGenericRef); err != nil {
		return backends, configManager, err
	}
	cmMap, err := structToMap(configManager)
	if err != nil {
		return backends, configManager, err
	}
	if _, err := processValue(cmMap, genericScheme, "_config_manager", rejectGenericRef); err != nil {
		return backends, configManager, err
	}
	return backends, configManager, nil
}

// rejectGenericRef is the dummy manager's resolver: any ${secret://…} reference
// is an error because no secrets manager is configured to resolve it. The
// message is neutral because the reference may sit in a policy or in config.
func rejectGenericRef(body, _ string) (string, error) {
	return "", fmt.Errorf("a managed secret reference (${secret://%s}) was found but no secrets manager is configured", body)
}
