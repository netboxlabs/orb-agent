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
	// RegisterUpdatePoliciesCallback registers the callback that reports the
	// policies whose secrets changed since they were resolved, by policy ID:
	// a nil error means a reference changed or resolves again and the
	// policy is to be applied with it, an error that a reference no longer
	// resolves, for that reason.
	RegisterUpdatePoliciesCallback(callback func(map[string]error))
	// Unresolved returns why a reference the policy uses does not resolve,
	// as last read, or nil when none of them failed since the policy
	// resolved it: a failure reported earlier may be out of date.
	Unresolved(policyID string) error
	// PolicyApplied tells the secrets manager that the version of the policy
	// with data, its references unresolved, now runs: the references only an
	// earlier version named no longer count for it.
	PolicyApplied(policyID string, data any)
	// ForgetPolicy drops a removed policy from the references it used, so it
	// is no longer reported and a reference no policy uses is no longer read.
	ForgetPolicy(policyID string)
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

func (v *dummyManager) RegisterUpdatePoliciesCallback(_ func(map[string]error)) {
}

func (v *dummyManager) Unresolved(_ string) error {
	return nil
}

func (v *dummyManager) PolicyApplied(_ string, _ any) {
}

func (v *dummyManager) ForgetPolicy(_ string) {
}

func (v *dummyManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, nil
}

func (v *dummyManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	return backends, configManager, nil
}
