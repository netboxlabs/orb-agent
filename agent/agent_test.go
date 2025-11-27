package agent

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockConfigManager implements configmgr.Manager for testing Stop delegation
type mockConfigManager struct {
	stopCalled bool
}

func (m *mockConfigManager) Start(_ config.Config, _ map[string]backend.Backend) error {
	return nil
}
func (m *mockConfigManager) GetContext(ctx context.Context) context.Context { return ctx }
func (m *mockConfigManager) Stop(_ context.Context) error                   { m.stopCalled = true; return nil }

func TestAgentStop_DelegatesToConfigManagerStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a := &orbAgent{logger: logger}

	mockMgr := &mockConfigManager{}
	// type assertion to satisfy compile-time check for interface
	var _ configmgr.Manager = mockMgr
	a.configManager = mockMgr

	// no backends running
	a.backends = map[string]backend.Backend{}

	a.Stop(context.Background())

	assert.True(t, mockMgr.stopCalled, "expected configManager.Stop to be called")
}

// mockPolicyManager implements policymgr.PolicyManager for testing
type mockPolicyManager struct {
	repo policies.PolicyRepo
}

func (m *mockPolicyManager) ManagePolicy(_ config.PolicyPayload)                       {}
func (m *mockPolicyManager) RemovePolicyDataset(_ string, _ string, _ backend.Backend) {}
func (m *mockPolicyManager) GetPolicyState() ([]policies.PolicyData, error) {
	return nil, nil
}

func (m *mockPolicyManager) GetRepo() policies.PolicyRepo {
	return m.repo
}

func (m *mockPolicyManager) ApplyBackendPolicies(_ backend.Backend) error {
	return nil
}

func (m *mockPolicyManager) RemoveBackendPolicies(_ backend.Backend, _ bool) error {
	return nil
}

func (m *mockPolicyManager) RemovePolicy(_ string, _ string, _ string) error {
	return nil
}

// mockSecretsManager implements secretsmgr.Manager for testing
type mockSecretsManager struct{}

func (m *mockSecretsManager) Start(_ context.Context) error {
	return nil
}
func (m *mockSecretsManager) RegisterUpdatePoliciesCallback(_ func(map[string]bool)) {}
func (m *mockSecretsManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, nil
}

func (m *mockSecretsManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	return backends, configManager, nil
}

func TestStart_FleetConfig_OverridesExistingOTLPGrpcURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{
				"common": map[string]any{
					"otlp": map[string]any{
						"grpc": "original:4317",
					},
				},
			},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start will fail when trying to start backends, but we can check the config before that
	err = orbAgent.Start(ctx, cancel)
	// We expect an error because there are no actual backends configured
	// But the important thing is that the config was modified
	require.Error(t, err)

	// Verify the config was modified by checking backendsCommon which is set in startBackends
	// The OTLP configuration happens before startBackends, so backendsCommon should have the updated value
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
}

func TestStart_FleetConfig_CreatesOTLPSectionWhenMissing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{
				"common": map[string]any{
					"other": "value",
				},
			},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.Error(t, err) // Expected to fail when starting backends

	// Verify the config was modified by checking backendsCommon which is set in startBackends
	// The OTLP configuration happens before startBackends, so backendsCommon should have the updated value
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
}

func TestStart_FleetConfig_CreatesCommonBackendWhenMissing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.Error(t, err) // Expected to fail when starting backends

	// Verify the config was modified by checking backendsCommon which is set in startBackends
	// The OTLP configuration happens before startBackends, so backendsCommon should have the updated value
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
}

func TestStart_NonFleetConfig_DoesNotModifyConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	originalGrpcURL := "original:4317"
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{
				"common": map[string]any{
					"otlp": map[string]any{
						"grpc": originalGrpcURL,
					},
				},
			},
			ConfigManager: config.ManagerConfig{
				Active: "local", // Not fleet
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.Error(t, err) // Expected to fail when starting backends

	// Verify the config was NOT modified by checking backendsCommon which is set in startBackends
	// For non-fleet config, the original value should remain
	assert.Equal(t, originalGrpcURL, orbAgent.backendsCommon.Otlp.Grpc, "grpc URL should remain unchanged for non-fleet config")
}
