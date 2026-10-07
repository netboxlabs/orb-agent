package policy_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/policy"
)

// MockRunner mocks the Runner
type MockRunner struct {
	mock.Mock
}

func (m *MockRunner) Configure(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client) error {
	args := m.Called(ctx, logger, name, policy, client)
	return args.Error(0)
}

func (m *MockRunner) Start() {
	m.Called()
}

func (m *MockRunner) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func TestManagerParsePolicies(t *testing.T) {
	manager := &policy.Manager{}

	t.Run("Valid Policies", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - 192.168.1.1/24
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "test", policies["policy1"].Config.Defaults.Comments)
	})

	t.Run("No Policies", func(t *testing.T) {
		yamlData := []byte(`network: {}`)
		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Equal(t, "no policies found in the request", err.Error())
	})
}

func TestManagerPolicyLifecycle(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager := policy.NewManager(context.Background(), logger, nil)
	yamlData := []byte(`
        policies:
          policy1:
            scope:
              targets:
                - 192.168.1.1/24
          policy2:
            scope:
              targets:
                - 192.168.2.1/24
          policy3:
            scope:
              targets: []
       `)

	policies, err := manager.ParsePolicies(yamlData)
	assert.NoError(t, err)

	// Start policies
	err = manager.StartPolicy("policy1", policies["policy1"])
	assert.NoError(t, err)
	err = manager.StartPolicy("policy2", policies["policy2"])
	assert.NoError(t, err)

	// Try to start policy 3
	err = manager.StartPolicy("policy3", policies["policy3"])
	assert.Contains(t, err.Error(), "no targets found in the policy")

	// Check if the policies exist
	assert.True(t, manager.HasPolicy("policy1"))
	assert.True(t, manager.HasPolicy("policy2"))
	assert.False(t, manager.HasPolicy("policy3"))

	// Stop policy 1
	err = manager.StopPolicy("policy1")
	assert.NoError(t, err)

	// Check if the policy exists
	assert.False(t, manager.HasPolicy("policy1"))
	assert.True(t, manager.HasPolicy("policy2"))
	assert.False(t, manager.HasPolicy("policy3"))

	// Stop Manager
	err = manager.Stop()
	assert.NoError(t, err)

	// Check if the policies exist
	assert.False(t, manager.HasPolicy("policy1"))
	assert.False(t, manager.HasPolicy("policy2"))
	assert.False(t, manager.HasPolicy("policy3"))
}

func TestManagerGetCapabilities(t *testing.T) {
	manager := &policy.Manager{}

	capabilities := manager.GetCapabilities()
	assert.Equal(t, []string{"targets, ports, exclude_ports, timing, fast_mode, ping_scan, top_ports, scan_types, max_retries"}, capabilities)
}

func TestManagerGetPolicyStatuses(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager := policy.NewManager(context.Background(), logger, nil)
	yamlData := []byte(`
        policies:
          policy1:
            scope:
              targets:
                - 192.168.1.1/24
       `)

	policies, err := manager.ParsePolicies(yamlData)
	assert.NoError(t, err)

	// Initially no policies, so no statuses
	statuses := manager.GetPolicyStatuses()
	assert.Empty(t, statuses)

	// Start policy
	err = manager.StartPolicy("policy1", policies["policy1"])
	assert.NoError(t, err)

	// Get statuses - should have policy1 with unknown status (no runs yet)
	statuses = manager.GetPolicyStatuses()
	assert.Len(t, statuses, 1)
	assert.Equal(t, "policy1", statuses[0].Name)
	assert.Equal(t, "unknown", statuses[0].Status)
	assert.Empty(t, statuses[0].Runs)

	// Stop policy
	err = manager.StopPolicy("policy1")
	assert.NoError(t, err)

	// Statuses should still include policy1 if it has runs
	_ = manager.GetPolicyStatuses()
	// If no runs were created, statuses will be empty
	// If runs were created, statuses will include the policy
	// This depends on whether the runner actually ran and created runs
}

// yaml.v3 panicked on a merge key beside a mapping used as a key; the
// maintained fork returns an error, so the request gets an answer.
func TestManager_ParsePolicies_MergeBesideComplexKeyIsAnError(t *testing.T) {
	manager := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	var err error
	require.NotPanics(t, func() {
		_, err = manager.ParsePolicies([]byte("policies:\n  ? {a: 1}\n  : x\n  <<: {k: v}\n"))
	})
	assert.ErrorContains(t, err, "unhashable")
}

// defaults.tenant goes through config.TenantParameters.UnmarshalYAML only when
// that method and ParsePolicies use the same YAML library; otherwise the
// decoder skips the method and a plain tenant name is rejected.
func TestManager_ParsePolicies_Tenant(t *testing.T) {
	m := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	parse := func(tenant string) (config.TenantParameters, error) {
		policies, err := m.ParsePolicies([]byte("policies:\n  p1:\n    config:\n      defaults:\n" +
			tenant + "    scope:\n      targets: [192.0.2.1]\n"))
		if err != nil {
			return config.TenantParameters{}, err
		}
		return policies["p1"].Config.Defaults.Tenant, nil
	}

	got, err := parse("        tenant: example-tenant\n")
	require.NoError(t, err)
	assert.Equal(t, config.TenantParameters{Name: "example-tenant"}, got)

	got, err = parse("        tenant:\n          name: example-tenant\n          group: example-group\n")
	require.NoError(t, err)
	assert.Equal(t, config.TenantParameters{Name: "example-tenant", Group: "example-group"}, got)

	_, err = parse("        tenant:\n          group: example-group\n")
	assert.ErrorContains(t, err, "mapping requires name")

	got, err = parse("        tenant: null\n")
	require.NoError(t, err)
	assert.Equal(t, config.TenantParameters{}, got)
}

func TestManager_StartPolicy_RejectsConflictingRd(t *testing.T) {
	m := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	err := m.StartPolicy("p1", config.Policy{
		Config: config.PolicyConfig{Defaults: config.Defaults{
			Vrf: config.VrfParameters{Name: "MyVRF", Rd: "65000:1"},
			Rd:  "65000:2",
		}},
		Scope: config.Scope{Targets: []string{"192.0.2.1"}},
	})
	assert.ErrorContains(t, err, `p1 : defaults.rd "65000:2" conflicts with defaults.vrf.rd "65000:1"`)
	assert.False(t, m.HasPolicy("p1"))
}
