package policy_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil)
	assert.NoError(t, err)

	t.Run("Valid Policy", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  port: 162
                - host: 192.168.1.2
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "192.168.1.1", policies["policy1"].Scope.Targets[0].Host)
		assert.Equal(t, uint16(162), policies["policy1"].Scope.Targets[0].Port)
		assert.Equal(t, snmp.ProtocolVersion2c, policies["policy1"].Scope.Authentication.ProtocolVersion)
		assert.Equal(t, "public", policies["policy1"].Scope.Authentication.Community)
		assert.Equal(t, "192.168.1.2", policies["policy1"].Scope.Targets[1].Host)
		assert.Equal(t, uint16(161), policies["policy1"].Scope.Targets[1].Port)
	})

	t.Run("Valid Policy with Embedded Mapping", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  port: 162
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		// With embedded mapping, policies should parse successfully
		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
	})

	t.Run("Invalid Policy", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            scope:
              targets:
                - host: 192.168.1.1
                  port: 162
    `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy1 : invalid policy : missing protocol version")
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
	manager, err := policy.NewManager(context.Background(), logger, nil)
	assert.NoError(t, err)
	yamlData := []byte(`
        policies:
          policy1:
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
          policy2:
            scope:
              targets:
                - host: 192.168.2.1
              authentication:
                protocol_version: SNMPv2c
                community: public
          policy3:
            scope:
              targets: []
              authentication:
                protocol_version: SNMPv2c
                community: public
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
	assert.Equal(t, []string{"targets"}, capabilities)
}
