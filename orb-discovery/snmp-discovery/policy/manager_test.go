package policy_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
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
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	assert.NoError(t, err)

	t.Run("Valid Policy", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
              lookup_extensions_dir: /tmp/extensions
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
              lookup_extensions_dir: /tmp/extensions
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

	t.Run("Invalid Policy - Missing Protocol Version", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
                  port: 162
    `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy1 : invalid policy : missing protocol version")
	})

	t.Run("Valid Policy - Explicit LookupExtensionsDir", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
              lookup_extensions_dir: /custom/extensions
            scope:
              targets:
                - host: 192.168.1.1
                  port: 162
              authentication:
                protocol_version: SNMPv2c
                community: public
    `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		// Verify explicit value is preserved
		assert.Equal(t, "/custom/extensions", policies["policy1"].Config.LookupExtensionsDir)
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
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	assert.NoError(t, err)
	yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
          policy2:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.2.1
              authentication:
                protocol_version: SNMPv2c
                community: public
          policy3:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets: []
              authentication:
                protocol_version: SNMPv2c
                community: public
          policy4:
            config:
              # No lookup_extensions_dir specified - should use default
            scope:
              targets:
                - host: 192.168.3.1
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
	err = manager.StartPolicy("policy4", policies["policy4"])
	assert.NoError(t, err)

	// Try to start policy 3
	err = manager.StartPolicy("policy3", policies["policy3"])
	assert.Contains(t, err.Error(), "no targets found in the policy")

	// Check if the policies exist
	assert.True(t, manager.HasPolicy("policy1"))
	assert.True(t, manager.HasPolicy("policy2"))
	assert.True(t, manager.HasPolicy("policy4"))
	assert.False(t, manager.HasPolicy("policy3"))

	// Stop policy 1
	err = manager.StopPolicy("policy1")
	assert.NoError(t, err)

	// Check if the policy exists
	assert.False(t, manager.HasPolicy("policy1"))
	assert.True(t, manager.HasPolicy("policy2"))
	assert.True(t, manager.HasPolicy("policy4"))
	assert.False(t, manager.HasPolicy("policy3"))

	// Stop Manager
	err = manager.Stop()
	assert.NoError(t, err)

	// Check if the policies exist
	assert.False(t, manager.HasPolicy("policy1"))
	assert.False(t, manager.HasPolicy("policy2"))
	assert.False(t, manager.HasPolicy("policy4"))
	assert.False(t, manager.HasPolicy("policy3"))
}

func TestManagerGetCapabilities(t *testing.T) {
	manager := &policy.Manager{}

	capabilities := manager.GetCapabilities()
	assert.Equal(t, []string{"targets"}, capabilities)
}

func TestManagerStartPolicyWithDeviceLookupExtensions(t *testing.T) {
	// Create a temporary directory for device lookup files
	tempDir := t.TempDir()

	// Create a sample YAML file with device information
	deviceYAML := `
devices:
  vendor1:
    device1: "Test Device 1"
    device2: "Test Device 2"
  vendor2:
    device3: "Test Device 3"
`
	yamlFile := filepath.Join(tempDir, "devices.yaml")
	err := os.WriteFile(yamlFile, []byte(deviceYAML), 0o644)
	assert.NoError(t, err)

	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockClient := new(MockDiodeClient)

	// Create mock manufacturer lookup
	manufacturerLookup := &data.ManufacturerLookup{}

	manager, err := policy.NewManager(ctx, logger, mockClient, manufacturerLookup)
	assert.NoError(t, err)

	// Create a policy with device lookup extensions directory
	policyData := config.Policy{
		Config: config.PolicyConfig{
			LookupExtensionsDir: tempDir,
		},
		Scope: config.Scope{
			Authentication: config.Authentication{
				ProtocolVersion: "SNMPv2c",
				Community:       "public",
			},
			Targets: []config.Target{
				{Host: "192.168.1.1", Port: 161},
			},
		},
	}

	// Start the policy - this should load device lookup extensions
	err = manager.StartPolicy("test-policy-with-devices", policyData)
	assert.NoError(t, err)

	// Verify policy was started
	assert.True(t, manager.HasPolicy("test-policy-with-devices"))

	// Clean up
	err = manager.StopPolicy("test-policy-with-devices")
	assert.NoError(t, err)
}
