package policy_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
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
		assert.Contains(t, err.Error(), `policy1 : invalid policy : target 192.168.1.1: no authentication configured`)
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

	t.Run("Unknown interface_name_source normalizes to auto", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              options:
                interface_name_source: wat
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
		require.Contains(t, policies, "policy1")
		opts := policies["policy1"].Config.Options
		assert.Nil(t, opts.InterfaceNameSource, "unknown value normalized to nil")
		assert.Equal(t, config.InterfaceNameSourceAuto, opts.InterfaceNameSourceMode())
	})

	t.Run("Valid interface_name_source is preserved", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              options:
                interface_name_source: ifname
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
		require.Contains(t, policies, "policy1")
		opts := policies["policy1"].Config.Options
		require.NotNil(t, opts.InterfaceNameSource)
		assert.Equal(t, "ifname", *opts.InterfaceNameSource)
	})

	t.Run("Environment Variable Resolution - Community", func(t *testing.T) {
		// Set test environment variable
		err := os.Setenv("SNMP_COMMUNITY", "test-community")
		require.NoError(t, err)
		defer func() { _ = os.Unsetenv("SNMP_COMMUNITY") }()

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
                community: ${SNMP_COMMUNITY}
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "test-community", policies["policy1"].Scope.Authentication.Community)
	})

	t.Run("Environment Variable Resolution - Username", func(t *testing.T) {
		// Set test environment variables
		err := os.Setenv("SNMP_USERNAME", "test-user")
		require.NoError(t, err)
		err = os.Setenv("SNMP_AUTH_PASS", "test-auth-pass")
		require.NoError(t, err)
		defer func() {
			_ = os.Unsetenv("SNMP_USERNAME")
			_ = os.Unsetenv("SNMP_AUTH_PASS")
		}()

		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv3
                security_level: authNoPriv
                username: ${SNMP_USERNAME}
                auth_protocol: SHA
                auth_passphrase: ${SNMP_AUTH_PASS}
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "test-user", policies["policy1"].Scope.Authentication.Username)
		assert.Equal(t, "test-auth-pass", policies["policy1"].Scope.Authentication.AuthPassphrase)
	})

	t.Run("Environment Variable Resolution - All Auth Fields", func(t *testing.T) {
		// Set test environment variables
		err := os.Setenv("SNMP_COMMUNITY", "test-community")
		require.NoError(t, err)
		err = os.Setenv("SNMP_USERNAME", "test-user")
		require.NoError(t, err)
		err = os.Setenv("SNMP_AUTH_PASS", "test-auth-pass")
		require.NoError(t, err)
		err = os.Setenv("SNMP_PRIV_PASS", "test-priv-pass")
		require.NoError(t, err)
		defer func() {
			_ = os.Unsetenv("SNMP_COMMUNITY")
			_ = os.Unsetenv("SNMP_USERNAME")
			_ = os.Unsetenv("SNMP_AUTH_PASS")
			_ = os.Unsetenv("SNMP_PRIV_PASS")
		}()

		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv3
                security_level: authPriv
                username: ${SNMP_USERNAME}
                auth_protocol: SHA
                auth_passphrase: ${SNMP_AUTH_PASS}
                priv_protocol: AES
                priv_passphrase: ${SNMP_PRIV_PASS}
          policy2:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.2
              authentication:
                protocol_version: SNMPv2c
                community: ${SNMP_COMMUNITY}
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Contains(t, policies, "policy2")

		// Check policy1 (SNMPv3)
		assert.Equal(t, "test-user", policies["policy1"].Scope.Authentication.Username)
		assert.Equal(t, "test-auth-pass", policies["policy1"].Scope.Authentication.AuthPassphrase)
		assert.Equal(t, "test-priv-pass", policies["policy1"].Scope.Authentication.PrivPassphrase)

		// Check policy2 (SNMPv2c)
		assert.Equal(t, "test-community", policies["policy2"].Scope.Authentication.Community)
	})

	t.Run("Environment Variable Resolution - No Substitution", func(t *testing.T) {
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
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "public", policies["policy1"].Scope.Authentication.Community)
	})

	t.Run("Environment Variable Resolution - Mixed Values", func(t *testing.T) {
		// Set test environment variable
		err := os.Setenv("SNMP_COMMUNITY", "test-community")
		require.NoError(t, err)
		defer func() { _ = os.Unsetenv("SNMP_COMMUNITY") }()

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
                community: ${SNMP_COMMUNITY}
          policy2:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.2
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Contains(t, policies, "policy2")

		// Check policy1 (with env var)
		assert.Equal(t, "test-community", policies["policy1"].Scope.Authentication.Community)

		// Check policy2 (without env var)
		assert.Equal(t, "public", policies["policy2"].Scope.Authentication.Community)
	})

	t.Run("Environment Variable Resolution - Missing Environment Variable", func(t *testing.T) {
		// Ensure the environment variable is not set
		err := os.Unsetenv("MISSING_SNMP_COMMUNITY")
		require.NoError(t, err)

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
                community: ${MISSING_SNMP_COMMUNITY}
       `)

		_, err = manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy1 : failed to resolve environment variables")
		assert.Contains(t, err.Error(), "failed to resolve community environment variable")
		assert.Contains(t, err.Error(), "environment variable MISSING_SNMP_COMMUNITY is not set")
	})

	t.Run("Environment Variable Resolution - Missing Username Environment Variable", func(t *testing.T) {
		// Ensure the environment variable is not set
		err := os.Unsetenv("MISSING_SNMP_USERNAME")
		require.NoError(t, err)

		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv3
                security_level: authNoPriv
                username: ${MISSING_SNMP_USERNAME}
                auth_protocol: SHA
                auth_passphrase: test-pass
       `)

		_, err = manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy1 : failed to resolve environment variables")
		assert.Contains(t, err.Error(), "failed to resolve username environment variable")
		assert.Contains(t, err.Error(), "environment variable MISSING_SNMP_USERNAME is not set")
	})
}

func TestManagerParsePolicies_ContextName(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	assert.NoError(t, err)

	t.Run("Environment Variable Resolution - context_name", func(t *testing.T) {
		err := os.Setenv("SNMP_CONTEXT_NAME", "mfpdirect")
		require.NoError(t, err)
		defer func() {
			_ = os.Unsetenv("SNMP_CONTEXT_NAME")
		}()

		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv3
                security_level: noAuthNoPriv
                username: testuser
                context_name: ${SNMP_CONTEXT_NAME}
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "mfpdirect", policies["policy1"].Scope.Authentication.ContextName)
	})

	t.Run("Environment Variable Resolution - Missing context_name Environment Variable", func(t *testing.T) {
		err := os.Unsetenv("MISSING_SNMP_CONTEXT_NAME")
		require.NoError(t, err)

		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv3
                security_level: noAuthNoPriv
                username: testuser
                context_name: ${MISSING_SNMP_CONTEXT_NAME}
       `)

		_, err = manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy1 : failed to resolve environment variables")
		assert.Contains(t, err.Error(), "failed to resolve context_name environment variable")
		assert.Contains(t, err.Error(), "environment variable MISSING_SNMP_CONTEXT_NAME is not set")
	})

	t.Run("Rejects context_name on SNMPv2c policy-level auth", func(t *testing.T) {
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
                context_name: mfpdirect
       `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy-level: context_name is only valid for SNMPv3")
	})

	t.Run("Rejects context_name on SNMPv2c per-target auth", func(t *testing.T) {
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
                    context_name: mfpdirect
       `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "target 192.168.1.1: context_name is only valid for SNMPv3")
	})

	t.Run("Rejects context_name in scope.authentication with no protocol_version", func(t *testing.T) {
		// hasPolicyAuth is false here (ProtocolVersion is unset), so the
		// per-field validateAuthentication check never runs. Without the
		// standalone check this block is silently discarded.
		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: noAuthNoPriv
                    username: testuser
              authentication:
                context_name: mfpdirect
       `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy-level: context_name is only valid for SNMPv3")
	})

	t.Run("Accepts context_name on SNMPv3 policy-level auth", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              lookup_extensions_dir: /tmp/extensions
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv3
                security_level: noAuthNoPriv
                username: testuser
                context_name: mfpdirect
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Equal(t, "mfpdirect", policies["policy1"].Scope.Authentication.ContextName)
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

func TestManagerApplyDefaults_RoleAndSite(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	assert.NoError(t, err)

	t.Run("Empty Role gets set to undefined", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "existing-site"
                # role is intentionally omitted (empty)
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "existing-site", policies["policy1"].Config.Defaults.Site)
	})

	t.Run("Empty Site gets set to default", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                role: "existing-role"
                # site is intentionally omitted (empty)
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "existing-role", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Site)
	})

	t.Run("Both Role and Site empty get default values", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: "test"
                # both role and site are intentionally omitted (empty)
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Site)
	})

	t.Run("Existing Role and Site values are preserved", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                role: "custom-role"
                site: "custom-site"
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "custom-role", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "custom-site", policies["policy1"].Config.Defaults.Site)
	})

	t.Run("Empty string Role and Site get default values", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                role: ""
                site: ""
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Site)
	})
}

func TestManagerApplyDefaults_Location(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	assert.NoError(t, err)

	t.Run("Existing Location value is preserved", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                role: "custom-role"
                site: "custom-site"
                location: "custom-location"
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "custom-location", policies["policy1"].Config.Defaults.Location)
		assert.Equal(t, "custom-role", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "custom-site", policies["policy1"].Config.Defaults.Site)
	})

	t.Run("All defaults (Role, Site) empty get default values", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: "test"
                # role and site are intentionally omitted (empty)
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Site)
	})

	t.Run("All defaults (Role, Site) as empty strings get default values", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                role: ""
                site: ""
                location: ""
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Role)
		assert.Equal(t, "undefined", policies["policy1"].Config.Defaults.Site)
	})
}

func TestManagerParsePoliciesWithPerTargetAuth(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	assert.NoError(t, err)

	t.Run("Valid Per-Target Auth - SNMPv2c", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  port: 161
                  authentication:
                    protocol_version: SNMPv2c
                    community: target-community
              authentication:
                protocol_version: SNMPv2c
                community: policy-community
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.NotNil(t, policies["policy1"].Scope.Targets[0].Authentication)
		assert.Equal(t, "SNMPv2c", policies["policy1"].Scope.Targets[0].Authentication.ProtocolVersion)
		assert.Equal(t, "target-community", policies["policy1"].Scope.Targets[0].Authentication.Community)
		assert.Equal(t, "policy-community", policies["policy1"].Scope.Authentication.Community)
	})

	t.Run("Valid Per-Target Auth - SNMPv3", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authPriv
                    username: target-user
                    auth_protocol: SHA
                    auth_passphrase: target-auth-pass
                    priv_protocol: AES
                    priv_passphrase: target-priv-pass
              authentication:
                protocol_version: SNMPv2c
                community: policy-community
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.NotNil(t, policies["policy1"].Scope.Targets[0].Authentication)
		assert.Equal(t, "SNMPv3", policies["policy1"].Scope.Targets[0].Authentication.ProtocolVersion)
		assert.Equal(t, "target-user", policies["policy1"].Scope.Targets[0].Authentication.Username)
		assert.Equal(t, "target-auth-pass", policies["policy1"].Scope.Targets[0].Authentication.AuthPassphrase)
		assert.Equal(t, "target-priv-pass", policies["policy1"].Scope.Targets[0].Authentication.PrivPassphrase)
	})

	t.Run("Mixed Configuration - Some Targets with Auth", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authPriv
                    username: target-user
                    auth_protocol: SHA
                    auth_passphrase: auth-pass
                    priv_protocol: AES
                    priv_passphrase: priv-pass
                - host: 192.168.1.2
              authentication:
                protocol_version: SNMPv2c
                community: fallback-community
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.NotNil(t, policies["policy1"].Scope.Targets[0].Authentication)
		assert.Nil(t, policies["policy1"].Scope.Targets[1].Authentication)
		assert.Equal(t, "fallback-community", policies["policy1"].Scope.Authentication.Community)
	})

	t.Run("Per-Target Auth Only - No Policy Auth", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv2c
                    community: target-community
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.NotNil(t, policies["policy1"].Scope.Targets[0].Authentication)
		assert.Equal(t, "target-community", policies["policy1"].Scope.Targets[0].Authentication.Community)
	})

	t.Run("Invalid - No Auth at All", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
       `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no authentication configured")
	})

	t.Run("Invalid Target Auth - Missing Community", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv2c
              authentication:
                protocol_version: SNMPv2c
                community: fallback
       `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "target 192.168.1.1")
		assert.Contains(t, err.Error(), "missing community")
	})

	t.Run("Environment Variable Resolution for Target Auth", func(t *testing.T) {
		err := os.Setenv("TARGET_COMMUNITY", "target-from-env")
		require.NoError(t, err)
		defer func() { _ = os.Unsetenv("TARGET_COMMUNITY") }()

		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv2c
                    community: ${TARGET_COMMUNITY}
              authentication:
                protocol_version: SNMPv2c
                community: policy-community
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "target-from-env", policies["policy1"].Scope.Targets[0].Authentication.Community)
		assert.Equal(t, "policy-community", policies["policy1"].Scope.Authentication.Community)
	})

	t.Run("Missing Environment Variable for Target Auth", func(t *testing.T) {
		err := os.Unsetenv("MISSING_TARGET_COMMUNITY")
		require.NoError(t, err)

		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv2c
                    community: ${MISSING_TARGET_COMMUNITY}
              authentication:
                protocol_version: SNMPv2c
                community: policy-community
       `)

		_, err = manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy1 : failed to resolve environment variables")
		assert.Contains(t, err.Error(), "target 192.168.1.1")
		assert.Contains(t, err.Error(), "failed to resolve community environment variable")
	})

	t.Run("Multiple Targets with Different Protocols", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv2c
                    community: v2c-community
                - host: 192.168.1.2
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authNoPriv
                    username: v3-user
                    auth_protocol: SHA
                    auth_passphrase: v3-pass
              authentication:
                protocol_version: SNMPv1
                community: fallback-community
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "SNMPv2c", policies["policy1"].Scope.Targets[0].Authentication.ProtocolVersion)
		assert.Equal(t, "SNMPv3", policies["policy1"].Scope.Targets[1].Authentication.ProtocolVersion)
		assert.Equal(t, "SNMPv1", policies["policy1"].Scope.Authentication.ProtocolVersion)
	})

	t.Run("Invalid - Target Without Auth and No Policy Fallback", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                comments: test
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv2c
                    community: target1-community
                - host: 192.168.1.2
       `)

		_, err := manager.ParsePolicies(yamlData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "target 192.168.1.2")
		assert.Contains(t, err.Error(), "no authentication configured and no policy-level fallback available")
	})
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

func TestManagerParsePoliciesWithOverrideDefaults(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	assert.NoError(t, err)

	t.Run("Valid Per-Target Override Defaults - Basic", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "New York"
                role: "switch"
                tags: ["network", "snmp"]
            scope:
              targets:
                - host: 192.168.1.1
                  port: 161
                  override_defaults:
                    site: "New York/DC-A"
                    role: "router"
                    tags: ["core", "production"]
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.NotNil(t, policies["policy1"].Scope.Targets[0].OverrideDefaults)
		assert.Equal(t, "New York/DC-A", policies["policy1"].Scope.Targets[0].OverrideDefaults.Site)
		assert.Equal(t, "router", policies["policy1"].Scope.Targets[0].OverrideDefaults.Role)
		assert.Equal(t, []string{"core", "production"}, policies["policy1"].Scope.Targets[0].OverrideDefaults.Tags)
		// Verify policy defaults unchanged
		assert.Equal(t, "New York", policies["policy1"].Config.Defaults.Site)
		assert.Equal(t, "switch", policies["policy1"].Config.Defaults.Role)
	})

	t.Run("Valid Per-Target Override Defaults - Nested Structures", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "Default Site"
                role: "switch"
                device:
                  description: "Policy Device"
                  tags: ["policy"]
                interface:
                  if_type: "other"
                  tags: ["policy-interface"]
                ip_address:
                  role: "anycast"
                  tenant: "default-tenant"
                  vrf: "default-vrf"
            scope:
              targets:
                - host: 192.168.1.1
                  override_defaults:
                    site: "Override Site"
                    device:
                      description: "Overridden Device"
                      tags: ["overridden"]
                    interface:
                      if_type: "1000base-t"
                      tags: ["override-interface"]
                    ip_address:
                      role: "loopback"
                      tenant: "override-tenant"
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		overrides := policies["policy1"].Scope.Targets[0].OverrideDefaults
		assert.NotNil(t, overrides)
		assert.Equal(t, "Override Site", overrides.Site)
		assert.Equal(t, "Overridden Device", overrides.Device.Description)
		assert.Equal(t, []string{"overridden"}, overrides.Device.Tags)
		assert.Equal(t, "1000base-t", overrides.Interface.Type)
		assert.Equal(t, []string{"override-interface"}, overrides.Interface.Tags)
		assert.Equal(t, "loopback", overrides.IPAddress.Role)
		assert.Equal(t, "override-tenant", overrides.IPAddress.Tenant)
	})

	t.Run("Mixed Configuration - Some Targets with Overrides", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "Default Site"
                role: "switch"
                tags: ["default"]
            scope:
              targets:
                - host: 192.168.1.1
                  override_defaults:
                    site: "Override Site"
                    role: "router"
                - host: 192.168.1.2
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.NotNil(t, policies["policy1"].Scope.Targets[0].OverrideDefaults)
		assert.Nil(t, policies["policy1"].Scope.Targets[1].OverrideDefaults)
		assert.Equal(t, "Override Site", policies["policy1"].Scope.Targets[0].OverrideDefaults.Site)
		assert.Equal(t, "Default Site", policies["policy1"].Config.Defaults.Site)
	})

	t.Run("Partial Override - Only Some Fields", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "Default Site"
                role: "switch"
                location: "Default Location"
                tags: ["default"]
            scope:
              targets:
                - host: 192.168.1.1
                  override_defaults:
                    role: "router"
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		overrides := policies["policy1"].Scope.Targets[0].OverrideDefaults
		assert.NotNil(t, overrides)
		assert.Equal(t, "router", overrides.Role)
		// Other fields should be empty in override (will be merged at runtime)
		assert.Equal(t, "", overrides.Site)
		assert.Equal(t, "", overrides.Location)
	})

	t.Run("Interface Patterns Override", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "Default Site"
                interface_patterns:
                  - match: "^Eth"
                    type: "1000base-t"
            scope:
              targets:
                - host: 192.168.1.1
                  override_defaults:
                    interface_patterns:
                      - match: "^GigabitEthernet"
                        type: "10gbase-x-sfpp"
                      - match: "^TenGigabitEthernet"
                        type: "25gbase-x-sfp28"
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		overrides := policies["policy1"].Scope.Targets[0].OverrideDefaults
		assert.NotNil(t, overrides)
		assert.Len(t, overrides.InterfacePatterns, 2)
		assert.Equal(t, "^GigabitEthernet", overrides.InterfacePatterns[0].Match)
		assert.Equal(t, "10gbase-x-sfpp", overrides.InterfacePatterns[0].Type)
		assert.Equal(t, "^TenGigabitEthernet", overrides.InterfacePatterns[1].Match)
		assert.Equal(t, "25gbase-x-sfp28", overrides.InterfacePatterns[1].Type)
	})

	t.Run("Empty Override Defaults - Uses Policy Defaults", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "Default Site"
                role: "switch"
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Nil(t, policies["policy1"].Scope.Targets[0].OverrideDefaults)
		assert.Equal(t, "Default Site", policies["policy1"].Config.Defaults.Site)
		assert.Equal(t, "switch", policies["policy1"].Config.Defaults.Role)
	})

	t.Run("Multiple Targets with Different Overrides", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "Default Site"
                role: "switch"
            scope:
              targets:
                - host: 192.168.1.1
                  override_defaults:
                    site: "Site A"
                    role: "router"
                - host: 192.168.1.2
                  override_defaults:
                    site: "Site B"
                    role: "firewall"
                - host: 192.168.1.3
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		assert.Equal(t, "Site A", policies["policy1"].Scope.Targets[0].OverrideDefaults.Site)
		assert.Equal(t, "router", policies["policy1"].Scope.Targets[0].OverrideDefaults.Role)
		assert.Equal(t, "Site B", policies["policy1"].Scope.Targets[1].OverrideDefaults.Site)
		assert.Equal(t, "firewall", policies["policy1"].Scope.Targets[1].OverrideDefaults.Role)
		assert.Nil(t, policies["policy1"].Scope.Targets[2].OverrideDefaults)
	})

	t.Run("Override Defaults with Per-Target Auth", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults:
                site: "Default Site"
                role: "switch"
            scope:
              targets:
                - host: 192.168.1.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authPriv
                    username: target-user
                    auth_protocol: SHA
                    auth_passphrase: auth-pass
                    priv_protocol: AES
                    priv_passphrase: priv-pass
                  override_defaults:
                    site: "Override Site"
                    role: "router"
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		assert.NoError(t, err)
		assert.Contains(t, policies, "policy1")
		target := policies["policy1"].Scope.Targets[0]
		assert.NotNil(t, target.Authentication)
		assert.Equal(t, "SNMPv3", target.Authentication.ProtocolVersion)
		assert.Equal(t, "target-user", target.Authentication.Username)
		assert.NotNil(t, target.OverrideDefaults)
		assert.Equal(t, "Override Site", target.OverrideDefaults.Site)
		assert.Equal(t, "router", target.OverrideDefaults.Role)
	})
}

func TestManagerApplyDefaults_CreateUnknownVlans(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	require.NoError(t, err)

	t.Run("Omitted options block defaults CreateUnknownVlans to true", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults: {}
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		require.NoError(t, err)
		require.Contains(t, policies, "policy1")
		opt := policies["policy1"].Config.Options.CreateUnknownVlans
		require.NotNil(t, opt, "CreateUnknownVlans should be *true after applyDefaults, got nil")
		assert.True(t, *opt, "CreateUnknownVlans should default to true when options block is omitted")
	})

	t.Run("Explicit create_unknown_vlans: true is preserved", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults: {}
              options:
                create_unknown_vlans: true
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		require.NoError(t, err)
		require.Contains(t, policies, "policy1")
		opt := policies["policy1"].Config.Options.CreateUnknownVlans
		require.NotNil(t, opt)
		assert.True(t, *opt)
	})

	t.Run("Explicit create_unknown_vlans: false is preserved", func(t *testing.T) {
		yamlData := []byte(`
        policies:
          policy1:
            config:
              defaults: {}
              options:
                create_unknown_vlans: false
            scope:
              targets:
                - host: 192.168.1.1
              authentication:
                protocol_version: SNMPv2c
                community: public
       `)

		policies, err := manager.ParsePolicies(yamlData)
		require.NoError(t, err)
		require.Contains(t, policies, "policy1")
		opt := policies["policy1"].Config.Options.CreateUnknownVlans
		require.NotNil(t, opt)
		assert.False(t, *opt, "Explicit false must be preserved — applyDefaults must not overwrite it")
	})
}

func TestManager_ParsePolicies_RejectsInvalidDiscoverModules(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	require.NoError(t, err)

	raw := []byte(`
policies:
  bad-policy:
    config:
      schedule: "@every 1m"
      options:
        discover_modules: fulls
    scope:
      targets:
        - host: 192.0.2.1
      authentication:
        protocol_version: SNMPv2c
        community: public
`)
	_, err = manager.ParsePolicies(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discover_modules")
	assert.Contains(t, err.Error(), "fulls")
}

// gopkg.in/yaml.v3 panicked on a merge key beside a mapping used as a key. In
// a policy request that is a parse error, so the caller gets an answer.
func TestManager_ParsePolicies_MergeBesideComplexKeyIsAnError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := policy.NewManager(context.Background(), logger, nil, nil)
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, err = manager.ParsePolicies([]byte("policies:\n  ? {a: 1}\n  : x\n  <<: {k: v}\n"))
	})
	assert.ErrorContains(t, err, "unhashable")
}

// rackPolicy is a policy request with one target, its defaults and the
// target's override_defaults given as maps (nil leaves the block out).
func rackPolicy(t *testing.T, host string, defaults, override map[string]any) []byte {
	t.Helper()
	target := map[string]any{"host": host}
	if override != nil {
		target["override_defaults"] = override
	}
	return rackPolicyTargets(t, defaults, target)
}

// rackPolicyTargets is a policy request with the given defaults (site DC1
// unless they name one) and targets.
func rackPolicyTargets(t *testing.T, defaults map[string]any, targets ...map[string]any) []byte {
	t.Helper()
	if defaults == nil {
		defaults = map[string]any{}
	}
	if _, ok := defaults["site"]; !ok {
		defaults["site"] = "DC1"
	}
	scopeTargets := make([]any, 0, len(targets))
	for _, target := range targets {
		scopeTargets = append(scopeTargets, target)
	}
	out, err := yaml.Marshal(map[string]any{"policies": map[string]any{"rack-policy": map[string]any{
		"config": map[string]any{"defaults": defaults},
		"scope": map[string]any{
			"targets":        scopeTargets,
			"authentication": map[string]any{"protocol_version": "SNMPv2c", "community": "public"},
		},
	}}})
	require.NoError(t, err)
	return out
}

// placed is a target at a U of the policy rack, with extra override keys.
func placed(host string, position any, face string, extra map[string]any) map[string]any {
	override := map[string]any{"position": position, "face": face}
	for k, v := range extra {
		override[k] = v
	}
	return map[string]any{"host": host, "override_defaults": override}
}

func TestManager_ParsePolicies_RackPlacement(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		defaults map[string]any
		override map[string]any
		wantErr  string
	}{
		{
			name:     "rack in policy defaults",
			host:     "192.0.2.1",
			defaults: map[string]any{"rack": "R12"},
		},
		{
			name:     "rack alone on a subnet target",
			host:     "192.0.2.0/24",
			override: map[string]any{"rack": "R12"},
		},
		{
			name:     "half U and a case-insensitive face, rack from the policy defaults",
			host:     "192.0.2.1",
			defaults: map[string]any{"rack": "R12"},
			override: map[string]any{"position": 40.5, "face": "Front"},
		},
		{
			name:     "lowest U, rack from override_defaults",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "R14", "position": 1, "face": "REAR"},
		},
		{
			name:     "a /8 is refused without listing its addresses",
			host:     "10.0.0.0/8",
			override: map[string]any{"rack": "R12", "position": 40, "face": "front"},
			wantErr:  "target 10.0.0.0/8: position and face need a single host",
		},
		{
			name:     "an IPv6 subnet is judged by its prefix",
			host:     "2001:db8::/64",
			override: map[string]any{"rack": "R12", "position": 40, "face": "front"},
			wantErr:  "target 2001:db8::/64: position and face need a single host",
		},
		{
			name:     "a /32 is a single host",
			host:     "192.0.2.1/32",
			override: map[string]any{"rack": "R12", "position": 10, "face": "front"},
		},
		{
			name:     "a hostname is a single host",
			host:     "switch-1.example.net",
			override: map[string]any{"rack": "R12", "position": 10, "face": "front"},
		},
		{
			name:     "position in policy defaults",
			host:     "192.0.2.1",
			defaults: map[string]any{"rack": "R12", "position": 10},
			wantErr:  "defaults: position and face are set per target, in override_defaults",
		},
		{
			name:     "face in policy defaults",
			host:     "192.0.2.1",
			defaults: map[string]any{"rack": "R12", "face": "front"},
			wantErr:  "defaults: position and face are set per target, in override_defaults",
		},
		{
			name:     "position without face",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "R12", "position": 10},
			wantErr:  "target 192.0.2.1: override_defaults position needs a face (front or rear)",
		},
		{
			name:     "face without position",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "R12", "face": "front"},
			wantErr:  "target 192.0.2.1: override_defaults face needs a position",
		},
		{
			name:     "position and face without a rack",
			host:     "192.0.2.1",
			override: map[string]any{"position": 10, "face": "front"},
			wantErr:  "target 192.0.2.1: override_defaults position and face need a rack, in defaults or override_defaults",
		},
		{
			name:     "a blank rack is no rack",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "  ", "position": 10, "face": "front"},
			wantErr:  "target 192.0.2.1: override_defaults position and face need a rack",
		},
		{
			name:     "face not front or rear",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "R12", "position": 10, "face": "side"},
			wantErr:  `target 192.0.2.1: override_defaults face "side" must be front or rear`,
		},
		{
			name:     "position below 1",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "R12", "position": 0.5, "face": "front"},
			wantErr:  "target 192.0.2.1: override_defaults position 0.5 must be 1 or more, in steps of 0.5",
		},
		{
			name:     "position not a multiple of 0.5",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "R12", "position": 40.25, "face": "front"},
			wantErr:  "target 192.0.2.1: override_defaults position 40.25 must be 1 or more, in steps of 0.5",
		},
		{
			name:     "position not finite",
			host:     "192.0.2.1",
			override: map[string]any{"rack": "R12", "position": math.Inf(1), "face": "front"},
			wantErr:  "target 192.0.2.1: override_defaults position +Inf must be 1 or more, in steps of 0.5",
		},
		{
			name:     "position and face on a range",
			host:     "192.0.2.2-10",
			override: map[string]any{"rack": "R12", "position": 10, "face": "front"},
			wantErr:  "target 192.0.2.2-10: position and face need a single host; a range or subnet would place every device at the same U",
		},
		{
			name:     "position and face on a subnet",
			host:     "192.0.2.0/30",
			override: map[string]any{"rack": "R12", "position": 10, "face": "front"},
			wantErr:  "target 192.0.2.0/30: position and face need a single host; a range or subnet would place every device at the same U",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.ParsePolicies(rackPolicy(t, tt.host, tt.defaults, tt.override))
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rack-policy : invalid policy : "+tt.wantErr)
		})
	}
}

func TestManager_ParsePolicies_RackPlacementSameU(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	policyRack := map[string]any{"rack": "R12", "location": "Hall 1"}

	tests := []struct {
		name     string
		defaults map[string]any // policyRack when nil
		targets  []map[string]any
		wantErr  string
	}{
		{
			name:    "same U and face",
			targets: []map[string]any{placed("192.0.2.10", 40, "front", nil), placed("192.0.2.11", 40, "front", nil)},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name:    "same U at a half U",
			targets: []map[string]any{placed("192.0.2.10", 40.5, "rear", nil), placed("192.0.2.11", 40.5, "rear", nil)},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40.5 rear",
		},
		{
			name: "same U after normalizing the face and rack",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "Front", map[string]any{"rack": " R12 "}),
				placed("192.0.2.11", 40, "front", nil),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name:     "no site is the undefined site",
			defaults: map[string]any{"rack": "R12", "site": ""},
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", map[string]any{"site": "undefined"}),
				placed("192.0.2.11", 40, "front", nil),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name: "same U once the policy defaults are merged in",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", map[string]any{"rack": "R12", "site": "DC1", "location": "Hall 1"}),
				placed("192.0.2.11", 40, "front", nil),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name: "the duplicate names the first target placed there",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				placed("192.0.2.11", 41, "front", nil),
				placed("192.0.2.12", 40, "front", nil),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.12 are both placed at R12 U40 front",
		},
		{
			name:    "opposite faces of one U",
			targets: []map[string]any{placed("192.0.2.10", 40, "front", nil), placed("192.0.2.11", 40, "rear", nil)},
		},
		{
			name:    "different U",
			targets: []map[string]any{placed("192.0.2.10", 40, "front", nil), placed("192.0.2.11", 40.5, "front", nil)},
		},
		{
			name: "different racks",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				placed("192.0.2.11", 40, "front", map[string]any{"rack": "R14"}),
			},
		},
		{
			name: "racks of one name in different locations",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				placed("192.0.2.11", 40, "front", map[string]any{"location": "Hall 2"}),
			},
		},
		{
			name:     "no location clashes with a location placed first",
			defaults: map[string]any{"rack": "R12"},
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", map[string]any{"location": "Hall 1"}),
				placed("192.0.2.11", 40, "front", nil),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name:     "no location placed first clashes with a location",
			defaults: map[string]any{"rack": "R12"},
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				placed("192.0.2.11", 40, "front", map[string]any{"location": "Hall 2"}),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name: "a blank location is no location",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", map[string]any{"location": "  "}),
				placed("192.0.2.11", 40, "front", map[string]any{"location": "Hall 2"}),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name: "a clash is found past a placement in another location",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				placed("192.0.2.11", 40, "front", map[string]any{"location": "Hall 2"}),
				placed("192.0.2.12", 40, "front", map[string]any{"location": "Hall 1"}),
			},
			wantErr: "targets 192.0.2.10 and 192.0.2.12 are both placed at R12 U40 front",
		},
		{
			name:     "no location clashes only at the same U and face",
			defaults: map[string]any{"rack": "R12"},
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				placed("192.0.2.11", 40, "rear", map[string]any{"location": "Hall 1"}),
				placed("192.0.2.12", 41, "front", map[string]any{"location": "Hall 1"}),
				placed("192.0.2.13", 40, "front", map[string]any{"location": "Hall 1", "rack": "R14"}),
				placed("192.0.2.14", 40, "front", map[string]any{"location": "Hall 1", "site": "DC2"}),
			},
		},
		{
			name: "racks of one name in different sites",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				placed("192.0.2.11", 40, "front", map[string]any{"site": "DC2"}),
			},
		},
		{
			name: "a target with the rack only takes no U",
			targets: []map[string]any{
				placed("192.0.2.10", 40, "front", nil),
				{"host": "192.0.2.11", "override_defaults": map[string]any{"rack": "R12"}},
				{"host": "192.0.2.12"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaults := tt.defaults
			if defaults == nil {
				defaults = maps.Clone(policyRack)
			}
			_, err := manager.ParsePolicies(rackPolicyTargets(t, defaults, tt.targets...))
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rack-policy : invalid policy : "+tt.wantErr)
		})
	}
}

// yaml.v3 refuses a bool for a number, and reads a scalar rack as its text.
func TestManager_ParsePolicies_RackPlacementScalarTypes(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)

	_, err = manager.ParsePolicies(rackPolicy(t, "192.0.2.1", map[string]any{"rack": "R12"},
		map[string]any{"position": true, "face": "front"}))
	require.Error(t, err, "a bool position is refused")

	// The agent re-marshals a policy, so an unquoted 01 arrives as 1 and 010
	// as 8: a number is refused rather than taken as another rack's name.
	for _, rack := range []any{12, 8, 26.0, true} {
		_, err = manager.ParsePolicies(rackPolicy(t, "192.0.2.1", map[string]any{"rack": rack},
			map[string]any{"position": 40, "face": "front"}))
		require.Error(t, err, "rack %v", rack)
		assert.Contains(t, err.Error(), `quote a numeric rack name, e.g. rack: "01"`)
	}

	policies, err := manager.ParsePolicies(rackPolicy(t, "192.0.2.1", map[string]any{"rack": "01"},
		map[string]any{"position": 40, "face": "front"}))
	require.NoError(t, err)
	assert.Equal(t, "01", string(policies["rack-policy"].Config.Defaults.Rack), "a quoted numeric rack name is kept as written")
}

// Two targets with one netbox_id update one device: they must place it at
// the same slot, and doing so is not a clash.
func TestManager_ParsePolicies_RackPlacementOneNetboxID(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	pinned := func(host string, position float64) map[string]any {
		target := placed(host, position, "front", nil)
		target["netbox_id"] = 42
		return target
	}

	_, err = manager.ParsePolicies(rackPolicyTargets(t, map[string]any{"rack": "R12"},
		pinned("192.0.2.10", 40), pinned("192.0.2.11", 41)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "targets 192.0.2.10 and 192.0.2.11 place netbox_id 42 at different slots")

	_, err = manager.ParsePolicies(rackPolicyTargets(t, map[string]any{"rack": "R12"},
		pinned("192.0.2.10", 40), pinned("192.0.2.11", 40)))
	require.NoError(t, err, "one device at one slot, named twice")

	rackOnly := func(host string, override map[string]any) map[string]any {
		return map[string]any{"host": host, "netbox_id": 42, "override_defaults": override}
	}
	_, err = manager.ParsePolicies(rackPolicyTargets(t, map[string]any{"site": "DC1"},
		rackOnly("192.0.2.10", map[string]any{"rack": "R12"}),
		map[string]any{"host": "192.0.2.11", "netbox_id": 42}))
	require.NoError(t, err, "a target that sends no rack leaves the other's in place")
	// netbox_id is dropped on any range or subnet syntax, a /32 included.
	differentSlots := "place netbox_id 42 at different slots"
	sameU := "are both placed at R12 U40 front"
	for name, tc := range map[string]struct {
		targets []map[string]any
		wantErr string
	}{
		"two racks":                       {[]map[string]any{rackOnly("192.0.2.10", map[string]any{"rack": "R12"}), rackOnly("192.0.2.11", map[string]any{"rack": "R13"})}, differentSlots},
		"a U and the same rack without":   {[]map[string]any{pinned("192.0.2.10", 40), rackOnly("192.0.2.11", map[string]any{"rack": "R12"})}, differentSlots},
		"one rack twice":                  {[]map[string]any{rackOnly("192.0.2.10", map[string]any{"rack": "R13"}), rackOnly("192.0.2.11", map[string]any{"rack": "R13"})}, ""},
		"a range pins nothing":            {[]map[string]any{rackOnly("192.0.2.10", map[string]any{"rack": "R13"}), rackOnly("192.0.2.16/29", map[string]any{"rack": "R14"})}, ""},
		"a /32 pins nothing":              {[]map[string]any{rackOnly("192.0.2.10", map[string]any{"rack": "R13"}), rackOnly("192.0.2.11/32", map[string]any{"rack": "R14"})}, ""},
		"two /32s are two devices":        {[]map[string]any{pinned("192.0.2.10/32", 40), pinned("192.0.2.11/32", 40)}, sameU},
		"two one-address ranges likewise": {[]map[string]any{pinned("192.0.2.10-192.0.2.10", 40), pinned("192.0.2.11-192.0.2.11", 40)}, sameU},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := manager.ParsePolicies(rackPolicyTargets(t, map[string]any{"rack": "R12"}, tc.targets...))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// Targets reaching one host each discover the same device, so they must send
// it one placement.
func TestManager_ParsePolicies_RackPlacementOneHost(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	racked := func(host string, port int, rack string) map[string]any {
		target := map[string]any{"host": host, "override_defaults": map[string]any{"rack": rack}}
		if port != 0 {
			target["port"] = port
		}
		return target
	}
	for name, tc := range map[string]struct {
		targets []map[string]any
		wantErr string
	}{
		"one address twice": {
			[]map[string]any{racked("192.0.2.10", 0, "R12"), racked("192.0.2.10", 0, "R13")},
			"targets 192.0.2.10 and 192.0.2.10 place host 192.0.2.10 at different slots",
		},
		"an address and its /32": {
			[]map[string]any{racked("192.0.2.10", 0, "R12"), racked("192.0.2.10/32", 0, "R13")},
			"place host 192.0.2.10 at different slots",
		},
		"IPv6 spelled two ways": {
			[]map[string]any{racked("2001:db8::1", 0, "R12"), racked("2001:DB8:0:0::1", 0, "R13")},
			"place host 2001:db8::1 at different slots",
		},
		"a name in two cases": {
			[]map[string]any{racked("SW1.example.com", 0, "R12"), racked("sw1.example.com", 0, "R13")},
			"place host sw1.example.com at different slots",
		},
		"the default port written out": {
			[]map[string]any{racked("192.0.2.10", 0, "R12"), racked("192.0.2.10", 161, "R13")},
			"place host 192.0.2.10 at different slots",
		},
		"one address on two ports":   {[]map[string]any{racked("192.0.2.10", 1161, "R12"), racked("192.0.2.10", 1162, "R13")}, ""},
		"a range beside an address":  {[]map[string]any{racked("192.0.2.16/29", 0, "R12"), racked("192.0.2.17", 0, "R13")}, ""},
		"one address twice at one U": {[]map[string]any{placed("192.0.2.10", 40, "front", nil), placed("192.0.2.10", 40, "front", nil)}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := manager.ParsePolicies(rackPolicyTargets(t, map[string]any{"rack": "R12"}, tc.targets...))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A shared identifier means two targets may update one device, so their
// placements must agree; only a shared strongest one, in Diode's matching
// order, says they do, so only that lets two targets share a U.
func TestManager_ParsePolicies_RackPlacementIdentityPrecedence(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	target := func(host string, netboxID int, tag, rack string, position float64) map[string]any {
		override := map[string]any{"rack": rack}
		if tag != "" {
			override["asset_tag"] = tag
		}
		if position != 0 {
			override["position"] = position
			override["face"] = "front"
		}
		out := map[string]any{"host": host, "override_defaults": override}
		if netboxID != 0 {
			out["netbox_id"] = netboxID
		}
		return out
	}
	sameU := "are both placed at R12 U40 front"
	for name, tc := range map[string]struct {
		targets []map[string]any
		wantErr string
	}{
		"two netbox_ids sharing a tag": {
			[]map[string]any{target("192.0.2.10", 41, "A1", "R12", 40), target("192.0.2.11", 42, "A1", "R12", 40)},
			"targets 192.0.2.10 and 192.0.2.11 " + sameU,
		},
		"a tag shared with a netbox_id target": {
			[]map[string]any{target("192.0.2.10", 42, "A1", "R12", 0), target("192.0.2.11", 0, "A1", "R13", 0)},
			"place asset_tag A1 at different slots",
		},
		"netbox_id first, then tag only": {[]map[string]any{target("192.0.2.10", 42, "A1", "R12", 40), target("192.0.2.11", 0, "A1", "R12", 40)}, sameU},
		"tag only, then netbox_id":       {[]map[string]any{target("192.0.2.10", 0, "A1", "R12", 40), target("192.0.2.11", 42, "A1", "R12", 40)}, sameU},
		"one host with two tags":         {[]map[string]any{target("192.0.2.10", 0, "A1", "R12", 40), target("192.0.2.10", 0, "A2", "R12", 40)}, sameU},
		"one host, a tag on one":         {[]map[string]any{target("192.0.2.10", 0, "A1", "R12", 40), target("192.0.2.10", 0, "", "R12", 40)}, sameU},
		"one netbox_id at one U":         {[]map[string]any{target("192.0.2.10", 42, "A1", "R12", 40), target("192.0.2.11", 42, "A1", "R12", 40)}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := manager.ParsePolicies(rackPolicyTargets(t, nil, tc.targets...))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A target is matched by its strongest identifier, so a shared one ties two
// targets only when it is the strongest of at least one.
func TestManager_ParsePolicies_RackPlacementTiesOnlyByAMatchedIdentifier(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	target := func(host string, netboxID int, tag, rack string) map[string]any {
		override := map[string]any{"rack": rack}
		if tag != "" {
			override["asset_tag"] = tag
		}
		out := map[string]any{"host": host, "override_defaults": override}
		if netboxID != 0 {
			out["netbox_id"] = netboxID
		}
		return out
	}
	for name, tc := range map[string]struct {
		targets []map[string]any
		wantErr string
	}{
		"two netbox_ids on one host":     {[]map[string]any{target("192.0.2.10", 41, "", "R12"), target("192.0.2.10", 42, "", "R13")}, ""},
		"two tags on one host":           {[]map[string]any{target("192.0.2.10", 0, "A1", "R12"), target("192.0.2.10", 0, "A2", "R13")}, ""},
		"a netbox_id and the bare host":  {[]map[string]any{target("192.0.2.10", 42, "", "R12"), target("192.0.2.10", 0, "", "R13")}, "place host 192.0.2.10 at different slots"},
		"a tag-only target, then the id": {[]map[string]any{target("192.0.2.11", 0, "A1", "R13"), target("192.0.2.10", 42, "A1", "R12")}, "place asset_tag A1 at different slots"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := manager.ParsePolicies(rackPolicyTargets(t, nil, tc.targets...))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A target without a rack still sends a site and any location, and NetBox
// refuses a device whose rack is in another, so one sharing a racked device
// must send that target's, or no location.
func TestManager_ParsePolicies_RackPlacementUnrackedTargets(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	racked := map[string]any{"host": "192.0.2.10", "netbox_id": 42, "override_defaults": map[string]any{"rack": "R12", "location": "Row 1"}}
	unracked := func(netboxID int, override map[string]any) map[string]any {
		return map[string]any{"host": "192.0.2.11", "netbox_id": netboxID, "override_defaults": override}
	}
	moved := "targets 192.0.2.10 and 192.0.2.11 send netbox_id 42 to different sites or locations, and 192.0.2.10 places it in rack R12"
	for name, tc := range map[string]struct {
		other   map[string]any
		wantErr string
	}{
		"another location":       {unracked(42, map[string]any{"location": "Row 2"}), moved},
		"another site":           {unracked(42, map[string]any{"site": "DC2"}), moved},
		"a location from an OID": {unracked(42, map[string]any{"location": ".1.3.6.1.2.1.1.6.0"}), "place netbox_id 42 in a location read from an OID"},
		"no location":            {unracked(42, map[string]any{}), ""},
		"the same location":      {unracked(42, map[string]any{"location": "Row 1"}), ""},
		"another device on the host": {func() map[string]any {
			other := unracked(41, map[string]any{"location": "Row 2"})
			other["host"] = "192.0.2.10"
			return other
		}(), ""},
	} {
		for _, rackedFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/racked first %v", name, rackedFirst), func(t *testing.T) {
				targets := []map[string]any{racked, tc.other}
				if !rackedFirst {
					targets = []map[string]any{tc.other, racked}
				}
				_, err := manager.ParsePolicies(rackPolicyTargets(t, nil, targets...))
				if tc.wantErr == "" {
					require.NoError(t, err)
					return
				}
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			})
		}
	}
}

// The asset tag is the device matcher Diode tries first, so targets sending
// one literal tag update one device and must send it one placement.
func TestManager_ParsePolicies_RackPlacementOneAssetTag(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	tagged := func(host, tag, rack string) map[string]any {
		return map[string]any{"host": host, "override_defaults": map[string]any{"asset_tag": tag, "rack": rack}}
	}
	differentSlots := "place asset_tag A1 at different slots"
	for name, tc := range map[string]struct {
		defaults map[string]any
		targets  []map[string]any
		wantErr  string
	}{
		"one tag in two racks":         {nil, []map[string]any{tagged("192.0.2.10", "A1", "R12"), tagged("192.0.2.11", "A1", "R13")}, "targets 192.0.2.10 and 192.0.2.11 " + differentSlots},
		"a padded tag is the same tag": {nil, []map[string]any{tagged("192.0.2.10", " A1 ", "R12"), tagged("192.0.2.11", "A1", "R13")}, differentSlots},
		"a policy tag over two Us": {
			map[string]any{"rack": "R12", "asset_tag": "A1"},
			[]map[string]any{placed("192.0.2.10", 40, "front", nil), placed("192.0.2.11", 41, "front", nil)},
			differentSlots,
		},
		"one tag at one U is one device": {
			map[string]any{"rack": "R12", "asset_tag": "A1"},
			[]map[string]any{placed("192.0.2.10", 40, "front", nil), placed("192.0.2.11", 40, "front", nil)},
			"",
		},
		"different tags":            {nil, []map[string]any{tagged("192.0.2.10", "A1", "R12"), tagged("192.0.2.11", "A2", "R13")}, ""},
		"a tag read from an OID":    {nil, []map[string]any{tagged("192.0.2.10", ".1.3.6.1.2.1.1.5.0", "R12"), tagged("192.0.2.11", ".1.3.6.1.2.1.1.5.0", "R13")}, ""},
		"a placeholder is not sent": {nil, []map[string]any{tagged("192.0.2.10", "N/A", "R12"), tagged("192.0.2.11", "N/A", "R13")}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := manager.ParsePolicies(rackPolicyTargets(t, tc.defaults, tc.targets...))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// Targets sharing a netbox_id must send it one location; one read from an
// OID is only known at scan time, so it cannot be shown to agree.
func TestManager_ParsePolicies_RackPlacementOneNetboxIDRefusesOIDLocations(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	sysLocation := ".1.3.6.1.2.1.1.6.0"
	pinned := func(host, location string) map[string]any {
		override := map[string]any{"rack": "R12"}
		if location != "" {
			override["location"] = location
		}
		return map[string]any{"host": host, "netbox_id": 42, "override_defaults": override}
	}

	for name, locations := range map[string][2]string{
		"both from the OID":  {sysLocation, sysLocation},
		"the first from it":  {sysLocation, "Row 1"},
		"the second from it": {"Row 1", sysLocation},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := manager.ParsePolicies(rackPolicyTargets(t, nil,
				pinned("192.0.2.10", locations[0]), pinned("192.0.2.11", locations[1])))
			require.Error(t, err)
			assert.Contains(t, err.Error(),
				"targets 192.0.2.10 and 192.0.2.11 place netbox_id 42 in a location read from an OID")
		})
	}

	_, err = manager.ParsePolicies(rackPolicyTargets(t, nil, pinned("192.0.2.10", sysLocation)))
	require.NoError(t, err, "one target alone has nothing to agree with")
}

// A location read from an OID is only known at scan time, so targets using
// one are left out of the same-U check rather than compared by the OID.
func TestManager_ParsePolicies_RackPlacementSameUSkipsOIDLocations(t *testing.T) {
	manager, err := policy.NewManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	require.NoError(t, err)
	sysLocation := ".1.3.6.1.2.1.1.6.0"

	for name, defaults := range map[string]map[string]any{
		"both read the location from an OID": {"rack": "A01", "location": sysLocation},
		"one reads it from an OID":           {"rack": "A01"},
	} {
		t.Run(name, func(t *testing.T) {
			second := map[string]any{"location": sysLocation}
			if _, ok := defaults["location"]; ok {
				second = nil
			}
			_, err := manager.ParsePolicies(rackPolicyTargets(
				t, defaults,
				placed("192.0.2.10", 42, "front", nil),
				placed("192.0.2.11", 42, "front", second),
			))
			require.NoError(t, err)
		})
	}
}
