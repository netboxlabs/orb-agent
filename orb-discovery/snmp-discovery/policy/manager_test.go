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
	"github.com/stretchr/testify/require"
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
