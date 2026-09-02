package policy

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// envPolicy is a minimal v2c policy whose community is under the caller's
// control, which is what a client posting to the API controls too.
const envPolicy = `
policies:
  p1:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v2c
        community: %q
      targets:
        - host: 192.0.2.1
`

func newTestManagerAllowing(names ...string) *Manager {
	return NewManager(context.Background(), testLogger, Options{AllowedEnvVars: names})
}

// The backend runs as a child of the agent and inherits its whole environment,
// so a policy that could name any variable would turn policy creation into a
// read of the agent's secrets, delivered to whatever host the policy targets.
func TestParsePolicies_RejectsAnEnvVarOutsideTheAllowlist(t *testing.T) {
	t.Setenv("DIODE_CLIENT_SECRET", "not-in-a-policy")
	m := newTestManagerAllowing("SNMP_COMMUNITY")

	_, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${DIODE_CLIENT_SECRET}"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "DIODE_CLIENT_SECRET")
	assert.NotContains(t, err.Error(), "not-in-a-policy", "the rejection must not echo the value back")
}

// With no allowlist configured the feature is off, not open.
func TestParsePolicies_RejectsEveryEnvVarWhenNoneAreAllowed(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "not-in-a-policy")
	m := newTestManager()

	_, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${SNMP_COMMUNITY}"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SNMP_COMMUNITY")
}

func TestParsePolicies_ResolvesAnAllowedEnvVar(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "read-only-community")
	m := newTestManagerAllowing("SNMP_COMMUNITY")

	policies, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${SNMP_COMMUNITY}"))

	require.NoError(t, err)
	assert.Equal(t, "read-only-community", policies["p1"].Scope.Authentication.Community)
}

// The allowlist gates references, not literals: a credential written out in the
// policy is unaffected by it.
func TestParsePolicies_LeavesALiteralCredentialAlone(t *testing.T) {
	m := newTestManager()

	policies, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "public"))

	require.NoError(t, err)
	assert.Equal(t, "public", policies["p1"].Scope.Authentication.Community)
}

// Every field the resolver substitutes reaches a device, so each one is a way
// out for a secret and each one is checked, at both levels a policy sets them.
func TestResolveAuthenticationEnvVars_ChecksEveryCredentialField(t *testing.T) {
	t.Setenv("OTHER_SECRET", "not-in-a-policy")

	fields := map[string]struct {
		set func(*config.Authentication)
		get func(config.Authentication) string
	}{
		"community":       {func(a *config.Authentication) { a.Community = "${OTHER_SECRET}" }, func(a config.Authentication) string { return a.Community }},
		"username":        {func(a *config.Authentication) { a.Username = "${OTHER_SECRET}" }, func(a config.Authentication) string { return a.Username }},
		"auth_passphrase": {func(a *config.Authentication) { a.AuthPassphrase = "${OTHER_SECRET}" }, func(a config.Authentication) string { return a.AuthPassphrase }},
		"priv_passphrase": {func(a *config.Authentication) { a.PrivPassphrase = "${OTHER_SECRET}" }, func(a config.Authentication) string { return a.PrivPassphrase }},
	}

	for label, f := range fields {
		t.Run("scope/"+label, func(t *testing.T) {
			m := newTestManagerAllowing("SNMP_COMMUNITY")
			pol := minimalPolicy(v2cAuth())
			f.set(&pol.Scope.Authentication)

			err := m.resolveAuthenticationEnvVars(&pol)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "OTHER_SECRET")
			assert.Equal(t, "${OTHER_SECRET}", f.get(pol.Scope.Authentication), "the reference must be left unresolved")
		})

		t.Run("target/"+label, func(t *testing.T) {
			m := newTestManagerAllowing("SNMP_COMMUNITY")
			pol := minimalPolicy(v2cAuth())
			auth := v2cAuth()
			pol.Scope.Targets[0].Authentication = &auth
			f.set(pol.Scope.Targets[0].Authentication)

			err := m.resolveAuthenticationEnvVars(&pol)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "OTHER_SECRET")
			assert.Equal(t, "${OTHER_SECRET}", f.get(*pol.Scope.Targets[0].Authentication), "the reference must be left unresolved")
		})
	}
}

// An allowed name that is not set is still an error, so a policy never runs
// with an empty credential it believed it had supplied.
func TestParsePolicies_RejectsAnAllowedEnvVarThatIsNotSet(t *testing.T) {
	m := newTestManagerAllowing("SNMP_COMMUNITY_UNSET")

	_, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${SNMP_COMMUNITY_UNSET}"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SNMP_COMMUNITY_UNSET")
}
