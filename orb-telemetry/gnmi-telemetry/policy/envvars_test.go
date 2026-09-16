package policy

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
)

// envPolicy is a minimal policy whose scope password is under the caller's
// control, which is what a client posting to the API controls too.
const envPolicy = `
policies:
  p1:
    config:
      metrics_interval: 30
    scope:
      password: %q
      targets:
        - host: 192.0.2.1
`

func newTestManagerAllowing(names ...string) *Manager {
	return NewManager(context.Background(), testLogger, Options{AllowedEnvVars: names, Dialer: testDialer()})
}

// The backend runs as a child of the agent and inherits its whole environment,
// so a policy that could name any variable would turn policy creation into a
// read of the agent's secrets, delivered to whatever host the policy targets.
func TestParsePolicies_RejectsAnEnvVarOutsideTheAllowlist(t *testing.T) {
	t.Setenv("DIODE_CLIENT_SECRET", "not-in-a-policy")
	m := newTestManagerAllowing("GNMI_PASSWORD")

	_, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${DIODE_CLIENT_SECRET}"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "DIODE_CLIENT_SECRET")
	assert.NotContains(t, err.Error(), "not-in-a-policy", "the rejection must not echo the value back")
}

// With no allowlist configured the feature is off, not open.
func TestParsePolicies_RejectsEveryEnvVarWhenNoneAreAllowed(t *testing.T) {
	t.Setenv("GNMI_PASSWORD", "not-in-a-policy")
	m := newTestManager()

	_, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${GNMI_PASSWORD}"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GNMI_PASSWORD")
}

func TestParsePolicies_ResolvesAnAllowedEnvVar(t *testing.T) {
	t.Setenv("GNMI_PASSWORD", "read-only-password")
	m := newTestManagerAllowing("GNMI_PASSWORD")

	policies, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${GNMI_PASSWORD}"))

	require.NoError(t, err)
	assert.Equal(t, "read-only-password", policies["p1"].Scope.Password)
}

// The allowlist gates references, not literals: a credential written out in the
// policy is unaffected by it.
func TestParsePolicies_LeavesALiteralCredentialAlone(t *testing.T) {
	m := newTestManager()

	policies, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "campus"))

	require.NoError(t, err)
	assert.Equal(t, "campus", policies["p1"].Scope.Password)
}

// Every field the resolver substitutes reaches a device or names a file the
// backend reads, so each one is a way out for a secret and each one is checked,
// at both levels a policy sets them.
func TestResolveCredentialEnvVars_ChecksEveryCredentialField(t *testing.T) {
	t.Setenv("OTHER_SECRET", "not-in-a-policy")

	scopeFields := map[string]struct {
		label string
		set   func(*config.Scope)
		get   func(config.Scope) string
	}{
		"username": {
			"scope.username",
			func(s *config.Scope) { s.Username = "${OTHER_SECRET}" },
			func(s config.Scope) string { return s.Username },
		},
		"password": {
			"scope.password",
			func(s *config.Scope) { s.Password = "${OTHER_SECRET}" },
			func(s config.Scope) string { return s.Password },
		},
		"tls.ca": {
			"scope.tls.ca",
			func(s *config.Scope) { s.TLS = &config.TLSConfig{CAFile: "${OTHER_SECRET}"} },
			func(s config.Scope) string { return s.TLS.CAFile },
		},
	}

	for name, f := range scopeFields {
		t.Run("scope/"+name, func(t *testing.T) {
			m := newTestManagerAllowing("GNMI_PASSWORD")
			pol := minimalPolicy()
			f.set(&pol.Scope)

			err := m.resolveCredentialEnvVars(&pol)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "OTHER_SECRET")
			assert.Contains(t, err.Error(), f.label, "the error must name the field")
			assert.Equal(t, "${OTHER_SECRET}", f.get(pol.Scope), "the reference must be left unresolved")
		})
	}

	targetFields := map[string]struct {
		label string
		set   func(*config.Target)
		get   func(config.Target) string
	}{
		"username": {
			"target 192.168.1.1 username",
			func(tt *config.Target) { v := "${OTHER_SECRET}"; tt.Username = &v },
			func(tt config.Target) string { return tt.ResolvedUsername() },
		},
		"password": {
			"target 192.168.1.1 password",
			func(tt *config.Target) { v := "${OTHER_SECRET}"; tt.Password = &v },
			func(tt config.Target) string { return tt.ResolvedPassword() },
		},
		"tls.ca": {
			"target 192.168.1.1 tls.ca",
			func(tt *config.Target) { tt.TLS = &config.TLSConfig{CAFile: "${OTHER_SECRET}"} },
			func(tt config.Target) string { return tt.ResolvedTLS().CAFile },
		},
	}

	for name, f := range targetFields {
		t.Run("target/"+name, func(t *testing.T) {
			m := newTestManagerAllowing("GNMI_PASSWORD")
			pol := minimalPolicy()
			f.set(&pol.Scope.Targets[0])

			err := m.resolveCredentialEnvVars(&pol)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "OTHER_SECRET")
			assert.Contains(t, err.Error(), f.label, "the error must name the field")
			assert.Equal(t, "${OTHER_SECRET}", f.get(pol.Scope.Targets[0]), "the reference must be left unresolved")
		})
	}
}

// An allowed name that is not set is still an error, so a policy never runs
// with an empty credential it believed it had supplied.
func TestParsePolicies_RejectsAnAllowedEnvVarThatIsNotSet(t *testing.T) {
	m := newTestManagerAllowing("GNMI_PASSWORD_UNSET")

	_, err := m.ParsePolicies(fmt.Appendf(nil, envPolicy, "${GNMI_PASSWORD_UNSET}"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "GNMI_PASSWORD_UNSET")
}
