package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The single most dangerous consequence of making Target.TLS a pointer: Go
// auto-dereferences field selectors, so every existing read compiles unchanged
// and panics at nil. resolveEnv takes the ADDRESS of three TLS fields, and nil
// is the default case — a policy with no tls block anywhere, which is the
// overwhelmingly common config. There is no gin.Recovery() and no recover() in
// this module, so an unguarded read here kills the POST with a stack trace.
//
// This test exists to fail loudly if the guard is ever removed.
func TestParsePoliciesDoesNotPanicWhenNoTargetHasATLSBlock(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.2
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	require.Len(t, policies["p1"].Scope.Targets, 2)
	for _, tgt := range policies["p1"].Scope.Targets {
		require.Nil(t, tgt.TLS, "no tls block means nil, not a zero struct")
		tls := tgt.ResolvedTLS()
		require.False(t, tls.SkipVerify)
		require.False(t, tls.Insecure)
		require.Empty(t, tls.CAFile)
	}
}

// A target with its own tls block still has its ${VAR} paths resolved, which is
// the behaviour the nil guard must not break.
func TestParsePoliciesResolvesTLSPathsWhenTheBlockIsPresent(t *testing.T) {
	t.Setenv("GNMI_CA", "/run/secrets/ca.pem")
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.1
          tls:
            ca: ${GNMI_CA}
        - host: 10.0.0.2
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	targets := policies["p1"].Scope.Targets
	require.NotNil(t, targets[0].TLS)
	require.Equal(t, "/run/secrets/ca.pem", targets[0].TLS.CAFile)
	require.Nil(t, targets[1].TLS)
}
