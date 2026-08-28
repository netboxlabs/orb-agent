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

// Inheritance must run BEFORE resolveEnv, not after. resolveEnv walks only the
// target list, so inheriting afterwards would copy a scope-level ${GNMI_PASS}
// into every target as that literal string, with resolution already past —
// every device in a subnet authenticating with the eleven characters
// "${GNMI_PASS}".
func TestScopeCredentialsAreInheritedAndThenResolved(t *testing.T) {
	t.Setenv("GNMI_PASS", "s3cret")
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      username: admin
      password: ${GNMI_PASS}
      port: 6030
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.2
          username: legacy
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	targets := policies["p1"].Scope.Targets

	require.Equal(t, "admin", targets[0].Username)
	require.Equal(t, "s3cret", targets[0].Password, "scope secret must be resolved, not literal")
	require.Equal(t, "10.0.0.1:6030", targets[0].Host, "scope port applied")

	require.Equal(t, "legacy", targets[1].Username, "target overrides scope")
	require.Equal(t, "s3cret", targets[1].Password, "unset fields still inherit")
}

// A tls block replaces the scope's wholesale rather than merging field by field.
// Merging is not expressible: a bool cannot distinguish "unset" from "false", so
// a target setting insecure would silently zero the scope's skip_verify and ca.
func TestTargetTLSBlockReplacesTheScopeBlockWholesale(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      tls:
        skip_verify: true
        ca: /run/secrets/ca.pem
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.2
          tls:
            insecure: true
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	targets := policies["p1"].Scope.Targets

	inherited := targets[0].ResolvedTLS()
	require.True(t, inherited.SkipVerify)
	require.Equal(t, "/run/secrets/ca.pem", inherited.CAFile)

	replaced := targets[1].ResolvedTLS()
	require.True(t, replaced.Insecure)
	require.False(t, replaced.SkipVerify, "target block replaces, so nothing is inherited")
	require.Empty(t, replaced.CAFile, "target block replaces, so nothing is inherited")
}

// Inheriting a pointer would alias one struct across every expanded target, and
// resolveEnv then writes through it once per target. MergeDefaults documents the
// same rule for the same reason: an inherited block is owned, not shared.
func TestInheritedTLSBlockIsCopiedNotAliased(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      tls:
        ca: /run/secrets/ca.pem
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.2
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	targets := policies["p1"].Scope.Targets
	require.NotSame(t, targets[0].TLS, targets[1].TLS, "each target owns its block")
}

// Origin distinguishes unset from an explicit "", so inheritance must test for
// nil. A target asking for origin-less paths must not inherit "openconfig".
func TestExplicitEmptyOriginIsNotOverwrittenByTheScope(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      origin: srl_nokia
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.2
          origin: ""
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	targets := policies["p1"].Scope.Targets
	// Deliberately not "openconfig": that is the built-in default, so asserting
	// it would pass whether the scope was inherited or ignored.
	require.Equal(t, "srl_nokia", targets[0].ResolvedOrigin())
	require.Equal(t, "", targets[1].ResolvedOrigin(), "explicit empty origin survives inheritance")
}

// An inline host:port wins over the port field, which wins over the scope's.
func TestPortPrecedenceIsInlineThenTargetThenScope(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      port: 6030
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.2
          port: 57400
        - host: 10.0.0.3:1234
          port: 57400
        - host: 10.0.0.4
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	hosts := []string{}
	for _, tgt := range policies["p1"].Scope.Targets {
		hosts = append(hosts, tgt.Host)
	}
	require.Equal(t, []string{
		"10.0.0.1:6030",  // scope
		"10.0.0.2:57400", // target beats scope
		"10.0.0.3:1234",  // inline beats both
		"10.0.0.4:6030",  // scope
	}, hosts)
}

func TestPortFallsBackToTheGNMIDefault(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.1
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1:9339", policies["p1"].Scope.Targets[0].Host)
}

// The cap must be checked AFTER env resolution. At validatePolicy time the host
// is still the literal "${SUBNET}", which parses as a hostname and sails past
// every bounds check — and then the runner enumerates 10.0.0.0/8 into hundreds
// of megabytes inside a container that does not have them.
func TestOverCapSubnetFromAnEnvVarIsRejected(t *testing.T) {
	t.Setenv("SUBNET", "10.0.0.0/8")
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: ${SUBNET}
`)
	_, err := m.ParsePolicies(data)
	require.Error(t, err, "an over-cap CIDR must not reach the runner")
	require.Contains(t, err.Error(), "10.0.0.0/8", "the error names the offending target")
}

func TestSubnetFromAnEnvVarIsAcceptedWhenItFits(t *testing.T) {
	t.Setenv("SUBNET", "10.0.0.0/24")
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: ${SUBNET}
`)
	policies, err := m.ParsePolicies(data)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.0/24", policies["p1"].Scope.Targets[0].Host,
		"a prefix is not expanded at parse time, only counted")
}

// The cap is per policy, so several entries that each fit can still exceed it.
func TestTheCapIsSummedAcrossTargets(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/23
        - host: 10.1.0.0/23
        - host: 10.2.0.0/23
`)
	_, err := m.ParsePolicies(data)
	require.Error(t, err, "3 x 510 exceeds the per-policy cap")
}

func TestIPv6PrefixIsRejectedWithAReason(t *testing.T) {
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: 2001:db8::/64
`)
	_, err := m.ParsePolicies(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enumerat")
}

// Keeping inline host:port while adding range syntax creates this trap: an
// operator carrying the documented "10.0.0.11:6030" habit forward to a range
// writes something Expand treats as a DNS name, which then retries a
// nonexistent host forever with only a generic dial error.
func TestARangeCarryingAnInlinePortIsRejected(t *testing.T) {
	m := newTestManager(t)
	for _, host := range []string{"10.0.0.1-10:6030", "10.0.0.0/24:6030"} {
		data := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: ` + host + `
`)
		_, err := m.ParsePolicies(data)
		require.Error(t, err, "host %q must be rejected", host)
		require.Contains(t, err.Error(), "port", "the error points at the port field")
	}
}

// An operator naming one device twice, with two credential sets, has a bug.
// Two entries for the same host at DIFFERENT ports are two real endpoints
// though — that is the Arista-and-Nokia pairing the docs teach.
func TestDuplicateTargetsAreRejectedUnlessThePortsDiffer(t *testing.T) {
	m := newTestManager(t)
	dup := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.5
          username: a
        - host: 10.0.0.5
          username: b
`)
	_, err := m.ParsePolicies(dup)
	require.Error(t, err)
	require.Contains(t, err.Error(), "10.0.0.5")

	distinct := []byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.5
          port: 6030
        - host: 10.0.0.5
          port: 57400
`)
	_, err = m.ParsePolicies(distinct)
	require.NoError(t, err, "same host, different ports: two endpoints, not a duplicate")
}
