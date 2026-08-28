package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Two ports on one address are two endpoints, whichever way the port is
// written. Keying the host and the port from different decisions — the host from
// hostWithoutPort, the port from the field alone — collapsed both of these to
// one key and rejected a valid policy.
func TestTwoInlinePortsOnOneHostAreTwoEndpoints(t *testing.T) {
	m := newTestManager(t)
	policies, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.5:6030
        - host: 10.0.0.5:57400
`))
	require.NoError(t, err, "two inline ports on one host are two endpoints")
	require.Len(t, policies["p1"].Scope.Targets, 2)
}

// The converse: one endpoint written two ways is a duplicate, and used not to be
// caught because the two spellings produced different keys.
func TestAnInlinePortAndThePortFieldNamingOneEndpointIsADuplicate(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.5:6030
        - host: 10.0.0.5
          port: 6030
`))
	require.Error(t, err, "inline :6030 and port: 6030 name the same endpoint")
	require.Contains(t, err.Error(), "two entries")
}

// The scope port participates too: a bare host inherits it, so a target naming
// the same address inline at that port is the same endpoint.
func TestTheScopePortIsUsedWhenMatchingDuplicates(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      port: 6030
      targets:
        - host: 10.0.0.5
        - host: 10.0.0.5:6030
`))
	require.Error(t, err)

	_, err = m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      port: 6030
      targets:
        - host: 10.0.0.5
        - host: 10.0.0.5:57400
`))
	require.NoError(t, err, "a different inline port is a different endpoint")
}

// The cap counts distinct addresses, not the sum of what each entry spans.
// Pinning hosts inside a subnet to give them their own credentials is the
// documented pattern, and against a /22 — the largest prefix the cap allows —
// summing rejected a policy that expands to 1022 targets, under the limit.
func TestPinnedHostsInsideASubnetDoNotCountTwiceAgainstTheCap(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: 10.0.0.5
          username: legacy
        - host: 10.0.0.6
          username: legacy
        - host: 10.0.0.7
          username: legacy
`))
	require.NoError(t, err, "a /22 plus three hosts inside it is still 1022 endpoints")
}

// Overlap only cancels at the same port. The same address reached on two ports is
// two subscriptions, so merging across ports would let a policy exceed the cap.
func TestOverlapAtADifferentPortStillCounts(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: 10.1.0.0/22
`))
	require.Error(t, err, "two non-overlapping /22s are 2044 endpoints")

	_, err = m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      port: 6030
      targets:
        - host: 10.0.0.0/22
        - host: 10.0.0.0/22
          port: 57400
`))
	require.Error(t, err, "the same /22 at two ports is 2044 subscriptions, not 1022")

	// And the same /22 at the same port really is just 1022.
	_, err = m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: 10.0.0.1-10
`))
	require.NoError(t, err, "a range wholly inside the subnet adds nothing")
}

// A hostname is one endpoint and cannot be compared with an address, so it is
// counted rather than merged.
func TestHostnamesAreCountedIndividually(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: switch-a.example.com
        - host: switch-b.example.com
`))
	require.NoError(t, err, "1022 + 2 is 1024, exactly the cap")

	_, err = m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: switch-a.example.com
        - host: switch-b.example.com
        - host: switch-c.example.com
`))
	require.Error(t, err, "1022 + 3 is over the cap")
}

// A single oversized entry names itself as the offender rather than being blamed
// on whichever target happened to come last.
func TestAnOversizedTargetIsNamedInTheError(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/20
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "10.0.0.0/20")
}

// No hostname, IP, CIDR or range holds a control character, and a host holding a
// newline is the only route by which policy text could forge a whole log record
// rather than fill one field.
func TestAHostWithControlCharactersIsRejected(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte("policies:\n  p1:\n    scope:\n      targets:\n" +
		"        - host: \"10.0.0.1\\nlevel=ERROR msg=forged\"\n"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "control character")
}

// A policy name reaches a log line on nearly every path through this backend, so
// it gets the same treatment as a host.
func TestAPolicyNameWithControlCharactersIsRejected(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte("policies:\n  \"p1\\nlevel=ERROR msg=forged\":\n    scope:\n      targets:\n        - host: 10.0.0.1\n"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "policy name")
	require.Contains(t, err.Error(), "control character")
}

// A tab is a control character but a legitimate part of nothing here, and an
// ordinary name still passes.
func TestOrdinaryNamesAndHostsStillPass(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  campus-fabric_01:
    scope:
      targets:
        - host: switch-a.example.com
        - host: 10.0.0.0/24
`))
	require.NoError(t, err)
}

// Validation and expansion must agree on what "the same endpoint" means.
// Validation lowercased the raw text while expansion canonicalized through
// net.ParseIP, so two spellings of one IPv6 address passed validation as two
// targets with two sets of credentials and were then merged by the expansion
// dedupe — leaving the effective config to depend on entry order, with only a
// warning to show for it.
func TestTwoSpellingsOfOneIPv6AddressAreRejectedAsADuplicate(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 2001:db8::1
          username: alice
        - host: 2001:0db8::1
          username: bob
`))
	require.Error(t, err, "the expansion would have merged these; validation must say so")
	require.Contains(t, err.Error(), "two entries")
}

// Upper-case hex is the same address too.
func TestIPv6CaseDoesNotMakeANewEndpoint(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 2001:DB8::1
        - host: 2001:db8::1
`))
	require.Error(t, err)
}

// An IPv4-mapped form names the same endpoint as the plain address, which is what
// the expansion dedupe already concluded.
func TestAnIPv4MappedAddressIsTheSameEndpoint(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.1
        - host: "::ffff:10.0.0.1"
`))
	require.Error(t, err)
}

// Two genuinely different addresses still pass, and a hostname is never compared
// against an address: Expand does not resolve DNS, so they cannot be known to be
// the same device.
func TestDistinctAddressesAndNamesStillPass(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 2001:db8::1
        - host: 2001:db8::2
        - host: switch-a.example.com
        - host: 10.0.0.1
`))
	require.NoError(t, err)
}

// The two layers must reach the same verdict for the same input. If they drift
// again, validation admits something expansion silently merges.
func TestValidationAndExpansionAgreeOnEndpointIdentity(t *testing.T) {
	for _, pair := range [][2]string{
		{"2001:db8::1", "2001:0db8::1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"10.0.0.1", "::ffff:10.0.0.1"},
		{"SWITCH-A.example.com", "switch-a.example.com"},
	} {
		require.Equal(t, canonicalHost(pair[0]), canonicalHost(pair[1]),
			"%q and %q name one endpoint", pair[0], pair[1])
		require.Equal(t,
			dedupeKey(ensurePort(pair[0], 9339)),
			dedupeKey(ensurePort(pair[1], 9339)),
			"expansion must agree for %q and %q", pair[0], pair[1])
	}
	require.NotEqual(t, canonicalHost("2001:db8::1"), canonicalHost("2001:db8::2"))
}
