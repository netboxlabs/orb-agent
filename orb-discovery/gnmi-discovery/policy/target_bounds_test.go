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

// A hostname may legally begin with an address and a hyphen. Expand passes it
// through as one endpoint, because it contains letters — so the port has to be
// appended, and a syntactic guess that saw "address, hyphen" assumed a range and
// skipped it, leaving gnmic to fail the dial for a missing port.
func TestAHostnameBeginningWithAnAddressStillGetsItsPort(t *testing.T) {
	m := newTestManager(t)
	policies, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      port: 6030
      targets:
        - host: 10.0.0.1-switch.example.com
        - host: 10.0.0.1-
`))
	require.NoError(t, err)
	hosts := []string{}
	for _, tgt := range policies["p1"].Scope.Targets {
		hosts = append(hosts, tgt.Host)
	}
	require.Equal(t, []string{
		"10.0.0.1-switch.example.com:6030",
		"10.0.0.1-:6030",
	}, hosts, "Expand treats both as hostnames, so both take the port")
}

// The other half of the same confusion: such a hostname carrying an inline port
// was rejected outright, with an error blaming a CIDR or range it is not.
func TestAHostnameBeginningWithAnAddressMayCarryAnInlinePort(t *testing.T) {
	m := newTestManager(t)
	policies, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.1-switch.example.com:6030
`))
	require.NoError(t, err, "this is a hostname with a port, not a range")
	require.Equal(t, "10.0.0.1-switch.example.com:6030", policies["p1"].Scope.Targets[0].Host)
}

// A real range carrying an inline port is still rejected, which is what that
// check exists for: Expand would read it as a DNS name and retry a nonexistent
// host forever with only a generic dial error.
func TestARealRangeWithAnInlinePortIsStillRejected(t *testing.T) {
	m := newTestManager(t)
	for _, host := range []string{"10.0.0.1-10:6030", "10.0.0.0/24:6030", "10.0.0.1-10.0.0.9:6030"} {
		_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: ` + host + `
`))
		require.Error(t, err, "host %q must be rejected", host)
		require.Contains(t, err.Error(), "port", "the error points at the port field")
	}
}

// End to end: a zoned IPv6 host whose interface name contains a hyphen is a
// valid endpoint and must reach the runner bracketed and ported, not fail the
// whole policy.
func TestAZonedIPv6HostWithAHyphenIsAccepted(t *testing.T) {
	m := newTestManager(t)
	policies, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      port: 6030
      targets:
        - host: fe80::1%br-lan
        - host: fe80::2%eth0
`))
	require.NoError(t, err, "a hyphen in the zone must not fail the policy")
	hosts := []string{}
	for _, tgt := range policies["p1"].Scope.Targets {
		hosts = append(hosts, tgt.Host)
	}
	require.Equal(t, []string{"[fe80::1%br-lan]:6030", "[fe80::2%eth0]:6030"}, hosts)
}

// The cap must use the same notion of endpoint identity as expansion. An
// IPv4-mapped form is not Is4, so it counted as an endpoint of its own while
// canonicalHost and dedupeKey collapsed it with the plain address — and a /22
// plus three pinned mapped hosts inside it was rejected as 1025 endpoints that
// expansion resolves to 1022.
func TestMappedIPv4HostsInsideASubnetDoNotCountTwice(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: "::ffff:10.0.0.1"
          username: a
        - host: "::ffff:10.0.0.2"
          username: b
        - host: "::ffff:10.0.0.3"
          username: c
`))
	require.NoError(t, err, "the mapped hosts are inside the /22, so this is 1022 endpoints")
}

// A genuine IPv6 address is still not merged into an IPv4 span, and still counts
// as its own endpoint.
func TestARealIPv6HostStillCountsSeparately(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: 2001:db8::1
        - host: 2001:db8::2
`))
	require.NoError(t, err, "1022 + 2 is exactly the cap")

	_, err = m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.0/22
        - host: 2001:db8::1
        - host: 2001:db8::2
        - host: 2001:db8::3
`))
	require.Error(t, err, "1022 + 3 is over it: real IPv6 hosts are not inside the /22")
}

// A zone identifier is an interface name, and Linux interface names are
// case-sensitive. net.ParseIP refuses any address carrying a zone, so the whole
// value fell to the lower-casing path meant for hostnames — collapsing two
// different links into one and rejecting the policy.
func TestCaseDistinctIPv6ZonesAreDifferentEndpoints(t *testing.T) {
	m := newTestManager(t)
	policies, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: fe80::1%eth0
        - host: fe80::1%Eth0
`))
	require.NoError(t, err, "eth0 and Eth0 are two links on Linux")
	require.Len(t, policies["p1"].Scope.Targets, 2)
}

// The same fallback also failed to canonicalize the address half, so one address
// written two ways counted as two endpoints. Both halves are handled now.
func TestTwoSpellingsOfOneZonedAddressAreOneEndpoint(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      targets:
        - host: fe80::0001%eth0
          username: alice
        - host: fe80::1%eth0
          username: bob
`))
	require.Error(t, err, "same address, same zone: one endpoint")
	require.Contains(t, err.Error(), "two entries")
}

// canonicalHost is shared with the expansion dedupe, so the two must still agree
// on every zoned form — that sharing is what keeps validation from admitting
// something expansion silently merges.
func TestValidationAndExpansionAgreeOnZonedAddresses(t *testing.T) {
	same := [][2]string{
		{"fe80::0001%eth0", "fe80::1%eth0"},
		{"FE80::1%eth0", "fe80::1%eth0"},
	}
	for _, pair := range same {
		require.Equal(t, canonicalHost(pair[0]), canonicalHost(pair[1]),
			"%q and %q are one endpoint", pair[0], pair[1])
		require.Equal(t,
			dedupeKey(ensurePort(pair[0], 9339)),
			dedupeKey(ensurePort(pair[1], 9339)),
			"expansion must agree for %q and %q", pair[0], pair[1])
	}

	differ := [][2]string{
		{"fe80::1%eth0", "fe80::1%Eth0"},
		{"fe80::1%eth0", "fe80::1%eth1"},
		{"fe80::1%eth0", "fe80::2%eth0"},
	}
	for _, pair := range differ {
		require.NotEqual(t, canonicalHost(pair[0]), canonicalHost(pair[1]),
			"%q and %q are different endpoints", pair[0], pair[1])
		require.NotEqual(t,
			dedupeKey(ensurePort(pair[0], 9339)),
			dedupeKey(ensurePort(pair[1], 9339)),
			"expansion must agree for %q and %q", pair[0], pair[1])
	}

	// Unchanged: a mapped IPv4 form still collapses onto the plain address.
	require.Equal(t, canonicalHost("::ffff:10.0.0.1"), canonicalHost("10.0.0.1"))
}
