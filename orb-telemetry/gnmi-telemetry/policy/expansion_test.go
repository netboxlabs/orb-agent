package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/targets"
)

// oversizedTargets are the shapes that expand past maxPolicyAddresses on their
// own. The range forms carrying CIDR suffixes are the ones a guard that parsed
// the notation itself read as a single address while targets.Expand walked the
// whole span.
var oversizedTargets = []string{
	"10.0.0.0/15",
	"10.0.0.0/8",
	"0.0.0.0/0",
	"10.0.0.0-10.255.255.255",
	"10.0.0.0/8-10.1.0.0/8",
	"10.0.0.0-10.1.0.0/16",
	"0.0.0.0/0-255.255.255.255/0",
}

// acceptedTargets stay within the budget on their own, including the shapes
// that resemble an oversized range but are not one. The two /16 forms are not
// here: the policy budget accepts them, but the per-target cap the validator
// applies first does not.
var acceptedTargets = []string{
	"192.168.1.1",
	"router.example.com",
	"my-switch-01.example.com",
	"10.0.0.0/32",
	"10.0.0.0/24",
	"10.0.0.0-100",
	"10.0.0.0/24-100",
	"10.0.0.0-10.0.0.9",
	"2001:db8::1",
}

// malformedTargets are left to targets.Expand, which reports what is wrong
// with them. The guard bounds a policy; it does not validate a target.
var malformedTargets = []string{
	"2001:db8::/32",
	"10.0.0.0/33",
	"10.0.0.1-10.0.0.0",
	"10.0.0.0-999",
	"2001:db8::1-2001:db8::5",
	"not a target",
}

// entries turns hosts into the target list the guard reads.
func entries(hosts ...string) []config.Target {
	list := make([]config.Target, 0, len(hosts))
	for _, host := range hosts {
		list = append(list, config.Target{Host: host})
	}
	return list
}

// sixteenSixteens is sixteen /16 entries. The policy as a whole expands to
// 1048544 addresses, one permanent subscription apiece, and the sixteen
// prefixes are a few hundred bytes so the request body limit never sees them.
func sixteenSixteens() []string {
	hosts := make([]string, 0, 16)
	for i := range 16 {
		hosts = append(hosts, fmt.Sprintf("10.%d.0.0/16", i))
	}
	return hosts
}

func TestCheckPolicyExpansion_RejectsOversizedTarget(t *testing.T) {
	for _, target := range oversizedTargets {
		err := checkPolicyExpansion(entries(target))
		require.Error(t, err, "target %s should be rejected", target)
		assert.ErrorContains(t, err, fmt.Sprintf("%d", maxPolicyAddresses))
	}
}

func TestCheckPolicyExpansion_AcceptsTargetWithinLimit(t *testing.T) {
	for _, target := range acceptedTargets {
		assert.NoError(t, checkPolicyExpansion(entries(target)), "target %s should be accepted", target)
	}
}

// The budget is the policy's, not each entry's. Every host here is accepted on
// its own, so a per-target ceiling passes all sixteen.
func TestCheckPolicyExpansion_RejectsManyTargetsThatEachFit(t *testing.T) {
	hosts := sixteenSixteens()
	for _, host := range hosts {
		require.NoError(t, checkPolicyExpansion(entries(host)), "host %s should fit on its own", host)
	}

	err := checkPolicyExpansion(entries(hosts...))
	require.Error(t, err)
	assert.ErrorContains(t, err, "1048544")
	assert.ErrorContains(t, err, "65536")
}

// The boundary: the budget is a ceiling the policy may reach, and one address
// past it is refused.
//
// Two /17 prefixes hold 32766 hosts apiece rather than 32768, since a prefix
// excludes its network and broadcast addresses, so a four address range makes
// up the difference and the policy lands on the ceiling exactly. The mixed
// notation is deliberate: it reaches the boundary through both arithmetics at
// once.
func TestCheckPolicyExpansion_BoundaryIsTheSum(t *testing.T) {
	atLimit := entries("10.0.0.0/17", "10.1.0.0/17", "192.0.2.0-3")
	require.NoError(t, checkPolicyExpansion(atLimit))

	overByOne := append(atLimit, config.Target{Host: "198.51.100.1"})
	err := checkPolicyExpansion(overByOne)
	require.Error(t, err)
	assert.ErrorContains(t, err, "65537")
}

func TestCheckPolicyExpansion_LeavesMalformedToExpand(t *testing.T) {
	for _, target := range malformedTargets {
		assert.NoError(t, checkPolicyExpansion(entries(target)), "target %s should not be rejected by the size guard", target)
	}
}

func policyWithTarget(host string) config.Policy {
	return policyWithTargets(host)
}

// A target past the per-target cap is refused by the cap, which fires ahead of
// the policy budget and names the smaller number.
func TestValidate_RejectsOversizedTarget(t *testing.T) {
	m := newTestManager()
	for _, host := range oversizedTargets {
		err := m.validatePolicy(policyWithTarget(host))
		require.Error(t, err, "target %s should be rejected", host)
		assert.ErrorContains(t, err, fmt.Sprintf("%d", targets.MaxExpand))
	}
}

func TestValidate_AcceptsTargetAtTheLimit(t *testing.T) {
	m := newTestManager()
	for _, host := range acceptedTargets {
		assert.NoError(t, m.validatePolicy(policyWithTarget(host)), "target %s should be accepted", host)
	}
}

// Every entry is one /16, so the per-target cap refuses the first of them
// before the policy budget is ever charged.
func TestValidate_RejectsPolicyOverTheBudget(t *testing.T) {
	m := newTestManager()
	err := m.validatePolicy(policyWithTargets(sixteenSixteens()...))
	require.Error(t, err)
	assert.ErrorContains(t, err, fmt.Sprintf("%d", targets.MaxExpand))
}

// A direct NewRunner call does not pass through validatePolicy, which is where
// the per-target cap lives, so the policy-wide budget has to hold there on its
// own or the collector still gets the million streams.
func TestNewRunner_RejectsPolicyOverTheBudget(t *testing.T) {
	_, err := NewRunner(t.Context(), testLogger, "p1", policyWithTargets(sixteenSixteens()...), &spyCollector{}, nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "1048544")
	assert.ErrorContains(t, err, "65536")
}

// The guard reads a target through targets.Count, which reports what
// targets.Expand returns: one empty address for an empty target. Teaching Count
// to refuse it would put the two back out of step, which is what reading a
// target once exists to prevent, so a blank host is refused by policy
// validation instead of by the count. The budget charges it the one address it
// costs, so a body full of blank hosts is still bounded.
func TestCheckPolicyExpansion_LeavesTheBlankHostToValidation(t *testing.T) {
	assert.NoError(t, checkPolicyExpansion(entries("")))

	count, err := targets.Count("")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), count)

	addrs, err := targets.Expand("")
	require.NoError(t, err)
	assert.Len(t, addrs, 1)

	blanks := make([]string, maxPolicyAddresses+1)
	err = checkPolicyExpansion(entries(blanks...))
	require.Error(t, err)
	assert.ErrorContains(t, err, "65537")
}

// A blank host is named by validatePolicy rather than folded into a size, so
// the more actionable message wins when a policy holds both a blank host and
// one past the per-target cap.
func TestValidate_ReportsTheBlankHostBeforeTheBudget(t *testing.T) {
	m := newTestManager()
	err := m.validatePolicy(policyWithTargets("  ", "10.0.0.0/16"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "host is required")
}

// Padding is stripped before the guard counts, not by it: a padded prefix is
// one targets.Count and targets.Expand both refuse, so it would contribute
// nothing to the budget and then fail to expand. normalizeTargetHosts is what
// keeps the three reading the same host.
func TestParsePolicies_TrimsAnOversizedTargetIntoTheBudget(t *testing.T) {
	padded := " 10.0.0.0/8 "
	require.NoError(t, checkPolicyExpansion(entries(padded)))
	_, err := targets.Expand(padded)
	require.Error(t, err)

	m := newTestManager()
	body := fmt.Sprintf(`policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: %q
`, padded)
	_, err = m.ParsePolicies([]byte(body))
	require.Error(t, err)
	assert.ErrorContains(t, err, "16777214")
	assert.ErrorContains(t, err, "1024")
}

// The budget counts distinct addresses, not the sum of every entry's size.
// Pinning a host inside a subnet to give it its own credentials is the
// documented way to do that, and expandTargets collapses the pin onto the
// address the subnet already produced, so charging the policy for both refused
// a policy whose expansion lands exactly on the ceiling.
//
// Two /17 prefixes hold 32766 hosts apiece, since a prefix excludes its network
// and broadcast addresses, so a four address range makes the union exactly
// 65536. The two pinned hosts, one of them written with an inline port, take
// the sum to 65538.
func TestCheckPolicyExpansion_CountsDistinctAddresses(t *testing.T) {
	atLimit := entries("10.0.0.0/17", "10.1.0.0/17", "192.0.2.0-3", "10.0.0.5", "10.1.0.9:6030")
	assert.NoError(t, checkPolicyExpansion(atLimit))

	// A hostname stands for one endpoint that no range can contain, so it is
	// what takes this policy past the ceiling.
	overByOne := append(atLimit, config.Target{Host: "router.example.com"})
	err := checkPolicyExpansion(overByOne)
	require.Error(t, err)
	assert.ErrorContains(t, err, "65537")
}
