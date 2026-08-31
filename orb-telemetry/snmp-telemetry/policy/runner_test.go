package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// policyWithTargets returns a valid policy whose targets are the given hosts.
func policyWithTargets(hosts ...string) config.Policy {
	pol := minimalPolicy(v2cAuth())
	pol.Scope.Targets = make([]config.Target, 0, len(hosts))
	for _, host := range hosts {
		pol.Scope.Targets = append(pol.Scope.Targets, config.Target{Host: host})
	}
	return pol
}

// TestNewRunner_RejectsUnexpandableTarget covers the targets a runner cannot
// turn into an address. Skipping one leaves a policy the API reports as
// running that polls nothing, which is what the non-empty-target check exists
// to prevent.
func TestNewRunner_RejectsUnexpandableTarget(t *testing.T) {
	for name, host := range map[string]string{
		"malformed prefix length": "10.0.0.1/99",
		"malformed range bound":   "10.0.0.1-10.0.0.999",
		"ipv6 cidr":               "2001:db8::/64",
		"inverted range":          "10.0.0.100-10.0.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewRunner(context.Background(), testLogger, "p1", policyWithTargets(host), &spyCollector{})
			require.Error(t, err, "an unexpandable target must fail the runner, not be skipped")
			assert.Contains(t, err.Error(), host, "the error must name the offending target")
		})
	}
}

// TestNewRunner_RejectsUnexpandableTargetAmongValidOnes verifies one bad
// target fails the whole policy rather than quietly reducing its scope. An
// operator who asked for two subnets and got one is not told which.
func TestNewRunner_RejectsUnexpandableTargetAmongValidOnes(t *testing.T) {
	_, err := NewRunner(context.Background(), testLogger, "p1",
		policyWithTargets("192.168.1.1", "10.0.0.1/99"), &spyCollector{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.1/99")
}

// TestNewRunner_AcceptsExpandableTargets guards the behaviour Expand goes out
// of its way to keep: a hostname is a valid target, including one with a
// hyphen, which the range branch has to decline before the CIDR and IP
// branches see it. "10.0.0.256" is in the list for the same reason: it is not
// range, CIDR or IP notation, so it reaches the hostname fallback and is a
// name to resolve, not an expansion failure.
func TestNewRunner_AcceptsExpandableTargets(t *testing.T) {
	for _, host := range []string{
		"snmp.example.com", "edge-router-1.example.com", "10.0.0.256", "192.168.1.1", "10.0.0.0/30",
	} {
		t.Run(host, func(t *testing.T) {
			r, err := NewRunner(context.Background(), testLogger, "p1", policyWithTargets(host), &spyCollector{})
			require.NoError(t, err)
			t.Cleanup(func() { _ = r.Stop() })
			assert.NotEmpty(t, r.scheduler.Jobs(), "an accepted target must schedule at least one job")
		})
	}
}

// TestStartPolicy_RejectsUnexpandableTarget is the operator-facing half: the
// expansion failure has to come back from the POST that submits the policy,
// and the policy must not be left registered.
func TestStartPolicy_RejectsUnexpandableTarget(t *testing.T) {
	m := newTestManager()
	err := m.StartPolicy("p1", policyWithTargets("10.0.0.1/99"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.1/99")
	assert.False(t, m.HasPolicy("p1"), "a policy that failed to start must not be registered")
}

// policyWithTargetEntries returns a valid policy whose scope is the given
// entries verbatim, so a test can vary port, ID and context.
func policyWithTargetEntries(list ...config.Target) config.Policy {
	pol := minimalPolicy(v2cAuth())
	pol.Scope.Targets = list
	return pol
}

// identities renders an expanded target list as "host:port id context" strings, so a
// test asserts which devices got a job rather than only how many did.
func identities(t *testing.T, r *Runner, list []config.Target) []string {
	t.Helper()
	out := make([]string, 0, len(list))
	for _, target := range list {
		out = append(out, newTargetKey(target, r.resolveTargetAuthentication(target)).String())
	}
	return out
}

// TestExpandTargets_CollapsesPrefixAndMemberAddress covers a policy naming a
// prefix and an address inside it. Both entries expand to the same collector
// identity, and WithSingletonMode bounds one job rather than one identity, so a
// second job for that address could erase the first's observations through
// forgetDevice and clear its recorded error.
func TestExpandTargets_CollapsesPrefixAndMemberAddress(t *testing.T) {
	r := &Runner{scope: policyWithTargets("10.0.0.0/30", "10.0.0.1").Scope}
	expanded, collapsed, err := r.expandTargets()
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0:161", "10.0.0.1:161", "10.0.0.2:161", "10.0.0.3:161"},
		identities(t, r, expanded), "the prefix's four addresses each keep one job and the repeat is dropped")
	assert.Equal(t, 1, collapsed)
}

// TestExpandTargets_CollapsesOverlappingPrefixes is the same defect written as
// two prefixes rather than a prefix and a member.
func TestExpandTargets_CollapsesOverlappingPrefixes(t *testing.T) {
	r := &Runner{scope: policyWithTargets("10.0.0.0/30", "10.0.0.2/31").Scope}
	expanded, collapsed, err := r.expandTargets()
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0:161", "10.0.0.1:161", "10.0.0.2:161", "10.0.0.3:161"},
		identities(t, r, expanded))
	assert.Equal(t, 2, collapsed)
}

// TestExpandTargets_CollapsesAfterThePortDefault guards the ordering: an entry
// leaving the port unset and one naming 161 reach the collector as the same
// endpoint, so a key read before the default is applied would keep both.
func TestExpandTargets_CollapsesAfterThePortDefault(t *testing.T) {
	r := &Runner{scope: policyWithTargetEntries(
		config.Target{Host: "10.0.0.1"},
		config.Target{Host: "10.0.0.1", Port: SNMPDefaultPort},
	).Scope}
	expanded, collapsed, err := r.expandTargets()
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1:161"}, identities(t, r, expanded))
	assert.Equal(t, 1, collapsed)
}

// TestExpandTargets_KeepsEntriesTheIdentityTellsApart is the other half: every
// dimension deviceKey and targetKey carry has to survive the collapse.
// Losing one here would silently reduce a policy's scope.
func TestExpandTargets_KeepsEntriesTheIdentityTellsApart(t *testing.T) {
	for name, list := range map[string][]config.Target{
		"port": {
			{Host: "10.0.0.1", Port: 161},
			{Host: "10.0.0.1", Port: 1161},
		},
		"netbox id": {
			{Host: "10.0.0.1", ID: "11"},
			{Host: "10.0.0.1", ID: "22"},
		},
		"snmp context": {
			{Host: "10.0.0.1", Authentication: &config.Authentication{ProtocolVersion: "SNMPv3", ContextName: "vlan-100"}},
			{Host: "10.0.0.1", Authentication: &config.Authentication{ProtocolVersion: "SNMPv3", ContextName: "vlan-200"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := &Runner{scope: policyWithTargetEntries(list...).Scope}
			expanded, collapsed, err := r.expandTargets()
			require.NoError(t, err)
			assert.Len(t, expanded, 2, "two entries the identity tells apart must each keep a job")
			assert.Equal(t, 0, collapsed)
			assert.Len(t, identities(t, r, expanded), 2)
			assert.NotEqual(t, identities(t, r, expanded)[0], identities(t, r, expanded)[1])
		})
	}
}

// TestExpandTargets_ReportsAnUnexpandableTarget keeps the collapse from
// swallowing the expansion failure the runner reports by name.
func TestExpandTargets_ReportsAnUnexpandableTarget(t *testing.T) {
	r := &Runner{scope: policyWithTargets("10.0.0.1", "10.0.0.1/99").Scope}
	_, _, err := r.expandTargets()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.1/99")
}

// TestNewRunner_SchedulesOneJobPerIdentity is the end-to-end half: the collapse
// has to reach the scheduler, since the per-job singleton is what the duplicate
// defeats.
func TestNewRunner_SchedulesOneJobPerIdentity(t *testing.T) {
	r, err := NewRunner(context.Background(), testLogger, "p1",
		policyWithTargets("10.0.0.0/30", "10.0.0.1"), &spyCollector{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Stop() })
	assert.Len(t, r.scheduler.Jobs(), 4, "the repeated address must not get a second job")
}

// TestNewRunner_ChargesTheBudgetBeforeCollapsing pins the charging order. Two
// overlapping prefixes collapse to 65536 addresses, inside the budget, but
// expansion allocates both spans before a duplicate can be found, so the guard
// counts the raw notation and refuses.
func TestNewRunner_ChargesTheBudgetBeforeCollapsing(t *testing.T) {
	_, err := NewRunner(context.Background(), testLogger, "p1",
		policyWithTargets("10.0.0.0/16", "10.0.0.0/16"), &spyCollector{})
	require.Error(t, err, "a policy may not name a prefix twice to pay for it once")
	assert.Contains(t, err.Error(), "more than the limit")
}

// v3ContextAuth returns a valid SNMPv3 target authentication selecting a
// context name, the second unrestricted string the target identity carries.
func v3ContextAuth(contextName string) *config.Authentication {
	auth := v3AuthAuth()
	auth.ContextName = contextName
	return &auth
}

// TestExpandTargets_KeepsTargetsThatOnlyACollidingKeyMerges covers two targets
// that a key built by joining the identity fields cannot tell apart: a NetBox
// ID carrying the separator that key uses for the context name, against the ID
// and context name it imitates. Neither string is restricted, so collapsing the
// pair drops a target the operator asked for and it is never polled.
func TestExpandTargets_KeepsTargetsThatOnlyACollidingKeyMerges(t *testing.T) {
	for name, list := range map[string][]config.Target{
		"id imitates a context name": {
			{Host: "10.0.0.1", Port: 161, ID: "a context=b"},
			{Host: "10.0.0.1", Port: 161, ID: "a", Authentication: v3ContextAuth("b")},
		},
		"context name imitates a second one": {
			{Host: "10.0.0.1", Port: 161, ID: "a", Authentication: v3ContextAuth("b context=c")},
			{Host: "10.0.0.1", Port: 161, ID: "a context=b", Authentication: v3ContextAuth("c")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := &Runner{scope: policyWithTargetEntries(list...).Scope}
			expanded, collapsed, err := r.expandTargets()
			require.NoError(t, err)
			assert.Len(t, expanded, 2, "two distinct targets must each keep a job")
			assert.Equal(t, 0, collapsed)
		})
	}
}

// TestNewRunner_SchedulesBothTargetsACollidingKeyWouldMerge is the same defect
// where it costs the operator: the collapse decides how many jobs exist, so a
// merged pair leaves one target with no job at all.
func TestNewRunner_SchedulesBothTargetsACollidingKeyWouldMerge(t *testing.T) {
	pol := policyWithTargetEntries(
		config.Target{Host: "10.0.0.1", Port: 161, ID: "a context=b"},
		config.Target{Host: "10.0.0.1", Port: 161, ID: "a", Authentication: v3ContextAuth("b")},
	)
	r, err := NewRunner(context.Background(), testLogger, "p1", pol, &spyCollector{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Stop() })
	assert.Len(t, r.scheduler.Jobs(), 2, "a target was collapsed into another and is never polled")
}
