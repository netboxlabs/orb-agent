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
