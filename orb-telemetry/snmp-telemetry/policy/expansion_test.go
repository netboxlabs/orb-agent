package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// oversizedTargets are the shapes that expand past maxTargetAddresses. The
// range forms carrying CIDR suffixes are the ones a guard that parsed the
// notation itself read as a single address while targets.Expand walked the
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

// acceptedTargets stay within the limit, including the shapes that resemble an
// oversized range but are not one.
var acceptedTargets = []string{
	"192.168.1.1",
	"router.example.com",
	"my-switch-01.example.com",
	"10.0.0.0/32",
	"10.0.0.0/24",
	"10.0.0.0/16",
	"10.0.0.0-100",
	"10.0.0.0/24-100",
	"10.0.0.0-10.0.0.9",
	"10.0.0.0/16-10.0.255.255/16",
	"2001:db8::1",
}

// malformedTargets are left to targets.Expand, which reports what is wrong
// with them. The guard bounds a target; it does not validate one.
var malformedTargets = []string{
	"2001:db8::/32",
	"10.0.0.0/33",
	"10.0.0.1-10.0.0.0",
	"10.0.0.0-999",
	"2001:db8::1-2001:db8::5",
	"not a target",
}

func TestCheckTargetExpansion_RejectsOversized(t *testing.T) {
	for _, target := range oversizedTargets {
		err := checkTargetExpansion(target)
		require.Error(t, err, "target %s should be rejected", target)
		assert.ErrorContains(t, err, target)
		assert.ErrorContains(t, err, fmt.Sprintf("%d", maxTargetAddresses))
	}
}

func TestCheckTargetExpansion_AcceptsWithinLimit(t *testing.T) {
	for _, target := range acceptedTargets {
		assert.NoError(t, checkTargetExpansion(target), "target %s should be accepted", target)
	}
}

func TestCheckTargetExpansion_LeavesMalformedToExpand(t *testing.T) {
	for _, target := range malformedTargets {
		assert.NoError(t, checkTargetExpansion(target), "target %s should not be rejected by the size guard", target)
	}
}

func policyWithTarget(host string) config.Policy {
	interval := 60
	return config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &interval},
		Scope: config.Scope{
			Authentication: v2cAuth(),
			Targets:        []config.Target{{Host: host}},
		},
	}
}

func TestValidate_RejectsOversizedTarget(t *testing.T) {
	m := newTestManager()
	for _, host := range oversizedTargets {
		err := m.validatePolicy(policyWithTarget(host))
		require.Error(t, err, "target %s should be rejected", host)
		assert.ErrorContains(t, err, host)
		assert.ErrorContains(t, err, fmt.Sprintf("%d", maxTargetAddresses))
	}
}

func TestValidate_AcceptsTargetAtTheLimit(t *testing.T) {
	m := newTestManager()
	for _, host := range acceptedTargets {
		assert.NoError(t, m.validatePolicy(policyWithTarget(host)), "target %s should be accepted", host)
	}
}

func TestNewRunner_RejectsOversizedTarget(t *testing.T) {
	for _, host := range oversizedTargets {
		_, err := NewRunner(t.Context(), testLogger, "p1", policyWithTarget(host), &spyCollector{})
		require.Error(t, err, "target %s should be rejected", host)
		assert.ErrorContains(t, err, "65536")
	}
}
