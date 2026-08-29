package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

func TestTargetAddressCount(t *testing.T) {
	cases := []struct {
		target string
		want   uint64
	}{
		{"192.168.1.1", 1},
		{"router.example.com", 1},
		{"my-switch-01.example.com", 1},
		{"10.0.0.0/32", 1},
		{"10.0.0.0/24", 256},
		{"10.0.0.0/16", 65536},
		{"10.0.0.0/15", 131072},
		{"10.0.0.0/8", 16777216},
		{"0.0.0.0/0", 4294967296},
		{"10.0.0.0-100", 1}, // last-octet form, bounded by construction
		{"10.0.0.0-10.0.0.9", 10},
		{"10.0.0.0-10.255.255.255", 16777216},
		{"2001:db8::/32", 1}, // IPv4 only; targets.Expand rejects it
		{"not a target", 1},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, targetAddressCount(tc.target), "target %s", tc.target)
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
	for _, host := range []string{"10.0.0.0/8", "0.0.0.0/0", "10.0.0.0/15", "10.0.0.0-10.255.255.255"} {
		err := m.validatePolicy(policyWithTarget(host))
		require.Error(t, err, "target %s should be rejected", host)
		assert.ErrorContains(t, err, host)
		assert.ErrorContains(t, err, fmt.Sprintf("%d", maxTargetAddresses))
	}
}

func TestValidate_AcceptsTargetAtTheLimit(t *testing.T) {
	m := newTestManager()
	for _, host := range []string{"10.0.0.0/16", "10.0.0.0/24", "192.168.1.1", "router.example.com"} {
		assert.NoError(t, m.validatePolicy(policyWithTarget(host)), "target %s should be accepted", host)
	}
}

func TestNewRunner_RejectsOversizedTarget(t *testing.T) {
	_, err := NewRunner(t.Context(), testLogger, "p1", policyWithTarget("10.0.0.0/8"), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "16777216")
	assert.ErrorContains(t, err, "65536")
}
