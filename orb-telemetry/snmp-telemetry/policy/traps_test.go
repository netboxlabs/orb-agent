package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

func TestValidateTrapListen(t *testing.T) {
	accepted := []string{"0.0.0.0:162", ":162", "127.0.0.1:1162", "[::]:162", "[fe80::1%en0]:162", "10.0.0.5:65535"}
	for _, listen := range accepted {
		assert.NoError(t, validateTrapListen(listen), listen)
	}
	rejected := map[string]string{
		"":                  "required",
		"   ":               "required",
		"162":               "missing port",
		"0.0.0.0":           "missing port",
		"0.0.0.0:0":         "port must be 1 to 65535",
		"0.0.0.0:65536":     "port must be 1 to 65535",
		"0.0.0.0:snmptrap":  "port must be 1 to 65535",
		"trap.example:162":  "host must be an IP address",
		"localhost:162":     "host must be an IP address",
		"0.0.0.0:162:extra": "too many colons",
	}
	for listen, want := range rejected {
		err := validateTrapListen(listen)
		require.Error(t, err, listen)
		assert.Contains(t, err.Error(), "scope.traps.listen", listen)
		assert.Contains(t, err.Error(), want, listen)
	}
}

func trapPolicy(interval *int, listen string) config.Policy {
	p := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: interval},
		Scope: config.Scope{
			Authentication: config.Authentication{ProtocolVersion: "SNMPv2c", Community: "public"},
			Targets:        []config.Target{{Host: "10.0.0.1"}},
		},
	}
	if listen != "" {
		p.Scope.Traps = &config.Traps{Listen: listen}
	}
	return p
}

func TestValidatePolicy_TrapsAndInterval(t *testing.T) {
	m := NewManager(t.Context(), testLogger, Options{})
	sixty := 60

	assert.NoError(t, m.validatePolicy(trapPolicy(&sixty, "")), "polling only is unchanged")
	assert.NoError(t, m.validatePolicy(trapPolicy(&sixty, "0.0.0.0:162")), "polling and traps")
	assert.NoError(t, m.validatePolicy(trapPolicy(nil, "0.0.0.0:162")), "traps only: no interval needed")

	err := m.validatePolicy(trapPolicy(nil, ""))
	require.Error(t, err)
	assert.Equal(t, "policy has neither metrics_interval nor scope.traps: nothing to do", err.Error())

	err = m.validatePolicy(trapPolicy(&sixty, "0.0.0.0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope.traps.listen")

	zero := 0
	err = m.validatePolicy(trapPolicy(&zero, "0.0.0.0:162"))
	require.Error(t, err, "a present interval is still range-checked")
	assert.Contains(t, err.Error(), "metrics_interval must be a positive integer")

	huge := maxPolicySeconds + 1
	err = m.validatePolicy(trapPolicy(&huge, ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metrics_interval must be at most")
}

// A policy with no metrics_interval polls nothing: no scheduler, no job, no
// collector call, no ForgetPolicy on stop. It still expands its targets and
// acquires the socket with them.
func TestRunner_TrapOnlySchedulesNothing(t *testing.T) {
	pool := newSpyPool()
	spy := &spyCollector{}
	pol := trapPolicy(nil, "0.0.0.0:1162")
	pol.Scope.Targets = []config.Target{{Host: "10.0.0.0/30"}}
	r, err := NewRunner(t.Context(), testLogger, "edge", pol, spy, pool)
	require.NoError(t, err)
	assert.Nil(t, r.scheduler, "a trap-only runner has no scheduler")
	assert.Len(t, pool.devices["edge"], 2)

	assert.NotPanics(t, r.Start)
	time.Sleep(50 * time.Millisecond)
	assert.Empty(t, spy.dials, "nothing was polled")

	require.NoError(t, r.Stop())
	assert.Equal(t, []string{"edge"}, pool.released)
	assert.Empty(t, spy.forgotten(), "there is no collector state to forget")
}

// The guard in NewRunner mirrors validatePolicy so a direct call cannot slip
// past.
func TestRunner_NeitherIntervalNorTrapsIsRejected(t *testing.T) {
	_, err := NewRunner(t.Context(), testLogger, "p1", trapPolicy(nil, ""), &spyCollector{}, newSpyPool())
	require.Error(t, err)
	assert.Equal(t, "policy has neither metrics_interval nor scope.traps: nothing to do", err.Error())
}

// Through the manager, so the whole start and stop path is exercised with
// the real lifecycle and none of it dereferences the absent scheduler.
func TestManager_TrapOnlyPolicyStartsAndStops(t *testing.T) {
	pool := newSpyPool()
	m := NewManager(t.Context(), testLogger, Options{TrapPool: pool})
	policies, err := m.ParsePolicies([]byte(`
policies:
  edge:
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - host: 10.0.0.1
      traps:
        listen: "0.0.0.0:1162"
`))
	require.NoError(t, err)
	require.NoError(t, m.StartPolicy("edge", policies["edge"]))
	require.True(t, m.HasPolicy("edge"))
	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "running", statuses[0].Status)

	require.NoError(t, m.StopPolicy("edge"))
	assert.Equal(t, []string{"acquire:edge", "release:edge"}, pool.callSequence())
	require.NoError(t, m.Stop())
}

func TestParsePolicies_ReadsTheTrapsBlock(t *testing.T) {
	m := NewManager(t.Context(), testLogger, Options{})
	policies, err := m.ParsePolicies([]byte(`
policies:
  edge:
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - host: 10.1.0.0/30
      traps:
        listen: "0.0.0.0:162"
`))
	require.NoError(t, err)
	require.NotNil(t, policies["edge"].Scope.Traps)
	assert.Equal(t, "0.0.0.0:162", policies["edge"].Scope.Traps.Listen)
	assert.Nil(t, policies["edge"].Config.MetricsInterval)
}
