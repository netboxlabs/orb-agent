package policy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// A policy with no metrics_interval polls nothing: no scheduler, no job and no
// collector call. It still expands its targets and acquires the socket with
// them, and its stop still forgets a policy the collector never heard of.
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
	assert.Empty(t, spy.dialed(), "nothing was polled")

	require.NoError(t, r.Stop())
	assert.Equal(t, []string{"edge"}, pool.released)
	assert.Equal(t, []string{"edge"}, spy.forgotten(), "the forget runs whatever the runner scheduled, and finds no state")
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

// A start that fails after the scheduler exists shuts it down. gocron starts a
// goroutine in NewScheduler, so a rejected policy that only cancelled its
// context would strand one for the life of the process, and a trap socket
// collision is a rejection that happens after the scheduler is built.
func TestRunner_FailedStartShutsDownTheScheduler(t *testing.T) {
	pool := newSpyPool()
	pool.acquireErr = errors.New("binding trap socket 0.0.0.0:1162: address already in use")
	sixty := 60

	baseline := schedulerGoroutines(t)
	const rejected = 20
	for range rejected {
		_, err := NewRunner(t.Context(), testLogger, "p1", trapPolicy(&sixty, "0.0.0.0:1162"), &spyCollector{}, pool)
		require.Error(t, err)
	}

	// Shutdown returns before the goroutine it stopped has finished unwinding,
	// so the count is polled rather than read once.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && schedulerGoroutines(t) > baseline {
		time.Sleep(10 * time.Millisecond)
	}
	assert.LessOrEqual(t, schedulerGoroutines(t), baseline,
		"every rejected policy's scheduler goroutine is gone, not %d of them left running", rejected)
}

// schedulerGoroutines counts the live goroutines gocron.NewScheduler started.
// The dump names the creator of every goroutine, which is what tells a
// scheduler's own goroutine apart from the rest of the test binary's.
func schedulerGoroutines(t *testing.T) int {
	t.Helper()
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "gocron/v2.NewScheduler")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// The listen string is re-checked in NewRunner as well as in validatePolicy,
// so a direct call cannot hand the pool a string the API would have refused.
func TestRunner_ValidatesTheListenString(t *testing.T) {
	pool := newSpyPool()
	_, err := NewRunner(t.Context(), testLogger, "p1", trapPolicy(nil, "trap.example:162"), &spyCollector{}, pool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope.traps.listen")
	assert.Contains(t, err.Error(), "host must be an IP address")
	assert.Empty(t, pool.callSequence(), "and nothing was acquired")
}

// The collector the manager builds for a profiles directory carries that
// directory's trap names, override files included, which is what a policy
// with its own profiles_dir registers.
func TestManager_CollectorCarriesItsProfilesDirsTrapNames(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "custom"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "custom", "traps.yml"), []byte(`
traps:
  - trap_oid: 1.3.6.1.4.1.99999.0.1
    trap_name: customWidgetFailed
`), 0o644))
	m := NewManager(t.Context(), testLogger, Options{})
	c, err := m.acquireCollector(dir)
	require.NoError(t, err)
	t.Cleanup(func() { m.releaseCollector(dir) })
	names := c.TrapNames()
	assert.Equal(t, "customWidgetFailed", names["1.3.6.1.4.1.99999.0.1"])
	assert.Equal(t, "bigipTrafficGroupStandby", names["1.3.6.1.4.1.3375.2.4.0.141"])
}
