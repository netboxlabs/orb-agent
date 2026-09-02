package policy

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// The orb agent polls GET /status on a timer while pushing policy updates, so
// gin serves StartPolicy, StopPolicy and GetPolicyStatuses from concurrent
// request goroutines. An unguarded policies map turns that overlap into
// "fatal error: concurrent map read and map write", which no recover can catch.
func TestManagerPolicyMapIsConcurrencySafe(t *testing.T) {
	m := newTestManager()
	interval := 3600

	policyFor := func(host string) config.Policy {
		return config.Policy{
			Config: config.PolicyConfig{MetricsInterval: &interval},
			Scope: config.Scope{
				Authentication: v2cAuth(),
				Targets:        []config.Target{{Host: host, Port: 161}},
			},
		}
	}

	// Warm the shared collector so the goroutines below contend on the policies
	// map rather than serialising on the profile load. It stays running for the
	// rest of the test: a profile set lives only while a policy uses it, so
	// stopping this one here would put every worker back on a cold cache.
	require.NoError(t, m.StartPolicy("warmup", policyFor("192.0.2.1")))

	const workers = 8
	const rounds = 40
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := range rounds {
				name := fmt.Sprintf("policy-%d-%d", w, r)
				_ = m.StartPolicy(name, policyFor("192.0.2.1"))
				m.HasPolicy(name)
				_ = m.StopPolicy(name)
			}
		}(w)
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds * 4 {
				m.GetPolicyStatuses()
			}
		}()
	}
	wg.Wait()

	require.NoError(t, m.Stop())
	require.Empty(t, m.GetPolicyStatuses())
}

// gatedCollector blocks inside ForgetPolicy so a runner can be held mid-stop,
// which is the window a DELETE and a POST for one policy name overlap in.
type gatedCollector struct {
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func newGatedCollector() *gatedCollector {
	return &gatedCollector{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gatedCollector) CollectTarget(_ context.Context, _ config.Target, _ *config.Authentication, _ string, _ collector.DialOptions) error {
	return nil
}

func (g *gatedCollector) ForgetPolicy(string) {
	close(g.entered)
	<-g.release
}

func (g *gatedCollector) unblock() {
	g.releaseOnce.Do(func() { close(g.release) })
}

// A stopping runner calls ForgetPolicy, which is keyed on the policy name
// alone. If StartPolicy may take the name before Stop returns, the old runner
// erases the replacement's freshly collected observations and poll state.
func TestStopPolicy_HoldsTheNameUntilTheRunnerHasStopped(t *testing.T) {
	m := newTestManager()
	// Warm the shared collector so StartPolicy below races on the name rather
	// than on the profile load. The reference is held for the whole test, since
	// a profile set no policy is using is discarded.
	_, err := m.acquireCollector("")
	require.NoError(t, err)
	t.Cleanup(func() { m.releaseCollector("") })

	gate := newGatedCollector()
	t.Cleanup(gate.unblock)

	r, err := NewRunner(m.ctx, testLogger, "p1", minimalPolicy(v2cAuth()), gate, nil)
	require.NoError(t, err)
	r.Start()
	m.policies["p1"] = r

	stopped := make(chan error, 1)
	go func() { stopped <- m.StopPolicy("p1") }()
	<-gate.entered

	started := make(chan error, 1)
	go func() { started <- m.StartPolicy("p1", minimalPolicy(v2cAuth())) }()

	select {
	case startErr := <-started:
		t.Fatalf("StartPolicy returned %v while the old runner was still stopping", startErr)
	case <-time.After(200 * time.Millisecond):
	}

	gate.unblock()
	require.NoError(t, <-stopped)
	require.NoError(t, <-started)
	require.True(t, m.HasPolicy("p1"))
	require.NoError(t, m.Stop())
}

// StartPolicy waits on a stopping runner's reservation instead of taking its
// name, so a DELETE and a POST for one name overlap on shared bookkeeping.
// Hammer that one name to keep the reservation map honest under -race.
func TestSameNameStartStopIsConcurrencySafe(t *testing.T) {
	m := newTestManager()
	// Warm the shared collector, and hold the reference for the whole test: a
	// profile set no policy is using is discarded.
	_, err := m.acquireCollector("")
	require.NoError(t, err)
	t.Cleanup(func() { m.releaseCollector("") })

	const workers = 8
	const rounds = 20
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				_ = m.StartPolicy("shared", minimalPolicy(v2cAuth()))
				m.HasPolicy("shared")
				_ = m.StopPolicy("shared")
			}
		}()
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds * 4 {
				m.GetPolicyStatuses()
			}
		}()
	}
	wg.Wait()

	require.NoError(t, m.Stop())
	require.Empty(t, m.GetPolicyStatuses())
}

// Only the name being stopped is held. A slow scheduler shutdown must not
// serialise the HTTP API, so other names and status reads carry on while one
// runner unwinds.
func TestStopPolicy_DoesNotBlockOtherNames(t *testing.T) {
	m := newTestManager()
	// Warm the shared collector, and hold the reference for the whole test: a
	// profile set no policy is using is discarded.
	_, err := m.acquireCollector("")
	require.NoError(t, err)
	t.Cleanup(func() { m.releaseCollector("") })

	gate := newGatedCollector()
	t.Cleanup(gate.unblock)
	r, err := NewRunner(m.ctx, testLogger, "slow", minimalPolicy(v2cAuth()), gate, nil)
	require.NoError(t, err)
	r.Start()
	m.policies["slow"] = r

	stopped := make(chan error, 1)
	go func() { stopped <- m.StopPolicy("slow") }()
	<-gate.entered

	require.NoError(t, m.StartPolicy("other", minimalPolicy(v2cAuth())))
	require.True(t, m.HasPolicy("other"))
	require.Len(t, m.GetPolicyStatuses(), 1)

	gate.unblock()
	require.NoError(t, <-stopped)
	require.NoError(t, m.Stop())
}

// A batch POST that fails partway has to undo the policies it started. Naming
// them by policy name stops whatever holds the name by then, so a DELETE and a
// POST for one of those names, both landing before the rollback, leave the
// rollback deleting a replacement the failed request never created.
//
// The interleave is written in sequence: what the rollback stops depends on the
// order the three requests reach the manager, not on their overlapping, and mu
// serialises the map operations anyway.
func TestStopPolicyHandle_LeavesAReplacementAlone(t *testing.T) {
	m := newTestManager()
	h, err := m.StartPolicyHandle("p1", minimalPolicy(v2cAuth()))
	require.NoError(t, err)

	// The concurrent DELETE, then the POST that recreated the name.
	require.NoError(t, m.StopPolicy("p1"))
	require.NoError(t, m.StartPolicy("p1", minimalPolicy(v2cAuth())))
	replacement := m.policies["p1"]
	require.NotNil(t, replacement)

	require.NoError(t, m.StopPolicyHandle(h))

	require.True(t, m.HasPolicy("p1"), "the rollback deleted the replacement")
	require.Same(t, replacement, m.policies["p1"], "the name holds a different runner")
	require.NoError(t, replacement.ctx.Err(), "the replacement's collections were cancelled")
	require.NoError(t, m.Stop())
}

// The other half: a rollback with nothing racing it still stops what it
// started, or a failed batch leaves its policies running.
func TestStopPolicyHandle_StopsTheRunnerItStarted(t *testing.T) {
	m := newTestManager()
	h, err := m.StartPolicyHandle("p1", minimalPolicy(v2cAuth()))
	require.NoError(t, err)
	started := m.policies["p1"]
	require.NotNil(t, started)

	require.NoError(t, m.StopPolicyHandle(h))

	require.False(t, m.HasPolicy("p1"), "the rollback left its own policy running")
	require.Error(t, started.ctx.Err(), "the runner was detached but never stopped")

	// A name already free is not an error: the DELETE that took it got there
	// first and stopped that runner itself.
	require.NoError(t, m.StopPolicyHandle(h))
	require.NoError(t, m.Stop())
}

// A handle naming no runner stops nothing, whatever name it carries. That is
// what a failed start returns, and falling back to the name would make it stop
// a policy the caller never created.
func TestStopPolicyHandle_AHandleWithNoRunnerStopsNothing(t *testing.T) {
	for _, h := range []Handle{{}, {name: "p1"}} {
		m := newTestManager()
		require.NoError(t, m.StartPolicy("p1", minimalPolicy(v2cAuth())))
		require.NoError(t, m.StopPolicyHandle(h))
		require.True(t, m.HasPolicy("p1"))
		require.NoError(t, m.Stop())
	}
}
