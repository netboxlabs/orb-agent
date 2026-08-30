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

	r, err := NewRunner(m.ctx, testLogger, "p1", minimalPolicy(v2cAuth()), gate)
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
	r, err := NewRunner(m.ctx, testLogger, "slow", minimalPolicy(v2cAuth()), gate)
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
