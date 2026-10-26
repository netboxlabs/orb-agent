package policy

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// pollRecorder records when each host was polled.
type pollRecorder struct {
	mu    sync.Mutex
	polls map[string][]time.Time
}

func newPollRecorder() *pollRecorder {
	return &pollRecorder{polls: make(map[string][]time.Time)}
}

func (p *pollRecorder) CollectTarget(_ context.Context, target config.Target, _ *config.Authentication, _ string, _ collector.DialOptions) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.polls[target.Host] = append(p.polls[target.Host], time.Now())
	return nil
}

func (p *pollRecorder) ForgetPolicy(string) {}

func (p *pollRecorder) TrapNames() map[string]string { return nil }

func (p *pollRecorder) Close() {}

func (p *pollRecorder) count(host string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.polls[host])
}

func (p *pollRecorder) first(host string) time.Time {
	return p.nth(host, 0)
}

func (p *pollRecorder) nth(host string, i int) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.polls[host][i]
}

// hourlyPolicy polls once an hour, so any poll a test sees within seconds is a
// first poll.
func hourlyPolicy(hosts ...string) config.Policy {
	pol := minimalPolicy(v2cAuth())
	interval := 3600
	pol.Config.MetricsInterval = &interval
	pol.Scope.Targets = nil
	for _, h := range hosts {
		pol.Scope.Targets = append(pol.Scope.Targets, config.Target{Host: h})
	}
	return pol
}

func hosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	return out
}

func TestFirstPollOffset(t *testing.T) {
	minute := time.Minute
	tests := []struct {
		name     string
		i, n     int
		interval time.Duration
		want     time.Duration
	}{
		{"one target polls at once", 0, 1, minute, 0},
		{"the first target polls at once", 0, 3, minute, 0},
		{"a small policy steps 10ms apart", 2, 3, minute, 20 * time.Millisecond},
		{"a large policy spreads over 10s", 1000, 2000, minute, 5 * time.Second},
		{"the last target stays inside the spread", 1999, 2000, minute, 9995 * time.Millisecond},
		{"the spread stays inside one interval", 1000, 2000, 2 * time.Second, time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firstPollOffset(tt.i, tt.n, tt.interval))
		})
	}
}

func TestRunner_PollsEveryTargetWhenItStarts(t *testing.T) {
	rec := newPollRecorder()
	all := hosts(3)
	r, err := NewRunner(context.Background(), testLogger, "p1", hourlyPolicy(all...), rec, nil)
	require.NoError(t, err)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		for _, h := range all {
			if rec.count(h) != 1 {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond, "every target must poll when the policy starts, not one interval later")
}

func TestRunner_SpreadsFirstPolls(t *testing.T) {
	rec := newPollRecorder()
	all := hosts(50)
	started := time.Now()
	r, err := NewRunner(context.Background(), testLogger, "p1", hourlyPolicy(all...), rec, nil)
	require.NoError(t, err)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		for _, h := range all {
			if rec.count(h) == 0 {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)

	// 50 targets 10ms apart: the first polls at once and the last 490ms later.
	// A run can start late but never early, so the last one bounds the spread.
	assert.Less(t, rec.first(all[0]).Sub(started), 2*time.Second)
	assert.GreaterOrEqual(t, rec.first(all[49]).Sub(started), 450*time.Millisecond)
}

// Each target keeps its first-poll offset on later polls, because gocron
// schedules every run from the one before, so the policy's polls stay spread.
func TestRunner_KeepsTheSpreadOnLaterPolls(t *testing.T) {
	rec := newPollRecorder()
	all := hosts(50)
	pol := hourlyPolicy(all...)
	interval := 2
	pol.Config.MetricsInterval = &interval
	pol.Config.SNMPTimeout = 1
	r, err := NewRunner(context.Background(), testLogger, "p1", pol, rec, nil)
	require.NoError(t, err)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool { return rec.count(all[0]) >= 2 && rec.count(all[49]) >= 2 }, 10*time.Second, 10*time.Millisecond)
	// 490ms apart on the first poll; a late run of the first target narrows the
	// gap, so the bound leaves room for one.
	assert.GreaterOrEqual(t, rec.nth(all[49], 1).Sub(rec.nth(all[0], 1)), 300*time.Millisecond)
}

// An edit reaches the backend as a remove followed by an apply. The devices the
// edit keeps must be polled again at once rather than one interval later, so
// their series miss no sample.
func TestStopThenStartPolicy_PollsKeptTargetsAtOnce(t *testing.T) {
	m := newTestManager()
	t.Cleanup(func() { _ = m.Stop() })
	rec := newPollRecorder()
	// Held by the test as well, so the edit's stop does not release it.
	m.collectorsByDir[""] = &cachedCollector{collector: rec, refs: 1}

	require.NoError(t, m.StartPolicy("p1", hourlyPolicy("192.0.2.1", "192.0.2.2")))
	require.Eventually(t, func() bool {
		return rec.count("192.0.2.1") == 1 && rec.count("192.0.2.2") == 1
	}, 5*time.Second, 10*time.Millisecond)

	require.NoError(t, m.StopPolicy("p1"))
	require.NoError(t, m.StartPolicy("p1", hourlyPolicy("192.0.2.1", "192.0.2.3")))
	require.Eventually(t, func() bool {
		return rec.count("192.0.2.1") == 2 && rec.count("192.0.2.3") == 1
	}, 5*time.Second, 10*time.Millisecond, "the kept and the added device must poll as soon as the edited policy starts")
	assert.Equal(t, 1, rec.count("192.0.2.2"), "the removed device must not be polled again")
}
