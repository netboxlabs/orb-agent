package policy

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// A rescan exists to pick up a device that was down when the policy was applied.
// Nothing else re-applies a policy: the config manager returns early on an
// unchanged git ref, and on a new commit whose diff touches no policy file.
func TestRescanPicksUpADeviceThatWasDownAtApplyTime(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.2:9339": dialingErr()})
	r := newRescanRunner(t, "10.0.0.0/30", dialer, 60*time.Millisecond)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(r.TargetStatuses()) == 1
	}, 3*time.Second, 10*time.Millisecond, "only .1 answers the first sweep")

	// The device finishes booting.
	dialer.mu.Lock()
	delete(dialer.capsErr, "10.0.0.2:9339")
	dialer.mu.Unlock()

	require.Eventually(t, func() bool {
		return len(r.TargetStatuses()) == 2
	}, 3*time.Second, 10*time.Millisecond, "the rescan admits the newcomer")
}

// The one thing a rescan must not do is disturb a working subscription. A device
// admitted by an earlier sweep must never be probed again: filtering after the
// probe rather than before would re-probe every live device, every tick, forever.
func TestRescanNeverReprobesASubscribedTarget(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.2:9339": dialingErr()})
	r := newRescanRunner(t, "10.0.0.0/30", dialer, 40*time.Millisecond)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(r.TargetStatuses()) == 1
	}, 3*time.Second, 10*time.Millisecond)

	// Let several ticks pass, then count how often the rejected address was
	// re-probed versus the admitted one.
	require.Eventually(t, func() bool {
		return countHost(dialer.dialedHosts(), "10.0.0.2:9339") >= 3
	}, 3*time.Second, 10*time.Millisecond, "the rejected address is re-probed each tick")

	// The admitted host is dialed exactly twice for the life of the policy: once
	// by the sweep that admitted it, once by the loop that subscribed. A third
	// dial would mean a rescan tick probed a live subscription.
	require.Equal(t, 2, countHost(dialer.dialedHosts(), "10.0.0.1:9339"),
		"a subscribed target is never re-probed")
	require.Equal(t, 1, dialer.closeCount("10.0.0.1:9339"),
		"only the admitting probe closed a session; the subscription stays open")
}

// Rescan is off by default, and the sweep goroutine must then actually exit
// rather than sit on a ticker for the life of the policy.
func TestRescanIsDisabledByDefault(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.2:9339": dialingErr()})
	r := newRescanRunner(t, "10.0.0.0/30", dialer, 0)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return countHost(dialer.dialedHosts(), "10.0.0.2:9339") == 1
	}, 3*time.Second, 10*time.Millisecond)

	time.Sleep(150 * time.Millisecond)
	require.Equal(t, 1, countHost(dialer.dialedHosts(), "10.0.0.2:9339"),
		"with rescan off the address is probed exactly once")
}

// A rescan tick must not outlive Stop. The sweep goroutine holds one WaitGroup
// count for its whole life, ticker included.
func TestStopEndsTheRescanLoop(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.2:9339": dialingErr()})
	r := newRescanRunner(t, "10.0.0.0/30", dialer, 30*time.Millisecond)
	r.Start()

	require.Eventually(t, func() bool {
		return countHost(dialer.dialedHosts(), "10.0.0.2:9339") >= 2
	}, 3*time.Second, 5*time.Millisecond)

	done := make(chan struct{})
	go func() { _ = r.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return: the rescan ticker outlived the runner")
	}

	before := len(dialer.dialedHosts())
	time.Sleep(120 * time.Millisecond)
	require.Equal(t, before, len(dialer.dialedHosts()), "no probe after Stop returned")
}

func countHost(hosts []string, want string) int {
	n := 0
	for _, h := range hosts {
		if h == want {
			n++
		}
	}
	return n
}

func newRescanRunner(t *testing.T, host string, dialer gnmi.Dialer, rescan time.Duration) *Runner {
	t.Helper()
	policy := config.Policy{
		Config: config.PolicyConfig{
			Mode:             config.ModeAuto,
			DebounceMs:       10,
			RescanIntervalMs: int(rescan / time.Millisecond),
		},
		Scope: config.Scope{Targets: []config.Target{{Host: host}}},
	}
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	r, err := NewRunner(context.Background(), slog.New(slog.DiscardHandler),
		"p1", policy, &recordingClient{}, dialer, store)
	require.NoError(t, err)
	r.backoffBase = time.Millisecond
	return r
}

// A too-frequent rescan is a continuous port scan of the operator's own campus,
// so a value under the floor is rejected rather than clamped: someone who wrote
// 5000 meant seconds and needs to learn the field is milliseconds, not to be
// silently handed a minute.
func TestRescanIntervalBelowTheFloorIsRejected(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      rescan_interval_ms: 5000
    scope:
      targets:
        - host: 10.0.0.1
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "rescan_interval_ms")

	_, err = m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      rescan_interval_ms: 0
    scope:
      targets:
        - host: 10.0.0.1
`))
	require.NoError(t, err, "0 means disabled, not too small")
}
