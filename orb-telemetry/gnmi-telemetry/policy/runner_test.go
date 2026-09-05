package policy

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
)

type spyCollector struct {
	mu      sync.Mutex
	started []collector.Options
	hosts   []string
	ports   []uint16
	forgot  []string
}

func (s *spyCollector) CollectTarget(_ context.Context, t config.Target, o collector.Options) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = append(s.started, o)
	s.hosts = append(s.hosts, t.Host)
	s.ports = append(s.ports, t.Port)
	return nil
}

func (s *spyCollector) ForgetPolicy(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgot = append(s.forgot, name)
}

func (s *spyCollector) TargetStatuses(string) []collector.TargetStatus { return nil }

// forgotten is what the lifecycle tests assert on.
func (s *spyCollector) forgotten() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forgot...)
}

// startedHosts is what the sweep tests assert on: bare hosts, in start order.
func (s *spyCollector) startedHosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hosts...)
}

func intp(i int) *int { return &i }

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRunnerStartsExplicitTargetsWithTheirModes(t *testing.T) {
	spy := &spyCollector{}
	policy := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: intp(30), Mode: "sample"},
		Scope:  config.Scope{Targets: []config.Target{{Host: "10.0.0.1", Port: 9339}, {Host: "10.0.0.2", Mode: "on_change"}}},
	}
	r, err := NewRunner(context.Background(), quietLogger(), "p", policy, spy, &gnmi.FakeDialer{})
	require.NoError(t, err)
	r.Start()
	require.NoError(t, r.Stop())
	spy.mu.Lock()
	defer spy.mu.Unlock()
	require.Len(t, spy.started, 2)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, spy.hosts)
	assert.Equal(t, []uint16{9339, config.DefaultGNMIPort}, spy.ports, "a target with no port dials the gNMI default")
	assert.Equal(t, 30*time.Second, spy.started[0].MetricsInterval)
	assert.Equal(t, "sample", spy.started[0].Mode, "the policy's mode")
	assert.Equal(t, "on_change", spy.started[1].Mode, "the target's mode wins")
	assert.Equal(t, "p", spy.started[0].PolicyName)
	assert.Equal(t, []string{"p"}, spy.forgot, "stop forgets the policy once")
}

func TestRunnerRejectsAMissingInterval(t *testing.T) {
	_, err := NewRunner(context.Background(), quietLogger(), "p", config.Policy{Scope: config.Scope{Targets: []config.Target{{Host: "h"}}}}, &spyCollector{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metrics_interval must be from 1")
}

func TestRunnerSweepsARangeBeforeSubscribing(t *testing.T) {
	spy := &spyCollector{}
	// The per-host dialer answers every probe with its own session, so every
	// address is admitted and concurrent probes share no fake; a /29 is six
	// hosts because the network and broadcast addresses are dropped.
	policy := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: intp(10)},
		Scope:  config.Scope{Targets: []config.Target{{Host: "10.0.0.0/29", Port: 9339}}},
	}
	r, err := NewRunner(context.Background(), quietLogger(), "p", policy, spy, newPerHostDialer(nil))
	require.NoError(t, err)
	r.Start()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		spy.mu.Lock()
		n := len(spy.started)
		spy.mu.Unlock()
		if n == 6 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NoError(t, r.Stop())
	spy.mu.Lock()
	defer spy.mu.Unlock()
	assert.Len(t, spy.started, 6)
	for _, h := range spy.hosts {
		assert.NotContains(t, h, ":", "an expanded host carries no port")
	}
}

func TestRunnerStopWaitsForTheSweep(t *testing.T) {
	spy := &spyCollector{}
	policy := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: intp(10)},
		Scope:  config.Scope{Targets: []config.Target{{Host: "10.0.0.0/24", Port: 9339}}},
	}
	// blockOn ignores ctx on purpose: it models a probe already past the point
	// of cancellation, so this measures whether Stop waits for the sweep
	// goroutine, not whether cancellation propagates.
	dialer := newPerHostDialer(nil)
	dialer.blockOn = make(chan struct{})
	r, err := NewRunner(context.Background(), quietLogger(), "p", policy, spy, dialer)
	require.NoError(t, err)
	r.Start()
	require.Eventually(t, func() bool { return len(dialer.dialedHosts()) > 0 }, 3*time.Second, 5*time.Millisecond)
	stopped := make(chan struct{})
	go func() {
		_ = r.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned while the sweep was still probing")
	case <-time.After(150 * time.Millisecond):
	}
	close(dialer.blockOn)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after the sweep was released")
	}
	spy.mu.Lock()
	defer spy.mu.Unlock()
	assert.Equal(t, []string{"p"}, spy.forgot, "the policy is forgotten after the sweep ended")
}
