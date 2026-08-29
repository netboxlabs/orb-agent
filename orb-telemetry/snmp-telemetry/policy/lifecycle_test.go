package policy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// spyCollector records the policy names it was told to forget.
type spyCollector struct {
	mu     sync.Mutex
	forgot []string
	dials  []collector.DialOptions
}

func (s *spyCollector) CollectTarget(_ context.Context, _ config.Target, _ *config.Authentication, _ string, dial collector.DialOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dials = append(s.dials, dial)
	return nil
}

func (s *spyCollector) ForgetPolicy(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgot = append(s.forgot, name)
}

func (s *spyCollector) forgotten() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forgot...)
}

func TestRunnerStop_ForgetsCollectorState(t *testing.T) {
	spy := &spyCollector{}
	r, err := NewRunner(context.Background(), testLogger, "p1", minimalPolicy(v2cAuth()), spy)
	require.NoError(t, err)
	require.NoError(t, r.Stop())
	assert.Equal(t, []string{"p1"}, spy.forgotten())
}

func TestStopPolicy_ForgetsCollectorState(t *testing.T) {
	spy := &spyCollector{}
	m := newTestManager()
	r, err := NewRunner(m.ctx, testLogger, "p1", minimalPolicy(v2cAuth()), spy)
	require.NoError(t, err)
	m.policies["p1"] = r

	require.NoError(t, m.StopPolicy("p1"))
	assert.Equal(t, []string{"p1"}, spy.forgotten())
	assert.False(t, m.HasPolicy("p1"))
}

func TestManagerStop_ForgetsEveryPolicy(t *testing.T) {
	spy := &spyCollector{}
	m := newTestManager()
	for _, name := range []string{"p1", "p2"} {
		r, err := NewRunner(m.ctx, testLogger, name, minimalPolicy(v2cAuth()), spy)
		require.NoError(t, err)
		m.policies[name] = r
	}

	require.NoError(t, m.Stop())
	assert.ElementsMatch(t, []string{"p1", "p2"}, spy.forgotten())
}

// ---------------------------------------------------------------------------
// Per-policy snmp_timeout and retries
// ---------------------------------------------------------------------------

func policyWithDial(intervalSec, timeoutSec, retries int) config.Policy {
	pol := minimalPolicy(v2cAuth())
	pol.Config.MetricsInterval = &intervalSec
	pol.Config.SNMPTimeout = timeoutSec
	pol.Config.Retries = retries
	return pol
}

func TestNewRunner_DerivesDialSettingsFromPolicy(t *testing.T) {
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(120, 12, 4), &spyCollector{})
	require.NoError(t, err)
	assert.Equal(t, 12*time.Second, r.snmpTimeout)
	assert.Equal(t, 4, r.retries)
}

func TestNewRunner_ZeroSNMPTimeoutFallsBackToDefault(t *testing.T) {
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 0, 0), &spyCollector{})
	require.NoError(t, err)
	assert.Equal(t, defaultSNMPTimeout, r.snmpTimeout)
	assert.Equal(t, 0, r.retries)
}

func TestNewRunner_RejectsTimeoutAtOrAboveInterval(t *testing.T) {
	// The run context is bounded by metrics_interval, so a dial allowed to take
	// the whole interval can never complete a collection.
	_, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 30, 0), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "snmp_timeout")

	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 45, 0), &spyCollector{})
	assert.Error(t, err)

	// The default applies before the comparison, so a short interval is caught
	// even when the policy never named a timeout.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(3, 0, 0), &spyCollector{})
	assert.Error(t, err)

	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 29, 0), &spyCollector{})
	assert.NoError(t, err)
}

func TestRunMetrics_PassesDialSettingsToCollector(t *testing.T) {
	spy := &spyCollector{}
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(120, 12, 4), spy)
	require.NoError(t, err)

	r.runMetrics(config.Target{Host: "192.168.1.1", Port: 161})
	require.Len(t, spy.dials, 1)
	assert.Equal(t, collector.DialOptions{Timeout: 12 * time.Second, Retries: 4}, spy.dials[0])
}

func TestValidate_RejectsNegativeDialSettings(t *testing.T) {
	m := newTestManager()
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, -1, 0)), "snmp_timeout")
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, 0, -1)), "retries")
}

// ---------------------------------------------------------------------------
// One policy targeting one endpoint more than once
// ---------------------------------------------------------------------------

// failingCollector fails collection for the targets whose NetBox ID is listed.
type failingCollector struct {
	failIDs map[string]bool
}

func (f *failingCollector) CollectTarget(_ context.Context, target config.Target, _ *config.Authentication, _ string, _ collector.DialOptions) error {
	if f.failIDs[target.ID] {
		return errors.New("unreachable")
	}
	return nil
}

func (f *failingCollector) ForgetPolicy(string) {}

// TestRunMetrics_SameEndpointTwiceKeepsErrorsApart covers a policy that names
// one host and port twice. Keying the error set by host and port alone let a
// healthy entry clear the failing one's error, so the policy reported itself
// healthy while half its targets were unreachable.
func TestRunMetrics_SameEndpointTwiceKeepsErrorsApart(t *testing.T) {
	c := &failingCollector{failIDs: map[string]bool{"11": true}}
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, 0), c)
	require.NoError(t, err)

	failing := config.Target{Host: "10.0.0.1", Port: 161, ID: "11"}
	healthy := config.Target{Host: "10.0.0.1", Port: 161, ID: "22"}

	r.runMetrics(failing)
	r.runMetrics(healthy)

	_, lastErr := r.GetLastError()
	require.Error(t, lastErr, "the healthy entry must not clear the failing one")
	assert.Contains(t, lastErr.Error(), "11")

	r.runMetrics(config.Target{Host: "10.0.0.1", Port: 161, ID: "11"})
	_, lastErr = r.GetLastError()
	assert.Error(t, lastErr, "the failing entry stays failing")
}

// TestRunMetrics_ContextNameDistinguishesErrorKeys covers two entries that share
// a host, port and NetBox ID and differ only by SNMPv3 context name.
func TestRunMetrics_ContextNameDistinguishesErrorKeys(t *testing.T) {
	target := config.Target{Host: "10.0.0.2", Port: 161, ID: "11"}
	a := &config.Authentication{ProtocolVersion: "SNMPv3", ContextName: "vlan-100"}
	b := &config.Authentication{ProtocolVersion: "SNMPv3", ContextName: "vlan-200"}

	assert.NotEqual(t, targetErrorKey(target, a), targetErrorKey(target, b))
	assert.Contains(t, targetErrorKey(target, a), "10.0.0.2:161")
}

// TestTargetErrorKey_PlainTargetIsHostAndPort keeps the common key readable: a
// target with no NetBox ID and no context name is still just host and port.
func TestTargetErrorKey_PlainTargetIsHostAndPort(t *testing.T) {
	target := config.Target{Host: "10.0.0.3", Port: 1161}
	assert.Equal(t, "10.0.0.3:1161", targetErrorKey(target, &config.Authentication{ProtocolVersion: "SNMPv2c"}))
	assert.Equal(t, "10.0.0.3:1161", targetErrorKey(target, nil))
}

// TestNewRunner_RejectsRetryInclusiveCeilingAtOrAboveInterval covers the ceiling
// a single request really has. A timed-out request is retried at the same
// timeout, so retries+1 attempts fit inside metrics_interval or the run has no
// room for the rest of the profile.
func TestNewRunner_RejectsRetryInclusiveCeilingAtOrAboveInterval(t *testing.T) {
	// Nine seconds, ten retries and a ten second interval: each attempt is
	// below the interval, the sequence is ten times past it.
	_, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(10, 9, 10), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "snmp_timeout")
	assert.ErrorContains(t, err, "retries")

	// Exactly at the interval is rejected, the same as a single attempt is.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 12, 4), &spyCollector{})
	assert.Error(t, err)

	// One retry short of the interval is accepted.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 12, 3), &spyCollector{})
	assert.NoError(t, err)

	// With no retries the message stays the single-attempt one.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 30, 0), &spyCollector{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "retries")

	// An outsized retries count is rejected rather than overflowing the
	// ceiling. This one is chosen so that attempts times five seconds wraps to
	// zero, which an unguarded multiply would read as comfortably inside the
	// interval.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, 1<<55-1), &spyCollector{})
	assert.Error(t, err)
}
