package policy

import (
	"context"
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
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 12, 4), &spyCollector{})
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
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 12, 4), spy)
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
