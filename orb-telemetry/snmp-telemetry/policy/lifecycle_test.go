package policy

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// spyCollector records the policy names it was told to forget.
type spyCollector struct {
	mu     sync.Mutex
	forgot []string
}

func (s *spyCollector) CollectTarget(context.Context, config.Target, *config.Authentication, string) error {
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
