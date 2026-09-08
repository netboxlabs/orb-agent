package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunnerStop_ForgetsCollectorState(t *testing.T) {
	spy := &spyCollector{}
	r, err := NewRunner(t.Context(), testLogger, "p1", minimalPolicy(), spy, nil)
	require.NoError(t, err)
	require.NoError(t, r.Stop())
	assert.Equal(t, []string{"p1"}, spy.forgotten())
}

func TestStopPolicy_ForgetsCollectorState(t *testing.T) {
	spy := &spyCollector{}
	m := newTestManager()
	r, err := NewRunner(m.ctx, testLogger, "p1", minimalPolicy(), spy, nil)
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
		r, err := NewRunner(m.ctx, testLogger, name, minimalPolicy(), spy, nil)
		require.NoError(t, err)
		m.policies[name] = r
	}

	require.NoError(t, m.Stop())
	assert.ElementsMatch(t, []string{"p1", "p2"}, spy.forgotten())
}
