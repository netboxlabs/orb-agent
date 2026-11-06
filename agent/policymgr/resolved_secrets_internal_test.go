package policymgr

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// TestRemovedPolicyKeepsItsResolvedValuesForAMinute removes a policy from the
// repo the policy manager hands out. What the backend printed about the
// policy before it was removed can still be waiting to be relayed, so its
// values mask the backend's output for a minute more; after that, the agent
// keeps none of them. Another policy's values are kept.
func TestRemovedPolicyKeepsItsResolvedValuesForAMinute(t *testing.T) {
	mem, err := policies.NewMemRepo()
	require.NoError(t, err)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	resolved := newResolvedSecrets()
	resolved.now = func() time.Time { return now }
	repo := &maskingRepo{PolicyRepo: mem, secrets: resolved}
	for _, id := range []string{"policy-1", "policy-2"} {
		require.NoError(t, repo.Update(policies.PolicyData{ID: id, Name: id, Backend: "worker"}))
	}
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.community", value: "c0mmun1ty-v4l"}})
	resolved.remember("policy-2", "worker", []resolvedValue{{path: "scope.password", value: "p4ssw0rd-v4l"}})
	const printed = "community c0mmun1ty-v4l, password p4ssw0rd-v4l"

	require.NoError(t, repo.Remove("policy-1"))
	now = now.Add(time.Minute)
	assert.Equal(t, "community ********, password ********", resolved.maskOutput("worker", printed),
		"a line relayed within a minute of the removal")

	now = now.Add(time.Second)
	assert.Equal(t, "community c0mmun1ty-v4l, password ********", resolved.maskOutput("worker", printed),
		"a line relayed later")
	assert.Empty(t, resolved.of("policy-1"), "the removed policy's values are dropped")
}

// TestPolicyKeepsTheValuesOfItsLastTwoResolutions resolves a policy's
// secret reference to a new value again and again, as a secret that rotates
// on every poll is. The agent keeps the values of the last two resolutions
// that differ, for a run reported before the last one, and no more: each
// value it keeps is one more it holds in memory and masks every relayed line
// with. A resolution to the same values, as a restart's replay makes, is not
// a new one.
func TestPolicyKeepsTheValuesOfItsLastTwoResolutions(t *testing.T) {
	resolved := newResolvedSecrets()
	rotation := func(n int) []resolvedValue {
		return []resolvedValue{{path: "scope.community", value: fmt.Sprintf("r0tat3d-v4lue-%03d", n)}}
	}
	for n := range 100 {
		resolved.remember("policy-1", "worker", rotation(n))
	}
	resolved.remember("policy-1", "worker", rotation(99))

	assert.ElementsMatch(t, append(rotation(98), rotation(99)...), resolved.of("policy-1"))
}
