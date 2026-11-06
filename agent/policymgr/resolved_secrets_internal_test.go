package policymgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// TestRemovedPolicyForgetsItsResolvedValues removes a policy from the repo
// the policy manager hands out: the agent keeps no value the policy's secret
// references resolved to, and masks nothing with it in what the backend
// prints afterwards. Another policy's values are kept.
func TestRemovedPolicyForgetsItsResolvedValues(t *testing.T) {
	mem, err := policies.NewMemRepo()
	require.NoError(t, err)
	resolved := newResolvedSecrets()
	repo := &maskingRepo{PolicyRepo: mem, secrets: resolved}
	for _, id := range []string{"policy-1", "policy-2"} {
		require.NoError(t, repo.Update(policies.PolicyData{ID: id, Name: id, Backend: "worker"}))
	}
	resolved.remember("policy-1", "worker", []resolvedValue{{path: "scope.community", value: "c0mmun1ty-v4l"}})
	resolved.remember("policy-2", "worker", []resolvedValue{{path: "scope.password", value: "p4ssw0rd-v4l"}})

	require.NoError(t, repo.Remove("policy-1"))

	assert.Empty(t, resolved.of("policy-1"), "the removed policy's values are dropped")
	assert.Equal(t, "community c0mmun1ty-v4l, password ********",
		resolved.maskOutput("worker", "community c0mmun1ty-v4l, password p4ssw0rd-v4l"))
}
