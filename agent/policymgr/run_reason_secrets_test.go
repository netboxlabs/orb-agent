package policymgr_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// TestRunReasonLeavesOutTheResolvedSecret has a backend report a failed run
// whose reason quotes the credential the policy's secret reference resolved
// to, as a worker's run reports an exception's text. The backend state
// manager stores what a backend reports through the repo's UpdateRuns, its
// only caller, and the heartbeat sends the stored runs to Fleet, so the
// stored reason may not carry the value, and still says what failed and
// which field was quoted (MON-857).
func TestRunReasonLeavesOutTheResolvedSecret(t *testing.T) {
	logs := &renderedLogs{}
	logger := logs.logger()
	mgr, err := policymgr.New(logger, startDoppler(t, logger, "SNMP_COMMUNITY", resolvedSecret), config.Config{})
	require.NoError(t, err)
	startBackend(t, logger, mgr, "worker", "orb-worker", worker.Register)

	const policyID, policyName = "policy-worker", "secret_ref_policy"
	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        policyID,
		DatasetID: "dataset-1",
		Name:      policyName,
		Backend:   "worker",
		Version:   1,
		Data: map[string]any{
			"scope": map[string]any{
				"authentication": map[string]any{"community": "${doppler://SNMP_COMMUNITY}"},
			},
		},
	}
	mgr.ManagePolicy(payload)
	require.Equal(t, policies.Running, storedPolicy(t, mgr, policyID).State, "the policy is applied")

	failed := "SNMP authentication failed for community '" + resolvedSecret + "' on 192.0.2.10"
	require.NoError(t, mgr.GetRepo().UpdateRuns(policyName, []policies.RunData{{ID: "run-1", Status: "failed", Reason: failed}}))
	reason := storedRun(t, mgr, policyID, "run-1").Reason
	assert.NotContains(t, reason, resolvedSecret, "the reason, sent in every heartbeat, leaves out the value")
	assert.Contains(t, reason, "SNMP authentication failed for community '********' on 192.0.2.10", "the reason still says what failed")
	assert.Contains(t, reason, "the secret reference at scope.authentication.community", "the reason names the field")

	t.Run("a long reason is kept to the bound a refusal is kept to", func(t *testing.T) {
		long := failed + "; " + strings.Repeat("x", 20000)
		require.NoError(t, mgr.GetRepo().UpdateRuns(policyName, []policies.RunData{{ID: "run-1", Status: "failed", Reason: long}}))
		reason := storedRun(t, mgr, policyID, "run-1").Reason
		assert.NotContains(t, reason, resolvedSecret)
		assert.Contains(t, reason, "... (truncated)")
		assert.Less(t, len(reason), 1024+200, "1 KiB of the reason, the marker and the note")
	})

	t.Run("a value the policy no longer references stays masked", func(t *testing.T) {
		// The backend keeps reporting a run it ran with the earlier value
		// after the policy changed.
		payload.Version = 2
		payload.Data = map[string]any{
			"scope": map[string]any{"authentication": map[string]any{"community": "plain-community"}},
		}
		mgr.ManagePolicy(payload)
		require.Equal(t, policies.Running, storedPolicy(t, mgr, policyID).State, "version 2 is applied")

		require.NoError(t, mgr.GetRepo().UpdateRuns(policyName, []policies.RunData{{ID: "run-1", Status: "failed", Reason: failed}}))
		assert.NotContains(t, storedRun(t, mgr, policyID, "run-1").Reason, resolvedSecret)
	})

	assert.Empty(t, logs.linesWith(0, resolvedSecret), "no log record carries the value")
}

// storedPolicy returns the policy the manager stores under policyID.
func storedPolicy(t *testing.T, mgr policymgr.PolicyManager, policyID string) policies.PolicyData {
	t.Helper()
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	for _, p := range state {
		if p.ID == policyID {
			return p
		}
	}
	require.FailNow(t, "the policy is stored", policyID)
	return policies.PolicyData{}
}

// storedRun returns the run runID of the policy stored under policyID.
func storedRun(t *testing.T, mgr policymgr.PolicyManager, policyID, runID string) policies.RunData {
	t.Helper()
	for _, r := range storedPolicy(t, mgr, policyID).Runs {
		if r.ID == runID {
			return r
		}
	}
	require.FailNow(t, "the run is stored", runID)
	return policies.RunData{}
}
