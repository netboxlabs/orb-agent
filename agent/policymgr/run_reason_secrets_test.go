package policymgr_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// TestRunReasonLeavesOutTheResolvedSecret has a backend report a failed run
// that quotes the credential the policy's secret reference resolved to: in
// its reason, as a worker's run reports an exception's text, and as its
// target and driver, which a backend can copy from the policy's scope. The
// backend state manager polls the backend's status and stores the runs, and
// the heartbeat sends the stored runs to Fleet, so no stored run may carry
// the value, and the reason still says what failed and which field was
// quoted (MON-857).
func TestRunReasonLeavesOutTheResolvedSecret(t *testing.T) {
	logs := &renderedLogs{}
	logger := logs.logger()
	mgr, err := policymgr.New(logger, startDoppler(t, logger, "SNMP_COMMUNITY", resolvedSecret), config.Config{})
	require.NoError(t, err)

	const policyID, policyName = "policy-worker", "secret_ref_policy"
	reported := &reportedRun{}
	startBackendServing(t, logger, mgr, "worker", "orb-worker", worker.Register, reported.answer(policyName))
	poll := pollingStatus(t, logger, mgr, "worker")

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
	require.Equal(t, policies.Running, storedPolicyByID(t, mgr, policyID).State, "the policy is applied")

	failed := "SNMP authentication failed for community '" + resolvedSecret + "' on 192.0.2.10"
	reported.set(backend.PolicyStatusRun{ID: "run-1", Status: "failed", Reason: failed, Targets: []string{"192.0.2.10", resolvedSecret}, Driver: resolvedSecret})
	poll()
	run := storedRun(t, mgr, policyID, "run-1")
	assert.NotContains(t, run.Reason, resolvedSecret, "the reason, sent in every heartbeat, leaves out the value")
	assert.Contains(t, run.Reason, "SNMP authentication failed for community '********' on 192.0.2.10", "the reason still says what failed")
	assert.Contains(t, run.Reason, "the secret reference at scope.authentication.community", "the reason names the field")
	assert.Equal(t, []string{"192.0.2.10", "********"}, run.Targets, "a target that is the value is masked, the others kept")
	assert.Equal(t, "********", run.Driver)

	t.Run("a long reason is kept to the bound a refusal is kept to", func(t *testing.T) {
		reported.set(backend.PolicyStatusRun{ID: "run-1", Status: "failed", Reason: failed + "; " + strings.Repeat("x", 20000)})
		poll()
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
		require.Equal(t, policies.Running, storedPolicyByID(t, mgr, policyID).State, "version 2 is applied")

		reported.set(backend.PolicyStatusRun{ID: "run-1", Status: "failed", Reason: failed})
		poll()
		assert.NotContains(t, storedRun(t, mgr, policyID, "run-1").Reason, resolvedSecret)
	})

	assert.Empty(t, logs.linesWith(0, resolvedSecret), "no log record carries the value")
}

// reportedRun is the run a backend stand-in reports for a policy in its
// status.
type reportedRun struct {
	mu  sync.Mutex
	run backend.PolicyStatusRun
}

func (r *reportedRun) set(run backend.PolicyStatusRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.run = run
}

// answer answers a request for the backend's status with the run, reported
// for the named policy.
func (r *reportedRun) answer(policyName string) func(w http.ResponseWriter, req *http.Request, _ []byte) bool {
	return func(w http.ResponseWriter, req *http.Request, _ []byte) bool {
		if req.Method != http.MethodGet || req.URL.Path != "/api/v1/status" {
			return false
		}
		r.mu.Lock()
		run := r.run
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(backend.StatusResponse{
			Version:  "1.0.0",
			Policies: []backend.PolicyStatus{{Name: policyName, Status: "running", Runs: []backend.PolicyStatusRun{run}}},
		})
		return true
	}
}

// pollingStatus starts the backend state manager's monitor of the named
// backend, storing what it polls in the policy manager's repo, as the agent
// does, and returns what makes it poll once: it returns once the poll's runs
// are stored.
func pollingStatus(t *testing.T, logger *slog.Logger, mgr policymgr.PolicyManager, name string) func() {
	t.Helper()
	ticks := make(chan time.Time)
	t.Cleanup(func() { close(ticks) })
	states := backend.NewStateManager("fleet", logger, make(chan string, 1), mgr.GetRepo(),
		backend.WithTickSource(func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }))
	states.StartBackendMonitor(name, backend.GetBackend(name))
	return func() {
		// The monitor takes the second tick only once it has stored what the
		// first one polled.
		ticks <- time.Now()
		ticks <- time.Now()
	}
}

// storedPolicyByID returns the policy the manager stores under policyID.
func storedPolicyByID(t *testing.T, mgr policymgr.PolicyManager, policyID string) policies.PolicyData {
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
	for _, r := range storedPolicyByID(t, mgr, policyID).Runs {
		if r.ID == runID {
			return r
		}
	}
	require.FailNow(t, "the run is stored", runID)
	return policies.RunData{}
}
