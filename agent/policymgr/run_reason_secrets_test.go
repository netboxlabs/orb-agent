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

// TestNoStoredRunCarriesAnEarlierHost points a policy's host at a secret
// three times, as rotating the secret does, while the backend goes on
// reporting the runs it ran with each host, as device-discovery keeps a
// target's runs across the policy's re-applies. The heartbeat sends the
// stored runs, so none may carry a host: the run of the first, started before
// the backend took the policy's previous resolution, is not stored, since the
// agent no longer keeps that host (MON-900), and the others are stored
// masked. The last host ends in a new line, which device-discovery leaves out
// of the target it reports (MON-901).
func TestNoStoredRunCarriesAnEarlierHost(t *testing.T) {
	logs := &renderedLogs{}
	logger := logs.logger()
	hosts := map[string]string{
		"HOST_A": "4a1c-host-a.invalid",
		"HOST_B": "4a1c-host-b.invalid",
		"HOST_C": "4a1c-host-c.invalid\n",
	}
	mgr, err := policymgr.New(logger, startDopplerSecrets(t, logger, hosts), config.Config{})
	require.NoError(t, err)

	const policyID, policyName = "policy-worker", "rotated_host_policy"
	reported := &reportedRun{}
	startBackendServing(t, logger, mgr, "worker", "orb-worker", worker.Register, reported.answer(policyName))
	poll := pollingStatus(t, logger, mgr, "worker")

	var runs []backend.PolicyStatusRun
	for i, name := range []string{"HOST_A", "HOST_B", "HOST_C"} {
		mgr.ManagePolicy(config.PolicyPayload{
			Action:    "manage",
			ID:        policyID,
			DatasetID: "dataset-1",
			Name:      policyName,
			Backend:   "worker",
			Version:   int32(i + 1),
			Data:      map[string]any{"scope": []any{map[string]any{"hostname": "${doppler://" + name + "}"}}},
		})
		require.Equal(t, policies.Running, storedPolicyByID(t, mgr, policyID).State, "the policy is applied with %s", name)

		host := strings.TrimSuffix(hosts[name], "\n")
		runs = append(runs, backend.PolicyStatusRun{
			ID: "run-" + name, Status: "failed", Reason: "Cannot connect to " + host, Targets: []string{host},
			CreatedAt: time.Now().UnixNano(),
		})
		reported.set(runs...)
		poll()
	}

	var ids []string
	for _, run := range storedPolicyByID(t, mgr, policyID).Runs {
		ids = append(ids, run.ID)
		assert.Equal(t, []string{"********"}, run.Targets, "the target of %s", run.ID)
		for _, host := range hosts {
			assert.NotContains(t, run.Reason, strings.TrimSuffix(host, "\n"), "the reason of %s", run.ID)
		}
	}
	assert.ElementsMatch(t, []string{"run-HOST_B", "run-HOST_C"}, ids)
	for name, host := range hosts {
		assert.Empty(t, logs.linesWith(0, strings.TrimSuffix(host, "\n")), "no log record carries %s", name)
	}
}

// reportedRun is the runs a backend stand-in reports for a policy in its
// status.
type reportedRun struct {
	mu   sync.Mutex
	runs []backend.PolicyStatusRun
}

func (r *reportedRun) set(runs ...backend.PolicyStatusRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = runs
}

// answer answers a request for the backend's status with the runs, reported
// for the named policy.
func (r *reportedRun) answer(policyName string) func(w http.ResponseWriter, req *http.Request, _ []byte) bool {
	return func(w http.ResponseWriter, req *http.Request, _ []byte) bool {
		if req.Method != http.MethodGet || req.URL.Path != "/api/v1/status" {
			return false
		}
		r.mu.Lock()
		runs := r.runs
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(backend.StatusResponse{
			Version:  "1.0.0",
			Policies: []backend.PolicyStatus{{Name: policyName, Status: "running", Runs: runs}},
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
