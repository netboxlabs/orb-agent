package policymgr_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// TestFailedApplyErrorLeavesOutTheResolvedSecret applies, to every backend the
// agent sends a policy's body to, a policy that puts a secret reference in a
// field the backend reads as an int. The backend refuses it with yaml.v3's
// type error, which quotes the value: whole up to 10 characters, its first 7
// beyond. Neither the log, at any level, nor the policy's stored reason, which
// the heartbeat sends to Fleet, may carry the part quoted, and the reason
// still says what is wrong (MON-825). It is checked on the first apply and on
// the replay after a backend restart, which re-applies the stored policy as a
// secrets refresh does.
func TestFailedApplyErrorLeavesOutTheResolvedSecret(t *testing.T) {
	for _, secret := range []struct {
		name, value string
		quoted      string // what the type error quotes, derived by hand
	}{
		{"value quoted whole", "k3Y-9xQz", "k3Y-9xQz"},
		{"value quoted truncated", resolvedSecret, "Pl41n-r"},
	} {
		t.Run(secret.name, func(t *testing.T) {
			logs := &renderedLogs{}
			logger := logs.logger()
			mgr, err := policymgr.New(logger, startDoppler(t, logger, "SNMP_RETRIES", secret.value), config.Config{})
			require.NoError(t, err)

			for _, tc := range policyBackends {
				t.Run(tc.backend, func(t *testing.T) {
					refusal := &typeErrorRefusal{}
					startBackendAnswering(t, logger, mgr, tc.backend, tc.executable, tc.register, refusal.answer)
					from := logs.len()

					policyID := "policy-" + tc.backend
					mgr.ManagePolicy(config.PolicyPayload{
						Action:    "manage",
						ID:        policyID,
						DatasetID: "dataset-1",
						Name:      "mistyped_secret_policy",
						Backend:   tc.backend,
						Version:   1,
						Data: map[string]any{
							// pktvisor refuses a policy that names no tap; the others pass it on.
							"input":  map[string]any{"tap": "default_pcap"},
							"config": map[string]any{"retries": "${doppler://SNMP_RETRIES}"},
						},
					})
					require.Contains(t, refusal.sent(), secret.quoted, "the backend's error quotes the value, so there was something to leak")
					assertReasonLeavesOutSecret(t, mgr, policyID, secret.quoted)
					assert.Empty(t, logs.linesWith(from, secret.quoted), "no log record carries the quoted value")

					be := backend.GetBackend(tc.backend)
					require.NoError(t, mgr.RemoveBackendPolicies(tc.backend, be, false))
					from = logs.len()
					require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), tc.backend, be))
					assertReasonLeavesOutSecret(t, mgr, policyID, secret.quoted)
					assert.Empty(t, logs.linesWith(from, secret.quoted), "no log record of the replay carries the quoted value")
				})
			}
		})
	}
}

// assertReasonLeavesOutSecret checks the stored policy failed with a reason
// that names the type error and leaves out quoted.
func assertReasonLeavesOutSecret(t *testing.T, mgr policymgr.PolicyManager, policyID, quoted string) {
	t.Helper()
	state, err := mgr.GetPolicyState()
	require.NoError(t, err)
	var stored *policies.PolicyData
	for i := range state {
		if state[i].ID == policyID {
			stored = &state[i]
		}
	}
	require.NotNil(t, stored, "the policy is stored")
	require.Equal(t, policies.FailedToApply, stored.State, "the backend refused the policy: %s", stored.BackendErr)
	assert.Contains(t, stored.BackendErr, "cannot unmarshal", "the reason still names the type error")
	assert.Contains(t, stored.BackendErr, "into int", "the reason still names the type wanted")
	assert.NotContains(t, stored.BackendErr, quoted, "the reason, sent in every heartbeat, leaves out the value")
}

// typeErrorRefusal answers a posted policy as a backend does whose policy type
// reads retries as an int: it decodes the field with yaml.v3, as the Go
// backends do, and answers 400 with the decode error under each key a backend
// client reads the message from.
type typeErrorRefusal struct {
	mu      sync.Mutex
	message string
}

func (r *typeErrorRefusal) answer(w http.ResponseWriter, body []byte) bool {
	message, status := "the posted policy has no retries field", http.StatusInternalServerError
	var doc yaml.Node
	if yaml.Unmarshal(body, &doc) == nil {
		if value := mappingValue(&doc, "retries"); value != nil {
			var retries int
			if err := value.Decode(&retries); err != nil {
				message, status = err.Error(), http.StatusBadRequest
			}
		}
	}
	r.mu.Lock()
	r.message = message
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"detail": message, "message": message, "error": message})
	return true
}

// sent returns the last message the refusal answered with.
func (r *typeErrorRefusal) sent() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.message
}

// mappingValue returns the value under the first mapping key named key in
// n, depth first, or nil.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
	}
	for _, child := range n.Content {
		if value := mappingValue(child, key); value != nil {
			return value
		}
	}
	return nil
}
