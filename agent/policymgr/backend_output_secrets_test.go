package policymgr_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// TestBackendOutputLeavesOutTheResolvedSecret has each backend's process
// print the credential a policy's secret reference resolved to, on stdout and
// on stderr, as a backend that prints its own errors can. The agent relays
// every line its backends print into its own log, and no record of it may
// carry the value (MON-857). A line names no policy, so it is masked with the
// values of every policy the backend runs. Each backend gets its own policy
// manager and its own value, so a line masked with another backend's values
// leaves its own in the log.
func TestBackendOutputLeavesOutTheResolvedSecret(t *testing.T) {
	for _, tc := range policyBackends {
		t.Run(tc.backend, func(t *testing.T) {
			logs := &renderedLogs{}
			logger := logs.logger()
			secret := "Pl41n-" + tc.backend + "-credential"
			mgr, err := policymgr.New(logger, startDoppler(t, logger, "SNMP_COMMUNITY", secret), config.Config{})
			require.NoError(t, err)
			stdout, stderr := startBackendPrinting(t, logger, mgr, tc.backend, tc.executable, tc.register)

			policyID := "policy-" + tc.backend
			mgr.ManagePolicy(config.PolicyPayload{
				Action:    "manage",
				ID:        policyID,
				DatasetID: "dataset-1",
				Name:      "secret_ref_policy",
				Backend:   tc.backend,
				Version:   1,
				Data: map[string]any{
					// pktvisor refuses a policy that names no tap; the others pass it on.
					"input": map[string]any{"tap": "default_pcap"},
					"scope": map[string]any{
						"authentication": map[string]any{"community": "${doppler://SNMP_COMMUNITY}"},
					},
				},
			})
			require.Equal(t, policies.Running, storedPolicyByID(t, mgr, policyID).State, "the policy is applied")
			from := logs.len()

			stdout <- "probe of 192.0.2.10 failed: bad community " + secret
			stderr <- `{"level":"error","message":"auth of 192.0.2.11 failed with community \"` + secret + `\""}`
			for _, said := range []string{"probe of 192.0.2.10 failed", "auth of 192.0.2.11 failed"} {
				require.Eventually(t, func() bool { return len(logs.linesWith(from, said)) > 0 }, 5*time.Second, 10*time.Millisecond,
					"the agent relays the line %q", said)
			}
			assert.Empty(t, logs.linesWith(from, secret), "no record of a relayed line carries the value")
			assert.NotEmpty(t, logs.linesWith(from, "bad community ********"), "the line is relayed with the value masked")
		})
	}
}
