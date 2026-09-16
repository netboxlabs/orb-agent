package policy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// asAgentWouldSend reproduces the transformation a fleet-delivered policy goes
// through: it arrives as JSON, so every number is a float64, and the agent then
// yaml.Marshals it into the {policies: {name: ...}} envelope it POSTs here.
//
// See agent/backend/gnmidiscovery, ApplyPolicy.
func asAgentWouldSend(t *testing.T, name, policyJSON string) []byte {
	t.Helper()
	var data any
	require.NoError(t, json.Unmarshal([]byte(policyJSON), &data))
	out, err := yaml.Marshal(map[string]any{"policies": map[string]any{name: data}})
	require.NoError(t, err)
	return out
}

// The knobs added for subnet scope are bare integer milliseconds rather than
// duration strings, and the stated reason was this path: a JSON number becomes a
// float64 and re-marshals in scientific notation. That rationale was never
// actually exercised — the other tests here all write YAML directly, which is the
// local path, not the fleet one.
//
// It holds: yaml.v3 decodes an integral float into an int field, so 3.6e+06
// arrives as 3600000. This test exists to keep it holding, because the failure
// would only appear for fleet-delivered policies and would look like the backend
// ignoring a value the operator set.
func TestFleetDeliveredIntervalsSurviveTheFloatRoundTrip(t *testing.T) {
	for _, ms := range []int{60000, 60001, 100000, 1234567, 3600000, 86400000, 999999999} {
		t.Run(fmt.Sprint(ms), func(t *testing.T) {
			body := asAgentWouldSend(t, "campus", fmt.Sprintf(`{
			  "config": {"rescan_interval_ms": %d, "probe_timeout_ms": 3000, "debounce_ms": 2000},
			  "scope": {"port": 6030, "targets": [{"host": "10.0.0.1"}]}
			}`, ms))

			m := newTestManager(t)
			policies, err := m.ParsePolicies(body)
			require.NoError(t, err)

			c := policies["campus"].Config
			require.Equal(t, ms, c.RescanIntervalMs, "the interval must survive as written")
			require.Equal(t, 3000, c.ProbeTimeoutMs)
			require.Equal(t, 2000, c.DebounceMs)
			require.Equal(t, uint16(6030), policies["campus"].Scope.Port)
		})
	}
}

// The boolean opt-in travels the same path, and a safety switch that silently
// failed to arrive would be the worst thing on it to lose.
func TestTheCredentialOptInSurvivesTheFleetPath(t *testing.T) {
	body := asAgentWouldSend(t, "campus", `{
	  "config": {"send_credentials_to_unverified_targets": true},
	  "scope": {
	    "username": "admin", "password": "campus-secret",
	    "tls": {"skip_verify": true},
	    "targets": [{"host": "10.0.0.0/24"}]
	  }
	}`)

	m := newTestManager(t)
	policies, err := m.ParsePolicies(body)
	require.NoError(t, err, "the opt-in has to arrive, or this policy is refused")
	require.True(t, policies["campus"].Config.SendCredentialsToUnverifiedTargets)
}

// And without it, the same fleet-delivered policy is refused — the gate is not
// bypassed by the delivery path.
func TestTheCredentialGateAppliesToFleetDeliveredPolicies(t *testing.T) {
	body := asAgentWouldSend(t, "campus", `{
	  "config": {},
	  "scope": {
	    "username": "admin", "password": "campus-secret",
	    "tls": {"skip_verify": true},
	    "targets": [{"host": "10.0.0.0/24"}]
	  }
	}`)

	m := newTestManager(t)
	_, err := m.ParsePolicies(body)
	require.Error(t, err)
	require.Contains(t, err.Error(), "send_credentials_to_unverified_targets")
}

// Validation applies on this path too: a sub-floor rescan is still rejected, and
// is small enough not to be re-marshalled in scientific notation, so it exercises
// the plain-integer case as well.
func TestFleetDeliveredValidationStillApplies(t *testing.T) {
	body := asAgentWouldSend(t, "campus", `{
	  "config": {"rescan_interval_ms": 5000},
	  "scope": {"targets": [{"host": "10.0.0.1"}]}
	}`)

	m := newTestManager(t)
	_, err := m.ParsePolicies(body)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rescan_interval_ms")
}
