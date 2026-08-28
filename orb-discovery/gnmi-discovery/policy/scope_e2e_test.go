package policy

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// The whole feature, end to end: a policy whose scope carries credentials and a
// CIDR, through parsing and inheritance and expansion and the probe, to the
// subscriptions that come out the far side.
func TestASubnetPolicyProbesWithoutCredentialsAndSubscribesWithThem(t *testing.T) {
	t.Setenv("GNMI_PASS", "campus-secret")

	m := newTestManager(t)
	policies, err := m.ParsePolicies([]byte(`
policies:
  campus:
    config:
      mode: on_change
    scope:
      username: admin
      password: ${GNMI_PASS}
      port: 6030
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/30
`))
	require.NoError(t, err)

	dialer := newPerHostDialer(map[string]error{"10.0.0.2:6030": dialingErr()})
	r := newRunnerFor(t, policies["campus"], dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(r.TargetStatuses()) == 1
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, "10.0.0.1:6030", r.TargetStatuses()[0].Host,
		"the scope port reached an address the operator never wrote")

	// The probe must be anonymous. gnmic attaches credentials as gRPC metadata on
	// every RPC including Capabilities, so a credentialed sweep would offer the
	// campus password to all 254 addresses in a /24 — and with skip_verify, to
	// anything at all that answers.
	rejected := dialer.specsFor("10.0.0.2:6030")
	require.NotEmpty(t, rejected)
	for _, spec := range rejected {
		require.Empty(t, spec.Username, "a probe must not carry a username")
		require.Empty(t, spec.Password, "a probe must not carry a password")
	}

	// The subscription that follows does carry them, inherited from the scope.
	var subscribed *gnmi.TargetSpec
	for _, spec := range dialer.specsFor("10.0.0.1:6030") {
		if spec.Password != "" {
			s := spec
			subscribed = &s
		}
	}
	require.NotNil(t, subscribed, "the admitted target subscribes with credentials")
	require.Equal(t, "admin", subscribed.Username)
	require.Equal(t, "campus-secret", subscribed.Password,
		"the scope secret was resolved from the environment, not passed through literally")
	require.True(t, subscribed.SkipVerify, "the scope TLS block was inherited")

	// The probe still carries the TLS settings: without them it cannot complete a
	// handshake against a device that requires one.
	require.True(t, rejected[0].SkipVerify, "a probe uses the resolved TLS block")
}

func newRunnerFor(t *testing.T, policy config.Policy, dialer gnmi.Dialer) *Runner {
	t.Helper()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	r, err := NewRunner(context.Background(), slog.New(slog.DiscardHandler),
		"campus", policy, &recordingClient{}, dialer, store)
	require.NoError(t, err)
	r.backoffBase = time.Millisecond
	return r
}
