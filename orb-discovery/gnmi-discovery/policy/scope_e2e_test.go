package policy

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
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

// Pinning one device inside a subnet is the documented way to give it its own
// credentials, so it must not be reported as a duplicate — with rescan on, that
// warning would repeat on every tick for the life of the policy. Two genuinely
// overlapping ranges still warn.
func TestAPinnedHostInsideASubnetIsNotWarnedAbout(t *testing.T) {
	for name, hosts := range map[string][]string{
		"pin first":    {"10.0.0.5", "10.0.0.0/29"},
		"subnet first": {"10.0.0.0/29", "10.0.0.5"},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			r := runnerWithHosts(t, hosts, slog.New(slog.NewTextHandler(&logs, nil)))
			_, _, err := r.admitTargets()
			require.NoError(t, err)
			require.NotContains(t, logs.String(), "duplicate",
				"a pinned host inside its own subnet is a supported config")
		})
	}

	var logs bytes.Buffer
	r := runnerWithHosts(t, []string{"10.0.0.0/29", "10.0.0.0-7"}, slog.New(slog.NewTextHandler(&logs, nil)))
	_, _, err := r.admitTargets()
	require.NoError(t, err)
	require.Contains(t, logs.String(), "duplicate",
		"two overlapping ranges are a mistake worth reporting")
}

// The pinned entry's own settings survive the overlap, in either write order.
func TestAPinnedHostInsideASubnetKeepsItsOwnSettings(t *testing.T) {
	for name, targetList := range map[string][]config.Target{
		"pin first": {
			{Host: "10.0.0.5", Username: "legacy"},
			{Host: "10.0.0.0/29"},
		},
		"subnet first": {
			{Host: "10.0.0.0/29"},
			{Host: "10.0.0.5", Username: "legacy"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := runnerWithTargets(t, targetList, slog.New(slog.DiscardHandler))
			expanded, err := r.expandTargets()
			require.NoError(t, err)

			var found bool
			for _, c := range expanded {
				if c.target.Host == "10.0.0.5:9339" {
					found = true
					require.Equal(t, "legacy", c.target.Username)
					require.True(t, c.explicit, "the pin is explicit, so it is never probed")
				}
			}
			require.True(t, found)
		})
	}
}

func runnerWithHosts(t *testing.T, hosts []string, logger *slog.Logger) *Runner {
	t.Helper()
	list := make([]config.Target, 0, len(hosts))
	for _, h := range hosts {
		list = append(list, config.Target{Host: h})
	}
	return runnerWithTargets(t, list, logger)
}

func runnerWithTargets(t *testing.T, list []config.Target, logger *slog.Logger) *Runner {
	t.Helper()
	for i := range list {
		if !strings.ContainsAny(list[i].Host, "/-") {
			list[i].Host = ensurePort(list[i].Host, config.DefaultGNMIPort)
		}
	}
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	r, err := NewRunner(context.Background(), logger, "p1",
		config.Policy{
			Config: config.PolicyConfig{Mode: config.ModeAuto, DebounceMs: 10},
			Scope:  config.Scope{Targets: list},
		},
		&recordingClient{}, newPerHostDialer(nil), store)
	require.NoError(t, err)
	return r
}
