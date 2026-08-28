package policy

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// The anonymous probe only postpones the credential by one RPC: admission is
// deliberately broad, and the subscription that follows sends this policy's
// password to whatever was admitted. Without TLS authenticating the far end,
// that means any service listening on the gNMI port inside the range.
//
// Refused by default because it is reachable by accident — a range that overlaps
// a server VLAN is a typo, not an attack.
func TestACredentialedRangeWithoutServerAuthIsRefused(t *testing.T) {
	for name, tlsBlock := range map[string]string{
		"skip_verify": "        skip_verify: true\n",
		// Worse than skip_verify: plaintext, so the password is also sniffable.
		"insecure": "        insecure: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t)
			_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      username: admin
      password: campus-secret
      tls:
` + tlsBlock + `      targets:
        - host: 10.0.0.0/24
`))
			require.Error(t, err)
			require.Contains(t, err.Error(), "10.0.0.0/24")
			require.Contains(t, err.Error(), "send_credentials_to_unverified_targets",
				"the error has to name the way out")
		})
	}
}

// Ranges are what changes the exposure: an attacker needs only to listen on a
// free address, rather than intercept a connection to a host the operator named.
// So naming the host explicitly is unaffected — the operator said where the
// credential may go.
func TestACredentialedExplicitHostIsUnaffected(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      username: admin
      password: campus-secret
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.11:6030
        - host: switch-a.example.com
        - host: fe80::1%br-lan
`))
	require.NoError(t, err, "an explicitly named host is the operator's own decision")
}

// Verified TLS authenticates the far end, so the credential only reaches
// endpoints the operator's CA vouches for. That is the supported way to do
// credentialed range discovery.
func TestACredentialedRangeWithVerifiedTLSIsAllowed(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      username: admin
      password: campus-secret
      tls:
        ca: /run/secrets/ca.pem
      targets:
        - host: 10.0.0.0/24
`))
	require.NoError(t, err)

	// The default is verified TLS with the system roots, which is also fine.
	_, err = m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      username: admin
      password: campus-secret
      targets:
        - host: 10.0.0.0/24
`))
	require.NoError(t, err, "no tls block means verified TLS with the system roots")
}

// The gate is on the password, not on any credential. A client certificate is
// not a bearer secret — TLS binds possession to the session, so an endpoint that
// receives one cannot replay it or relay it to a real device. Gating it would
// break mTLS range discovery, which is the strongest configuration available.
func TestMTLSWithoutAPasswordIsAllowedOverARange(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      tls:
        skip_verify: true
        cert: /run/secrets/client.pem
        key: /run/secrets/client.key
      targets:
        - host: 10.0.0.0/24
`))
	require.NoError(t, err, "no password means no bearer secret to disclose")
}

// A username is not a secret — it is usually "admin" — and gating on it would
// refuse mTLS plus a username over a range, which discloses nothing reusable.
func TestAUsernameWithoutAPasswordIsAllowedOverARange(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      username: admin
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/24
`))
	require.NoError(t, err)
}

// An explicitly emptied password blocks inheritance, so it must also clear the
// gate: that target sends no secret.
func TestAnEmptiedPasswordClearsTheGate(t *testing.T) {
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    scope:
      username: admin
      password: campus-secret
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/24
          password: ""
`))
	require.NoError(t, err, "the range inherits no password, so nothing is disclosed")
}

// The opt-in permits it, and says so out loud every time the policy is applied.
func TestTheOptInPermitsItAndWarns(t *testing.T) {
	var logs bytes.Buffer
	m := newManagerWithLogger(t, slog.New(slog.NewTextHandler(&logs, nil)))
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      send_credentials_to_unverified_targets: true
    scope:
      username: admin
      password: campus-secret
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/24
`))
	require.NoError(t, err)
	require.Contains(t, logs.String(), "not authenticated",
		"opting in does not make it quiet")
	require.Contains(t, logs.String(), "range_targets=1")
}

// And it stays visible after the day it was set: the sweep run carries it, so it
// shows in Fleet rather than only in a container log nobody re-reads.
func TestTheSweepRunReportsTheUnverifiedCredentialOptIn(t *testing.T) {
	m := newTestManager(t)
	policies, err := m.ParsePolicies([]byte(`
policies:
  campus:
    config:
      send_credentials_to_unverified_targets: true
    scope:
      username: admin
      password: campus-secret
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/30
`))
	require.NoError(t, err)

	dialer := newPerHostDialer(nil)
	dialer.defaultCapsErr = dialingErr()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	r, err := NewRunner(t.Context(), slog.New(slog.DiscardHandler), "campus",
		policies["campus"], &recordingClient{}, dialer, store)
	require.NoError(t, err)
	r.backoffBase = time.Millisecond
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	run := sweepRunFor(t, r)
	require.Contains(t, run.Reason, "not authenticated")
	require.Contains(t, run.Reason, "1 range target(s)")
}

// A policy on the supported path says nothing about it.
func TestASweepRunIsSilentWhenTheServerIsVerified(t *testing.T) {
	policy := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeAuto, DebounceMs: 10},
		Scope: config.Scope{
			Targets: []config.Target{{Host: "10.0.0.0/30"}},
		},
	}
	dialer := newPerHostDialer(nil)
	dialer.defaultCapsErr = dialingErr()
	r := newRunnerFor(t, policy, dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	run := sweepRunFor(t, r)
	require.NotContains(t, run.Reason, "not authenticated")
}

func newManagerWithLogger(t *testing.T, logger *slog.Logger) *Manager {
	t.Helper()
	m, err := NewManager(t.Context(), logger, nil,
		&gnmi.FakeDialer{Session: &gnmi.FakeSession{}}, "")
	require.NoError(t, err)
	return m
}
