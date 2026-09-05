package policy

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// testDialer is what every manager test starts policies through. This runner
// dials at Start, so a manager built with the real dialer would have each of
// these tests reach the network. The session must be non-nil and carry non-nil
// capabilities: a FakeDialer with no session hands back a typed-nil session the
// collector dereferences, and profile selection reads caps.Vendor. The shared
// fake is safe across concurrent runners, its only writes going under the
// session's own mutex, and the hour-long replay keeps the concurrency tests
// from re-sending empty snapshots every 20ms.
func testDialer() gnmi.Dialer {
	return &gnmi.FakeDialer{Session: &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{}, SampleReplay: time.Hour}}
}

func newTestManager() *Manager {
	return NewManager(context.Background(), testLogger, Options{Dialer: testDialer()})
}

func minimalPolicy() config.Policy {
	interval := 30
	return config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &interval},
		Scope: config.Scope{
			Targets: []config.Target{{Host: "192.168.1.1"}},
		},
	}
}

// policyWithTargets builds a policy over the given hosts, which is what the
// expansion and host-shape tests vary.
func policyWithTargets(hosts ...string) config.Policy {
	pol := minimalPolicy()
	pol.Scope.Targets = make([]config.Target, 0, len(hosts))
	for _, host := range hosts {
		pol.Scope.Targets = append(pol.Scope.Targets, config.Target{Host: host})
	}
	return pol
}

// parseOne parses a single-policy body and returns the policy under "test".
func parseOne(t *testing.T, m *Manager, body string) config.Policy {
	t.Helper()
	policies, err := m.ParsePolicies([]byte(body))
	require.NoError(t, err)
	pol, ok := policies["test"]
	require.True(t, ok)
	return pol
}

// ---------------------------------------------------------------------------
// validatePolicy — metrics_interval
// ---------------------------------------------------------------------------

// A policy with no interval subscribes at no cadence, so accepting one leaves
// the operator with a policy the API reports as running and that collects
// nothing.
func TestValidate_MissingMetricsInterval(t *testing.T) {
	m := newTestManager()
	pol := config.Policy{Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.1"}}}}
	assert.ErrorContains(t, m.validatePolicy(pol), "metrics_interval is required")
}

func TestValidate_MetricsIntervalBounds(t *testing.T) {
	m := newTestManager()
	for _, seconds := range []int{0, -1, config.MaxDurationSeconds + 1} {
		pol := minimalPolicy()
		pol.Config.MetricsInterval = &seconds
		assert.ErrorContains(t, m.validatePolicy(pol), "metrics_interval must be from 1", "interval %d", seconds)
	}
	for _, seconds := range []int{1, 30, config.MaxDurationSeconds} {
		pol := minimalPolicy()
		pol.Config.MetricsInterval = &seconds
		assert.NoError(t, m.validatePolicy(pol), "interval %d", seconds)
	}
}

func TestParsePolicies_RejectsAMissingMetricsInterval(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    scope:
      targets:
        - host: 10.0.0.1
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "metrics_interval is required")
}

// ---------------------------------------------------------------------------
// validatePolicy: mode
// ---------------------------------------------------------------------------

// The collector accepts auto, on_change and sample. A mode it does not know
// fails every target's start, leaving a policy the API reports as running.
func TestParsePolicies_RejectsAnUnknownMode(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
      mode: target_defined
    scope:
      targets:
        - host: 10.0.0.1
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "mode must be auto, on_change or sample")
}

func TestValidate_AcceptsEveryKnownMode(t *testing.T) {
	m := newTestManager()
	for _, mode := range []string{"", "auto", "on_change", "sample"} {
		pol := minimalPolicy()
		pol.Config.Mode = mode
		assert.NoError(t, m.validatePolicy(pol), "policy mode %q", mode)

		target := minimalPolicy()
		target.Scope.Targets[0].Mode = mode
		assert.NoError(t, m.validatePolicy(target), "target mode %q", mode)
	}
}

// ---------------------------------------------------------------------------
// validatePolicy: credentials on an unverified range
// ---------------------------------------------------------------------------

// A sweep admits whatever answers on the port. Without TLS authenticating the
// server, an unrelated service anywhere in the range collects the campus
// password, so the policy has to say it accepts that.
func TestParsePolicies_RejectsACredentialedRangeWithoutServerVerification(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      username: admin
      password: campus
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/24
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "send_credentials_to_unverified_targets")
}

func TestParsePolicies_AcceptsACredentialedRangeWhenTheOperatorOptsIn(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
      send_credentials_to_unverified_targets: true
    scope:
      username: admin
      password: campus
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/24
`))
	require.NoError(t, err)
}

// The rule is about ranges. A single host is an address the operator wrote
// down, so nothing unexpected can be behind it.
func TestParsePolicies_AcceptsACredentialedSingleHostWithoutTheOptIn(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      username: admin
      password: campus
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.1
`))
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// validatePolicy: host shapes
// ---------------------------------------------------------------------------

// One port cannot describe a range of devices reached on different ones, and
// the expansion would carry the inline suffix into every derived address.
func TestParsePolicies_RejectsAnInlinePortOnARange(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 10.0.0.0/24:6030
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "cannot carry an inline port")
}

// net.SplitHostPort accepts a service name and Go's dialer resolves one, so an
// unchecked "10.0.0.1:http" reaches a device on port 80 while every check here
// reads it as an unported host with a strange name.
func TestParsePolicies_RejectsAServiceNameAsAnInlinePort(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 10.0.0.1:http
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "inline port")
}

// The collector dials Host with Port, so a Host that still carried its port
// would be dialled as "10.0.0.1:6030:9339".
func TestParsePolicies_SplitsAnInlinePortOutOfTheHost(t *testing.T) {
	pol := parseOne(t, newTestManager(), `
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      port: 57400
      targets:
        - host: 10.0.0.1:6030
`)
	require.Len(t, pol.Scope.Targets, 1)
	assert.Equal(t, "10.0.0.1", pol.Scope.Targets[0].Host)
	assert.Equal(t, uint16(6030), pol.Scope.Targets[0].Port, "the inline port wins over the scope's")
}

// A bracketed IPv6 literal is how the operator writes one that carries no
// port. The brackets are part of the port syntax, so they come off with it.
func TestParsePolicies_UnbracketsAnIPv6Host(t *testing.T) {
	pol := parseOne(t, newTestManager(), `
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      port: 57400
      targets:
        - host: "[2001:db8::1]"
`)
	require.Len(t, pol.Scope.Targets, 1)
	assert.Equal(t, "2001:db8::1", pol.Scope.Targets[0].Host)
	assert.Equal(t, uint16(57400), pol.Scope.Targets[0].Port, "the scope's port, inherited")
}

// A target entry with no host clears the non-empty list check and expands to a
// single empty destination, so the runner would subscribe to nothing while the
// API reports the policy as running.
func TestValidate_RejectsBlankTargetHost(t *testing.T) {
	m := newTestManager()
	for _, host := range []string{"", " ", "\t", "  \n "} {
		err := m.validatePolicy(policyWithTargets(host))
		require.Error(t, err, "host %q should be rejected", host)
		assert.ErrorContains(t, err, "host is required")
	}
}

// The blank host arrives in the request body, so the check has to hold on the
// parse path and not only on a direct validatePolicy call.
func TestParsePolicies_RejectsTargetWithNoHost(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - {}
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "host is required")
}

// TestParsePolicies_TrimsPaddedTargetHost pins that a padded host is normalised
// once at parse time. Without it the blank check trims but the stored value does
// not, so the target passes validation and then expands to an unresolvable
// hostname.
func TestParsePolicies_TrimsPaddedTargetHost(t *testing.T) {
	m := newTestManager()
	pol := policyWithTargets(" 192.0.2.1 ")
	normalizeTargetHosts(&pol)
	assert.Equal(t, "192.0.2.1", pol.Scope.Targets[0].Host)
	assert.NoError(t, m.validatePolicy(pol))

	blank := policyWithTargets("   ")
	normalizeTargetHosts(&blank)
	assert.Error(t, m.validatePolicy(blank), "a host that is only whitespace is still blank")
}

// One target's expansion is capped by targets.MaxExpand, which fires ahead of
// the policy-wide budget: a /16 is one entry that would open 65534 streams.
func TestParsePolicies_RejectsATargetOverThePerTargetCap(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 10.0.0.0/16
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "more than the 1024 one target may hold")
}

// ---------------------------------------------------------------------------
// validatePolicy: one device, once
// ---------------------------------------------------------------------------

// A target's identity is the device. Everything below validation keys on the
// bare host, the runner's subscribed map, the sweep's pre-marking, the
// collector's loop, so a second entry for a host already named is silently
// dropped rather than refused. Keying those on the port instead would only move
// the collision into the series store, where the two would share device_ip and
// policy.
func TestParsePolicies_RejectsTwoPortsOnOneHost(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 10.0.0.1
          port: 6030
        - host: 10.0.0.1
          port: 57400
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "duplicate of target")
}

// The inline spelling of the same mistake. The check runs after the host and
// the port have been decided together, so it cannot be evaded by writing the
// port on the other side of the colon.
func TestParsePolicies_RejectsTwoInlinePortsOnOneHost(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 10.0.0.1:6030
        - host: 10.0.0.1:57400
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "duplicate of target")
}

// Two spellings of one address are one device. Comparing the raw text would let
// these through and leave the effective configuration to depend on which entry
// the collector happened to start first.
func TestParsePolicies_RejectsTwoSpellingsOfOneAddress(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: "[2001:db8::1]"
        - host: 2001:0db8::1
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "duplicate of target")
}

// A range is not part of the check. Pinning a host inside a subnet is the
// documented way to give one device its own credentials, and the sweep's
// expansion dedupe is what resolves it: the explicit entry wins the address.
func TestParsePolicies_AcceptsAHostPinnedInsideARange(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.0/24
`))
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// validatePolicy: rescan_interval_ms
// ---------------------------------------------------------------------------

// A rescan re-probes every unsubscribed address the policy names, so a tick a
// second is a permanent scan of the subnet.
func TestParsePolicies_RejectsARescanIntervalBelowTheFloor(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
      rescan_interval_ms: 1000
    scope:
      targets:
        - host: 10.0.0.0/24
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "rescan_interval_ms must be 0 or at least 60000")
}

// ---------------------------------------------------------------------------
// ParsePolicies: scope inheritance
// ---------------------------------------------------------------------------

// Inheritance happens once, at parse time, so validation and the collector both
// read the credentials and the port a target will actually be reached with. A
// target's own value wins, including an explicit empty one.
func TestParsePolicies_InheritsTheScopeIntoEveryTarget(t *testing.T) {
	pol := parseOne(t, newTestManager(), `
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      username: campus
      password: secret
      port: 57400
      targets:
        - host: 10.0.0.1
        - host: 10.0.0.2
          port: 6030
        - host: 10.0.0.3
          username: pinned
`)
	require.Len(t, pol.Scope.Targets, 3)
	for _, target := range pol.Scope.Targets {
		assert.NotZero(t, target.Port, "host %s carries no port", target.Host)
		assert.Equal(t, "secret", target.ResolvedPassword(), "host %s", target.Host)
	}
	assert.Equal(t, "campus", pol.Scope.Targets[0].ResolvedUsername())
	assert.Equal(t, uint16(57400), pol.Scope.Targets[0].Port)
	assert.Equal(t, "campus", pol.Scope.Targets[1].ResolvedUsername())
	assert.Equal(t, uint16(6030), pol.Scope.Targets[1].Port, "the target's own port wins")
	assert.Equal(t, "pinned", pol.Scope.Targets[2].ResolvedUsername(), "the target's own username wins")
}

// ---------------------------------------------------------------------------
// ParsePolicies: credential environment variables
// ---------------------------------------------------------------------------

func TestParsePolicies_ResolvesAnAllowedScopePassword(t *testing.T) {
	t.Setenv("GNMI_PASSWORD", "from-the-environment")
	m := NewManager(context.Background(), testLogger, Options{AllowedEnvVars: []string{"GNMI_PASSWORD"}, Dialer: testDialer()})

	pol := parseOne(t, m, `
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      password: ${GNMI_PASSWORD}
      targets:
        - host: 10.0.0.1
`)
	assert.Equal(t, "from-the-environment", pol.Scope.Password)
	assert.Equal(t, "from-the-environment", pol.Scope.Targets[0].ResolvedPassword(),
		"the target inherited the reference and resolves to the same value")
}

// With no allowlist configured the feature is off, not open: the backend
// inherits the agent's environment and the value goes on the wire.
func TestParsePolicies_RejectsAScopePasswordReferenceThatIsNotAllowed(t *testing.T) {
	t.Setenv("GNMI_PASSWORD", "not-in-a-policy")
	m := newTestManager()

	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      password: ${GNMI_PASSWORD}
      targets:
        - host: 10.0.0.1
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "scope.password")
	assert.ErrorContains(t, err, "GNMI_PASSWORD")
	assert.NotContains(t, err.Error(), "not-in-a-policy", "the rejection must not echo the value back")
}

// ---------------------------------------------------------------------------
// validateProfilesDir
// ---------------------------------------------------------------------------

// A profiles_dir arrives in the request body, so one that climbs out of the
// root is refused before anything reads it. The rest of the rule is covered in
// profilesdir_test.go.
func TestStartPolicy_RejectsProfilesDirThatWalksUpward(t *testing.T) {
	m := newTestManagerRootedAt(t.TempDir())
	pol := minimalPolicy()
	pol.Config.ProfilesDir = "../../etc"
	require.Error(t, m.StartPolicy("policy-a", pol))
	assert.Empty(t, m.policies)
}

// ---------------------------------------------------------------------------
// Stop on empty manager
// ---------------------------------------------------------------------------

func TestStop_EmptyManager(t *testing.T) {
	m := newTestManager()
	assert.NoError(t, m.Stop())
}

// ---------------------------------------------------------------------------
// GetPolicyStatuses
// ---------------------------------------------------------------------------

// statusCollector reports a fixed set of target statuses, which is where a
// policy's state now comes from: the runner keeps none of its own.
type statusCollector struct {
	spyCollector
	statuses []collector.TargetStatus
}

func (s *statusCollector) TargetStatuses(string) []collector.TargetStatus { return s.statuses }

func managerWith(t *testing.T, name string, c Collector) *Manager {
	t.Helper()
	m := newTestManager()
	r, err := NewRunner(m.ctx, testLogger, name, minimalPolicy(), c, testDialer())
	require.NoError(t, err)
	m.policies[name] = r
	return m
}

func TestGetPolicyStatuses_ReportsTheCollectorsTargets(t *testing.T) {
	c := &statusCollector{statuses: []collector.TargetStatus{
		{Host: "10.0.0.1", Mode: "on_change", Up: true},
	}}
	m := managerWith(t, "policy1", c)

	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "policy1", statuses[0].Name)
	assert.Equal(t, "running", statuses[0].Status)
	assert.Nil(t, statuses[0].LastError)
	assert.Nil(t, statuses[0].LastErrorAt)
	assert.Equal(t, c.statuses, statuses[0].Targets)
}

// The runner keeps no error state, so a policy reports as failing exactly when
// one of its targets does.
func TestGetPolicyStatuses_ReportsTheFirstTargetError(t *testing.T) {
	c := &statusCollector{statuses: []collector.TargetStatus{
		{Host: "10.0.0.1", Up: true},
		{Host: "10.0.0.2", LastError: "connection refused"},
	}}
	m := managerWith(t, "policy1", c)

	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "running_with_errors", statuses[0].Status)
	require.NotNil(t, statuses[0].LastError)
	assert.Equal(t, "connection refused", *statuses[0].LastError)
	require.NotNil(t, statuses[0].LastErrorAt)
}

// ---------------------------------------------------------------------------
// GetCapabilities
// ---------------------------------------------------------------------------

// The agent reads this to decide what it may send. The three delivery modes
// are what a policy may name in mode, on top of the targets capability every
// backend of this shape declares.
func TestGetCapabilities(t *testing.T) {
	assert.Equal(t, []string{"targets", "on_change", "sample", "get"}, newTestManager().GetCapabilities())
}

// ---------------------------------------------------------------------------
// ParsePolicies — unknown key reporting
// ---------------------------------------------------------------------------

func TestParsePolicies_WarnsOnUnknownKey(t *testing.T) {
	var buf bytes.Buffer
	m := NewManager(context.Background(), slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Options{Dialer: testDialer()})

	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      metrics_interval: 30
      metrics_intervl: 10
    scope:
      targets:
        - host: 192.0.2.1
`))
	require.NoError(t, err, "an unrecognized key stays non-fatal")
	assert.Contains(t, buf.String(), "metrics_intervl")
}

// ---------------------------------------------------------------------------
// Empty target list
// ---------------------------------------------------------------------------

// The per-target validation loop runs zero times when scope.targets is absent,
// so the policy used to be accepted, subscribe to nothing, and still report
// itself as running.
func TestValidate_NoTargets(t *testing.T) {
	m := newTestManager()
	interval := 30
	pol := config.Policy{Config: config.PolicyConfig{MetricsInterval: &interval}}
	assert.ErrorContains(t, m.validatePolicy(pol), "no targets")
}

func TestParsePolicies_RejectsPolicyWithNoTargets(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      metrics_interval: 30
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "no targets")
}

func TestParsePolicies_RejectsEmptyTargetList(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      metrics_interval: 30
    scope:
      targets: []
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "no targets")
}

func TestStartPolicy_RejectsPolicyWithNoTargets(t *testing.T) {
	m := newTestManager()
	pol := minimalPolicy()
	pol.Scope.Targets = nil
	require.ErrorContains(t, m.StartPolicy("policy-a", pol), "no targets")
	assert.Empty(t, m.policies)
}

func TestParsePolicies_RejectsAnInlinePortOfZero(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  test:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 10.0.0.1:0
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "inline port")
}

// The manager builds the default dialer, so it is the only place the sessions
// it dials can be told which logger to raise their own events on.
func TestNewManager_GivesTheDefaultDialerItsLogger(t *testing.T) {
	m := NewManager(context.Background(), testLogger, Options{})
	dialer, ok := m.dialer.(*gnmi.GnmicDialer)
	require.True(t, ok, "a nil dialer defaults to the gnmic one")
	assert.Same(t, testLogger, dialer.Logger)
}
