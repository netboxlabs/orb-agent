package policy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/go-co-op/gocron/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func newTestManager() *Manager {
	return NewManager(context.Background(), testLogger, "")
}

func v2cAuth() config.Authentication {
	return config.Authentication{ProtocolVersion: "SNMPv2c", Community: "public"}
}

func v3AuthAuth() config.Authentication {
	return config.Authentication{
		ProtocolVersion: "SNMPv3",
		SecurityLevel:   "authNoPriv",
		Username:        "admin",
		AuthPassphrase:  "secret123",
		AuthProtocol:    "SHA",
	}
}

func v3PrivAuth() config.Authentication {
	return config.Authentication{
		ProtocolVersion: "SNMPv3",
		SecurityLevel:   "authPriv",
		Username:        "admin",
		AuthPassphrase:  "secret123",
		AuthProtocol:    "SHA",
		PrivPassphrase:  "priv456",
		PrivProtocol:    "AES",
	}
}

func minimalPolicy(auth config.Authentication) config.Policy {
	interval := 60
	return config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &interval},
		Scope: config.Scope{
			Authentication: auth,
			Targets:        []config.Target{{Host: "192.168.1.1"}},
		},
	}
}

// ---------------------------------------------------------------------------
// validatePolicy — authentication
// ---------------------------------------------------------------------------

func TestValidate_V2cPolicyAuth(t *testing.T) {
	m := newTestManager()
	require.NoError(t, m.validatePolicy(minimalPolicy(v2cAuth())))
}

func TestValidate_V3PolicyAuth_AuthNoPriv(t *testing.T) {
	m := newTestManager()
	require.NoError(t, m.validatePolicy(minimalPolicy(v3AuthAuth())))
}

func TestValidate_V3PolicyAuth_AuthPriv(t *testing.T) {
	m := newTestManager()
	require.NoError(t, m.validatePolicy(minimalPolicy(v3PrivAuth())))
}

func TestValidate_NoAuthNoPolicyFallback(t *testing.T) {
	m := newTestManager()
	interval := 60
	pol := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &interval},
		Scope: config.Scope{
			Targets: []config.Target{{Host: "192.168.1.1"}},
		},
	}
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "no authentication configured")
}

func TestValidate_MissingProtocolVersion(t *testing.T) {
	// Authentication without ProtocolVersion is not treated as a policy-level auth,
	// so targets without per-target auth get "no authentication configured" error.
	m := newTestManager()
	auth := config.Authentication{Community: "public"} // no ProtocolVersion
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.Error(t, err)
}

func TestValidate_PerTargetMissingProtocolVersion(t *testing.T) {
	// Per-target auth with no ProtocolVersion triggers the missing protocol version error.
	m := newTestManager()
	bad := config.Authentication{Community: "public"} // no ProtocolVersion
	interval := 60
	pol := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &interval},
		Scope: config.Scope{
			Targets: []config.Target{{Host: "10.0.0.1", Authentication: &bad}},
		},
	}
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "missing protocol version")
}

func TestValidate_UnsupportedProtocolVersion(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{ProtocolVersion: "SNMPv99", Community: "public"}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "unsupported protocol version")
}

func TestNormalizeProtocolVersion(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"2c", "SNMPv2c"},
		{"v2c", "SNMPv2c"},
		{"2", "SNMPv2c"},
		{"v2", "SNMPv2c"},
		{"SNMPv2c", "SNMPv2c"},
		{"1", "SNMPv1"},
		{"v1", "SNMPv1"},
		{"SNMPv1", "SNMPv1"},
		{"3", "SNMPv3"},
		{"v3", "SNMPv3"},
		{"SNMPv3", "SNMPv3"},
		{"unknown", "unknown"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, normalizeProtocolVersion(tc.input), "input: %s", tc.input)
	}
}

func TestValidate_ProtocolVersionAliasesAccepted(t *testing.T) {
	m := newTestManager()
	for _, alias := range []string{"2c", "v2c", "2", "v2"} {
		yaml := fmt.Sprintf(`policies:
  test:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: %s
        community: public
      targets:
        - host: 192.168.1.1
`, alias)
		policies, err := m.ParsePolicies([]byte(yaml))
		assert.NoError(t, err, "alias %q should be accepted", alias)
		if err == nil {
			assert.Equal(t, "SNMPv2c", policies["test"].Scope.Authentication.ProtocolVersion, "alias %q should normalize to SNMPv2c", alias)
		}
	}
}

func TestValidate_V2cMissingCommunity(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{ProtocolVersion: "SNMPv2c"}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "missing community")
}

func TestValidate_V1MissingCommunity(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{ProtocolVersion: "SNMPv1"}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "missing community")
}

func TestValidate_V3InvalidSecurityLevel(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{ProtocolVersion: "SNMPv3", SecurityLevel: "bad"}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "invalid security level")
}

func TestValidate_V3AuthNoPrivMissingUser(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{
		ProtocolVersion: "SNMPv3", SecurityLevel: "authNoPriv",
		AuthPassphrase: "secret", AuthProtocol: "SHA",
	}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "missing username")
}

func TestValidate_V3AuthNoPrivMissingPassphrase(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{
		ProtocolVersion: "SNMPv3", SecurityLevel: "authNoPriv",
		Username: "admin", AuthProtocol: "SHA",
	}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "missing auth passphrase")
}

func TestValidate_V3AuthPrivMissingPrivPassphrase(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{
		ProtocolVersion: "SNMPv3", SecurityLevel: "authPriv",
		Username: "admin", AuthPassphrase: "secret", AuthProtocol: "SHA",
		PrivProtocol: "AES",
	}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "missing priv passphrase")
}

func TestValidate_V3AuthPrivMissingPrivProtocol(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{
		ProtocolVersion: "SNMPv3", SecurityLevel: "authPriv",
		Username: "admin", AuthPassphrase: "secret", AuthProtocol: "SHA",
		PrivPassphrase: "priv",
	}
	pol := minimalPolicy(auth)
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "missing priv protocol")
}

func TestValidate_PerTargetAuth(t *testing.T) {
	m := newTestManager()
	interval := 60
	auth := v2cAuth()
	pol := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &interval},
		Scope: config.Scope{
			Targets: []config.Target{{Host: "10.0.0.1", Authentication: &auth}},
		},
	}
	require.NoError(t, m.validatePolicy(pol))
}

// ---------------------------------------------------------------------------
// validatePolicy — metrics_interval
// ---------------------------------------------------------------------------

func TestValidate_MissingMetricsInterval(t *testing.T) {
	m := newTestManager()
	pol := config.Policy{
		Scope: config.Scope{
			Authentication: v2cAuth(),
			Targets:        []config.Target{{Host: "10.0.0.1"}},
		},
	}
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "metrics_interval")
}

func TestValidate_ZeroMetricsInterval(t *testing.T) {
	m := newTestManager()
	zero := 0
	pol := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &zero},
		Scope: config.Scope{
			Authentication: v2cAuth(),
			Targets:        []config.Target{{Host: "10.0.0.1"}},
		},
	}
	err := m.validatePolicy(pol)
	assert.ErrorContains(t, err, "metrics_interval")
}

// A device exposing its MIB in a named context returns nothing for the default
// context, so an absent context_name looks like a successful empty walk.
func TestValidateAuthentication_ContextNameAcceptedForV3(t *testing.T) {
	m := newTestManager()
	err := m.validateAuthentication(&config.Authentication{
		ProtocolVersion: "SNMPv3",
		SecurityLevel:   "authPriv",
		Username:        "admin",
		AuthProtocol:    "SHA",
		AuthPassphrase:  "authpass",
		PrivProtocol:    "AES",
		PrivPassphrase:  "privpass",
		ContextName:     "vrf-mgmt",
	}, "scope")
	if err != nil {
		t.Errorf("context_name rejected for SNMPv3: %v", err)
	}
}

// v1 and v2c have no context concept. Ignoring the field would make a
// misconfigured policy look healthy while returning nothing.
func TestValidateAuthentication_ContextNameRejectedForV1AndV2c(t *testing.T) {
	m := newTestManager()
	for _, version := range []string{"SNMPv1", "SNMPv2c"} {
		err := m.validateAuthentication(&config.Authentication{
			ProtocolVersion: version,
			Community:       "public",
			ContextName:     "vrf-mgmt",
		}, "scope")
		if err == nil {
			t.Errorf("%s: context_name accepted, want rejection", version)
			continue
		}
		if !strings.Contains(err.Error(), "context_name") {
			t.Errorf("%s: error %q does not name the offending field", version, err)
		}
	}
}

// ---------------------------------------------------------------------------
// applyDefaults
// ---------------------------------------------------------------------------

func TestApplyDefaults_SetsDefaultPort(t *testing.T) {
	m := newTestManager()
	pol := minimalPolicy(v2cAuth())
	pol.Scope.Targets[0].Port = 0
	m.applyDefaults(&pol)
	assert.Equal(t, uint16(SNMPDefaultPort), pol.Scope.Targets[0].Port)
}

func TestApplyDefaults_PreservesExistingPort(t *testing.T) {
	m := newTestManager()
	pol := minimalPolicy(v2cAuth())
	pol.Scope.Targets[0].Port = 1161
	m.applyDefaults(&pol)
	assert.Equal(t, uint16(1161), pol.Scope.Targets[0].Port)
}

// ---------------------------------------------------------------------------
// Stop on empty manager
// ---------------------------------------------------------------------------

func TestStop_EmptyManager(t *testing.T) {
	m := newTestManager()
	assert.NoError(t, m.Stop())
}

// stubScheduler stands in for gocron's scheduler so Stop can be driven without
// a real one, which takes seconds to time out. Embedding the interface leaves
// its other methods nil, which is fine: Runner.Stop only calls StopJobs and
// Shutdown.
type stubScheduler struct {
	gocron.Scheduler
	err   error
	stops int
}

func (s *stubScheduler) StopJobs() error {
	s.stops++
	return s.err
}

func (s *stubScheduler) Shutdown() error { return s.err }

func stubRunner(err error) (*Runner, *stubScheduler) {
	s := &stubScheduler{err: err}
	return &Runner{scheduler: s, targetErrs: make(map[string]error)}, s
}

// Stop drained the policy map before stopping the runners, so the first
// failure returned early and left the rest of them polling with no entry in
// the map for /status to report.
func TestStop_AttemptsEveryRunnerAndJoinsErrors(t *testing.T) {
	m := newTestManager()
	failingA, _ := stubRunner(fmt.Errorf("scheduler wedged"))
	failingB, _ := stubRunner(fmt.Errorf("scheduler wedged"))
	healthy, healthySched := stubRunner(nil)
	m.policies["policy-a"] = failingA
	m.policies["policy-b"] = failingB
	m.policies["policy-c"] = healthy

	err := m.Stop()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy-a")
	assert.Contains(t, err.Error(), "policy-b")
	assert.Equal(t, 1, healthySched.stops, "a runner after a failing one must still be stopped")
	assert.Empty(t, m.policies)
}

// ---------------------------------------------------------------------------
// GetPolicyStatuses — error tracking
// ---------------------------------------------------------------------------

func TestGetPolicyStatuses_NoError(t *testing.T) {
	m := newTestManager()
	r := &Runner{targetErrs: make(map[string]error)}
	m.policies["policy1"] = r

	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "policy1", statuses[0].Name)
	assert.Equal(t, "running", statuses[0].Status)
	assert.Nil(t, statuses[0].LastError)
	assert.Nil(t, statuses[0].LastErrorAt)
}

func TestGetPolicyStatuses_WithError(t *testing.T) {
	m := newTestManager()
	r := &Runner{targetErrs: make(map[string]error)}
	m.policies["policy1"] = r

	someErr := fmt.Errorf("connection timed out")
	r.SetTargetError("192.168.1.1:161", someErr)

	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "running_with_errors", statuses[0].Status)
	require.NotNil(t, statuses[0].LastError)
	assert.Contains(t, *statuses[0].LastError, "192.168.1.1:161")
	assert.Contains(t, *statuses[0].LastError, "connection timed out")
	require.NotNil(t, statuses[0].LastErrorAt)
}

func TestGetPolicyStatuses_ErrorThenClear(t *testing.T) {
	m := newTestManager()
	r := &Runner{targetErrs: make(map[string]error)}
	m.policies["policy1"] = r

	r.SetTargetError("192.168.1.1:161", fmt.Errorf("some error"))
	r.ClearTargetError("192.168.1.1:161")

	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 1)
	assert.Equal(t, "running", statuses[0].Status)
	assert.Nil(t, statuses[0].LastError)
	assert.Nil(t, statuses[0].LastErrorAt)
}

func TestGetPolicyStatuses_MixedState(t *testing.T) {
	m := newTestManager()
	healthy := &Runner{targetErrs: make(map[string]error)}
	failing := &Runner{targetErrs: make(map[string]error)}
	m.policies["healthy-policy"] = healthy
	m.policies["failing-policy"] = failing

	failing.SetTargetError("10.0.0.1:161", fmt.Errorf("unreachable"))

	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 2)

	byName := make(map[string]Status, 2)
	for _, s := range statuses {
		byName[s.Name] = s
	}

	assert.Equal(t, "running", byName["healthy-policy"].Status)
	assert.Nil(t, byName["healthy-policy"].LastError)

	assert.Equal(t, "running_with_errors", byName["failing-policy"].Status)
	require.NotNil(t, byName["failing-policy"].LastError)
	assert.Contains(t, *byName["failing-policy"].LastError, "10.0.0.1:161")
}

// ---------------------------------------------------------------------------
// ParsePolicies — unknown key reporting
// ---------------------------------------------------------------------------

func TestParsePolicies_WarnsOnUnknownKey(t *testing.T) {
	var buf bytes.Buffer
	m := NewManager(context.Background(), slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), "")

	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      metrics_interval: 60
      snmp_timout: 10
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - host: 192.0.2.1
`))
	require.NoError(t, err, "an unrecognized key stays non-fatal")
	assert.Contains(t, buf.String(), "snmp_timout")
}
