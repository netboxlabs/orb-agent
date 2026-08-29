package policy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
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
// validateProfilesDir
// ---------------------------------------------------------------------------

func TestValidateProfilesDir_AcceptsAbsoluteAndRelative(t *testing.T) {
	dir := t.TempDir()
	got, err := validateProfilesDir(dir + string(filepath.Separator))
	require.NoError(t, err)
	assert.Equal(t, dir, got)

	got, err = validateProfilesDir("./profiles/overrides")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("profiles", "overrides"), got)
}

// A profiles_dir arrives in the request body, so one that climbs out of the
// directory it names is refused before anything reads it.
func TestValidateProfilesDir_RejectsUpwardTraversal(t *testing.T) {
	for _, dir := range []string{"..", "../overrides", "profiles/../../overrides"} {
		_, err := validateProfilesDir(dir)
		require.Error(t, err, dir)
		assert.Contains(t, err.Error(), "SNMP profiles directory")
	}
}

func TestStartPolicy_RejectsProfilesDirThatWalksUpward(t *testing.T) {
	m := newTestManager()
	pol := minimalPolicy(v2cAuth())
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

// TestValidateProfilesDir_DotsAnywhereRejected pins the deliberately blunt rule:
// any ".." is refused, including one inside a directory name. filepath.Clean
// resolves an interior traversal first, so /opt/profiles/../../etc becomes /etc
// and is accepted, which is no wider than naming /etc outright.
func TestValidateProfilesDir_DotsAnywhereRejected(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    string
		wantErr bool
	}{
		{name: "interior traversal is resolved", dir: "/opt/profiles/../../etc", want: "/etc"},
		{name: "leading traversal is rejected", dir: "../../etc", wantErr: true},
		{name: "dots inside a name are rejected too", dir: "/opt/a..b", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateProfilesDir(tt.dir)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Empty target list
// ---------------------------------------------------------------------------

// The per-target validation loop runs zero times when scope.targets is absent,
// so the policy used to be accepted, start no jobs, and still report itself as
// running: an operator would see a healthy policy that collects nothing.
func TestValidate_NoTargets(t *testing.T) {
	m := newTestManager()
	interval := 60
	pol := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: &interval},
		Scope:  config.Scope{Authentication: v2cAuth()},
	}
	assert.ErrorContains(t, m.validatePolicy(pol), "no targets")
}

func TestParsePolicies_RejectsPolicyWithNoTargets(t *testing.T) {
	m := newTestManager()
	_, err := m.ParsePolicies([]byte(`
policies:
  p1:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v2c
        community: public
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
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets: []
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "no targets")
}

func TestStartPolicy_RejectsPolicyWithNoTargets(t *testing.T) {
	m := newTestManager()
	pol := minimalPolicy(v2cAuth())
	pol.Scope.Targets = nil
	require.ErrorContains(t, m.StartPolicy("policy-a", pol), "no targets")
	assert.Empty(t, m.policies)
}

// ---------------------------------------------------------------------------
// validatePolicy: v3 protocol names
// ---------------------------------------------------------------------------

// Names the SNMP client resolves and names it does not, mixed together. The
// tests below assert the validator agrees with the client for every one of
// them, so a list written beside the validator would not survive.
var protocolNames = []string{
	"", "NoAuth", "NoPriv",
	"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512",
	"DES", "AES", "AES192", "AES256", "AES192C", "AES256C",
	"SHA3", "3DES", "sha", "aes", "none", "SHA-256",
}

func v3ProtocolAuth(authProtocol, privProtocol string) config.Authentication {
	return config.Authentication{
		ProtocolVersion: "SNMPv3",
		SecurityLevel:   "noAuthNoPriv",
		Username:        "admin",
		AuthProtocol:    authProtocol,
		PrivProtocol:    privProtocol,
	}
}

// snmp.NewClient resolves both protocol names for every v3 policy, so one it
// cannot resolve fails every collection before it connects. Whatever the client
// accepts, validation must accept, and nothing more.
func TestValidate_V3AuthProtocolMatchesTheClient(t *testing.T) {
	m := newTestManager()
	for _, name := range protocolNames {
		auth := v3ProtocolAuth(name, "")
		_, clientErr := snmp.NewClient(t.Context(), "192.0.2.1", 161, 1, time.Second, &auth, testLogger)
		err := m.validatePolicy(minimalPolicy(auth))
		if clientErr != nil {
			require.Error(t, err, "auth protocol %q: the client rejects it, so validation must too", name)
			assert.ErrorContains(t, err, name)
			continue
		}
		require.NoError(t, err, "auth protocol %q: the client accepts it, so validation must too", name)
	}
}

func TestValidate_V3PrivProtocolMatchesTheClient(t *testing.T) {
	m := newTestManager()
	for _, name := range protocolNames {
		auth := v3ProtocolAuth("", name)
		_, clientErr := snmp.NewClient(t.Context(), "192.0.2.1", 161, 1, time.Second, &auth, testLogger)
		err := m.validatePolicy(minimalPolicy(auth))
		if clientErr != nil {
			require.Error(t, err, "priv protocol %q: the client rejects it, so validation must too", name)
			assert.ErrorContains(t, err, name)
			continue
		}
		require.NoError(t, err, "priv protocol %q: the client accepts it, so validation must too", name)
	}
}

// An omitted protocol name is not an error: the client maps it to the default.
func TestValidate_V3EmptyProtocolNamesKeepTheDefaults(t *testing.T) {
	m := newTestManager()
	auth := v3ProtocolAuth("", "")
	require.NoError(t, m.validatePolicy(minimalPolicy(auth)))

	w, err := snmp.NewClient(t.Context(), "192.0.2.1", 161, 1, time.Second, &auth, testLogger)
	require.NoError(t, err)
	c, ok := w.(*snmp.Client)
	require.True(t, ok)
	params, ok := c.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	require.True(t, ok)
	assert.Equal(t, gosnmp.NoAuth, params.AuthenticationProtocol)
	assert.Equal(t, gosnmp.NoPriv, params.PrivacyProtocol)
}

// A v1 or v2c policy never reaches the v3 protocol tables, so a stale name
// carried alongside a community string is not a policy that cannot collect.
func TestValidate_V2cIgnoresV3ProtocolNames(t *testing.T) {
	m := newTestManager()
	auth := config.Authentication{ProtocolVersion: "SNMPv2c", Community: "public", AuthProtocol: "SHA3"}
	require.NoError(t, m.validatePolicy(minimalPolicy(auth)))
}

// ---------------------------------------------------------------------------
// validatePolicy: target host
// ---------------------------------------------------------------------------

// A target entry with no host clears the non-empty list check and expands to a
// single empty destination, so the runner schedules an SNMP job against nothing
// while the API reports the policy as running.
func TestValidate_RejectsBlankTargetHost(t *testing.T) {
	m := newTestManager()
	for _, host := range []string{"", " ", "\t", "  \n "} {
		err := m.validatePolicy(policyWithTarget(host))
		require.Error(t, err, "host %q should be rejected", host)
		assert.ErrorContains(t, err, "target host must not be empty")
	}
}

// The blank host arrives in the request body, so the check has to hold on the
// parse path and not only on a direct validatePolicy call.
func TestParsePolicies_RejectsTargetWithNoHost(t *testing.T) {
	m := newTestManager()
	body := `policies:
  test:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: v2c
        community: public
      targets:
        - {}
`
	_, err := m.ParsePolicies([]byte(body))
	require.Error(t, err)
	assert.ErrorContains(t, err, "target host must not be empty")
}

// TrimSpace decides emptiness and nothing else. A host with padding around it
// is left as the policy wrote it: validation does not rewrite a target, and
// trimming one here would hand the expander a different string from the one it
// reads out of the policy.
// TestParsePolicies_TrimsPaddedTargetHost pins that a padded host is normalised
// once at parse time. Without it the blank check trims but the stored value does
// not, so the target passes validation and then expands to an unresolvable
// hostname.
func TestParsePolicies_TrimsPaddedTargetHost(t *testing.T) {
	m := newTestManager()
	pol := policyWithTarget(" 192.0.2.1 ")
	normalizeTargetHosts(&pol)
	assert.Equal(t, "192.0.2.1", pol.Scope.Targets[0].Host)
	assert.NoError(t, m.validatePolicy(pol))

	blank := policyWithTarget("   ")
	normalizeTargetHosts(&blank)
	assert.Error(t, m.validatePolicy(blank), "a host that is only whitespace is still blank")
}
