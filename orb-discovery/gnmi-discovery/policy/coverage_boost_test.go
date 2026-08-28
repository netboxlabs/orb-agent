package policy

// coverage_boost_test.go — behavioral tests targeting the functions with low or
// zero coverage:
//   - Manager lifecycle: HasPolicy, StartPolicy, StopPolicy, Stop, GetCapabilities,
//     GetPolicyStatuses, deriveStatus, NewManager (error path), ParsePolicies (extra
//     branches), ensurePort (empty host), resolveEnv (unset env var)
//   - Runner GET mode: deliverGet (full poll loop), selectProfile (vendor match,
//     pinned-unknown fallback, nil-caps path)
//   - filterNotification: update-kept, update-dropped, delete-kept, delete-dropped
//   - debounce loop: timer-reset branch (re-arm while already armed, drain timer.C)

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// ─── Manager lifecycle ────────────────────────────────────────────────────────

// TestNewManagerBadProfilesDir verifies that a nonexistent profilesDir is handled
// gracefully — LoadProfilesWithLogger logs a warning but still succeeds with the
// bundled profiles (the override dir is optional). NewManager must return no error.
func TestNewManagerBadProfilesDir(t *testing.T) {
	t.Parallel()
	// A non-existent override dir is treated as "no overrides" (warn + continue)
	// by LoadProfilesWithLogger, so NewManager must succeed.
	m, err := NewManager(context.Background(), slog.Default(), nil,
		&gnmi.FakeDialer{Session: &gnmi.FakeSession{}},
		"/nonexistent/profiles/dir/that/cannot/exist",
	)
	require.NoError(t, err, "NewManager with a nonexistent profilesDir must succeed (override dir is optional)")
	require.NotNil(t, m)
}

// TestManagerHasPolicy checks HasPolicy before and after StartPolicy.
func TestManagerHasPolicy(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)

	require.False(t, m.HasPolicy("missing"), "HasPolicy must be false for unknown policy")

	pol := minimalPolicy("10.0.0.1:9339")
	require.NoError(t, m.StartPolicy("p1", pol))
	defer func() { _ = m.StopPolicy("p1") }()
	require.True(t, m.HasPolicy("p1"), "HasPolicy must be true after StartPolicy")
}

// TestManagerStartPolicyNoTargets covers the early-return error path in StartPolicy.
func TestManagerStartPolicyNoTargets(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	err := m.StartPolicy("empty", config.Policy{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no targets")
}

// TestManagerStartPolicyUnknownProfile covers the "pins unknown profile" error.
func TestManagerStartPolicyUnknownProfile(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	pol := config.Policy{
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1", Profile: "no_such_profile"}}},
	}
	err := m.StartPolicy("bad-profile", pol)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown profile")
}

// TestManagerStartPolicyExists verifies that a second StartPolicy for the same
// name returns ErrPolicyExists (so the HTTP handler maps it to 409) and does NOT
// add a second runner — the check-and-insert is atomic under the manager lock.
func TestManagerStartPolicyExists(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	pol := minimalPolicy("10.0.0.1:9339")

	require.NoError(t, m.StartPolicy("p1", pol))
	defer func() { _ = m.StopPolicy("p1") }()
	require.ErrorIs(t, m.StartPolicy("p1", pol), ErrPolicyExists, "second StartPolicy for same name must return ErrPolicyExists")
}

// TestManagerStopPolicyUnknown verifies that stopping a non-existent policy returns ErrPolicyNotFound.
func TestManagerStopPolicyUnknown(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	require.ErrorIs(t, m.StopPolicy("ghost"), ErrPolicyNotFound, "StopPolicy on unknown name must return ErrPolicyNotFound")
	require.False(t, m.HasPolicy("ghost"))
}

// TestManagerStopPolicyRunning starts then stops a real policy and verifies it
// is removed from the map.
func TestManagerStopPolicyRunning(t *testing.T) {
	pol := minimalOnChangePolicy("h:1")
	m, _ := newManagerWithFake(t, &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream:  []gnmi.Notification{{SyncDone: true}},
	})

	require.NoError(t, m.StartPolicy("p1", pol))
	require.True(t, m.HasPolicy("p1"))
	require.NoError(t, m.StopPolicy("p1"))
	require.False(t, m.HasPolicy("p1"), "policy must be removed from map after StopPolicy")
}

// TestManagerStopAll starts two policies and calls Stop(); both must be
// removed and the returned error must be nil.
func TestManagerStopAll(t *testing.T) {
	m, _ := newManagerWithFake(t, &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream:  []gnmi.Notification{{SyncDone: true}},
	})

	require.NoError(t, m.StartPolicy("p1", minimalOnChangePolicy("h:1")))
	require.NoError(t, m.StartPolicy("p2", minimalOnChangePolicy("h:2")))
	require.NoError(t, m.Stop())
	require.False(t, m.HasPolicy("p1"))
	require.False(t, m.HasPolicy("p2"))
}

// TestManagerGetCapabilities verifies the static capability list.
func TestManagerGetCapabilities(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	caps := m.GetCapabilities()
	require.Contains(t, caps, "targets")
	require.Contains(t, caps, "on_change")
	require.Contains(t, caps, "sample")
	require.Contains(t, caps, "get")
}

// TestManagerGetPolicyStatusesEmpty returns an empty slice when no policies are running.
func TestManagerGetPolicyStatusesEmpty(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	require.Empty(t, m.GetPolicyStatuses())
}

// TestManagerGetPolicyStatusesRunning starts a policy and verifies that
// GetPolicyStatuses returns an entry for it.
func TestManagerGetPolicyStatusesRunning(t *testing.T) {
	rec := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode:       config.ModeOnChange,
			DebounceMs: 30,
			Defaults:   config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	m, err := NewManager(context.Background(), slog.Default(), rec, &gnmi.FakeDialer{Session: &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
	}}, "")
	require.NoError(t, err)

	require.NoError(t, m.StartPolicy("p1", pol))
	defer func() { _ = m.Stop() }()

	// wait for at least one ingest then inspect statuses
	require.Eventually(t, func() bool { return rec.count() >= 1 }, 2*time.Second, 20*time.Millisecond)

	statuses := m.GetPolicyStatuses()
	require.Len(t, statuses, 1)
	require.Equal(t, "p1", statuses[0].Name)
	require.NotEmpty(t, statuses[0].Status)
}

// ─── deriveStatus ─────────────────────────────────────────────────────────────

func TestDeriveStatusNoRuns(t *testing.T) {
	t.Parallel()
	require.Equal(t, "unknown", deriveStatus(nil))
	require.Equal(t, "unknown", deriveStatus([]*Run{}))
}

func TestDeriveStatusRunning(t *testing.T) {
	t.Parallel()
	runs := []*Run{
		{Status: RunStatusCompleted},
		{Status: RunStatusRunning},
	}
	require.Equal(t, "running", deriveStatus(runs))
}

func TestDeriveStatusLatestCompleted(t *testing.T) {
	t.Parallel()
	runs := []*Run{
		{Status: RunStatusCompleted},
		{Status: RunStatusFailed},
	}
	require.Equal(t, "completed", deriveStatus(runs), "newest-first: first element is latest")
}

func TestDeriveStatusLatestFailed(t *testing.T) {
	t.Parallel()
	runs := []*Run{
		{Status: RunStatusFailed},
		{Status: RunStatusCompleted},
	}
	require.Equal(t, "failed", deriveStatus(runs))
}

// ─── ParsePolicies extra branches ────────────────────────────────────────────

// TestParsePoliciesInvalidYAML covers the yaml.Unmarshal error branch in ParsePolicies.
func TestParsePoliciesInvalidYAML(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte(":\tinvalid: yaml: {"))
	require.Error(t, err)
}

// TestParsePoliciesNoPolicies covers the "no policies found" branch.
func TestParsePoliciesNoPolicies(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	_, err := m.ParsePolicies([]byte("policies: {}\n"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "no policies")
}

// TestParsePoliciesUnsetEnvVar covers the resolveEnv failure path.
func TestParsePoliciesUnsetEnvVar(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    config: {}
    scope:
      targets:
        - host: ${GNMI_HOST_THAT_IS_NOT_SET_XYZZY}
`)
	_, err := m.ParsePolicies(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to resolve environment variables")
}

// TestParsePoliciesTargetBadMode covers the per-target mode validation branch.
func TestParsePoliciesTargetBadMode(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    config: {}
    scope:
      targets:
        - host: 10.0.0.1
          mode: streaming
`)
	_, err := m.ParsePolicies(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid mode")
}

// TestParsePoliciesEmptyTargetHost covers the "target with empty host" branch.
func TestParsePoliciesEmptyTargetHost(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    config: {}
    scope:
      targets:
        - host: ""
`)
	_, err := m.ParsePolicies(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty host")
}

// TestParsePoliciesTargetOverrideDefaultsBadRegex covers the per-target
// override_defaults regex validation path.
func TestParsePoliciesTargetOverrideDefaultsExcludePattern(t *testing.T) {
	t.Parallel()
	m := newTestManager(t)
	data := []byte(`
policies:
  p1:
    config: {}
    scope:
      targets:
        - host: 10.0.0.1
          override_defaults:
            interface_exclude_patterns:
              - "[bad"
`)
	_, err := m.ParsePolicies(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid")
}

// ─── ensurePort edge: empty host ──────────────────────────────────────────────

func TestEnsurePortEmpty(t *testing.T) {
	t.Parallel()
	require.Equal(t, "", ensurePort("", config.DefaultGNMIPort))
}

func TestEnsurePort(t *testing.T) {
	t.Parallel()
	var dp uint16 = config.DefaultGNMIPort
	cases := map[string]string{
		"10.0.0.1":                 fmt.Sprintf("10.0.0.1:%d", dp),            // IPv4, no port
		"10.0.0.1:830":             "10.0.0.1:830",                            // IPv4 with port (unchanged)
		"router1.example.com":      fmt.Sprintf("router1.example.com:%d", dp), // hostname, no port
		"router1.example.com:9339": "router1.example.com:9339",                // hostname with port (unchanged)
		"2001:db8::1":              fmt.Sprintf("[2001:db8::1]:%d", dp),       // bare IPv6 literal -> bracketed
		"[2001:db8::1]:830":        "[2001:db8::1]:830",                       // bracketed IPv6 with port (unchanged)
		"[2001:db8::1]":            fmt.Sprintf("[2001:db8::1]:%d", dp),       // bracketed IPv6, no port
		"a:b:c":                    "a:b:c",                                   // malformed host:port -> untouched
		"fe80::1%eth0":             fmt.Sprintf("[fe80::1%%eth0]:%d", dp),     // zone-qualified IPv6 -> bracketed
	}
	for in, want := range cases {
		require.Equal(t, want, ensurePort(in, dp), "ensurePort(%q)", in)
	}
}

// ─── filterNotification ──────────────────────────────────────────────────────

// TestFilterNotificationUpdates exercises the update-allowed and update-dropped
// branches of filterNotification.
func TestFilterNotificationUpdates(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	profile, ok := store.Get("_base")
	require.True(t, ok)

	r := &Runner{
		ctx:    context.Background(),
		name:   "filter-test",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
	}

	// Get an allowed path from the profile's subscribe paths.
	allowed := profile.SubscribePaths()
	require.NotEmpty(t, allowed, "profile must have subscribe paths")
	allowedPath := allowed[0]
	disallowedPath := "/some/path/not/in/the/profile/at/all"

	n := gnmi.Notification{
		Updates: []gnmi.Update{
			{Path: allowedPath, Value: "val1"},
			{Path: disallowedPath, Value: "val2"},
		},
	}
	out := r.filterNotification(n, profile)
	require.Len(t, out.Updates, 1, "only the allowed update must survive")
	require.Equal(t, allowedPath, out.Updates[0].Path)
}

// TestFilterNotificationDeletes exercises the delete-allowed and delete-dropped
// branches of filterNotification.
func TestFilterNotificationDeletes(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	profile, ok := store.Get("_base")
	require.True(t, ok)

	r := &Runner{
		ctx:    context.Background(),
		name:   "filter-del-test",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
	}

	// AllowsDelete accepts paths overlapping a curated subtree. Interface and
	// network-instance (VRF/VLAN removal) deletes are curated and must survive;
	// an out-of-scope subtree (e.g. /acl) must be dropped.
	ifaceDelete := "/interfaces/interface[name=Eth1]"
	niDelete := "/network-instances/network-instance[name=blue]"
	disallowedDelete := "/acl/acl-sets[name=foo]"

	n := gnmi.Notification{
		Deletes: []string{ifaceDelete, niDelete, disallowedDelete},
	}
	out := r.filterNotification(n, profile)
	require.Len(t, out.Deletes, 2, "curated interface + network-instance deletes survive; /acl is dropped")
	require.Contains(t, out.Deletes, ifaceDelete)
	require.Contains(t, out.Deletes, niDelete)
}

// TestFilterNotificationNoUpdatesNoDeletes verifies that a notification with
// neither updates nor deletes is returned unchanged.
func TestFilterNotificationNoUpdatesNoDeletes(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	profile, ok := store.Get("_base")
	require.True(t, ok)

	r := &Runner{
		ctx:    context.Background(),
		name:   "filter-empty",
		states: map[string]*targetState{},
		logger: slog.Default(),
	}
	n := gnmi.Notification{SyncDone: true}
	out := r.filterNotification(n, profile)
	require.True(t, out.SyncDone)
	require.Empty(t, out.Updates)
	require.Empty(t, out.Deletes)
}

// ─── selectProfile ────────────────────────────────────────────────────────────

// TestSelectProfileVendorMatch verifies that caps.Vendor triggers a non-_base
// profile when one matches.
func TestSelectProfileVendorMatch(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	r := &Runner{
		ctx:    context.Background(),
		name:   "sel-test",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
		store:  store,
		policy: config.Policy{Config: config.PolicyConfig{}},
	}

	caps := &gnmi.CapabilitiesResult{Vendor: "Arista"}
	p := r.selectProfile(config.Target{Host: "h:1"}, caps)
	require.NotEqual(t, "_base", p.Name, "Arista vendor string must match an Arista profile")
}

// TestSelectProfilePrefersNOS verifies that the NOS hint biases profile
// selection: a Dell-built SONiC box (Vendor "Dell", NOS "SONiC") selects the
// sonic overlay, not dell_os10 — while plain Dell OS10 (no NOS) selects dell_os10.
func TestSelectProfilePrefersNOS(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	r := &Runner{
		ctx:    context.Background(),
		name:   "sel-nos",
		states: map[string]*targetState{"h:1": {}, "h:2": {}},
		logger: slog.Default(),
		store:  store,
		policy: config.Policy{Config: config.PolicyConfig{}},
	}

	dellSonic := r.selectProfile(config.Target{Host: "h:1"}, &gnmi.CapabilitiesResult{Vendor: "Dell", NOS: "SONiC"})
	require.Equal(t, "sonic", dellSonic.Name, "NOS hint SONiC must select the sonic overlay over dell_os10")

	dellOS10 := r.selectProfile(config.Target{Host: "h:2"}, &gnmi.CapabilitiesResult{Vendor: "Dell"})
	require.Equal(t, "dell_os10", dellOS10.Name, "plain Dell (no NOS) selects dell_os10")
}

// TestSelectProfileNilCaps verifies that nil capabilities fall back to _base.
func TestSelectProfileNilCaps(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	r := &Runner{
		ctx:    context.Background(),
		name:   "sel-nil",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
		store:  store,
		policy: config.Policy{Config: config.PolicyConfig{}},
	}
	p := r.selectProfile(config.Target{Host: "h:1"}, nil)
	require.Equal(t, "_base", p.Name)
}

// TestSelectProfilePinnedValid verifies that a pinned, known profile is returned directly.
func TestSelectProfilePinnedValid(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	r := &Runner{
		ctx:    context.Background(),
		name:   "sel-pinned",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
		store:  store,
		policy: config.Policy{Config: config.PolicyConfig{}},
	}
	p := r.selectProfile(config.Target{Host: "h:1", Profile: "arista_eos"}, nil)
	require.Equal(t, "arista_eos", p.Name)
}

// TestSelectProfilePinnedUnknownFallsBack covers the "pinned profile not found"
// warning + fallback path in selectProfile (profile was valid at StartPolicy time
// but is gone at dial time).
func TestSelectProfilePinnedUnknownFallsBack(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	r := &Runner{
		ctx:    context.Background(),
		name:   "sel-gone",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
		store:  store,
		policy: config.Policy{Config: config.PolicyConfig{}},
	}
	// "ghost_profile" was never loaded
	p := r.selectProfile(config.Target{Host: "h:1", Profile: "ghost_profile"}, nil)
	// must fall back to whatever Match returns (likely _base for empty vendor)
	require.NotNil(t, p)
}

// TestSelectProfileUnknownVendorFallsToBase verifies that an unrecognized vendor
// returns _base (and counts the metric).
func TestSelectProfileUnknownVendorFallsToBase(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	r := &Runner{
		ctx:    context.Background(),
		name:   "sel-unknown-vendor",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
		store:  store,
		policy: config.Policy{Config: config.PolicyConfig{}},
	}
	caps := &gnmi.CapabilitiesResult{Vendor: "ClearlyFakeVendorXYZZY"}
	p := r.selectProfile(config.Target{Host: "h:1"}, caps)
	require.Equal(t, "_base", p.Name)
}

// ─── deliverGet ───────────────────────────────────────────────────────────────

// TestRunnerGetModeIngests drives a runner in explicit "get" mode (mode: get) so
// that deliverGet is exercised: first poll fires immediately, ingest happens,
// then the ticker loop runs at least once more.
func TestRunnerGetModeIngests(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	// GetOnce returns a hostname update — enough to identify the device.
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"},
		GetResult: gnmi.Notification{
			Updates: []gnmi.Update{
				{Path: "/system/state/hostname", Value: "gw1"},
			},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode:          config.ModeGet,
			GetIntervalMs: 50, // short interval so the ticker loop fires in-test
			DebounceMs:    10,
			Defaults:      config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.3:9339"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "get-test", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	// First GetOnce fires immediately, flush happens.
	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond,
		"deliverGet must ingest on first poll")
	// Let the ticker fire at least once more to exercise the loop body.
	require.Eventually(t, func() bool { return client.count() >= 2 }, 2*time.Second, 20*time.Millisecond,
		"deliverGet must ingest on subsequent polls")
}

// TestRunnerGetModeGetError verifies that a GetOnce failure is returned as an
// error (causing targetLoop to log + reconnect), not swallowed.
func TestRunnerGetModeGetError(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	dialErr := errors.New("get rpc failed")
	fake := &gnmi.FakeSession{
		Caps:   &gnmi.CapabilitiesResult{Vendor: "Arista"},
		GetErr: dialErr,
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode:          config.ModeGet,
			GetIntervalMs: 100,
			DebounceMs:    10,
			Defaults:      config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "get-err", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.backoffBase = 10 * time.Millisecond
	r.Start()
	defer func() { _ = r.Stop() }()

	// The error must surface in the target's LastError.
	require.Eventually(t, func() bool {
		for _, ts := range r.TargetStatuses() {
			if ts.Host == "h:1" && ts.LastError != "" {
				return true
			}
		}
		return false
	}, 2*time.Second, 20*time.Millisecond, "GetOnce error must appear in TargetStatuses.LastError")
}

// allRejectSession is a gnmi.Session that rejects every Subscribe mode
// synchronously (simulating a target that advertises neither ON_CHANGE nor
// SAMPLE), so the auto-ladder falls through all the way to deliverGet.
type allRejectSession struct {
	caps      *gnmi.CapabilitiesResult
	getResult gnmi.Notification
	stopSubs  int32 // count of StopSubscribe calls (race-safe via atomic)
}

func (s *allRejectSession) Capabilities(_ context.Context) (*gnmi.CapabilitiesResult, error) {
	return s.caps, nil
}

func (s *allRejectSession) Subscribe(_ context.Context, _ gnmi.Mode, _ []string, _ int) (<-chan gnmi.Notification, <-chan error, error) {
	return nil, nil, errors.New("mode not supported by this test target")
}

func (s *allRejectSession) GetOnce(_ context.Context, _ []string) (gnmi.Notification, error) {
	return s.getResult, nil
}
func (s *allRejectSession) GetConfig(_ context.Context) ([]byte, error) { return nil, nil }
func (s *allRejectSession) StopSubscribe()                              { atomic.AddInt32(&s.stopSubs, 1) }
func (s *allRejectSession) Close() error                                { return nil }

type allRejectDialer struct{ sess *allRejectSession }

func (d *allRejectDialer) Dial(_ context.Context, _ gnmi.TargetSpec) (gnmi.Session, error) {
	return d.sess, nil
}

// TestRunnerAutoFallsBackToGet covers the full auto-ladder path where both
// ON_CHANGE and SAMPLE are rejected synchronously, so the runner falls through
// to deliverGet. allRejectSession makes both Subscribe calls fail immediately.
func TestRunnerAutoFallsBackToGet(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	sess := &allRejectSession{
		caps: &gnmi.CapabilitiesResult{Vendor: "Arista"},
		getResult: gnmi.Notification{
			Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "fallback1"}},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode:             config.ModeAuto,
			DebounceMs:       10,
			SampleIntervalMs: 30,
			GetIntervalMs:    50,
			Defaults:         config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.5:9339"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "auto-get-fallback", pol, client,
		&allRejectDialer{sess: sess}, store)
	require.NoError(t, err)
	r.backoffBase = 5 * time.Millisecond
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 3*time.Second, 20*time.Millisecond,
		"auto-ladder must fall through to GET and ingest")
	require.Eventually(t, func() bool {
		for _, ts := range r.TargetStatuses() {
			if ts.Host == "10.0.0.5:9339" && ts.ActiveMode == "get" {
				return true
			}
		}
		return false
	}, 2*time.Second, 20*time.Millisecond, "active_mode must become get after full fallback")
	require.GreaterOrEqual(t, atomic.LoadInt32(&sess.stopSubs), int32(1),
		"StopSubscribe must be called to tear down the prior subscription before GET fallback")
}

// TestRunnerCapabilitiesError covers the Capabilities-failure path in runOnce:
// the error is logged / surfaced in LastError but discovery continues with _base.
func TestRunnerCapabilitiesError(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	fake := &gnmi.FakeSession{
		CapsErr:         errors.New("TLS handshake failed"),
		OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r-caps-err"}}},
			{SyncDone: true},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode:       config.ModeOnChange,
			DebounceMs: 20,
			Defaults:   config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "caps-err", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	// ingest still proceeds despite caps error (_base is used)
	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond,
		"caps error must not block discovery — _base must be used and ingest must succeed")
}

// TestRunnerNetboxIDOnDevice verifies that a target with netbox_id threads the
// source_match key onto the Device entity so the flush is never gated on a name.
func TestRunnerNetboxIDOnDevice(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		// No hostname update — the device would normally be skipped without netbox_id.
		OnChangeStream: []gnmi.Notification{
			{SyncDone: true},
		},
	}
	client := &recordingClient{}
	nbID := 42
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode:       config.ModeOnChange,
			DebounceMs: 20,
			Defaults:   config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1", NetboxID: &nbID}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "netbox-id-test", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond,
		"target with netbox_id must ingest even without a hostname leaf")

	last := client.lastIngested()
	dev, ok := last[0].(*diode.Device)
	require.True(t, ok)
	require.NotNil(t, dev.Metadata["source_match"])
}

// ─── debounce loop: timer-reset branch ────────────────────────────────────────

// TestDebouncerRearmWhileArmed verifies that triggering while the timer is
// already armed (and the timer has fired between the two triggers) drains
// timer.C correctly and re-arms — covering the "drain a possibly-fired timer"
// branch in loop(). Strategy: arm with a very short window so the timer fires
// before the second trigger, then trigger again.
func TestDebouncerRearmWhileArmed(t *testing.T) {
	t.Parallel()
	// Use a short window so the first trigger arms and the timer fires quickly.
	d := NewDebouncer(5 * time.Millisecond)
	defer d.Stop()

	d.Trigger() // first arm
	// Wait for the timer to fire (drains the fired channel) then trigger again;
	// the second trigger must drain timer.C and re-arm — covering that branch.
	<-d.C() // first fire

	d.Trigger() // second arm — re-arms an already-fired timer
	select {
	case <-d.C(): // second fire — branch was covered
	case <-time.After(500 * time.Millisecond):
		t.Fatal("debouncer did not re-fire after re-arm")
	}
}

// TestDebouncerTimerNotArmedBranch covers the path where Trigger fires when the
// timer is NOT yet armed (armed=false at start), so the !armed guard skips the
// drain. This is the normal first-trigger path with a zero-window debouncer.
func TestDebouncerTimerNotArmedBranch(t *testing.T) {
	t.Parallel()
	d := NewDebouncer(0) // zero window: armed=false when first trigger arrives
	defer d.Stop()

	d.Trigger()
	select {
	case <-d.C():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("debouncer with zero window did not fire")
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// minimalPolicy returns a minimal valid policy with a single target.
func minimalPolicy(host string) config.Policy {
	return config.Policy{
		Config: config.PolicyConfig{
			Mode:       config.ModeOnChange,
			DebounceMs: 20,
			Defaults:   config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: host}}},
	}
}

// minimalOnChangePolicy is the same as minimalPolicy but using ON_CHANGE — handy
// alias so test names stay readable.
func minimalOnChangePolicy(host string) config.Policy { return minimalPolicy(host) }

// newManagerWithFake builds a Manager wired to the given FakeSession and also
// returns a recordingClient so callers can assert ingests.
func newManagerWithFake(t *testing.T, fake *gnmi.FakeSession) (*Manager, *recordingClient) {
	t.Helper()
	client := &recordingClient{}
	m, err := NewManager(context.Background(), slog.Default(), client,
		&gnmi.FakeDialer{Session: fake}, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Stop() })
	return m, client
}

// TestDeliverGetReflushesOnDebounce verifies the GET-mode ingest-retry path: the
// single-flight retry timer fires deb.Trigger() on a transient Diode transport
// failure, and deliverGet must consume deb.C() and re-flush (previously it only
// watched the ticker, so the 5s retry was a no-op until the next get poll).
func TestDeliverGetReflushesOnDebounce(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	base, ok := store.Get("_base")
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Runner{
		ctx:    ctx,
		name:   "get-retry",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
		// Huge interval so the ticker never fires during the test — the only extra
		// flush must come from the debouncer (the retry path under test).
		policy: config.Policy{Config: config.PolicyConfig{GetIntervalMs: 600000}},
	}
	fake := &gnmi.FakeSession{GetResult: gnmi.Notification{
		Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "gw1"}},
	}}
	deb := NewDebouncer(5 * time.Millisecond)
	defer deb.Stop()

	var flushes int32
	flush := func() { atomic.AddInt32(&flushes, 1) }

	done := make(chan struct{})
	go func() {
		_ = r.deliverGet("h:1", fake, base, mapping.NewDeviceModel(), deb, flush)
		close(done)
	}()

	// Initial do() flushes once.
	require.Eventually(t, func() bool { return atomic.LoadInt32(&flushes) >= 1 }, 2*time.Second, 10*time.Millisecond,
		"deliverGet must flush on the initial poll")
	// Simulate the retry timer firing: deb.Trigger -> deliverGet consumes deb.C() -> re-flush.
	deb.Trigger()
	require.Eventually(t, func() bool { return atomic.LoadInt32(&flushes) >= 2 }, 2*time.Second, 10*time.Millisecond,
		"deliverGet must re-flush when the debouncer fires (GET-mode ingest retry)")

	cancel()
	<-done
}
