package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// An early stream failure keeps the target's gRPC status readable, so the
// code that refused the stream is not lost behind the sentinel.
func TestEarlyStreamFailureKeepsTheStatusCode(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Runner{ctx: ctx, logger: slog.Default(), states: map[string]*targetState{}}

	errs := make(chan error, 1)
	errs <- status.Error(codes.InvalidArgument, "on_change not supported")
	deb := NewDebouncer(0)
	defer deb.Stop()
	got := r.streamLoop("h", base, 0, make(chan gnmi.Notification), errs, mapping.NewDeviceModel(), deb, func() {})

	require.ErrorIs(t, got, errEarlyStreamFailure)
	require.Equal(t, codes.InvalidArgument, status.Code(got))
}

func capsRefused(c codes.Code, first int32) func(int32) error {
	return func(call int32) error {
		if first == 0 || call <= first {
			return status.Error(c, "refused")
		}
		return nil
	}
}

// A short refusal of Capabilities redials instead of deciding the connection:
// the next connection negotiates from the device's answer, here PROTO for the
// stream, and runs clean.
func TestCapabilitiesRefusedOnceRedialsAndNegotiates(t *testing.T) {
	srv := &gnmiTarget{
		capsErr:   capsRefused(codes.Unauthenticated, 1),
		encodings: []gnmiproto.Encoding{gnmiproto.Encoding_JSON_IETF, gnmiproto.Encoding_PROTO},
	}
	r, client, d, _ := runAgainst(t, srv, config.ModeOnChange, nil)

	requireSettled(t, client, d, 2)
	require.EqualValues(t, 2, d.dials.Load())
	require.EqualValues(t, 1, srv.subs.Load(), "the refused attempt subscribed to nothing")
	require.Equal(t, []gnmiproto.Encoding{gnmiproto.Encoding_PROTO}, srv.subscribeEncodings(),
		"the stream uses the encoding Capabilities offered")
	require.Empty(t, targetStatus(t, r).DegradedReason)
}

// A device that refuses Capabilities on every attempt but serves Subscribe
// goes on with _base after three attempts, as it always did on the first, and
// says why in its status.
func TestCapabilitiesRefusedEveryTimeIngestsOnBaseAfterThreeAttempts(t *testing.T) {
	srv := &gnmiTarget{capsErr: capsRefused(codes.Unavailable, 0)}
	r, client, d, logs := runAgainst(t, srv, config.ModeAuto, nil)

	requireSettled(t, client, d, capsAttempts)
	require.EqualValues(t, capsAttempts, d.dials.Load())
	require.EqualValues(t, 1, srv.subs.Load(), "only the last attempt went past Capabilities")
	st := targetStatus(t, r)
	require.Contains(t, st.DegradedReason, "capabilities failed on 3 attempts in a row")
	require.Contains(t, logs.String(), "profile=_base")
}

// A connection on _base that never synced does not make the next ones skip
// Capabilities: they go back to redialling through it, one RPC each.
func TestBaseConnectionThatNeverSyncedRestartsTheCount(t *testing.T) {
	srv := &gnmiTarget{
		capsErr: capsRefused(codes.Unavailable, 0),
		getErr:  always(codes.Unavailable),
		subErr:  always(codes.Unavailable),
	}
	_, _, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

	require.Eventually(t, func() bool { return d.dials.Load() >= 2*capsAttempts+1 }, 5*time.Second, 10*time.Millisecond)
	// Three Capabilities, the _base attempt's Gets and subscriptions, then
	// three Capabilities again.
	require.Regexp(t, `^CCC[GS]*S[GS]*CCC`, srv.eventLog())
}

// Unimplemented is the device's answer, not a refusal to wait out: _base at
// once, on the first connection.
func TestCapabilitiesUnimplementedUsesBaseAtOnce(t *testing.T) {
	srv := &gnmiTarget{capsErr: capsRefused(codes.Unimplemented, 0)}
	r, client, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

	requireSettled(t, client, d, 1)
	require.Empty(t, targetStatus(t, r).DegradedReason)
}

// A Capabilities call that never answers ends at the setup deadline and is
// retried like any other transient failure.
func TestCapabilitiesHangTimesOut(t *testing.T) {
	srv := &gnmiTarget{capsHang: true}
	r, client, d, _ := runAgainst(t, srv, config.ModeAuto, func(r *Runner) { r.setupTimeout = 50 * time.Millisecond })

	require.Eventually(t, func() bool {
		st := r.TargetStatuses()
		return len(st) == 1 && strings.Contains(st[0].LastError, "DeadlineExceeded")
	}, 2*time.Second, 10*time.Millisecond)
	require.GreaterOrEqual(t, d.dials.Load(), int32(1))
	requireSettled(t, client, d, capsAttempts)
	require.Contains(t, targetStatus(t, r).DegradedReason, "capabilities")
}

// capsScriptSession answers Capabilities from its dialer's script, one entry
// per call; a nil entry, or a call past the end, answers.
type capsScriptSession struct {
	*gnmi.FakeSession
	d *capsScriptDialer
}

func (s *capsScriptSession) Capabilities(context.Context) (*gnmi.CapabilitiesResult, error) {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	s.d.events.WriteString("C")
	s.d.calls++
	if n := s.d.calls; n <= len(s.d.script) && s.d.script[n-1] != nil {
		return nil, s.d.script[n-1]
	}
	return &gnmi.CapabilitiesResult{Vendor: "Example"}, nil
}

func (s *capsScriptSession) Subscribe(ctx context.Context, mode gnmi.Mode, paths []string, iv int) (<-chan gnmi.Notification, <-chan error, error) {
	s.d.mu.Lock()
	s.d.events.WriteString("S")
	s.d.mu.Unlock()
	return s.FakeSession.Subscribe(ctx, mode, paths, iv)
}

// capsScriptDialer hands out sessions that stream a hostname and a sync, then
// drop the stream on the dials dropStream picks.
type capsScriptDialer struct {
	script     []error
	dropStream func(dial int32) bool
	noOnChange bool // Subscribe(on_change) is refused, so no connection syncs
	dialErr    func(dial int32) error
	onDial     func()
	dials      atomic.Int32

	mu     sync.Mutex
	calls  int
	events strings.Builder // C per Capabilities, S per Subscribe
}

func (d *capsScriptDialer) Dial(context.Context, gnmi.TargetSpec) (gnmi.Session, error) {
	dial := d.dials.Add(1)
	if d.onDial != nil {
		d.onDial()
	}
	if d.dialErr != nil {
		if err := d.dialErr(dial); err != nil {
			return nil, err
		}
	}
	fake := &gnmi.FakeSession{
		OnChangeSupport: !d.noOnChange,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "sw1"}}},
			{SyncDone: true},
		},
	}
	if d.dropStream != nil && d.dropStream(dial) {
		fake.StreamErr = status.Error(codes.Unavailable, "stream reset")
	}
	return &capsScriptSession{FakeSession: fake, d: d}, nil
}

func (d *capsScriptDialer) eventLog() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.events.String()
}

func capsScriptRunner(t *testing.T, store *mapping.Store, dialer *capsScriptDialer) (*Runner, *recordingClient, *syncBuf) {
	t.Helper()
	return capsScriptRunnerWith(t, store, dialer, 5*time.Millisecond, nil)
}

func capsScriptRunnerWith(t *testing.T, store *mapping.Store, dialer *capsScriptDialer, backoff time.Duration,
	tune func(*Runner),
) (*Runner, *recordingClient, *syncBuf) {
	t.Helper()
	logs := &syncBuf{}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeOnChange, DebounceMs: 10, Defaults: config.Defaults{Site: "lab", Role: "router"}},
		Scope:  config.Scope{Targets: []config.Target{{Host: "192.0.2.30:57400"}}},
	}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r, err := NewRunner(context.Background(), logger, "p1", pol, client, dialer, store)
	require.NoError(t, err)
	r.backoffBase = backoff
	if tune != nil {
		tune(r)
	}
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })
	return r, client, logs
}

// The failures that send a target to _base are consecutive: a Capabilities
// answer in between starts the count again.
func TestCapabilitiesAnswerRestartsTheFailureCount(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	refused := status.Error(codes.Unavailable, "refused")
	dialer := &capsScriptDialer{
		script:     []error{refused, nil, refused, refused, refused},
		dropStream: func(int32) bool { return true },
	}
	capsScriptRunner(t, store, dialer)

	require.Eventually(t, func() bool { return dialer.dials.Load() >= 6 }, 5*time.Second, 5*time.Millisecond)
	require.Regexp(t, `^CCSCCCS`, dialer.eventLog())
}

// The degraded reason stays through the degraded session's flushes and is
// cleared by the next connection that sets up clean.
func TestCleanSetupClearsTheDegradedReason(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	refused := status.Error(codes.Unavailable, "refused")
	dialer := &capsScriptDialer{
		script:     []error{refused, refused, refused},
		dropStream: func(dial int32) bool { return dial == capsAttempts },
	}
	r, _, _ := capsScriptRunner(t, store, dialer)

	// Dial 4 answers Capabilities; once it has subscribed, its setup is done.
	require.Eventually(t, func() bool {
		return dialer.dials.Load() == capsAttempts+1 && strings.Count(dialer.eventLog(), "S") == 2 &&
			targetStatus(t, r).DegradedReason == ""
	}, 5*time.Second, 5*time.Millisecond)
}

// The profile and the manufacturer come from the Capabilities answer that
// followed the refusal, not from _base.
func TestCapabilitiesRefusedOnceSelectsTheProfileFromTheAnswer(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "example.yaml"),
		[]byte("extends: _base\nmatch:\n  vendor: Example\n"), 0o600))
	store, err := mapping.LoadProfiles(dir)
	require.NoError(t, err)

	dialer := &capsScriptDialer{script: []error{status.Error(codes.Unauthenticated, "refused")}}
	_, client, logs := capsScriptRunner(t, store, dialer)

	require.Eventually(t, func() bool { return client.count() > 0 }, 2*time.Second, 10*time.Millisecond)
	require.EqualValues(t, 2, dialer.dials.Load())
	require.Contains(t, logs.String(), "profile=example")
	require.NotContains(t, logs.String(), "profile=_base")
	require.Equal(t, "Example", *ingestedDevice(t, client).DeviceType.Manufacturer.Name)
}

// Paths a probe kept without an answer leave the session degraded; the next
// connection probes them again and, answered, runs clean.
func TestUnansweredProbeDegradesUntilTheNextConnection(t *testing.T) {
	var refusing atomic.Bool
	refusing.Store(true)
	srv := &gnmiTarget{getErr: func([]string) error {
		if refusing.Load() {
			return status.Error(codes.Unauthenticated, "AAA server timeout")
		}
		return nil
	}}
	r, client, d, _ := runAgainst(t, srv, config.ModeOnChange, nil)

	require.Eventually(t, func() bool { return client.count() > 0 }, 5*time.Second, 10*time.Millisecond)
	require.Contains(t, targetStatus(t, r).DegradedReason, "path probe")
	require.Equal(t, "SN-0001", *ingestedDevice(t, client).Serial, "every path kept")

	refusing.Store(false)
	gets := srv.gets.Load()
	srv.dropStreams()
	require.Eventually(t, func() bool {
		return d.dials.Load() >= 2 && client.count() > 1 && targetStatus(t, r).DegradedReason == ""
	}, 5*time.Second, 10*time.Millisecond)
	require.Greater(t, srv.gets.Load(), gets, "the new connection probed again")
}

// GET mode uses no probe, so a probe that got no answer on the way down the
// auto ladder does not mark the Get session degraded.
func TestGetRungDoesNotCarryTheProbe(t *testing.T) {
	srv := &gnmiTarget{subErr: always(codes.Unavailable)}
	// The probes of both streaming rungs get no answer; the Get polls do.
	srv.getErr = func([]string) error {
		if !srv.sawSample.Load() {
			return status.Error(codes.Unavailable, "busy")
		}
		return nil
	}
	r, client, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

	requireSettled(t, client, d, 1)
	st := targetStatus(t, r)
	require.Equal(t, "get", st.ActiveMode)
	require.Empty(t, st.DegradedReason)
}

// refuseComponents refuses, while on, every Get that asks for a component leaf.
func refuseComponents(c codes.Code, on *atomic.Bool) func([]string) error {
	return func(paths []string) error {
		if !on.Load() {
			return nil
		}
		for _, p := range paths {
			if strings.HasPrefix(p, "/components/") {
				return status.Error(c, "refused")
			}
		}
		return nil
	}
}

// getPoll runs a GET target, then refuses its component paths with code c and
// returns the device of a poll made entirely under that refusal. The serial
// changes on the device meanwhile, so a value carried forward shows as the old one.
func getPoll(t *testing.T, c codes.Code) (*diode.Device, TargetStatus) {
	t.Helper()
	var refusing atomic.Bool
	srv := &gnmiTarget{getErr: refuseComponents(c, &refusing)}
	r, client, _, _ := runAgainst(t, srv, config.ModeGet, func(r *Runner) { r.policy.Config.GetIntervalMs = 30 })

	require.Eventually(t, func() bool { return client.count() > 0 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, "SN-0001", *ingestedDevice(t, client).Serial)

	// Refused first, so no poll can fetch the new serial before the refusal.
	refusing.Store(true)
	srv.serial.Store("SN-0002")
	n := client.count()
	require.Eventually(t, func() bool { return client.count() >= n+2 }, 5*time.Second, 10*time.Millisecond)
	return ingestedDevice(t, client), targetStatus(t, r)
}

// A path whose Get failed with a transient code keeps what the previous poll
// found, rather than flipping the device type for a poll.
func TestGetPollKeepsAPathThatFailedTransiently(t *testing.T) {
	for _, c := range []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.Unauthenticated, codes.Aborted} {
		t.Run(c.String(), func(t *testing.T) {
			dev, st := getPoll(t, c)
			require.Equal(t, "MODEL-1", *dev.DeviceType.Model)
			require.NotNil(t, dev.Serial)
			require.Equal(t, "SN-0001", *dev.Serial, "the previous poll's value, not a fresh one")
			require.Equal(t, 1, strings.Count(st.DegradedReason, "Get poll"), "said once, however many polls")
		})
	}
}

// Any other code drops the path for that poll, as before.
func TestGetPollDropsAPathTheTargetRefuses(t *testing.T) {
	for _, c := range []codes.Code{
		codes.InvalidArgument, codes.Unimplemented, codes.NotFound,
		codes.PermissionDenied, codes.Internal, codes.Unknown, codes.FailedPrecondition,
	} {
		t.Run(c.String(), func(t *testing.T) {
			dev, st := getPoll(t, c)
			require.Equal(t, "Unknown", *dev.DeviceType.Model)
			require.Nil(t, dev.Serial)
			require.Empty(t, st.DegradedReason)
		})
	}
}

// degraded_reason is an additive /status field, left out when empty.
func TestDegradedReasonInStatusJSON(t *testing.T) {
	b, err := json.Marshal(TargetStatus{Host: "192.0.2.1:57400", DegradedReason: "reason"})
	require.NoError(t, err)
	require.Contains(t, string(b), `"degraded_reason":"reason"`)
	b, err = json.Marshal(TargetStatus{Host: "192.0.2.1:57400"})
	require.NoError(t, err)
	require.NotContains(t, string(b), "degraded_reason")
}

// specDialer records the specs it is asked to dial.
type specDialer struct {
	countingGnmicDialer
	mu    sync.Mutex
	specs []gnmi.TargetSpec
}

func (d *specDialer) Dial(ctx context.Context, spec gnmi.TargetSpec) (gnmi.Session, error) {
	d.mu.Lock()
	d.specs = append(d.specs, spec)
	d.mu.Unlock()
	return d.countingGnmicDialer.Dial(ctx, spec)
}

// One setup timeout bounds Capabilities and the path probe: the runner hands
// its own to the session it dials.
func TestRunnerHandsItsSetupTimeoutToTheSession(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	r, err := NewRunner(context.Background(), slog.Default(), "p1", config.Policy{}, &recordingClient{}, &specDialer{}, store)
	require.NoError(t, err)
	require.Equal(t, gnmi.SetupTimeout, r.setupTimeout)

	addr := startGNMITarget(t, &gnmiTarget{})
	d := &specDialer{}
	_, _, _, _ = runAgainstWith(t, addr, d, config.ModeOnChange, func(r *Runner) { r.setupTimeout = 1234 * time.Millisecond })
	require.Eventually(t, func() bool { return d.dials.Load() > 0 }, 2*time.Second, 5*time.Millisecond)
	d.mu.Lock()
	defer d.mu.Unlock()
	require.Equal(t, 1234*time.Millisecond, d.specs[0].SetupTimeout)
}

// A slow, strict device: every Get takes 400 ms, and it refuses any Get or
// Subscribe that names a subtree it does not model. The probe must reach every
// path within the setup deadline (scaled down here from 30 s), so that subtree
// is pruned and the device streams, hostname included.
func TestSlowStrictDeviceStreams(t *testing.T) {
	unmodelled := func(paths []string) bool {
		for _, p := range paths {
			if strings.Contains(p, "switched-vlan") {
				return true
			}
		}
		return false
	}
	srv := &gnmiTarget{
		getErr: func(paths []string) error {
			time.Sleep(400 * time.Millisecond)
			if unmodelled(paths) {
				return status.Error(codes.InvalidArgument, "unknown path")
			}
			return nil
		},
		subErr: func(paths []string) error {
			if unmodelled(paths) {
				return status.Error(codes.InvalidArgument, "unknown path in subscription")
			}
			return nil
		},
	}
	r, client, _, _ := runAgainst(t, srv, config.ModeAuto, func(r *Runner) { r.setupTimeout = 4 * time.Second })

	require.Eventually(t, func() bool { return client.count() > 0 }, 15*time.Second, 20*time.Millisecond)
	require.Equal(t, "sw1", *ingestedDevice(t, client).Name)
	require.Equal(t, "on_change", targetStatus(t, r).ActiveMode)
}

// A device that refuses ON_CHANGE outright and answers NotFound for a list it
// holds nothing in: the refusal is the mode's, so the sample rung still
// subscribes to that list.
func TestOnChangeRefusalKeepsNotFoundPathsForSample(t *testing.T) {
	srv := &gnmiTarget{}
	srv.getErr = func(paths []string) error {
		for _, p := range paths {
			if strings.Contains(p, "/vlans/vlan/") {
				return status.Error(codes.NotFound, "no vlans")
			}
		}
		return nil
	}
	srv.subErr = func([]string) error {
		if !srv.sawSample.Load() {
			return status.Error(codes.InvalidArgument, "ON_CHANGE not supported")
		}
		return nil
	}
	r, client, _, _ := runAgainst(t, srv, config.ModeAuto, nil)

	require.Eventually(t, func() bool { return client.count() > 0 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, "sample", targetStatus(t, r).ActiveMode)
	reqs := srv.subscribeRequests()
	last := reqs[len(reqs)-1]
	require.True(t, slices.ContainsFunc(last, func(p string) bool { return strings.Contains(p, "/vlans/vlan/") }),
		"the sample subscription keeps the empty list: %v", last)
}

// The runner pins the profile's hostname path, so no retry drops it.
func TestRunnerPinsTheHostnamePath(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		OnChangeSupport: true,
		OnChangeStream:  []gnmi.Notification{{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "sw1"}}}, {SyncDone: true}},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeOnChange, DebounceMs: 10, Defaults: config.Defaults{Site: "lab", Role: "router"}},
		Scope:  config.Scope{Targets: []config.Target{{Host: "192.0.2.40:57400"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p1", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	require.Eventually(t, func() bool { return client.count() > 0 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, r.Stop())
	require.Equal(t, []string{"/system/state/hostname"}, fake.Pinned)
}

// A device that never answers Get is probed once per connection, not once
// per rung of the auto ladder.
func TestUnansweredProbeIsNotRepeatedPerRung(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	srv := &gnmiTarget{getErr: always(codes.Unavailable)}
	srv.subErr = func([]string) error {
		if !srv.sawSample.Load() {
			return status.Error(codes.InvalidArgument, "ON_CHANGE not supported")
		}
		return nil
	}
	r, client, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

	requireSettled(t, client, d, 1)
	require.Equal(t, "sample", targetStatus(t, r).ActiveMode)
	require.EqualValues(t, 1+2*len(base.SubscribePaths()), srv.gets.Load(),
		"one multi-path Get, then each path concurrently and once more alone, for the on_change rung only")
}

// Wrong credentials cost few RPCs: the attempts that redial through
// Capabilities cost one each, and the attempt that goes on with _base costs
// no more than an attempt cost before.
func TestWrongCredentialsRPCsPerAttempt(t *testing.T) {
	srv := &gnmiTarget{
		capsErr: capsRefused(codes.Unauthenticated, 0),
		getErr:  always(codes.Unauthenticated),
		subErr:  always(codes.Unauthenticated),
	}
	_, _, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

	require.Eventually(t, func() bool { return d.dials.Load() >= capsAttempts+1 }, 5*time.Second, 5*time.Millisecond)
	attempts := strings.Split(srv.eventLog(), "C")[1:] // each attempt starts with Capabilities
	for i, a := range attempts[:capsAttempts-1] {
		require.Empty(t, a, "attempt %d: Capabilities alone", i+1)
	}
	full := 1 + len(attempts[capsAttempts-1])
	t.Logf("the _base attempt with wrong credentials made %d RPCs (%s)", full, "C"+attempts[capsAttempts-1])
	require.LessOrEqual(t, full, 69, "develop made 69 per attempt")
}

// A path that fails on every poll and never had a value carries nothing
// forward, so the session is not reported degraded for it.
func TestGetPollWithNothingToCarryIsNotDegraded(t *testing.T) {
	srv := &gnmiTarget{getErr: func(paths []string) error {
		for _, p := range paths {
			if strings.Contains(p, "switched-vlan") {
				return status.Error(codes.Unavailable, "busy")
			}
		}
		return nil
	}}
	r, client, _, _ := runAgainst(t, srv, config.ModeGet, func(r *Runner) { r.policy.Config.GetIntervalMs = 30 })

	require.Eventually(t, func() bool { return client.count() >= 3 }, 5*time.Second, 10*time.Millisecond)
	require.Empty(t, targetStatus(t, r).DegradedReason)
}

// A poll that carried values forward marks the session degraded until the
// next clean poll.
func TestGetPollDegradationClearsOnTheNextCleanPoll(t *testing.T) {
	var refusing atomic.Bool
	srv := &gnmiTarget{getErr: refuseComponents(codes.Unavailable, &refusing)}
	r, client, _, _ := runAgainst(t, srv, config.ModeGet, func(r *Runner) { r.policy.Config.GetIntervalMs = 30 })

	require.Eventually(t, func() bool { return client.count() > 0 }, 5*time.Second, 10*time.Millisecond)
	refusing.Store(true)
	require.Eventually(t, func() bool { return targetStatus(t, r).DegradedReason != "" }, 5*time.Second, 5*time.Millisecond)
	refusing.Store(false)
	require.Eventually(t, func() bool { return targetStatus(t, r).DegradedReason == "" }, 5*time.Second, 5*time.Millisecond)
}

// After a _base connection has synced, a reconnect goes on with _base at once,
// and its reason says that rather than counting attempts it did not make.
func TestBaseReasonAfterASyncedBaseConnection(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	refused := status.Error(codes.Unavailable, "refused")
	script := make([]error, 20)
	for i := range script {
		script[i] = refused
	}
	// The _base connection syncs and drops; the next one goes on with _base.
	dialer := &capsScriptDialer{script: script, dropStream: func(dial int32) bool { return dial == capsAttempts }}
	r, client, _ := capsScriptRunner(t, store, dialer)

	require.Eventually(t, func() bool {
		return dialer.dials.Load() == capsAttempts+1 && strings.Count(dialer.eventLog(), "S") == 2
	}, 2*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return client.count() > 0 }, 2*time.Second, 5*time.Millisecond)
	reason := targetStatus(t, r).DegradedReason
	require.Contains(t, reason, "as on the earlier connection that synced")
	require.NotContains(t, reason, "in a row")
}

// A strict device that answers ResourceExhausted to Gets past a small
// concurrency limit still streams: the paths the concurrent probe left without
// an answer are asked again one at a time, so its unsupported subtree is found
// and pruned before the subscription.
func TestConcurrencyLimitedStrictDeviceStreams(t *testing.T) {
	for _, limit := range []int32{1, 2, 4} {
		t.Run(fmt.Sprintf("limit %d", limit), func(t *testing.T) {
			var inflight atomic.Int32
			unmodelled := func(paths []string) bool {
				return slices.ContainsFunc(paths, func(p string) bool { return strings.Contains(p, "/vlans/vlan/") })
			}
			srv := &gnmiTarget{
				getErr: func(paths []string) error {
					defer inflight.Add(-1)
					if inflight.Add(1) > limit {
						return status.Error(codes.ResourceExhausted, "too many concurrent RPCs")
					}
					time.Sleep(30 * time.Millisecond)
					if unmodelled(paths) {
						return status.Error(codes.InvalidArgument, "unknown path")
					}
					return nil
				},
				subErr: func(paths []string) error {
					if unmodelled(paths) {
						return status.Error(codes.InvalidArgument, "unknown path in subscription")
					}
					return nil
				},
			}
			r, client, d, _ := runAgainst(t, srv, config.ModeAuto, nil)

			requireSettled(t, client, d, 1)
			st := targetStatus(t, r)
			require.Equal(t, "on_change", st.ActiveMode)
			require.Empty(t, st.DegradedReason, "every path got an answer in the end")
		})
	}
}
