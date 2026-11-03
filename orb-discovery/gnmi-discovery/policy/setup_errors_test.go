package policy

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	require.Contains(t, st.DegradedReason, "capabilities")
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
	// Three Capabilities, the _base attempt's subscriptions, then three
	// Capabilities again.
	require.Regexp(t, `^CCCS+CCCS`, srv.eventLog())
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
	r, client, _ := capsScriptRunner(t, store, dialer)

	// The degraded connection drops before it flushes; the next one ingests.
	require.Eventually(t, func() bool { return dialer.dials.Load() == capsAttempts+1 && client.count() >= 1 },
		5*time.Second, 5*time.Millisecond)
	require.Empty(t, targetStatus(t, r).DegradedReason)
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

	requireSettled(t, client, d, 3)
	st := targetStatus(t, r)
	require.Equal(t, "get", st.ActiveMode)
	require.Empty(t, st.DegradedReason)
}
