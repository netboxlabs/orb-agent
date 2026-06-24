package policy

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	diodepb "github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// recordingClient captures Ingest calls.
type recordingClient struct {
	mu         sync.Mutex
	ingested   [][]diode.Entity
	lastOptN   int      // number of IngestOptions on the most recent call
	respErrors []string // if set, returned as IngestResponse.Errors (Go err stays nil)
}

func (c *recordingClient) Ingest(_ context.Context, entities []diode.Entity, opts ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ingested = append(c.ingested, entities)
	c.lastOptN = len(opts) // diode.IngestOption is opaque; we can only assert one was passed
	return &diodepb.IngestResponse{Errors: c.respErrors}, nil
}

func (c *recordingClient) IngestProto(context.Context, []*diodepb.Entity, ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	return &diodepb.IngestResponse{}, nil
}
func (c *recordingClient) Close() error { return nil }
func (c *recordingClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ingested)
}

func (c *recordingClient) lastIngested() []diode.Entity {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.ingested) == 0 {
		return nil
	}
	return c.ingested[len(c.ingested)-1]
}

func TestRunnerOnChangeIngests(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeOnChange, DebounceMs: 30, Defaults: config.Defaults{Site: "lab", Role: "router"}},
		Scope:  config.Scope{Targets: []config.Target{{Host: "10.0.0.1:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p1", pol, client,
		&gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)
}

// M6.2 — subscribe-rejection causes auto-fallback to SAMPLE.
func TestRunnerAutoFallsBackToSample(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Nokia"},
		OnChangeSupport: false, // ON_CHANGE rejected
		SampleSnapshots: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "n1"}}, SyncDone: true},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeAuto, DebounceMs: 30, SampleIntervalMs: 100,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.2:57400"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p2", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()
	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)
}

// M6.2 HIGH-3 — a transient stream error must NOT permanently demote the target
// from on_change to sample/get across reconnects.
func TestRunnerAutoDoesNotDemoteOnStreamError(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true, // ON_CHANGE works…
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
		StreamErr: errors.New("transient stream drop"), // …but the stream keeps dropping
	}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeAuto, DebounceMs: 20,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p3", pol, &recordingClient{}, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.backoffBase = 15 * time.Millisecond // force quick reconnects within the test
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	// span several reconnect cycles; active_mode must stay on_change, never sample/get
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case <-deadline:
			return // stayed on_change the whole time -> pass
		default:
			for _, ts := range r.TargetStatuses() {
				if ts.Host == "h:1" {
					require.NotEqual(t, "sample", ts.ActiveMode, "stream error must not demote to sample")
					require.NotEqual(t, "get", ts.ActiveMode)
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// M6.2 — the real gnmic transport reports an ON_CHANGE rejection ASYNCHRONOUSLY:
// Subscribe returns nil and the error arrives on the stream BEFORE any data. The
// auto ladder must treat that early stream failure as "mode unviable" and
// downgrade to SAMPLE (not retry on_change forever). The fake mimics this with
// OnChangeSupport=true (sync Subscribe succeeds), an EMPTY OnChangeStream, and a
// StreamErr that therefore fires before any notification.
func TestRunnerAutoDowngradesOnAsyncOnChangeRejection(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
		OnChangeSupport: true,                                            // sync Subscribe(OnChange) succeeds…
		OnChangeStream:  nil,                                             // …but yields NO data…
		StreamErr:       errors.New("ON_CHANGE not supported by target"), // …then errors early (async rejection)
		SampleSnapshots: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "a1"}}, SyncDone: true},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeAuto, DebounceMs: 20, SampleIntervalMs: 100,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.0.0.9:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p7", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.backoffBase = 15 * time.Millisecond // quick reconnect/downgrade within the test
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond,
		"runner must downgrade to SAMPLE and ingest after the async ON_CHANGE rejection")
	require.Eventually(t, func() bool {
		for _, ts := range r.TargetStatuses() {
			if ts.Host == "10.0.0.9:6030" && ts.ActiveMode == "sample" {
				return true
			}
		}
		return false
	}, time.Second, 20*time.Millisecond, "active_mode must become sample")
}

// M6.2 MED-2 — ON_CHANGE must hold debounced flushes until the initial
// sync_response arrives; a partial pre-sync dump must never be ingested.
func TestRunnerOnChangeHoldsFlushUntilSync(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	// Updates (incl. hostname) arrive but NO sync_response — the fake blocks after
	// replay. A partial initial dump must not be ingested before sync.
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{Updates: []gnmi.Update{{Path: "/interfaces/interface[name=Eth1]/state/admin-status", Value: "UP"}}},
			// no SyncDone
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 20,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p4", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()
	time.Sleep(200 * time.Millisecond) // well past debounce; with no sync, flush stays suppressed
	require.Equal(t, 0, client.count(), "must not ingest a partial device before the initial sync completes")
}

// Codex — SAMPLE must ALSO hold the first debounced flush until the initial
// sync_response (gNMI STREAM/SAMPLE emits one after the first full dump), so a
// slow initial SAMPLE dump can't ingest a partial device. The fake delivers
// hostname+interface data but NO SyncDone, and the prune interval is long enough
// that no prune tick lands within the assertion window — so the only thing that
// could release the flush gate would be a (here-absent) sync_response.
func TestRunnerSampleHoldsFlushUntilSync(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"},
		SampleSnapshots: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{Updates: []gnmi.Update{{Path: "/interfaces/interface[name=Eth1]/state/admin-status", Value: "UP"}}},
			// no SyncDone
		},
		SampleReplay: 2 * time.Second, // don't re-send within the window
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			// long sample interval => prune ticker (the fallback) won't fire in-window
			Mode: config.ModeSample, DebounceMs: 20, SampleIntervalMs: 5000,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p-sample-hold", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()
	time.Sleep(200 * time.Millisecond) // well past debounce; no sync + no prune tick => suppressed
	require.Equal(t, 0, client.count(), "SAMPLE must not ingest a partial device before the initial sync (sync_response) arrives")
}

// Codex — FALLBACK: a non-compliant SAMPLE target that never emits a
// sync_response must still ingest after the first prune tick (one sample
// interval), because rotate() also releases the flush gate (synced=true). The
// fake delivers data with NO SyncDone and a short sample interval; the prune tick
// must eventually flush.
func TestRunnerSampleFlushesViaPruneTickWithoutSync(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"},
		SampleSnapshots: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			// no SyncDone — target never sends sync_response
		},
		SampleReplay: 40 * time.Millisecond,
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			// short sample interval => prune ticker fires quickly and is the only
			// path to synced=true here (no SyncDone in the stream)
			Mode: config.ModeSample, DebounceMs: 20, SampleIntervalMs: 60,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p-sample-fallback", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()
	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond,
		"SAMPLE without sync_response must still ingest after the first prune tick (fallback)")
}

// M6.2 — run_id is stamped on every ingested entity, WithIngestMetadata is
// passed, and a completed run is recorded in the RunStore.
func TestRunnerStampsRunIDAndRecordsRun(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 20,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p5", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)

	// every ingested batch's Device carries a run_id…
	client.mu.Lock()
	last := client.ingested[len(client.ingested)-1]
	optN := client.lastOptN
	client.mu.Unlock()
	dev := last[0].(*diode.Device)
	require.NotEmpty(t, dev.Metadata["run_id"])
	// …and the ingest call also carried WithIngestMetadata (run_id/policy_name).
	require.GreaterOrEqual(t, optN, 1, "ingest must pass WithIngestMetadata")

	// a completed run is recorded for the policy
	require.Eventually(t, func() bool {
		runs := r.Runs()
		return len(runs) >= 1 && runs[0].Status == RunStatusCompleted && runs[0].EntityCount >= 1
	}, time.Second, 20*time.Millisecond)
}

// M6.2 HIGH — resp.Errors (non-nil Go error is nil) must mark the run failed
// and surface the diode error in LastError.
func TestRunnerMarksRunFailedOnDiodeErrors(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
	}
	// Go error is nil but Diode reports per-entity errors — must be a failed run.
	client := &recordingClient{respErrors: []string{"device: name required"}}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 20,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p6", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool {
		runs := r.Runs()
		return len(runs) >= 1 && runs[0].Status == RunStatusFailed
	}, 2*time.Second, 20*time.Millisecond)
	// LastError reflects the diode errors, not cleared as success
	for _, ts := range r.TargetStatuses() {
		if ts.Host == "h:1" {
			require.Contains(t, ts.LastError, "device: name required")
		}
	}
}

// streamLoop drain: when notes closes after the producer already buffered a
// non-nil error on errs, the notes-closed case must drain and return the error
// rather than silently returning nil. This tests the path deterministically by
// closing notes FIRST (so the notes-closed case always wins the select), with
// a pre-buffered error already sitting on errs.
func TestStreamLoopDrainsErrOnNotesClose(t *testing.T) {
	t.Parallel()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	profile, _ := store.Get("_base")

	r := &Runner{
		ctx:    context.Background(),
		name:   "drain-test",
		states: map[string]*targetState{"h:1": {}},
		logger: slog.Default(),
	}

	errs := make(chan error, 1)
	notes := make(chan gnmi.Notification)

	sentinel := errors.New("ON_CHANGE not supported")
	errs <- sentinel // pre-buffer — simulates the race where errs lands before notes closes
	close(notes)     // notes closes first; this is the case that was racy before the fix

	got := r.streamLoop("h:1", profile, 0, notes, errs,
		mapping.NewDeviceModel(), NewDebouncer(0), func() {})

	require.ErrorIs(t, got, errEarlyStreamFailure, "notes-closed drain must surface buffered early-failure as errEarlyStreamFailure")
	_ = sentinel // referenced to keep import alive
}

// M6.3 — TargetStatuses surfaces the active delivery mode after the runner
// connects and sets up the subscription.
func TestRunnerReportsActiveMode(t *testing.T) {
	store, _ := mapping.LoadProfiles("")
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{{SyncDone: true}},
	}
	pol := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeOnChange, DebounceMs: 20},
		Scope:  config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, _ := NewRunner(context.Background(), slog.Default(), "p", pol, &recordingClient{}, &gnmi.FakeDialer{Session: fake}, store)
	r.Start()
	defer func() { _ = r.Stop() }()
	require.Eventually(t, func() bool {
		for _, ts := range r.TargetStatuses() {
			if ts.Host == "h:1" && ts.ActiveMode == "on_change" {
				return true
			}
		}
		return false
	}, time.Second, 20*time.Millisecond)
}

func TestRunnerSetsPrimaryIPFromHost(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{
				{Path: "/system/state/hostname", Value: "r1"},
				{Path: "/interfaces/interface[name=Loopback0]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.7.7.7]/state/prefix-length", Value: 32},
			}},
			{SyncDone: true},
		},
	}
	client := &recordingClient{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeOnChange, DebounceMs: 20,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: "10.7.7.7:6030"}}},
	}
	r, err := NewRunner(context.Background(), slog.Default(), "p", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)
	last := client.lastIngested()
	dev := last[0].(*diode.Device)
	require.NotNil(t, dev.PrimaryIp4)
	require.Equal(t, "10.7.7.7/32", *dev.PrimaryIp4.Address)
}

func TestTargetHostIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.7.7.7:6030", "10.7.7.7"},         // IPv4 host:port
		{"10.7.7.7", "10.7.7.7"},              // bare IPv4
		{"[2001:db8::1]:6030", "2001:db8::1"}, // bracketed IPv6 host:port
		{"[2001:db8::1]", "2001:db8::1"},      // bracketed IPv6, no port
		{"2001:db8::1", "2001:db8::1"},        // bare IPv6 (SplitHostPort fails -> used as-is)
		{"[fe80::1%eth0]:6030", "fe80::1"},    // zoned IPv6 -> zone dropped
		{"router1.lab:6030", ""},              // DNS name with port -> skip
		{"router1.lab", ""},                   // bare DNS name -> skip
		{"", ""},                              // empty -> skip
	}
	for _, c := range cases {
		require.Equal(t, c.want, targetHostIP(c.in), "host=%q", c.in)
	}
}
