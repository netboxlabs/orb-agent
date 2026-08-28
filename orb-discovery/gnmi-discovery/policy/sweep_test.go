package policy

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// perHostDialer answers differently per address, which the shared FakeDialer
// cannot do: it holds one session and ignores the TargetSpec entirely. The
// classification matrix needs a distinct verdict per host, and concurrent probes
// need distinct sessions or the -race detector fires on FakeSession's fields.
type perHostDialer struct {
	capsErr        map[string]error // by host:port; absent falls back to defaultCapsErr
	defaultCapsErr error            // nil means the probe succeeds
	dialErr        error

	mu       sync.Mutex
	dialed   []string
	closed   map[string]int
	inFlight int
	peak     int
	blockOn  chan struct{} // when non-nil, Capabilities waits on it
}

func newPerHostDialer(capsErr map[string]error) *perHostDialer {
	return &perHostDialer{capsErr: capsErr, closed: map[string]int{}}
}

func (d *perHostDialer) Dial(_ context.Context, spec gnmi.TargetSpec) (gnmi.Session, error) {
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	d.mu.Lock()
	d.dialed = append(d.dialed, spec.Host)
	d.mu.Unlock()
	// Embed a real FakeSession so an admitted target's loop can run: it needs
	// Subscribe and the rest of the interface, not just the two methods the
	// probe touches.
	return &perHostSession{
		FakeSession: &gnmi.FakeSession{
			Caps:            &gnmi.CapabilitiesResult{Vendor: "Arista"},
			OnChangeSupport: true,
			OnChangeStream: []gnmi.Notification{
				{Updates: []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}},
				{SyncDone: true},
			},
		},
		dialer: d, host: spec.Host,
	}, nil
}

func (d *perHostDialer) dialedHosts() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

func (d *perHostDialer) closeCount(host string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed[host]
}

type perHostSession struct {
	*gnmi.FakeSession
	dialer *perHostDialer
	host   string
}

func (s *perHostSession) Capabilities(_ context.Context) (*gnmi.CapabilitiesResult, error) {
	s.dialer.mu.Lock()
	s.dialer.inFlight++
	if s.dialer.inFlight > s.dialer.peak {
		s.dialer.peak = s.dialer.inFlight
	}
	s.dialer.mu.Unlock()
	defer func() {
		s.dialer.mu.Lock()
		s.dialer.inFlight--
		s.dialer.mu.Unlock()
	}()

	if s.dialer.blockOn != nil {
		// Deliberately NOT selecting on ctx: this simulates a probe already past
		// the point of cancellation, so the test measures whether Stop waits for
		// the sweep goroutine rather than whether cancellation propagates.
		<-s.dialer.blockOn
	}
	// Under the lock: the rescan tests bring a device up mid-run by mutating
	// capsErr while probes are in flight.
	s.dialer.mu.Lock()
	err, scripted := s.dialer.capsErr[s.host]
	fallback := s.dialer.defaultCapsErr
	s.dialer.mu.Unlock()
	if scripted {
		return nil, err
	}
	if fallback != nil {
		return nil, fallback
	}
	return &gnmi.CapabilitiesResult{Vendor: "Arista"}, nil
}

func (s *perHostSession) Close() error {
	s.dialer.mu.Lock()
	s.dialer.closed[s.host]++
	s.dialer.mu.Unlock()
	return s.FakeSession.Close()
}

func handshakeErr(msg string) error {
	return status.Error(codes.Unavailable, "connection error: desc = \"transport: "+msg+"\"")
}

func dialingErr() error {
	return status.Error(codes.Unavailable,
		"connection error: desc = \"transport: Error while dialing: dial tcp: connect: connection refused\"")
}

// The gate may only conclude "something is listening on the gNMI port". Anything
// that answered — even by rejecting the RPC, even by failing a TLS handshake —
// is a device. Only silence is absence.
//
// The handshake cases are the ones an allow-list got wrong: a campus of devices
// with self-signed certs, or an mTLS device probed without a client cert, all
// answer with codes.Unavailable and would read as an empty subnet.
func TestAdmissionAdmitsAnythingThatAnswered(t *testing.T) {
	admitted := map[string]error{
		"ok":            nil,
		"unauthed":      status.Error(codes.Unauthenticated, "no credentials"),
		"forbidden":     status.Error(codes.PermissionDenied, "denied"),
		"no gnmi svc":   status.Error(codes.Unimplemented, "unknown service gnmi.gNMI"),
		"self-signed":   handshakeErr("authentication handshake failed: x509: certificate signed by unknown authority"),
		"mtls required": handshakeErr("error reading server preface: remote error: tls: certificate required"),
		"loaded device": status.Error(codes.ResourceExhausted, "busy"),
	}
	for name, err := range admitted {
		if got := admits(err); !got {
			t.Errorf("%s: admits(%v) = false, want true", name, err)
		}
	}

	rejected := map[string]error{
		"refused":  dialingErr(),
		"timeout":  status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
		"canceled": status.Error(codes.Canceled, "context canceled"),
	}
	for name, err := range rejected {
		if got := admits(err); got {
			t.Errorf("%s: admits(%v) = true, want false", name, err)
		}
	}
}

// A sweep is cancelled by Stop and by a rescan tick. Counting those probes as
// rejections would report a fabricated tally on every shutdown.
func TestCanceledProbesAreNotCountedAsRejections(t *testing.T) {
	require.True(t, isCanceled(status.Error(codes.Canceled, "context canceled")))
	require.True(t, isCanceled(context.Canceled))
	require.False(t, isCanceled(dialingErr()))
}

func TestSweepSubscribesOnlyToRespondingAddresses(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{
		"10.0.0.2:9339": dialingErr(),
		"10.0.0.3:9339": dialingErr(),
	})
	r := newSweepRunner(t, "10.0.0.0/30", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(r.TargetStatuses()) == 1
	}, 3*time.Second, 10*time.Millisecond, "only the responding address becomes a target")
	require.Equal(t, "10.0.0.1:9339", r.TargetStatuses()[0].Host)
}

// Every probed session must be closed on every path. gnmic dials without
// WithBlock, so Dial hands back a live ClientConn even for a dead address; an
// unclosed one reconnect-loops in the background, per rejected address, per
// sweep and per rescan tick.
func TestEveryProbedSessionIsClosedIncludingRejections(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.2:9339": dialingErr()})
	r := newSweepRunner(t, "10.0.0.0/30", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(dialer.dialedHosts()) >= 2
	}, 3*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		return dialer.closeCount("10.0.0.2:9339") == 1
	}, 3*time.Second, 10*time.Millisecond, "a rejected probe still closes its session")
}

// A single host is the operator asserting the device exists. Probing it would
// regress today's retry-forever behaviour: a device that is merely rebooting
// would be dropped for the life of the policy.
func TestASingleHostIsNeverProbed(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.5:9339": dialingErr()})
	r := newSweepRunner(t, "10.0.0.5", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(r.TargetStatuses()) == 1
	}, 3*time.Second, 10*time.Millisecond, "a named host is admitted without a probe")
}

// Stop must not return while the sweep goroutine is still running. Start does
// wg.Add on its own side of the return precisely so that wg.Add happens-before
// any wg.Wait; an uncounted sweep would let Stop report success while the sweep
// carried on probing, outliving its own runner.
//
// Cancellation is a separate concern and works: a probe that honours ctx exits
// promptly on Stop, which is what keeps DELETE from blocking. This test blocks
// past that point on purpose.
func TestStopWaitsForAnInFlightSweep(t *testing.T) {
	dialer := newPerHostDialer(nil)
	dialer.blockOn = make(chan struct{})
	r := newSweepRunner(t, "10.0.0.0/24", dialer)
	r.Start()

	// Wait for a probe to actually be in flight. The sweep checks for
	// cancellation before each probe, so a Stop that races Start exits at once —
	// correct, but it would make this assertion vacuous.
	require.Eventually(t, func() bool {
		return len(dialer.dialedHosts()) > 0
	}, 3*time.Second, 5*time.Millisecond)

	stopped := make(chan struct{})
	go func() {
		_ = r.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Stop returned while the sweep was still probing")
	case <-time.After(150 * time.Millisecond):
	}

	close(dialer.blockOn)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after the sweep was released")
	}
}

func newSweepRunner(t *testing.T, host string, dialer gnmi.Dialer) *Runner {
	t.Helper()
	policy := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeAuto, DebounceMs: 10},
		Scope:  config.Scope{Targets: []config.Target{{Host: host}}},
	}
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	r, err := NewRunner(context.Background(), slog.New(slog.DiscardHandler),
		"p1", policy, &recordingClient{}, dialer, store)
	require.NoError(t, err)
	r.backoffBase = time.Millisecond
	return r
}

// A dead address costs the full probe timeout, so the sweep probes in parallel —
// but bounded, because each probe holds a TLS handshake rather than a datagram.
func TestProbesRunConcurrentlyButBounded(t *testing.T) {
	dialer := newPerHostDialer(nil)
	// Reject everything, so the only dials are probes: an admitted target starts
	// a loop that dials again, which would make the count unstable.
	dialer.defaultCapsErr = dialingErr()
	r := newSweepRunner(t, "10.0.0.0/24", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(dialer.dialedHosts()) == 254
	}, 5*time.Second, 10*time.Millisecond, "all addresses probed")

	dialer.mu.Lock()
	peak := dialer.peak
	dialer.mu.Unlock()
	require.Greater(t, peak, 1, "probes must not be sequential")
	require.LessOrEqual(t, peak, probeConcurrency, "probes must stay bounded")
}
