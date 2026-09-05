package policy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
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
	specs    []gnmi.TargetSpec
	closed   map[string]int
	inFlight int
	peak     int
	hang     map[string]bool // hosts whose Capabilities waits for ctx
	blockOn  chan struct{}   // when non-nil, Capabilities waits on it
}

func newPerHostDialer(capsErr map[string]error) *perHostDialer {
	return &perHostDialer{capsErr: capsErr, closed: map[string]int{}, hang: map[string]bool{}}
}

func (d *perHostDialer) Dial(_ context.Context, spec gnmi.TargetSpec) (gnmi.Session, error) {
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	d.mu.Lock()
	d.dialed = append(d.dialed, spec.Host)
	d.specs = append(d.specs, spec)
	d.mu.Unlock()
	// Embed a real FakeSession so an admitted target's loop can run: it needs
	// Subscribe and the rest of the interface, not just the two methods the
	// probe touches.
	return &perHostSession{
		FakeSession: &gnmi.FakeSession{
			Caps:            &gnmi.CapabilitiesResult{Vendor: "acme"},
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

func (s *perHostSession) Capabilities(ctx context.Context) (*gnmi.CapabilitiesResult, error) {
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

	s.dialer.mu.Lock()
	hang := s.dialer.hang[s.host]
	s.dialer.mu.Unlock()
	if hang {
		// Never returns on its own: the probe's own deadline has to end it, which
		// is what produces a genuine localStop.
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}

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
	return &gnmi.CapabilitiesResult{Vendor: "acme"}, nil
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
//
// The two deadline/cancel cases are the ones a code-only classifier got wrong in
// the opposite direction. grpc-go produces DeadlineExceeded and Canceled locally
// when the probe's own context ends, and a server may also send either of them
// itself — so the code cannot separate them and the local context has to.
func TestAdmissionAdmitsAnythingThatAnswered(t *testing.T) {
	admitted := map[string]probeResult{
		"ok":            {},
		"unauthed":      {err: status.Error(codes.Unauthenticated, "no credentials")},
		"forbidden":     {err: status.Error(codes.PermissionDenied, "denied")},
		"no gnmi svc":   {err: status.Error(codes.Unimplemented, "unknown service gnmi.gNMI")},
		"self-signed":   {err: handshakeErr("authentication handshake failed: x509: certificate signed by unknown authority")},
		"mtls required": {err: handshakeErr("error reading server preface: remote error: tls: certificate required")},
		"loaded device": {err: status.Error(codes.ResourceExhausted, "busy")},
		// Server-sent, with the probe's own context still live: a peer answered.
		"server deadline": {err: status.Error(codes.DeadlineExceeded, "deadline_exceeded")},
		"server canceled": {err: status.Error(codes.Canceled, "rpc canceled by server")},
		// A deadline that fires just after a successful reply must not retract it.
		"answered then expired": {localStop: true},
	}
	for name, res := range admitted {
		if got := admits(res); !got {
			t.Errorf("%s: admits(%+v) = false, want true", name, res)
		}
	}

	rejected := map[string]probeResult{
		"refused": {err: dialingErr()},
		// Our own deadline or cancellation ended the call, so nothing came back.
		"local timeout":  {err: status.Error(codes.DeadlineExceeded, "context deadline exceeded"), localStop: true},
		"local cancel":   {err: status.Error(codes.Canceled, "context canceled"), localStop: true},
		"dial/tls fault": {err: errors.New("open /run/secrets/ca.pem: no such file or directory")},
	}
	for name, res := range rejected {
		if got := admits(res); got {
			t.Errorf("%s: admits(%+v) = true, want false", name, res)
		}
	}
}

// A sweep is cancelled by Stop and by a rescan tick. Counting those probes as
// rejections would report a fabricated tally on every shutdown.
func TestCanceledProbesAreNotCountedAsRejections(t *testing.T) {
	require.True(t, isCanceled(context.Canceled))
	require.False(t, isCanceled(dialingErr()))
	// A peer answering with codes.Canceled is not this runner shutting down.
	require.False(t, isCanceled(status.Error(codes.Canceled, "rpc canceled by server")),
		"a remote status must never read as a local shutdown")
}

func TestSweepSubscribesOnlyToRespondingAddresses(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{
		"10.0.0.2:9339": dialingErr(),
		"10.0.0.3:9339": dialingErr(),
	})
	r, spy := newSweepRunner(t, "10.0.0.0/30", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(spy.startedHosts()) == 1
	}, 3*time.Second, 10*time.Millisecond, "only the responding address becomes a target")
	require.Equal(t, []string{"10.0.0.1"}, spy.startedHosts())
}

// Every probed session must be closed on every path. gnmic dials without
// WithBlock, so Dial hands back a live ClientConn even for a dead address; an
// unclosed one reconnect-loops in the background, per rejected address, per
// sweep and per rescan tick.
func TestEveryProbedSessionIsClosedIncludingRejections(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.2:9339": dialingErr()})
	r, _ := newSweepRunner(t, "10.0.0.0/30", dialer)
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
	r, spy := newSweepRunner(t, "10.0.0.5", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(spy.startedHosts()) == 1
	}, 3*time.Second, 10*time.Millisecond, "a named host is admitted without a probe")
	require.Equal(t, []string{"10.0.0.5"}, spy.startedHosts())
	require.Empty(t, dialer.dialedHosts(), "a named host is never probed")
}

// newSweepRunner builds a runner over one target and the spy the sweep tests
// read what was started from.
func newSweepRunner(t *testing.T, host string, dialer gnmi.Dialer) (*Runner, *spyCollector) {
	t.Helper()
	spy := &spyCollector{}
	policy := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: intp(10)},
		Scope:  config.Scope{Targets: []config.Target{{Host: host}}},
	}
	r, err := NewRunner(context.Background(), quietLogger(), "p1", policy, spy, dialer)
	require.NoError(t, err)
	return r, spy
}

// A dead address costs the full probe timeout, so the sweep probes in parallel —
// but bounded, because each probe holds a TLS handshake rather than a datagram.
func TestProbesRunConcurrentlyButBounded(t *testing.T) {
	dialer := newPerHostDialer(nil)
	// Reject everything, so the only dials are probes: an admitted target starts
	// a loop that dials again, which would make the count unstable.
	dialer.defaultCapsErr = dialingErr()
	r, _ := newSweepRunner(t, "10.0.0.0/24", dialer)
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

// One device answering with codes.Canceled must not abandon the sweep. Reading a
// peer's status as "the policy is going away" discarded every address the other
// probes had already admitted and started no subscriptions at all — a single
// misbehaving device silently killing discovery for the whole subnet, with only a
// Debug line to show for it.
func TestAPeerAnsweringCanceledDoesNotAbandonTheSweep(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{
		"10.0.0.1:9339": status.Error(codes.Canceled, "rpc canceled by server"),
	})
	r, spy := newSweepRunner(t, "10.0.0.0/29", dialer) // .1 through .6
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(spy.startedHosts()) == 6
	}, 3*time.Second, 10*time.Millisecond,
		"every address answered, the Canceled one included")
	// Six targets is below the jitter threshold, so the loops start
	// concurrently with no gap between them and the order is not deterministic.
	assert.ElementsMatch(t,
		[]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"},
		spy.startedHosts())
}

// A server that sends DeadlineExceeded itself has answered, so the address holds
// a device. Classifying on the code alone dropped it as silence.
func TestAServerSentDeadlineIsAdmitted(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{
		"10.0.0.1:9339": status.Error(codes.DeadlineExceeded, "deadline_exceeded"),
		"10.0.0.2:9339": dialingErr(),
	})
	r, spy := newSweepRunner(t, "10.0.0.0/30", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(spy.startedHosts()) == 1
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{"10.0.0.1"}, spy.startedHosts(),
		"the server answered; only the refused address is absent")
}

// The probe's own deadline expiring is still the one thing that means silence.
func TestAnAddressThatNeverRepliesIsRejected(t *testing.T) {
	dialer := newPerHostDialer(nil)
	dialer.hang = map[string]bool{"10.0.0.1:9339": true}
	spy := &spyCollector{}
	policy := config.Policy{
		Config: config.PolicyConfig{MetricsInterval: intp(10), ProbeTimeoutMs: 80},
		Scope:  config.Scope{Targets: []config.Target{{Host: "10.0.0.0/30"}}},
	}
	r, err := NewRunner(context.Background(), quietLogger(), "p1", policy, spy, dialer)
	require.NoError(t, err)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(spy.startedHosts()) == 1
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{"10.0.0.2"}, spy.startedHosts(),
		"only .2 answered; .1 went silent and gets no subscription")
}

// The key separates two ports on one address and collapses two spellings of
// one address, so the sweep cannot subscribe to one device twice.
func TestDedupeKeySeparatesPorts(t *testing.T) {
	require.NotEqual(t, dedupeKey("10.0.0.1", 6030), dedupeKey("10.0.0.1", 57400))
	require.Equal(t, dedupeKey("2001:0db8::1", 9339), dedupeKey("2001:db8::1", 9339))
}
