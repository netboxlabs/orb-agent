package policy

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// The delay doubles from the base up to the ceiling it is given, and a lower
// ceiling takes effect at once.
func TestReconnectBackoffDoublesUpToTheCeiling(t *testing.T) {
	b := newReconnectBackoff(time.Second)
	var got []time.Duration
	for range 12 {
		got = append(got, b.delay(defaultCredentialBackoffCap))
	}
	require.Equal(t, []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second,
		64 * time.Second, 128 * time.Second, 256 * time.Second, 512 * time.Second,
		defaultCredentialBackoffCap, defaultCredentialBackoffCap,
	}, got)
	require.Equal(t, defaultBackoffCap, b.delay(defaultBackoffCap))

	b.reset()
	require.Equal(t, time.Second, b.delay(defaultBackoffCap))
}

// Only credentials refused on every attempt so far slow the backoff: once they
// have worked, a refusal backs off like any other failure.
func TestSlowBackoffOnlyForCredentialsThatNeverWorked(t *testing.T) {
	require.False(t, (&setupHistory{}).slowBackoff())
	require.True(t, (&setupHistory{credsRefused: true}).slowBackoff())
	require.False(t, (&setupHistory{credsRefused: true, credsWorked: true}).slowBackoff())
	require.Equal(t, 15*time.Minute, defaultCredentialBackoffCap)
	require.Equal(t, 30*time.Second, defaultBackoffCap)
}

// dialTimes records when each dial happened.
type dialTimes struct {
	mu sync.Mutex
	at []time.Time
}

func (d *dialTimes) add() {
	d.mu.Lock()
	d.at = append(d.at, time.Now())
	d.mu.Unlock()
}

func (d *dialTimes) gaps() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []time.Duration
	for i := 1; i < len(d.at); i++ {
		out = append(out, d.at[i].Sub(d.at[i-1]))
	}
	return out
}

// Wrong credentials back off past the usual cap, toward the credential cap
// (scaled down here from 30 s and 15 min).
func TestWrongCredentialsBackOffPastTheUsualCap(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	refused := status.Error(codes.Unauthenticated, "bad credentials")
	script := make([]error, 50)
	for i := range script {
		script[i] = refused
	}
	dialer := &capsScriptDialer{script: script, noOnChange: true}
	times := &dialTimes{}
	dialer.onDial = times.add
	r, _, _ := capsScriptRunnerWith(t, store, dialer, 5*time.Millisecond, func(r *Runner) {
		r.backoffCap = 20 * time.Millisecond
		r.credentialBackoffCap = 300 * time.Millisecond
	})
	_ = r

	require.Eventually(t, func() bool { return dialer.dials.Load() >= 7 }, 5*time.Second, 5*time.Millisecond)
	gaps := times.gaps()
	// 5, 10, 20, 40, 80, 160 ms: the last gaps are past the usual cap.
	require.Greater(t, gaps[5], 4*r.backoffCap, gaps)
}

// Credentials that Capabilities once accepted are not "never worked": a later
// refusal warns on every attempt and backs off like any other failure.
func TestCredentialsAcceptedOnceWarnOnEveryRefusal(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	refused := status.Error(codes.Unauthenticated, "bad credentials")
	// Answered once, on a connection that never syncs, then refused.
	dialer := &capsScriptDialer{script: []error{nil, refused, refused}, noOnChange: true}
	_, _, logs := capsScriptRunner(t, store, dialer)

	require.Eventually(t, func() bool { return dialer.dials.Load() >= 3 }, 5*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool {
		return strings.Count(logs.String(), "level=WARN msg=\"gnmi target loop error\"") >= 3
	}, 2*time.Second, 5*time.Millisecond, logs.String())
	require.NotContains(t, logs.String(), "level=DEBUG msg=\"gnmi target loop error\"")
}

// A device that refuses Capabilities with Unauthenticated for good but serves
// Subscribe has working credentials once it syncs: its later refusals warn.
func TestCredentialsThatSyncedWarnOnEveryRefusal(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	refused := status.Error(codes.Unauthenticated, "refused")
	script := make([]error, 20)
	for i := range script {
		script[i] = refused
	}
	// The _base connection syncs and drops; the next one goes on with _base.
	dialer := &capsScriptDialer{script: script, dropStream: func(dial int32) bool { return dial == capsAttempts }}
	_, _, logs := capsScriptRunner(t, store, dialer)

	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "level=WARN msg=\"gnmi capabilities failed\"")
	}, 2*time.Second, 5*time.Millisecond, logs.String())
	require.EqualValues(t, capsAttempts+1, dialer.dials.Load())
}

// A failure that is not a credential refusal warns, even after one that was.
func TestDialFailureAfterACredentialRefusalWarns(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	dialer := &capsScriptDialer{
		script:     []error{status.Error(codes.Unauthenticated, "refused")},
		noOnChange: true,
		dialErr: func(dial int32) error {
			if dial >= 2 {
				return errors.New("tls: bad certificate")
			}
			return nil
		},
	}
	_, _, logs := capsScriptRunner(t, store, dialer)

	require.Eventually(t, func() bool { return dialer.dials.Load() >= 3 }, 2*time.Second, 5*time.Millisecond)
	require.NotContains(t, logs.String(), "level=DEBUG msg=\"gnmi target loop error\" policy=p1 host=192.0.2.30:57400 error=\"tls")
	require.Contains(t, logs.String(), "level=WARN msg=\"gnmi target loop error\" policy=p1 host=192.0.2.30:57400 error=\"tls")
}

// A target whose credentials are refused says so once at WARN; the repeats,
// which carry nothing new, drop to DEBUG.
func TestWrongCredentialsWarnOnceThenDebug(t *testing.T) {
	srv := &gnmiTarget{
		capsErr: capsRefused(codes.Unauthenticated, 0),
		getErr:  always(codes.Unauthenticated),
		subErr:  always(codes.Unauthenticated),
	}
	_, _, d, logs := runAgainst(t, srv, config.ModeAuto, nil)

	require.Eventually(t, func() bool { return d.dials.Load() >= capsAttempts+2 }, 5*time.Second, 10*time.Millisecond)
	var warns, debugs int
	for _, l := range strings.Split(logs.String(), "\n") {
		if !strings.Contains(l, "Unauthenticated") {
			continue
		}
		switch {
		case strings.Contains(l, "level=WARN"):
			warns++
		case strings.Contains(l, "level=DEBUG"):
			debugs++
		}
	}
	require.Equal(t, 1, warns, logs.String())
	require.GreaterOrEqual(t, debugs, capsAttempts)
}

// A device whose credentials work, here one that refuses Capabilities for good
// but serves Subscribe, is not treated as having wrong credentials.
func TestCredentialsThatWorkedWarnAgain(t *testing.T) {
	h := &setupHistory{credsRefused: true}
	require.Equal(t, "WARN", h.logLevel().String())
	h.attemptLogged()
	require.Equal(t, "DEBUG", h.logLevel().String())
	h.credsWorked = true
	require.Equal(t, "WARN", h.logLevel().String())
}

// A connection that stayed up past its sync for longer than the backoff cap
// resets the backoff, so a stream that drops now and then reconnects at the
// base delay rather than at the delay earlier failures built up. Scaled down
// from a 30 s cap.
func TestBackoffResetsAfterAConnectionThatLasted(t *testing.T) {
	srv := &gnmiTarget{dropAfter: 400 * time.Millisecond}
	_, _, d, _ := runAgainst(t, srv, config.ModeOnChange, func(r *Runner) {
		r.backoffBase = 10 * time.Millisecond
		r.backoffCap = 300 * time.Millisecond
	})

	require.Eventually(t, func() bool { return d.dials.Load() >= 6 }, 10*time.Second, 10*time.Millisecond)
	// Each gap is the 400 ms the stream lasted plus the backoff: without the
	// reset the fifth gap's backoff is 160 ms, with it 10 ms.
	require.Less(t, d.gaps()[4], 400*time.Millisecond+120*time.Millisecond, d.gaps())
}

// A device that syncs and then drops at once is not redialled in a tight
// loop: a connection that did not last past the cap does not reset the
// backoff, which settles at the cap.
func TestBackoffSettlesAtTheCapWhenStreamsDropAfterSync(t *testing.T) {
	srv := &gnmiTarget{dropAfter: 30 * time.Millisecond}
	_, _, d, _ := runAgainst(t, srv, config.ModeOnChange, func(r *Runner) {
		r.backoffBase = 5 * time.Millisecond
		r.backoffCap = 150 * time.Millisecond
	})

	require.Eventually(t, func() bool { return d.dials.Load() >= 8 }, 10*time.Second, 10*time.Millisecond)
	gaps := d.gaps()
	for _, g := range gaps[5:] {
		require.GreaterOrEqual(t, g, 150*time.Millisecond, "redialled before the capped backoff: %v", gaps)
	}
}

// The time a connection lasted is counted from its first sync, not its last:
// a GET target syncs on every poll, and one that polled for longer than the
// cap still resets the backoff when its Gets start failing.
func TestBackoffCountsFromTheFirstSync(t *testing.T) {
	srv := &gnmiTarget{}
	srv.getErr = func([]string) error {
		if time.Since(time.Unix(0, srv.lastCaps.Load())) > 400*time.Millisecond {
			return status.Error(codes.Unavailable, "busy")
		}
		return nil
	}
	_, _, d, _ := runAgainst(t, srv, config.ModeGet, func(r *Runner) {
		r.policy.Config.GetIntervalMs = 50
		r.backoffBase = 10 * time.Millisecond
		r.backoffCap = 300 * time.Millisecond
	})

	require.Eventually(t, func() bool { return d.dials.Load() >= 6 }, 10*time.Second, 10*time.Millisecond)
	require.Less(t, d.gaps()[4], 400*time.Millisecond+120*time.Millisecond, d.gaps())
}

// A connection must outlast the delay its failures built up, not only the cap,
// before it resets the backoff. Credentials refused for six attempts build a
// delay past the cap; the connection that then works lasts longer than the cap
// but not that delay, so the next wait is the cap rather than the base.
func TestBackoffResetNeedsTheCurrentDelayToo(t *testing.T) {
	const working = 7 // the first attempt whose credentials are accepted
	srv := &gnmiTarget{dropAfter: 300 * time.Millisecond}
	refused := func() error {
		if srv.caps.Load() < working {
			return status.Error(codes.Unauthenticated, "bad credentials")
		}
		return nil
	}
	srv.capsErr = func(int32) error { return refused() }
	srv.getErr = func([]string) error { return refused() }
	srv.subErr = func([]string) error { return refused() }
	_, client, d, _ := runAgainst(t, srv, config.ModeOnChange, func(r *Runner) {
		r.backoffBase = 10 * time.Millisecond
		r.backoffCap = 100 * time.Millisecond
		r.credentialBackoffCap = 2 * time.Second
	})

	require.Eventually(t, func() bool { return d.dials.Load() >= working+1 }, 10*time.Second, 10*time.Millisecond)
	require.Positive(t, client.count(), "the working connection ingested")
	// The working connection lasted about 300 ms; then the capped 100 ms wait,
	// where a reset would wait 10 ms.
	require.GreaterOrEqual(t, d.gaps()[working-1], 300*time.Millisecond+80*time.Millisecond, d.gaps())
}

// With credentials that never worked, the step-down lines are quiet like the
// refusal: at INFO at most on the first attempt, at DEBUG after.
func TestWrongCredentialsQuietTheStepDownLines(t *testing.T) {
	// PermissionDenied goes on with _base on the first attempt, and walks the
	// ladder there; Unauthenticated redials first, so its first walk is a repeat.
	firstINFO := map[codes.Code]int{codes.PermissionDenied: 1, codes.Unauthenticated: 0}
	for c, want := range firstINFO {
		t.Run(c.String(), func(t *testing.T) {
			srv := &gnmiTarget{
				capsErr: func(int32) error { return status.Error(c, "bad credentials") },
				getErr:  always(c),
				subErr:  always(c),
			}
			_, _, d, logs := runAgainst(t, srv, config.ModeAuto, nil)

			require.Eventually(t, func() bool { return d.dials.Load() >= 6 }, 10*time.Second, 5*time.Millisecond)
			for _, msg := range []string{"on_change not available, using sample", "sample not available, using get"} {
				out := logs.String()
				require.Equal(t, want, strings.Count(out, `level=INFO msg="`+msg), msg)
				require.Positive(t, strings.Count(out, `level=DEBUG msg="`+msg), msg)
			}
		})
	}
}

// A target matched by netbox_id whose device sends no hostname never has a
// trustworthy sync, but a successful flush shows its credentials work: after
// its stream drops it redials at the usual backoff, not the credential one.
// Capabilities refuses the credentials every time, as on a device that never
// answers it. Scaled down from 30 s and 15 min.
func TestFlushCountsAsWorkingCredentials(t *testing.T) {
	srv := &gnmiTarget{
		noHostname: true,
		dropAfter:  150 * time.Millisecond,
		capsErr:    capsRefused(codes.Unauthenticated, 0),
	}
	id := 7
	_, client, d, _ := runAgainst(t, srv, config.ModeOnChange, func(r *Runner) {
		r.policy.Scope.Targets[0].NetboxID = &id
		r.backoffBase = 10 * time.Millisecond
		r.backoffCap = 50 * time.Millisecond
		r.credentialBackoffCap = 2 * time.Second
	})

	require.Eventually(t, func() bool { return d.dials.Load() >= 9 }, 10*time.Second, 10*time.Millisecond)
	require.Positive(t, client.count(), "the netbox_id target ingests")
	gaps := d.gaps()
	for _, g := range gaps[capsAttempts:] {
		require.Less(t, g, 150*time.Millisecond+100*time.Millisecond, "waited past the usual cap: %v", gaps)
	}
}

// A flush counts only for a connection that delivered something. An explicit
// SAMPLE stream flushes on its prune tick even when the device sent nothing;
// a device that holds the subscription silently and then refuses the
// credentials has not shown they work, so it backs off toward the credential
// ceiling. Scaled down from 30 s and 15 min.
func TestFlushWithoutDataDoesNotCountAsWorking(t *testing.T) {
	srv := &gnmiTarget{
		capsErr: capsRefused(codes.Unauthenticated, 0),
		getErr:  always(codes.Unauthenticated),
		subErr: func([]string) error {
			time.Sleep(250 * time.Millisecond)
			return status.Error(codes.Unauthenticated, "bad credentials")
		},
	}
	id := 7
	_, _, d, _ := runAgainst(t, srv, config.ModeSample, func(r *Runner) {
		r.policy.Scope.Targets[0].NetboxID = &id
		r.policy.Config.SampleIntervalMs = 50
		r.backoffCap = 50 * time.Millisecond
		r.credentialBackoffCap = 5 * time.Second
	})

	// Without data the delay keeps doubling; counted as working it would stay
	// at the 250 ms the device holds the stream plus the 50 ms cap.
	require.Eventually(t, func() bool {
		return slices.ContainsFunc(d.gaps(), func(g time.Duration) bool { return g >= 500*time.Millisecond })
	}, 8*time.Second, 20*time.Millisecond, "gaps stayed at the usual cap")
}

// A flush also starts the backoff-reset clock: a netbox_id target with no
// hostname leaf never syncs trustworthily, and a stream of its that lasts past
// the cap resets the backoff from its first flush. Scaled down from 30 s.
func TestFlushStartsTheBackoffResetClock(t *testing.T) {
	srv := &gnmiTarget{noHostname: true, dropAfter: 400 * time.Millisecond}
	id := 7
	_, client, d, _ := runAgainst(t, srv, config.ModeOnChange, func(r *Runner) {
		r.policy.Scope.Targets[0].NetboxID = &id
		r.backoffBase = 10 * time.Millisecond
		r.backoffCap = 300 * time.Millisecond
	})

	require.Eventually(t, func() bool { return d.dials.Load() >= 6 }, 10*time.Second, 10*time.Millisecond)
	require.Positive(t, client.count())
	// Without the reset the fifth gap's backoff is 160 ms, with it 10 ms.
	require.Less(t, d.gaps()[4], 400*time.Millisecond+120*time.Millisecond, d.gaps())
}

// A Get answer is a delivery: a netbox_id target with no hostname leaf, polled
// over GET, counts as working once a poll it flushed came back, even though no
// poll is a trustworthy sync. Its Gets start failing 300 ms into each
// connection; it redials at the usual backoff. Scaled down from 30 s and 15 min.
func TestGetAnswerCountsAsDelivered(t *testing.T) {
	srv := &gnmiTarget{noHostname: true, capsErr: capsRefused(codes.Unauthenticated, 0)}
	srv.getErr = func([]string) error {
		if time.Since(time.Unix(0, srv.lastCaps.Load())) > 300*time.Millisecond {
			return status.Error(codes.Unavailable, "busy")
		}
		return nil
	}
	id := 7
	_, client, d, _ := runAgainst(t, srv, config.ModeGet, func(r *Runner) {
		r.policy.Scope.Targets[0].NetboxID = &id
		r.policy.Config.GetIntervalMs = 50
		r.backoffBase = 10 * time.Millisecond
		r.backoffCap = 50 * time.Millisecond
		r.credentialBackoffCap = 2 * time.Second
	})

	require.Eventually(t, func() bool { return d.dials.Load() >= 9 }, 10*time.Second, 10*time.Millisecond)
	require.Positive(t, client.count())
	gaps := d.gaps()
	for _, g := range gaps[capsAttempts:] {
		require.Less(t, g, 300*time.Millisecond+150*time.Millisecond, "waited past the usual cap: %v", gaps)
	}
}

// What a connection delivered is its own: a later connection that delivers
// nothing, and only flushes on its SAMPLE tick, does not reset the backoff
// however long it stays up. Scaled down from 30 s.
func TestDeliveryIsPerConnection(t *testing.T) {
	var subs atomic.Int32
	srv := &gnmiTarget{dropAfter: 100 * time.Millisecond}
	srv.subErr = func([]string) error {
		if subs.Add(1) == 1 {
			return nil // the first connection streams, then drops
		}
		time.Sleep(400 * time.Millisecond) // later ones hold silently, then fail
		return status.Error(codes.Unavailable, "busy")
	}
	_, _, d, _ := runAgainst(t, srv, config.ModeSample, func(r *Runner) {
		r.policy.Config.SampleIntervalMs = 50
		r.backoffBase = 10 * time.Millisecond
		r.backoffCap = 300 * time.Millisecond
	})

	// Without a delivery the delay grows to the cap: some gap reaches the 400 ms
	// hold plus most of the cap, where a reset would keep it near 410 ms.
	require.Eventually(t, func() bool {
		return slices.ContainsFunc(d.gaps(), func(g time.Duration) bool { return g >= 400*time.Millisecond+200*time.Millisecond })
	}, 10*time.Second, 20*time.Millisecond, "the backoff kept resetting")
}
