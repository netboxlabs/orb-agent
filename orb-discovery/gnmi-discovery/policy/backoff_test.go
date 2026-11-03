package policy

import (
	"errors"
	"strings"
	"sync"
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

// A connection that synced resets the backoff, so a target whose stream drops
// now and then reconnects at the base delay rather than at the delay its
// first failures built up.
func TestBackoffResetsAfterASync(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	dialer := &capsScriptDialer{dropStream: func(int32) bool { return true }}
	var mu sync.Mutex
	var at []time.Time
	dialer.onDial = func() {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
	}
	const base = 40 * time.Millisecond
	capsScriptRunnerWith(t, store, dialer, base, nil)

	require.Eventually(t, func() bool { return dialer.dials.Load() >= 6 }, 5*time.Second, 5*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	// Without the reset the fifth gap is sixteen times the base.
	require.Less(t, at[5].Sub(at[4]), 4*base)
}
