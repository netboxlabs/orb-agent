package policy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// spyCollector records the policy names it was told to forget.
type spyCollector struct {
	mu     sync.Mutex
	forgot []string
	dials  []collector.DialOptions
}

func (s *spyCollector) CollectTarget(_ context.Context, _ config.Target, _ *config.Authentication, _ string, dial collector.DialOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dials = append(s.dials, dial)
	return nil
}

func (s *spyCollector) ForgetPolicy(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgot = append(s.forgot, name)
}

func (s *spyCollector) forgotten() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forgot...)
}

func TestRunnerStop_ForgetsCollectorState(t *testing.T) {
	spy := &spyCollector{}
	r, err := NewRunner(context.Background(), testLogger, "p1", minimalPolicy(v2cAuth()), spy)
	require.NoError(t, err)
	require.NoError(t, r.Stop())
	assert.Equal(t, []string{"p1"}, spy.forgotten())
}

func TestStopPolicy_ForgetsCollectorState(t *testing.T) {
	spy := &spyCollector{}
	m := newTestManager()
	r, err := NewRunner(m.ctx, testLogger, "p1", minimalPolicy(v2cAuth()), spy)
	require.NoError(t, err)
	m.policies["p1"] = r

	require.NoError(t, m.StopPolicy("p1"))
	assert.Equal(t, []string{"p1"}, spy.forgotten())
	assert.False(t, m.HasPolicy("p1"))
}

func TestManagerStop_ForgetsEveryPolicy(t *testing.T) {
	spy := &spyCollector{}
	m := newTestManager()
	for _, name := range []string{"p1", "p2"} {
		r, err := NewRunner(m.ctx, testLogger, name, minimalPolicy(v2cAuth()), spy)
		require.NoError(t, err)
		m.policies[name] = r
	}

	require.NoError(t, m.Stop())
	assert.ElementsMatch(t, []string{"p1", "p2"}, spy.forgotten())
}

// ---------------------------------------------------------------------------
// Per-policy snmp_timeout and retries
// ---------------------------------------------------------------------------

func policyWithDial(intervalSec, timeoutSec, retries int) config.Policy {
	pol := minimalPolicy(v2cAuth())
	pol.Config.MetricsInterval = &intervalSec
	pol.Config.SNMPTimeout = timeoutSec
	pol.Config.Retries = retries
	return pol
}

func TestNewRunner_DerivesDialSettingsFromPolicy(t *testing.T) {
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(120, 12, 4), &spyCollector{})
	require.NoError(t, err)
	assert.Equal(t, 12*time.Second, r.snmpTimeout)
	assert.Equal(t, 4, r.retries)
}

func TestNewRunner_ZeroSNMPTimeoutFallsBackToDefault(t *testing.T) {
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 0, 0), &spyCollector{})
	require.NoError(t, err)
	assert.Equal(t, defaultSNMPTimeout, r.snmpTimeout)
	assert.Equal(t, 0, r.retries)
}

func TestNewRunner_RejectsTimeoutAtOrAboveInterval(t *testing.T) {
	// The run context is bounded by metrics_interval, so a dial allowed to take
	// the whole interval can never complete a collection.
	_, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 30, 0), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "snmp_timeout")

	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 45, 0), &spyCollector{})
	assert.Error(t, err)

	// The default applies before the comparison, so a short interval is caught
	// even when the policy never named a timeout.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(3, 0, 0), &spyCollector{})
	assert.Error(t, err)

	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 29, 0), &spyCollector{})
	assert.NoError(t, err)
}

func TestRunMetrics_PassesDialSettingsToCollector(t *testing.T) {
	spy := &spyCollector{}
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(120, 12, 4), spy)
	require.NoError(t, err)

	r.runMetrics(config.Target{Host: "192.168.1.1", Port: 161})
	require.Len(t, spy.dials, 1)
	assert.Equal(t, collector.DialOptions{Timeout: 12 * time.Second, Retries: 4}, spy.dials[0])
}

func TestValidate_RejectsNegativeDialSettings(t *testing.T) {
	m := newTestManager()
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, -1, 0)), "snmp_timeout")
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, 0, -1)), "retries")
}

// ---------------------------------------------------------------------------
// Seconds that cannot be represented as a Duration
// ---------------------------------------------------------------------------

// Multiplying seconds by time.Second wraps above the representable range, and
// the wrapped value is small: 40423014371506394 seconds becomes about a
// microsecond. Every later check compares the wrapped durations, so an
// outsized interval reads as a valid tight one and the policy schedules a
// near-continuous collection.
func TestValidate_RejectsSecondsThatCannotBeADuration(t *testing.T) {
	m := newTestManager()
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(40423014371506394, 5, 0)), "metrics_interval")
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(maxPolicySeconds+1, 5, 0)), "metrics_interval")
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, 20211507185753197, 0)), "snmp_timeout")
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, maxPolicySeconds+1, 0)), "snmp_timeout")

	require.NoError(t, m.validatePolicy(policyWithDial(maxPolicySeconds, maxPolicySeconds, 0)),
		"the bound itself is accepted")
}

// NewRunner is where the multiply happens, and it is reachable without the
// API, so it carries the bound too.
func TestNewRunner_RejectsSecondsThatCannotBeADuration(t *testing.T) {
	_, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(40423014371506394, 5, 0), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "metrics_interval")

	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(maxPolicySeconds+1, 5, 0), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "metrics_interval")

	// The interval is sane, so only the timeout can be at fault, and it must be
	// named rather than reported as a timeout below a tiny interval.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 20211507185753197, 0), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "snmp_timeout")

	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, maxPolicySeconds+1, 0), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "snmp_timeout")
}

// The bound is on the seconds, so what survives it converts faithfully: the
// durations the runner keeps are the ones the policy asked for, not a wrapped
// remainder.
func TestNewRunner_KeepsTheDurationsAtTheBound(t *testing.T) {
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(maxPolicySeconds, maxPolicySeconds-1, 0), &spyCollector{})
	require.NoError(t, err)
	assert.Equal(t, maxPolicySeconds*time.Second, r.metricsInterval)
	assert.Equal(t, (maxPolicySeconds-1)*time.Second, r.snmpTimeout)
}

// The retry ceiling multiplies snmp_timeout by the capped attempt count. With
// the durations and the retry count all bounded that product stays inside the
// range, so the largest policy the bounds allow still reports the warning
// rather than wrapping past the comparison.
func TestNewRunner_RetryCeilingHoldsAtTheBound(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	_, err := NewRunner(t.Context(), lg, "p1", policyWithDial(maxPolicySeconds, maxPolicySeconds-1, maxPolicyRetries), &spyCollector{})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "SNMP retries can exceed the collection interval")
}

// ---------------------------------------------------------------------------
// One policy targeting one endpoint more than once
// ---------------------------------------------------------------------------

// failingCollector fails collection for the targets whose NetBox ID is listed.
type failingCollector struct {
	failIDs map[string]bool
}

func (f *failingCollector) CollectTarget(_ context.Context, target config.Target, _ *config.Authentication, _ string, _ collector.DialOptions) error {
	if f.failIDs[target.ID] {
		return errors.New("unreachable")
	}
	return nil
}

func (f *failingCollector) ForgetPolicy(string) {}

// TestRunMetrics_SameEndpointTwiceKeepsErrorsApart covers a policy that names
// one host and port twice. Keying the error set by host and port alone let a
// healthy entry clear the failing one's error, so the policy reported itself
// healthy while half its targets were unreachable.
func TestRunMetrics_SameEndpointTwiceKeepsErrorsApart(t *testing.T) {
	c := &failingCollector{failIDs: map[string]bool{"11": true}}
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, 0), c)
	require.NoError(t, err)

	failing := config.Target{Host: "10.0.0.1", Port: 161, ID: "11"}
	healthy := config.Target{Host: "10.0.0.1", Port: 161, ID: "22"}

	r.runMetrics(failing)
	r.runMetrics(healthy)

	_, lastErr := r.GetLastError()
	require.Error(t, lastErr, "the healthy entry must not clear the failing one")
	assert.Contains(t, lastErr.Error(), "11")

	r.runMetrics(config.Target{Host: "10.0.0.1", Port: 161, ID: "11"})
	_, lastErr = r.GetLastError()
	assert.Error(t, lastErr, "the failing entry stays failing")
}

// TestRunMetrics_ContextNameDistinguishesErrorKeys covers two entries that share
// a host, port and NetBox ID and differ only by SNMPv3 context name.
func TestRunMetrics_ContextNameDistinguishesErrorKeys(t *testing.T) {
	target := config.Target{Host: "10.0.0.2", Port: 161, ID: "11"}
	a := &config.Authentication{ProtocolVersion: "SNMPv3", ContextName: "vlan-100"}
	b := &config.Authentication{ProtocolVersion: "SNMPv3", ContextName: "vlan-200"}

	assert.NotEqual(t, newTargetKey(target, a), newTargetKey(target, b))
	assert.Contains(t, newTargetKey(target, a).String(), "10.0.0.2:161")
}

// TestTargetKey_PlainTargetIsHostAndPort keeps the common key readable: a
// target with no NetBox ID and no context name is still just host and port.
func TestTargetKey_PlainTargetIsHostAndPort(t *testing.T) {
	target := config.Target{Host: "10.0.0.3", Port: 1161}
	assert.Equal(t, "10.0.0.3:1161", newTargetKey(target, &config.Authentication{ProtocolVersion: "SNMPv2c"}).String())
	assert.Equal(t, "10.0.0.3:1161", newTargetKey(target, nil).String())
}

// TestNewRunner_WarnsWhenRetriesCanExceedTheInterval separates the two cases.
// A single attempt that fills the interval can never produce a sample and is
// rejected. A retry sequence that reaches the interval only does so against a
// device that never answers, so it warns and the policy still starts.
func TestNewRunner_WarnsWhenRetriesCanExceedTheInterval(t *testing.T) {
	capture := func(pol config.Policy) (string, error) {
		var buf bytes.Buffer
		lg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		_, err := NewRunner(t.Context(), lg, "p1", pol, &spyCollector{})
		return buf.String(), err
	}

	// Nine seconds, ten retries, a ten second interval: each attempt fits, the
	// sequence does not. Accepted with a warning.
	out, err := capture(policyWithDial(10, 9, 10))
	require.NoError(t, err)
	assert.Contains(t, out, "SNMP retries can exceed the collection interval")

	// Exactly at the interval warns too.
	out, err = capture(policyWithDial(60, 12, 4))
	require.NoError(t, err)
	assert.Contains(t, out, "SNMP retries can exceed the collection interval")

	// One retry short of the interval is silent.
	out, err = capture(policyWithDial(60, 12, 3))
	require.NoError(t, err)
	assert.NotContains(t, out, "SNMP retries can exceed the collection interval")

	// A single attempt filling the interval is still an error, not a warning.
	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(30, 30, 0), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "snmp_timeout")
	assert.NotContains(t, err.Error(), "retries")

	// The largest retries the bound allows still warns rather than being
	// refused: eleven attempts of six seconds overrun a minute only against a
	// device that never answers. A count past the bound is a different case
	// and is rejected, since the client sizes an allocation with it.
	out, err = capture(policyWithDial(60, 6, maxPolicyRetries))
	require.NoError(t, err)
	assert.Contains(t, out, "SNMP retries can exceed the collection interval")
}

// ---------------------------------------------------------------------------
// Stopping a policy whose collection is still running
// ---------------------------------------------------------------------------

// stallingCollector models a collection slow enough to still be running when
// its policy is deleted. It records its observation only when the run was not
// cancelled, the way the real collector abandons a run whose context is done
// before it rebuilds the device store.
type stallingCollector struct {
	// runner is set by the test once the runner exists, so ForgetPolicy can
	// see whether the run had already been cancelled when it was called.
	runner *Runner

	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once

	mu                sync.Mutex
	store             map[string][]string
	forgotAfterCancel bool
}

func newStallingCollector() *stallingCollector {
	return &stallingCollector{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		store:   make(map[string][]string),
	}
}

func (s *stallingCollector) CollectTarget(ctx context.Context, target config.Target, _ *config.Authentication, policyName string, _ collector.DialOptions) error {
	s.enterOnce.Do(func() { close(s.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.release:
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[policyName] = append(s.store[policyName], target.Host)
	return nil
}

func (s *stallingCollector) ForgetPolicy(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgotAfterCancel = s.runner != nil && s.runner.ctx.Err() != nil
	delete(s.store, name)
}

func (s *stallingCollector) stored(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.store[name]...)
}

func (s *stallingCollector) forgetSawCancel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forgotAfterCancel
}

func (s *stallingCollector) unblock() {
	s.releaseOnce.Do(func() { close(s.release) })
}

// A policy deleted while a collection is running must not have that collection
// write its observations back after the state was dropped. Asserting the store
// is empty as Stop returns would pass against that, so the stalled run is let
// through to completion first.
func TestRunnerStop_CancelsACollectionStillInFlight(t *testing.T) {
	c := newStallingCollector()
	r, err := NewRunner(context.Background(), testLogger, "p1", policyWithDial(60, 5, 0), c)
	require.NoError(t, err)
	c.runner = r
	t.Cleanup(c.unblock)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.runMetrics(config.Target{Host: "192.0.2.1", Port: 161})
	}()
	<-c.entered

	require.NoError(t, r.Stop())
	assert.True(t, c.forgetSawCancel(), "the run must be cancelled before its state is dropped")

	c.unblock()
	<-done
	assert.Empty(t, c.stored("p1"), "a stopped policy's collection repopulated the store")
}

// gocron can only wait for a collection that is already running, so a run the
// scheduler cannot cancel holds the delete open for the whole stop timeout and
// then fails it. Cancelling before that wait is what lets the wait succeed.
func TestRunnerStop_CancelsBeforeWaitingForTheScheduler(t *testing.T) {
	c := newStallingCollector()
	r, err := NewRunner(context.Background(), testLogger, "p1", policyWithDial(60, 5, 0), c)
	require.NoError(t, err)
	c.runner = r
	t.Cleanup(c.unblock)

	r.Start()
	jobs := r.scheduler.Jobs()
	require.Len(t, jobs, 1)
	// The run bounds itself at metrics_interval, a minute here, so nothing but
	// Stop can end it inside the scheduler's ten second stop timeout.
	require.NoError(t, jobs[0].RunNow())
	<-c.entered

	start := time.Now()
	require.NoError(t, r.Stop(), "the scheduler timed out waiting for the collection")
	assert.Less(t, time.Since(start), 5*time.Second)
}

// TestRunMetrics_CollidingIdentityFieldsKeepErrorsApart is the error-map half of
// the same defect. The healthy target's collection must not clear an error
// belonging to a target that only looks the same once the identity fields are
// joined into one string.
func TestRunMetrics_CollidingIdentityFieldsKeepErrorsApart(t *testing.T) {
	c := &failingCollector{failIDs: map[string]bool{"a context=b": true}}
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, 0), c)
	require.NoError(t, err)

	failing := config.Target{Host: "10.0.0.1", Port: 161, ID: "a context=b"}
	healthy := config.Target{Host: "10.0.0.1", Port: 161, ID: "a", Authentication: v3ContextAuth("b")}

	r.runMetrics(failing)
	r.runMetrics(healthy)

	_, lastErr := r.GetLastError()
	require.Error(t, lastErr, "a healthy target cleared an unrelated target's error")
	assert.Contains(t, lastErr.Error(), "unreachable")
}

// ---------------------------------------------------------------------------
// A retry count the SNMP client allocates on
// ---------------------------------------------------------------------------

// gosnmp starts every request with make([]uint32, 0, Retries+1), so the policy
// field is an allocation size the caller chooses. A few billion is a valid
// capacity of several gigabytes and exhausts the process on the first
// scheduled collection; near MaxInt the addition wraps and the capacity is
// rejected instead. Neither reaches a device, so the value is refused where the
// other policy bounds are.
func TestValidate_RejectsRetriesAboveTheCeiling(t *testing.T) {
	m := newTestManager()
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, 5, maxPolicyRetries+1)), "retries")
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, 5, 1<<31)), "retries")
	assert.ErrorContains(t, m.validatePolicy(policyWithDial(60, 5, math.MaxInt)), "retries")

	require.NoError(t, m.validatePolicy(policyWithDial(60, 5, maxPolicyRetries)),
		"the ceiling itself is accepted")
}

// NewRunner builds the dial options the client is constructed from and is
// reachable without the API, so it carries the bound too.
func TestNewRunner_RejectsRetriesAboveTheCeiling(t *testing.T) {
	_, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, maxPolicyRetries+1), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "retries")

	_, err = NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, math.MaxInt), &spyCollector{})
	require.Error(t, err)
	assert.ErrorContains(t, err, "retries")

	// The ceiling itself is accepted, and reaches the collector unchanged.
	spy := &spyCollector{}
	r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, maxPolicyRetries), spy)
	require.NoError(t, err)
	r.runMetrics(config.Target{Host: "192.168.1.1", Port: 161})
	require.Len(t, spy.dials, 1)
	assert.Equal(t, maxPolicyRetries, spy.dials[0].Retries)
}
