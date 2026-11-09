package secretsmgr

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// stubFetcher is a programmable fetch func for pollingBase tests. It is
// safe for concurrent reads and rewrites of the values/errs maps.
type stubFetcher struct {
	mu     sync.Mutex
	values map[string]string
	errs   map[string]error
	calls  atomic.Int32
}

func newStubFetcher() *stubFetcher {
	return &stubFetcher{values: map[string]string{}, errs: map[string]error{}}
}

func (s *stubFetcher) setValue(body, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[body] = v
	delete(s.errs, body)
}

func (s *stubFetcher) setError(body string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs[body] = err
}

func (s *stubFetcher) fn(body string) (string, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err, ok := s.errs[body]; ok {
		return "", err
	}
	if v, ok := s.values[body]; ok {
		return v, nil
	}
	return "", fmt.Errorf("stub: not found %q", body)
}

func newBaseForTest(t *testing.T, scheme string, fetch fetchFunc) *pollingBase {
	t.Helper()
	b := &pollingBase{}
	b.init(context.Background(), newTestLogger(), scheme, fetch)
	return b
}

func TestPollingBase_ResolveBodyCachesValue(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)

	v, err := b.resolveBody("k", "policy-a")
	require.NoError(t, err)
	require.Equal(t, "v1", v)

	v2, err := b.resolveBody("k", "policy-b")
	require.NoError(t, err)
	require.Equal(t, "v1", v2)
	require.EqualValues(t, 1, s.calls.Load())

	b.mu.Lock()
	require.True(t, b.usedVars["k"].policyIDs["policy-a"])
	require.True(t, b.usedVars["k"].policyIDs["policy-b"])
	b.mu.Unlock()
}

func TestPollingBase_PollSecretsDetectsChange(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)

	gotCalls := make(chan map[string]error, 1)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { gotCalls <- m })

	_, _ = b.resolveBody("k", "policy-1")
	s.setValue("k", "v2")

	b.pollSecrets()
	select {
	case m := <-gotCalls:
		require.Equal(t, map[string]error{"policy-1": nil}, m)
	case <-time.After(time.Second):
		t.Fatal("expected callback not invoked")
	}
	b.mu.Lock()
	require.Equal(t, "v2", b.usedVars["k"].Value)
	b.mu.Unlock()
}

func TestPollingBase_PollSecretsStickyFailure(t *testing.T) {
	s := newStubFetcher()
	s.setValue("a", "va1")
	s.setValue("b", "vb1")
	b := newBaseForTest(t, "scheme", s.fn)

	gotCalls := make(chan map[string]error, 1)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { gotCalls <- m })

	_, _ = b.resolveBody("a", "policy-shared")
	_, _ = b.resolveBody("b", "policy-shared")

	// One fails, one changes — failure must stick for the shared policy.
	s.setError("a", errors.New("boom"))
	s.setValue("b", "vb2")

	b.pollSecrets()
	select {
	case m := <-gotCalls:
		require.Len(t, m, 1)
		require.ErrorContains(t, m["policy-shared"], "boom")
	case <-time.After(time.Second):
		t.Fatal("expected sticky-failure callback not invoked")
	}
	b.mu.Lock()
	entry, present := b.usedVars["a"]
	b.mu.Unlock()
	require.True(t, present, "a failed entry stays, so the next poll reads it again")
	require.True(t, entry.failed, "a failed entry is marked failed, so its value is not served")
}

func TestPollingBase_SolvePolicySecrets(t *testing.T) {
	s := newStubFetcher()
	s.setValue("TOKEN", "s3cret")
	b := newBaseForTest(t, "scheme", s.fn)

	payload := config.PolicyPayload{
		ID: "p1",
		Data: map[string]any{
			"auth": map[string]any{"token": "${scheme://TOKEN}"},
		},
	}
	out, err := b.SolvePolicySecrets(payload)
	require.NoError(t, err)
	auth := out.Data.(map[string]any)["auth"].(map[string]any)
	require.Equal(t, "s3cret", auth["token"])
}

// TestPollingBase_SolvePolicySecrets_GenericScheme verifies that the
// provider-agnostic ${secret://…} scheme resolves identically to the
// provider's native scheme, and that a payload mixing both forms across two
// separate string leaves resolves both.
func TestPollingBase_SolvePolicySecrets_GenericScheme(t *testing.T) {
	s := newStubFetcher()
	s.setValue("TOKEN", "s3cret")
	s.setValue("OTHER", "0th3r")
	b := newBaseForTest(t, "scheme", s.fn)

	payload := config.PolicyPayload{
		ID: "p1",
		Data: map[string]any{
			"auth": map[string]any{
				"native":  "${scheme://TOKEN}",
				"generic": "${secret://OTHER}",
			},
		},
	}
	out, err := b.SolvePolicySecrets(payload)
	require.NoError(t, err)
	auth := out.Data.(map[string]any)["auth"].(map[string]any)
	require.Equal(t, "s3cret", auth["native"])
	require.Equal(t, "0th3r", auth["generic"])
}

// TestPollingBase_SolveConfigSecrets_GenericScheme verifies the config-secrets
// path also accepts the provider-agnostic ${secret://…} scheme.
func TestPollingBase_SolveConfigSecrets_GenericScheme(t *testing.T) {
	s := newStubFetcher()
	s.setValue("FS", "fs1")
	b := newBaseForTest(t, "scheme", s.fn)

	backends := map[string]any{}
	cm := config.ManagerConfig{
		Active: "fleet",
		Sources: config.Sources{
			Fleet: config.FleetManager{ClientSecret: "${secret://FS}"},
		},
	}

	_, outCM, err := b.SolveConfigSecrets(backends, cm)
	require.NoError(t, err)
	require.Equal(t, "fs1", outCM.Sources.Fleet.ClientSecret)
}

func TestPollingBase_SolveConfigSecretsClearsTracking(t *testing.T) {
	s := newStubFetcher()
	s.setValue("BE", "be1")
	s.setValue("FS", "fs1")
	b := newBaseForTest(t, "scheme", s.fn)

	backends := map[string]any{"o": map[string]any{"t": "${scheme://BE}"}}
	cm := config.ManagerConfig{
		Active: "fleet",
		Sources: config.Sources{
			Fleet: config.FleetManager{ClientSecret: "${scheme://FS}"},
		},
	}

	outBE, outCM, err := b.SolveConfigSecrets(backends, cm)
	require.NoError(t, err)
	require.Equal(t, "be1", outBE["o"].(map[string]any)["t"])
	require.Equal(t, "fs1", outCM.Sources.Fleet.ClientSecret)
	b.mu.Lock()
	require.Empty(t, b.usedVars)
	b.mu.Unlock()
}

func TestPollingBase_NoCallbackWhenNothingChanged(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)

	called := atomic.Bool{}
	b.RegisterUpdatePoliciesCallback(func(map[string]error) { called.Store(true) })

	_, _ = b.resolveBody("k", "p1")
	b.pollSecrets()
	require.False(t, called.Load())
}

// TestPollingBase_ConcurrentResolveAndPoll exercises the race-safety claim:
// many goroutines call resolveBody for distinct and overlapping bodies while
// pollSecrets runs in parallel. The race detector and a final cache audit
// catch lost updates, deadlocks, or duplicate cache entries.
func TestPollingBase_ConcurrentResolveAndPoll(t *testing.T) {
	s := newStubFetcher()
	const N = 32
	for i := 0; i < N; i++ {
		s.setValue(fmt.Sprintf("k%d", i), fmt.Sprintf("v%d-1", i))
	}
	b := newBaseForTest(t, "scheme", s.fn)
	b.RegisterUpdatePoliciesCallback(func(map[string]error) {})

	var wg sync.WaitGroup
	// Concurrent resolveBody across distinct policies and bodies.
	for p := 0; p < 8; p++ {
		wg.Add(1)
		go func(policy int) {
			defer wg.Done()
			for i := 0; i < N; i++ {
				body := fmt.Sprintf("k%d", i)
				if _, err := b.resolveBody(body, fmt.Sprintf("policy-%d", policy)); err != nil {
					t.Errorf("resolveBody(%s): %v", body, err)
					return
				}
			}
		}(p)
	}
	// Concurrent poll cycles, with the server rotating half the values.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			for j := 0; j < N; j += 2 {
				s.setValue(fmt.Sprintf("k%d", j), fmt.Sprintf("v%d-2", j))
			}
			b.pollSecrets()
		}
	}()

	wg.Wait()

	b.mu.Lock()
	require.Len(t, b.usedVars, N, "every body should appear exactly once in the cache")
	for i := 0; i < N; i++ {
		entry, ok := b.usedVars[fmt.Sprintf("k%d", i)]
		require.True(t, ok, "missing cache entry for k%d", i)
		require.NotEmpty(t, entry.policyIDs, "entry k%d should have at least one policyID", i)
	}
	b.mu.Unlock()
}

// TestPollingBase_RegisterCallbackAfterStart verifies that registering the
// callback after a poll cycle has begun is race-free and that the freshly
// registered callback is observed by the next cycle.
func TestPollingBase_RegisterCallbackAfterStart(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)

	// First cycle: no callback registered → no panic, no-op.
	_, _ = b.resolveBody("k", "policy-1")
	b.pollSecrets()

	// Register callback concurrently with a second poll. Buffer is sized to
	// absorb both potential sends (the concurrent poll + the final poll
	// below) so the callback never blocks regardless of interleaving.
	got := make(chan map[string]error, 4)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	}()
	go func() {
		defer wg.Done()
		s.setValue("k", "v2")
		b.pollSecrets()
	}()
	wg.Wait()

	// At this point the callback is registered; another poll cycle should
	// observe a change if one was pending (or no change if the race already
	// delivered v2 to the cache). Force a known change and verify delivery.
	s.setValue("k", "v3")
	b.pollSecrets()

	select {
	case m := <-got:
		require.Equal(t, map[string]error{"policy-1": nil}, m)
	case <-time.After(time.Second):
		t.Fatal("callback not invoked after registration")
	}
}

// receiveChange returns the policies a poll reported, failing when it reported
// none. The callback runs inside pollSecrets, so a report is already sent.
func receiveChange(t *testing.T, got <-chan map[string]error) map[string]error {
	t.Helper()
	select {
	case m := <-got:
		return m
	default:
		t.Fatal("expected the poll to report its policies")
		return nil
	}
}

func requireNoChange(t *testing.T, got <-chan map[string]error) {
	t.Helper()
	select {
	case m := <-got:
		t.Fatalf("expected no report, got %v", m)
	default:
	}
}

// A read that fails is reported once, with its error, for every policy that
// uses the reference. The reference stays polled: a read that keeps failing
// reports nothing more, and once it resolves the policies are re-applied, even
// with the value it had before.
func TestPollingBase_AFailedReadIsReportedOnceAndPolledUntilItResolves(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	_, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)

	readErr := errors.New("secret not found: k")
	s.setError("k", readErr)
	b.pollSecrets()
	m := receiveChange(t, got)
	require.Len(t, m, 1)
	require.ErrorIs(t, m["policy-1"], readErr)

	b.pollSecrets()
	requireNoChange(t, got)

	s.setValue("k", "v1")
	b.pollSecrets()
	require.Equal(t, map[string]error{"policy-1": nil}, receiveChange(t, got))

	// Resolved again, the next poll reports nothing, the value is served from
	// the cache, and a new failure is reported again.
	b.pollSecrets()
	requireNoChange(t, got)
	calls := s.calls.Load()
	v, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)
	require.Equal(t, "v1", v)
	require.Equal(t, calls, s.calls.Load(), "a reference that resolves again is served from the cache")
	s.setError("k", readErr)
	b.pollSecrets()
	require.ErrorIs(t, receiveChange(t, got)["policy-1"], readErr)
}

// A failed reference is not served from the cache: a policy that resolves it
// again, as a re-delivery does, reads it from the provider.
func TestPollingBase_AFailedReferenceIsReadAgainWhenResolved(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)
	b.RegisterUpdatePoliciesCallback(func(map[string]error) {})
	_, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)

	s.setError("k", errors.New("secret not found: k"))
	b.pollSecrets()
	_, err = b.resolveBody("k", "policy-1")
	require.Error(t, err, "the value read before the failure must not be served")

	s.setValue("k", "v2")
	v, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)
	require.Equal(t, "v2", v)
}

// A reference that does not resolve when a policy is applied is polled too, so
// the policy is re-applied once it resolves, without a restart.
func TestPollingBase_AReferenceThatFailsAtFirstResolveIsPolled(t *testing.T) {
	s := newStubFetcher()
	s.setError("k", errors.New("secret not found: k"))
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })

	_, err := b.resolveBody("k", "policy-1")
	require.Error(t, err)
	b.pollSecrets()
	requireNoChange(t, got)

	s.setValue("k", "v1")
	b.pollSecrets()
	require.Equal(t, map[string]error{"policy-1": nil}, receiveChange(t, got))
}

// Once one policy resolves a failed reference again, as its re-delivery does,
// the next poll re-applies only the policies still failing on it: the one that
// resolved it already runs with the value.
func TestPollingBase_RecoveryReappliesOnlyThePoliciesStillFailing(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	for _, id := range []string{"policy-1", "policy-2"} {
		_, err := b.resolveBody("k", id)
		require.NoError(t, err)
	}

	s.setError("k", errors.New("secret not found: k"))
	b.pollSecrets()
	require.Len(t, receiveChange(t, got), 2)

	s.setValue("k", "v1")
	v, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)
	require.Equal(t, "v1", v)

	b.pollSecrets()
	require.Equal(t, map[string]error{"policy-2": nil}, receiveChange(t, got))
}

// A policy that resolves a failed reference again after another policy did is
// no longer failing on it either: the next poll re-applies neither.
func TestPollingBase_PoliciesThatResolvedAFailedReferenceAreNotReappliedByThePoll(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	for _, id := range []string{"policy-1", "policy-2"} {
		_, err := b.resolveBody("k", id)
		require.NoError(t, err)
	}
	s.setError("k", errors.New("secret not found: k"))
	b.pollSecrets()
	require.Len(t, receiveChange(t, got), 2)

	s.setValue("k", "v1")
	for _, id := range []string{"policy-1", "policy-2"} {
		_, err := b.resolveBody("k", id)
		require.NoError(t, err)
	}
	b.pollSecrets()
	requireNoChange(t, got)
}

// A poll that finds a reference failing tells the policies that use it while
// resolves of that reference change who fails on it. Run with -race; without
// it, the unguarded version ended in "concurrent map iteration and map write".
func TestPollingBase_APollTellsThePoliciesWhileResolvesChangeThem(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	fetch := func(string) (string, error) {
		if healthy.Load() {
			return "v", nil
		}
		return "", errors.New("sealed")
	}
	b := newBaseForTest(t, "scheme", fetch)
	b.RegisterUpdatePoliciesCallback(func(map[string]error) {})
	for i := 0; i < 3; i++ {
		_, _ = b.resolveBody("k", fmt.Sprintf("p%d", i))
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = b.resolveBody("k", fmt.Sprintf("p%d", i%3))
		}
	}()
	for n := 0; n < 2000; n++ {
		healthy.Store(false)
		b.pollSecrets()
		healthy.Store(true)
		b.pollSecrets()
	}
	close(stop)
	wg.Wait()
}

// A resolve whose own read fails while a poll finds the reference resolving
// again is served the poll's value.
func TestPollingBase_AResolveRacingARecoveringPollIsServedThePollsValue(t *testing.T) {
	var mu sync.Mutex
	resolveEntered := make(chan struct{})
	releaseResolve := make(chan struct{})
	healthy, resolving := false, false
	fetch := func(string) (string, error) {
		mu.Lock()
		isResolve := resolving
		resolving = false
		h := healthy
		mu.Unlock()
		if isResolve {
			close(resolveEntered)
			<-releaseResolve
			return "", errors.New("connection reset")
		}
		if h {
			return "v1", nil
		}
		return "", errors.New("sealed")
	}
	b := newBaseForTest(t, "scheme", fetch)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	_, err := b.resolveBody("k", "policy-1")
	require.Error(t, err)

	mu.Lock()
	resolving = true
	mu.Unlock()
	type result struct {
		v   string
		err error
	}
	done := make(chan result, 1)
	go func() { v, err := b.resolveBody("k", "policy-2"); done <- result{v, err} }()
	<-resolveEntered
	mu.Lock()
	healthy = true
	mu.Unlock()
	b.pollSecrets()
	require.Equal(t, map[string]error{"policy-1": nil}, receiveChange(t, got))
	close(releaseResolve)
	r := <-done
	require.NoError(t, r.err, "the poll read it meanwhile: its value is served")
	require.Equal(t, "v1", r.v)
}

// A policy that resolved a failed reference again stays among its users, so a
// later change of its value re-applies it with the others.
func TestPollingBase_APolicyThatResolvedAFailedReferenceIsReappliedOnItsNextChange(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	for _, id := range []string{"policy-1", "policy-2"} {
		_, err := b.resolveBody("k", id)
		require.NoError(t, err)
	}
	s.setError("k", errors.New("sealed"))
	b.pollSecrets()
	receiveChange(t, got)
	s.setValue("k", "v1")
	_, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)
	b.pollSecrets()
	require.Equal(t, map[string]error{"policy-2": nil}, receiveChange(t, got))

	s.setValue("k", "v2")
	b.pollSecrets()
	require.Equal(t, map[string]error{"policy-1": nil, "policy-2": nil}, receiveChange(t, got))
}

// A policy failing on several references is reported with the first in order,
// the same every time.
func TestPollingBase_APolicyFailingOnSeveralReferencesIsReportedWithTheFirst(t *testing.T) {
	for i := 0; i < 20; i++ {
		s := newStubFetcher()
		b := newBaseForTest(t, "scheme", s.fn)
		got := make(chan map[string]error, 1)
		b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
		for _, k := range []string{"a", "b", "c", "d"} {
			s.setValue(k, "v")
			_, err := b.resolveBody(k, "policy-1")
			require.NoError(t, err)
		}
		for _, k := range []string{"a", "b", "c", "d"} {
			s.setError(k, errors.New("gone: "+k))
		}
		b.pollSecrets()
		require.EqualError(t, receiveChange(t, got)["policy-1"], "gone: a")
	}
}

// Unresolved answers, from the cache, the failure of a reference the policy
// is still failing on, and nil once the policy resolved it again.
func TestPollingBase_UnresolvedAnswersAStandingFailureOnly(t *testing.T) {
	s := newStubFetcher()
	s.setValue("k", "v1")
	b := newBaseForTest(t, "scheme", s.fn)
	b.RegisterUpdatePoliciesCallback(func(map[string]error) {})
	_, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)
	require.NoError(t, b.Unresolved("policy-1"))

	readErr := errors.New("secret not found: k")
	s.setError("k", readErr)
	b.pollSecrets()
	calls := s.calls.Load()
	require.ErrorIs(t, b.Unresolved("policy-1"), readErr)
	require.Equal(t, calls, s.calls.Load(), "Unresolved reads no secret")
	require.NoError(t, b.Unresolved("policy-2"), "a policy that does not use it")

	s.setValue("k", "v1")
	_, err = b.resolveBody("k", "policy-1")
	require.NoError(t, err)
	require.NoError(t, b.Unresolved("policy-1"))
}

// A policy whose edit onto another reference is applied no longer uses the
// first one: the reference failing
// later does not report the policy, and one no policy uses is dropped.
func TestPollingBase_APolicyEditedOffAReferenceIsNotReportedForIt(t *testing.T) {
	s := newStubFetcher()
	s.setValue("old/community", "public")
	s.setValue("new/community", "public2")
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	_, err := b.SolvePolicySecrets(config.PolicyPayload{ID: "policy-1", Data: map[string]any{"c": "${scheme://old/community}"}})
	require.NoError(t, err)
	v2 := map[string]any{"c": "${scheme://new/community}"}
	_, err = b.SolvePolicySecrets(config.PolicyPayload{ID: "policy-1", Data: v2})
	require.NoError(t, err)
	b.PolicyApplied("policy-1", v2)

	s.setError("old/community", errors.New("secret not found: old/community"))
	b.pollSecrets()
	requireNoChange(t, got)
	b.mu.Lock()
	_, kept := b.usedVars["old/community"]
	b.mu.Unlock()
	require.False(t, kept, "a reference no policy uses is not read again")
	require.NoError(t, b.Unresolved("policy-1"))
}

// A removed policy is forgotten: a reference only it used, even one that never
// resolved, is no longer read.
func TestPollingBase_AForgottenPolicysReferencesAreNoLongerRead(t *testing.T) {
	s := newStubFetcher()
	s.setError("typo/path", errors.New("secret not found: typo/path"))
	s.setValue("shared", "v")
	b := newBaseForTest(t, "scheme", s.fn)
	b.RegisterUpdatePoliciesCallback(func(map[string]error) {})
	_, err := b.resolveBody("typo/path", "policy-1")
	require.Error(t, err)
	for _, id := range []string{"policy-1", "policy-2"} {
		_, err = b.resolveBody("shared", id)
		require.NoError(t, err)
	}

	b.ForgetPolicy("policy-1")

	b.mu.Lock()
	defer b.mu.Unlock()
	require.NotContains(t, b.usedVars, "typo/path")
	require.Equal(t, map[string]bool{"policy-2": true}, b.usedVars["shared"].policyIDs)
}

// A policy edited off a reference that is failing is not re-applied when that
// reference resolves again, and is no longer unresolved on its account.
func TestPollingBase_APolicyEditedOffAFailingReferenceIsNotReappliedForIt(t *testing.T) {
	s := newStubFetcher()
	s.setValue("old", "v")
	s.setValue("new", "v")
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	for _, id := range []string{"policy-1", "policy-2"} {
		_, err := b.SolvePolicySecrets(config.PolicyPayload{ID: id, Data: map[string]any{"c": "${scheme://old}"}})
		require.NoError(t, err)
	}
	s.setError("old", errors.New("sealed"))
	b.pollSecrets()
	require.Len(t, receiveChange(t, got), 2)

	v2 := map[string]any{"c": "${scheme://new}"}
	_, err := b.SolvePolicySecrets(config.PolicyPayload{ID: "policy-1", Data: v2})
	require.NoError(t, err)
	b.PolicyApplied("policy-1", v2)
	require.NoError(t, b.Unresolved("policy-1"))

	s.setValue("old", "v")
	b.pollSecrets()
	require.Equal(t, map[string]error{"policy-2": nil}, receiveChange(t, got))
}

// A policy failing on two references, one of which another policy resolved
// again since, is still unresolved on account of the other.
func TestPollingBase_UnresolvedLooksPastAReferenceThatResolvesAgain(t *testing.T) {
	s := newStubFetcher()
	s.setValue("a", "v")
	s.setValue("b", "v")
	b := newBaseForTest(t, "scheme", s.fn)
	b.RegisterUpdatePoliciesCallback(func(map[string]error) {})
	for _, k := range []string{"a", "b"} {
		_, err := b.resolveBody(k, "policy-1")
		require.NoError(t, err)
	}
	_, err := b.resolveBody("a", "policy-2")
	require.NoError(t, err)
	bErr := errors.New("gone: b")
	s.setError("a", errors.New("gone: a"))
	s.setError("b", bErr)
	b.pollSecrets()

	s.setValue("a", "v")
	_, err = b.resolveBody("a", "policy-2")
	require.NoError(t, err)

	require.ErrorIs(t, b.Unresolved("policy-1"), bErr)
}

// Resolving an update does not drop the references of the version still
// running: until the update is applied, a reference only the running version
// names still reports the policy, so revoking it stops that version.
func TestPollingBase_ResolvingAnUpdateKeepsTheRunningVersionsReferences(t *testing.T) {
	s := newStubFetcher()
	s.setValue("old", "v")
	b := newBaseForTest(t, "scheme", s.fn)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	v1 := map[string]any{"c": "${scheme://old}"}
	_, err := b.SolvePolicySecrets(config.PolicyPayload{ID: "policy-1", Data: v1})
	require.NoError(t, err)
	b.PolicyApplied("policy-1", v1)

	_, err = b.SolvePolicySecrets(config.PolicyPayload{ID: "policy-1", Data: map[string]any{"c": "${scheme://new}"}})
	require.Error(t, err, "the update's secret does not resolve")

	s.setError("old", errors.New("revoked"))
	b.pollSecrets()
	require.ErrorContains(t, receiveChange(t, got)["policy-1"], "revoked")
}

// A poll's read of a failed reference that fails after a resolve read it
// successfully, as a re-delivery does, is out of date: the reference stays
// healthy and the poll reports nothing for it.
func TestPollingBase_APollsFailedReadOvertakenByASuccessfulResolveIsDropped(t *testing.T) {
	var mu sync.Mutex
	failing, armed := true, false
	entered, release := make(chan struct{}), make(chan struct{})
	fetch := func(string) (string, error) {
		mu.Lock()
		gate, down := armed, failing
		armed = false
		mu.Unlock()
		if gate {
			close(entered)
			<-release
			return "", errors.New("connection reset")
		}
		if down {
			return "", errors.New("sealed")
		}
		return "v1", nil
	}
	b := newBaseForTest(t, "scheme", fetch)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	_, err := b.resolveBody("k", "policy-1")
	require.Error(t, err, "the reference fails from the start")

	mu.Lock()
	armed, failing = true, false
	mu.Unlock()
	done := make(chan struct{})
	go func() { b.pollSecrets(); close(done) }()
	<-entered
	v, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)
	require.Equal(t, "v1", v)
	close(release)
	<-done

	requireNoChange(t, got)
	require.NoError(t, b.Unresolved("policy-1"))
	b.mu.Lock()
	defer b.mu.Unlock()
	require.False(t, b.usedVars["k"].failed)
}

// A reference dropped while a poll reads it, and resolved again by another
// policy meanwhile, is a new entry: the poll's read of the old one is
// discarded, even when it fails, so the policy that resolved it keeps running.
func TestPollingBase_APollsReadOfAReplacedReferenceIsDiscarded(t *testing.T) {
	var mu sync.Mutex
	armed := false
	entered, release := make(chan struct{}), make(chan struct{})
	fetch := func(string) (string, error) {
		mu.Lock()
		gate := armed
		armed = false
		mu.Unlock()
		if gate {
			close(entered)
			<-release
			return "", errors.New("connection reset")
		}
		return "v1", nil
	}
	b := newBaseForTest(t, "scheme", fetch)
	got := make(chan map[string]error, 4)
	b.RegisterUpdatePoliciesCallback(func(m map[string]error) { got <- m })
	_, err := b.resolveBody("k", "policy-1")
	require.NoError(t, err)

	mu.Lock()
	armed = true
	mu.Unlock()
	done := make(chan struct{})
	go func() { b.pollSecrets(); close(done) }()
	<-entered
	b.ForgetPolicy("policy-1")
	_, err = b.resolveBody("k", "policy-2")
	require.NoError(t, err)
	close(release)
	<-done

	requireNoChange(t, got)
	require.NoError(t, b.Unresolved("policy-2"))
	b.mu.Lock()
	defer b.mu.Unlock()
	require.False(t, b.usedVars["k"].failed)
}
