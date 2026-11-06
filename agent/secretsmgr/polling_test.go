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
