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

	gotCalls := make(chan map[string]bool, 1)
	b.RegisterUpdatePoliciesCallback(func(m map[string]bool) { gotCalls <- m })

	_, _ = b.resolveBody("k", "policy-1")
	s.setValue("k", "v2")

	b.pollSecrets()
	select {
	case m := <-gotCalls:
		require.Equal(t, map[string]bool{"policy-1": true}, m)
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

	gotCalls := make(chan map[string]bool, 1)
	b.RegisterUpdatePoliciesCallback(func(m map[string]bool) { gotCalls <- m })

	_, _ = b.resolveBody("a", "policy-shared")
	_, _ = b.resolveBody("b", "policy-shared")

	// One fails, one changes — failure must stick for the shared policy.
	s.setError("a", errors.New("boom"))
	s.setValue("b", "vb2")

	b.pollSecrets()
	select {
	case m := <-gotCalls:
		require.Equal(t, map[string]bool{"policy-shared": false}, m)
	case <-time.After(time.Second):
		t.Fatal("expected sticky-failure callback not invoked")
	}
	b.mu.Lock()
	_, present := b.usedVars["a"]
	b.mu.Unlock()
	require.False(t, present, "failed entry must be evicted")
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
	b.RegisterUpdatePoliciesCallback(func(map[string]bool) { called.Store(true) })

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
	b.RegisterUpdatePoliciesCallback(func(map[string]bool) {})

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
	got := make(chan map[string]bool, 4)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b.RegisterUpdatePoliciesCallback(func(m map[string]bool) { got <- m })
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
		require.Equal(t, map[string]bool{"policy-1": true}, m)
	case <-time.After(time.Second):
		t.Fatal("callback not invoked after registration")
	}
}
