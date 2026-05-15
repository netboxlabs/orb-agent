package secretsmgr

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// stubFetcher is a programmable fetch func for pollingBase tests.
type stubFetcher struct {
	values map[string]string
	errs   map[string]error
	calls  atomic.Int32
}

func newStubFetcher() *stubFetcher {
	return &stubFetcher{values: map[string]string{}, errs: map[string]error{}}
}

func (s *stubFetcher) fn(body string) (string, error) {
	s.calls.Add(1)
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
	s.values["k"] = "v1"
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
	s.values["k"] = "v1"
	b := newBaseForTest(t, "scheme", s.fn)

	gotCalls := make(chan map[string]bool, 1)
	b.RegisterUpdatePoliciesCallback(func(m map[string]bool) { gotCalls <- m })

	_, _ = b.resolveBody("k", "policy-1")
	s.values["k"] = "v2"

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
	s.values["a"] = "va1"
	s.values["b"] = "vb1"
	b := newBaseForTest(t, "scheme", s.fn)

	gotCalls := make(chan map[string]bool, 1)
	b.RegisterUpdatePoliciesCallback(func(m map[string]bool) { gotCalls <- m })

	_, _ = b.resolveBody("a", "policy-shared")
	_, _ = b.resolveBody("b", "policy-shared")

	// One fails, one changes — failure must stick for the shared policy.
	s.errs["a"] = errors.New("boom")
	s.values["b"] = "vb2"

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
	s.values["TOKEN"] = "s3cret"
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
	s.values["BE"] = "be1"
	s.values["FS"] = "fs1"
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
	s.values["k"] = "v1"
	b := newBaseForTest(t, "scheme", s.fn)

	called := atomic.Bool{}
	b.RegisterUpdatePoliciesCallback(func(map[string]bool) { called.Store(true) })

	_, _ = b.resolveBody("k", "p1")
	b.pollSecrets()
	require.False(t, called.Load())
}
