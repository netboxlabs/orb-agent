package secretsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// fakeDelineaSecret is what our fake server serves; only fields we care about.
type fakeDelineaSecret struct {
	Name  string                  `json:"Name"`
	ID    int                     `json:"ID"`
	Items []fakeDelineaSecretItem `json:"Items"`
}

type fakeDelineaSecretItem struct {
	Slug      string `json:"Slug"`
	ItemValue string `json:"ItemValue"`
}

// fakeDelineaServer returns an httptest.Server emulating the three endpoints
// the SDK calls. secrets is keyed both by stringified ID and by secretPath.
type fakeDelineaServer struct {
	*httptest.Server
	mu          sync.Mutex
	byID        map[int]fakeDelineaSecret
	byPath      map[string]fakeDelineaSecret
	authCalls   atomic.Int32
	secretCalls atomic.Int32
}

func newFakeDelineaServer() *fakeDelineaServer {
	f := &fakeDelineaServer{
		byID:   make(map[int]fakeDelineaSecret),
		byPath: make(map[string]fakeDelineaSecret),
	}
	mux := http.NewServeMux()

	// Health check endpoint — SDK calls this to detect Secret Server vs Platform.
	// Returning {"healthy":true} makes checkPlatformDetails treat this as a
	// regular Secret Server and proceed to /oauth2/token for auth.
	mux.HandleFunc("/api/v1/healthcheck", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"healthy":true}`))
	})

	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		f.authCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-token","token_type":"bearer","expires_in":3600,"refresh_token":""}`))
	})

	mux.HandleFunc("/api/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		f.secretCalls.Add(1)
		// "/api/v1/secrets/<id>" — id "0" with ?secretPath= means by-path
		idStr := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
		f.mu.Lock()
		defer f.mu.Unlock()

		if idStr == "0" {
			path := r.URL.Query().Get("secretPath")
			s, ok := f.byPath[path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(s)
			return
		}
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		s, ok := f.byID[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(s)
	})

	f.Server = httptest.NewServer(mux)
	return f
}

func (f *fakeDelineaServer) putByID(id int, s fakeDelineaSecret) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s.ID = id
	f.byID[id] = s
}

func (f *fakeDelineaServer) putByPath(path string, s fakeDelineaSecret) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byPath[path] = s
}

func TestDelineaStart_ConfigValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		cfg     config.DelineaManager
		wantErr string
	}{
		{
			name:    "both ServerURL and Tenant empty",
			cfg:     config.DelineaManager{Username: "u", Password: "p"},
			wantErr: "exactly one of server_url or tenant",
		},
		{
			name:    "both ServerURL and Tenant set",
			cfg:     config.DelineaManager{ServerURL: "https://example.com", Tenant: "example", Username: "u", Password: "p"},
			wantErr: "exactly one of server_url or tenant",
		},
		{
			name:    "missing username",
			cfg:     config.DelineaManager{ServerURL: "https://example.com", Password: "p"},
			wantErr: "username is required",
		},
		{
			name:    "missing password",
			cfg:     config.DelineaManager{ServerURL: "https://example.com", Username: "u"},
			wantErr: "password is required",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &delineaManager{preLogger: newTestLogger(), config: tc.cfg}
			err := m.Start(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestDelineaStart_ResolvesEnvCredentials(t *testing.T) {
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "hunter2"}}})

	t.Setenv("DELINEA_TEST_USER", "svc_orb")
	t.Setenv("DELINEA_TEST_PASS", "real-secret")

	m := &delineaManager{
		preLogger: newTestLogger(),
		config: config.DelineaManager{
			ServerURL: fake.URL,
			Username:  "${DELINEA_TEST_USER}",
			Password:  "${DELINEA_TEST_PASS}",
		},
	}
	require.NoError(t, m.Start(context.Background()))
	assert.Equal(t, "svc_orb", m.config.Username)
	assert.Equal(t, "real-secret", m.config.Password)

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.NoError(t, err)
}

func TestDelineaStart_UnsetEnvFailsClearly(t *testing.T) {
	m := &delineaManager{
		preLogger: newTestLogger(),
		config: config.DelineaManager{
			ServerURL: "https://example.com",
			Username:  "svc_orb",
			Password:  "${DELINEA_TEST_DEFINITELY_UNSET}",
		},
	}
	err := m.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolving delinea password from environment")
}

func TestDelineaSolvePolicySecrets_ByID(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)

	fake.putByID(42, fakeDelineaSecret{
		Name: "orb-test",
		Items: []fakeDelineaSecretItem{
			{Slug: "password", ItemValue: "hunter2"},
		},
	})

	m := &delineaManager{
		preLogger: newTestLogger(),
		config: config.DelineaManager{
			ServerURL: fake.URL,
			Username:  "u",
			Password:  "p",
		},
	}
	require.NoError(t, m.Start(context.Background()))

	out, err := m.SolvePolicySecrets(config.PolicyPayload{
		ID:   "policy-1",
		Data: map[string]any{"creds": "${delinea://id/42/password}"},
	})
	require.NoError(t, err)

	data := out.Data.(map[string]any)
	assert.Equal(t, "hunter2", data["creds"])
}

func TestDelineaSolvePolicySecrets_ByPath(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)

	fake.putByPath("/Servers/prod-db", fakeDelineaSecret{
		Name: "prod-db",
		ID:   7,
		Items: []fakeDelineaSecretItem{
			{Slug: "password", ItemValue: "rotated-1"},
		},
	})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	out, err := m.SolvePolicySecrets(config.PolicyPayload{
		ID:   "policy-1",
		Data: map[string]any{"creds": "${delinea://path/Servers/prod-db/password}"},
	})
	require.NoError(t, err)
	assert.Equal(t, "rotated-1", out.Data.(map[string]any)["creds"])
}

func TestDelineaSolvePolicySecrets_CacheHit(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	payload := config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${delinea://id/1/password}"}}
	_, err := m.SolvePolicySecrets(payload)
	require.NoError(t, err)
	first := fake.secretCalls.Load()

	_, err = m.SolvePolicySecrets(payload)
	require.NoError(t, err)
	assert.Equal(t, first, fake.secretCalls.Load(), "second resolve should hit cache, not server")
}

func TestDelineaSolvePolicySecrets_FieldMissing(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "username", ItemValue: "demo"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `field "password" not found`)
}

func TestDelineaSolvePolicySecrets_ServerError(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	// no secrets added → 404

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${delinea://id/99/password}"}})
	require.Error(t, err)
}

func TestDelineaSolvePolicySecrets_BadGrammar(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	cases := []string{
		"${delinea://}",
		"${delinea://garbage}",
		"${delinea://id/abc/password}",
		"${delinea://id/1}",
		"${delinea://path/onlyone}",
		"${delinea://other/1/x}",
	}
	for _, ph := range cases {
		ph := ph
		t.Run(ph, func(t *testing.T) {
			t.Parallel()
			_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": ph}})
			require.Error(t, err)
		})
	}
}

func TestDelineaPolling_DetectsChange(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	changed := make(chan map[string]bool, 1)
	m.RegisterUpdatePoliciesCallback(func(ids map[string]bool) { changed <- ids })

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "policy-A", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.NoError(t, err)

	// Mutate the server-side value, then trigger pollSecrets directly.
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v2"}}})
	m.pollSecrets()

	select {
	case ids := <-changed:
		require.Contains(t, ids, "policy-A")
		assert.True(t, ids["policy-A"], "value-changed signal should be true")
	case <-time.After(2 * time.Second):
		t.Fatal("expected callback to fire on change")
	}
	assert.Equal(t, "v2", m.usedVars["id/1/password"].Value, "cache should be updated to v2")
}

// A failed poll must evict the cached value so a subsequent resolve goes
// back to Delinea instead of returning a stale credential the policy manager
// has already removed.
func TestDelineaPolling_FetchFailureEvictsCache(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))
	m.RegisterUpdatePoliciesCallback(func(map[string]bool) {})

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "policy-A", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.NoError(t, err)

	// Make subsequent fetches fail.
	fake.mu.Lock()
	delete(fake.byID, 1)
	fake.mu.Unlock()
	m.pollSecrets()

	m.mu.Lock()
	_, stillCached := m.usedVars["id/1/password"]
	m.mu.Unlock()
	assert.False(t, stillCached, "failed poll must evict the cache entry so the next resolve re-fetches from Delinea")
}

func TestDelineaPolling_FetchFailureSignalsFalse(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	changed := make(chan map[string]bool, 1)
	m.RegisterUpdatePoliciesCallback(func(ids map[string]bool) { changed <- ids })

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "policy-A", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.NoError(t, err)

	fake.Close() // server now returns errors
	m.pollSecrets()

	select {
	case ids := <-changed:
		require.Contains(t, ids, "policy-A")
		assert.False(t, ids["policy-A"], "fetch-failure signal should be false")
	case <-time.After(2 * time.Second):
		t.Fatal("expected callback to fire on fetch failure")
	}
}

// Two policies resolving the same uncached reference concurrently must both
// end up registered as dependents of the cached entry — a later goroutine's
// write must not overwrite the earlier goroutine's policyIDs map.
func TestDelineaResolveBody_ConcurrentMergesPolicyIDs(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("policy-%d", i)
			_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: id, Data: map[string]any{"c": "${delinea://id/1/password}"}})
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	cached, ok := m.usedVars["id/1/password"]
	require.True(t, ok)
	got := len(cached.policyIDs)
	m.mu.Unlock()
	assert.Equal(t, n, got, "every concurrent policy should be registered in the cache entry")
}

// When one cached secret fails to fetch and another for the same policy
// changes value in the same poll cycle, the policy must be reported as
// failed (false), not changed (true), regardless of map-iteration order.
func TestDelineaPolling_FailureIsStickyAcrossMultipleSecrets(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})
	fake.putByID(2, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	changed := make(chan map[string]bool, 1)
	m.RegisterUpdatePoliciesCallback(func(ids map[string]bool) { changed <- ids })

	_, err := m.SolvePolicySecrets(config.PolicyPayload{
		ID: "policy-A",
		Data: map[string]any{
			"a": "${delinea://id/1/password}",
			"b": "${delinea://id/2/password}",
		},
	})
	require.NoError(t, err)

	// One secret changes, the other goes missing (404).
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v2"}}})
	fake.mu.Lock()
	delete(fake.byID, 2)
	fake.mu.Unlock()

	m.pollSecrets()

	select {
	case ids := <-changed:
		require.Contains(t, ids, "policy-A")
		assert.False(t, ids["policy-A"], "failure should be sticky even when another secret changed")
	case <-time.After(2 * time.Second):
		t.Fatal("expected callback to fire")
	}
}

func TestDelineaSolveConfigSecrets(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(5, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "be-secret"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	backends := map[string]any{
		"common": map[string]any{
			"diode": map[string]any{
				"client_secret": "${delinea://id/5/password}",
			},
		},
	}
	cm := config.ManagerConfig{
		Active: "git",
		Sources: config.Sources{
			Git: config.GitManager{
				URL:      "https://example/repo.git",
				Password: "${delinea://id/5/password}",
			},
		},
	}

	gotBackends, gotCM, err := m.SolveConfigSecrets(backends, cm)
	require.NoError(t, err)
	assert.Equal(t, "be-secret", gotBackends["common"].(map[string]any)["diode"].(map[string]any)["client_secret"])
	assert.Equal(t, "be-secret", gotCM.Sources.Git.Password)
	// config-time secrets should not be tracked
	assert.Empty(t, m.usedVars)
}
