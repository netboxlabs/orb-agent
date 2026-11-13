package secretsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"
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

	changed := make(chan map[string]error, 1)
	m.RegisterUpdatePoliciesCallback(func(ids map[string]error) { changed <- ids })

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "policy-A", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.NoError(t, err)

	// Mutate the server-side value, then trigger pollSecrets directly.
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v2"}}})
	m.pollSecrets()

	select {
	case ids := <-changed:
		require.Contains(t, ids, "policy-A")
		assert.NoError(t, ids["policy-A"], "value-changed signal should carry no error")
	case <-time.After(2 * time.Second):
		t.Fatal("expected callback to fire on change")
	}
	assert.Equal(t, "v2", m.usedVars["id/1/password"].Value, "cache should be updated to v2")
}

// A failed poll must stop serving the cached value so a subsequent resolve
// goes back to Delinea instead of returning a stale credential the policy
// manager has already stopped, while the entry stays for the next poll.
func TestDelineaPolling_FetchFailureStopsServingTheCachedValue(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))
	m.RegisterUpdatePoliciesCallback(func(map[string]error) {})

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "policy-A", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.NoError(t, err)

	// Make subsequent fetches fail.
	fake.mu.Lock()
	delete(fake.byID, 1)
	fake.mu.Unlock()
	m.pollSecrets()

	m.mu.Lock()
	entry, stillCached := m.usedVars["id/1/password"]
	m.mu.Unlock()
	assert.True(t, stillCached, "a failed entry stays, so the next poll reads it again")
	assert.True(t, entry.failed, "a failed entry is marked failed, so the next resolve re-fetches from Delinea")
}

func TestDelineaPolling_FetchFailureSignalsTheError(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v1"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	changed := make(chan map[string]error, 1)
	m.RegisterUpdatePoliciesCallback(func(ids map[string]error) { changed <- ids })

	_, err := m.SolvePolicySecrets(config.PolicyPayload{ID: "policy-A", Data: map[string]any{"c": "${delinea://id/1/password}"}})
	require.NoError(t, err)

	fake.Close() // server now returns errors
	m.pollSecrets()

	select {
	case ids := <-changed:
		require.Contains(t, ids, "policy-A")
		assert.Error(t, ids["policy-A"], "fetch-failure signal should carry the error")
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

	changed := make(chan map[string]error, 1)
	m.RegisterUpdatePoliciesCallback(func(ids map[string]error) { changed <- ids })

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
		assert.Error(t, ids["policy-A"], "failure should be sticky even when another secret changed")
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

// newStubDelineaServer answers the health check and the token grant the SDK
// performs before its first read, and hands every secret request to secrets.
func newStubDelineaServer(t *testing.T, secrets http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/healthcheck", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"healthy":true}`))
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fake-token","token_type":"bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/api/v1/secrets/", secrets)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fetchWithin runs m.fetch(body) and fails the test if it has not returned
// within limit, so a read that hangs fails instead of stalling the suite.
func fetchWithin(t *testing.T, m *delineaManager, body string, limit time.Duration) (string, time.Duration, error) {
	t.Helper()
	type result struct {
		val string
		err error
	}
	done := make(chan result, 1)
	began := time.Now()
	go func() {
		val, err := m.fetch(body)
		done <- result{val, err}
	}()
	select {
	case r := <-done:
		return r.val, time.Since(began), r.err
	case <-time.After(limit):
		t.Fatalf("read of %q did not return within %s", body, limit)
		return "", 0, nil
	}
}

// A connection reset while the secret is read is an error, not a panic.
func TestDelineaFetch_ConnectionResetReturnsAnError(t *testing.T) {
	t.Parallel()
	srv := newStubDelineaServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0) // close with a RST
		}
		_ = conn.Close()
	})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: srv.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	_, _, err := fetchWithin(t, m, "id/1/password", 10*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get secret id=1")
}

// A Secret Server that accepts the read and never answers fails it after the
// configured timeout.
func TestDelineaFetch_SilentServerTimesOut(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := newStubDelineaServer(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) }) // runs before srv.Close

	const timeout = 300 * time.Millisecond
	m := &delineaManager{
		preLogger: newTestLogger(),
		config:    config.DelineaManager{ServerURL: srv.URL, Username: "u", Password: "p"},
		timeout:   timeout,
	}
	require.NoError(t, m.Start(context.Background()))

	_, took, err := fetchWithin(t, m, "id/1/password", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.GreaterOrEqual(t, took, timeout)
	assert.Less(t, took, 3*time.Second, "one read, retries included, stays within the timeout")
}

// The SDK's bearer token is not left in the process environment, which the
// backends the agent starts inherit.
func TestDelineaFetch_LeavesNoTokenInTheEnvironment(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v"}}})

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	val, err := m.fetch("id/1/password")
	require.NoError(t, err)
	assert.Equal(t, "v", val)

	prefix := "SS_AT_" + url.QueryEscape(fake.URL)
	for _, kv := range os.Environ() {
		assert.False(t, strings.HasPrefix(kv, prefix), "the token cache must not be in the environment: %s", strings.SplitN(kv, "=", 2)[0])
	}
}

func TestDelineaStart_Timeout(t *testing.T) {
	t.Parallel()
	seconds := func(n int) *int { return &n }
	cases := []struct {
		name    string
		timeout *int
		want    time.Duration
	}{
		{"unset", nil, 60 * time.Second},
		{"set", seconds(5), 5 * time.Second},
		{"zero", seconds(0), 60 * time.Second},
		{"negative", seconds(-1), 60 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &delineaManager{
				preLogger: newTestLogger(),
				config:    config.DelineaManager{ServerURL: "https://secrets.example.invalid", Username: "u", Password: "p", Timeout: tc.timeout},
			}
			require.NoError(t, m.Start(context.Background()))
			assert.Equal(t, tc.want, m.timeout, "the limit of one read")
			assert.Equal(t, tc.want, m.client.Timeout, "the SDK's limit of one attempt")
			assert.True(t, m.client.DisableRetries, "one attempt per read")
		})
	}
}

// A server_url over plain HTTP keeps working, as it did before the SDK began
// refusing one to a host other than the loopback, and the agent warns once.
func TestDelineaStart_PlainHTTPServerURL(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)
	fake.putByID(1, fakeDelineaSecret{Items: []fakeDelineaSecretItem{{Slug: "password", ItemValue: "v"}}})

	// The SDK does not take 0.0.0.0 for a loopback address, but Go dials it on
	// this host, so the read reaches the fake server.
	u, err := url.Parse(fake.URL)
	require.NoError(t, err)
	logger, buf := newCapturingLogger()
	m := &delineaManager{
		preLogger: logger,
		config:    config.DelineaManager{ServerURL: "HTTP://0.0.0.0:" + u.Port(), Username: "svc_orb", Password: "synthetic-password-42"},
	}
	require.NoError(t, m.Start(context.Background()))

	val, err := m.fetch("id/1/password")
	require.NoError(t, err)
	assert.Equal(t, "v", val)

	logs := buf.String()
	assert.Equal(t, 1, strings.Count(logs, `"level":"WARN"`), logs)
	assert.Contains(t, logs, "plain HTTP")
	assert.NotContains(t, logs, "synthetic-password-42")
}

func TestDelineaStart_HTTPSServerURLDoesNotWarn(t *testing.T) {
	t.Parallel()
	logger, buf := newCapturingLogger()
	m := &delineaManager{
		preLogger: logger,
		config:    config.DelineaManager{ServerURL: "https://secrets.example.invalid", Username: "u", Password: "p"},
	}
	require.NoError(t, m.Start(context.Background()))
	assert.False(t, m.client.AllowInsecureHTTP)
	assert.NotContains(t, buf.String(), `"level":"WARN"`)
}

// newFakeDelineaPlatform emulates the Delinea Platform: its health check, its
// client-credentials grant, and a vault broker naming vaultURL as the default
// vault, where the SDK sends the secret requests.
func newFakeDelineaPlatform(t *testing.T, vaultURL string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/healthcheck", http.NotFound)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"healthy":true}`))
	})
	mux.HandleFunc("/identity/api/oauth2/token/xpmplatform", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"platform-token","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/vaultbroker/api/vaults", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"vaults": []map[string]any{{
			"vaultId": "vault-1", "name": "main", "type": "SecretServer",
			"isDefault": true, "isActive": true,
			"connection": map[string]any{"url": vaultURL},
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// allowed_vault_hosts reaches the SDK: a vault on a host the Platform does not
// share is refused unless it is listed.
func TestDelineaStart_AllowedVaultHosts(t *testing.T) {
	t.Parallel()
	// A port nothing listens on: a read routed to the vault fails to connect.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	vaultHost := l.Addr().String()
	require.NoError(t, l.Close())
	platform := newFakeDelineaPlatform(t, "https://"+vaultHost)

	read := func(t *testing.T, allowed []string) error {
		t.Helper()
		m := &delineaManager{
			preLogger: newTestLogger(),
			config: config.DelineaManager{
				ServerURL: platform.URL, Username: "client-id", Password: "client-secret",
				AllowedVaultHosts: allowed,
			},
			timeout: 5 * time.Second,
		}
		require.NoError(t, m.Start(context.Background()))
		_, _, err := fetchWithin(t, m, "id/1/password", 10*time.Second)
		require.Error(t, err)
		return err
	}

	err = read(t, nil)
	assert.Contains(t, err.Error(), "untrusted vault host")

	err = read(t, []string{"vault.example.invalid", vaultHost})
	assert.NotContains(t, err.Error(), "untrusted vault host")
	assert.Contains(t, err.Error(), "connection refused", "the read was sent to the vault")
}

func TestDelineaStart_AllowedVaultHostsRejectsAURL(t *testing.T) {
	t.Parallel()
	m := &delineaManager{
		preLogger: newTestLogger(),
		config: config.DelineaManager{
			ServerURL: "https://secrets.example.invalid", Username: "u", Password: "p",
			AllowedVaultHosts: []string{"https://vault.example.invalid"},
		},
	}
	err := m.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_vault_hosts")
}

// A secret Secret Server reports missing carries the HTTP status in a typed error.
func TestDelineaFetch_NotFoundCarriesTheStatus(t *testing.T) {
	t.Parallel()
	fake := newFakeDelineaServer()
	t.Cleanup(fake.Close)

	m := &delineaManager{preLogger: newTestLogger(), config: config.DelineaManager{ServerURL: fake.URL, Username: "u", Password: "p"}}
	require.NoError(t, m.Start(context.Background()))

	_, err := m.fetch("id/99/password")
	var httpErr *server.HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)
}
