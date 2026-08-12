package secretsmgr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// fakeDSVServer emulates the two DSV endpoints the SDK calls:
//
//	POST /v1/token           — OAuth client-credentials token
//	GET  /v1/secrets/<path>  — a single secret with a data map
type fakeDSVServer struct {
	*httptest.Server
	mu          sync.Mutex
	secrets     map[string]map[string]any // keyed by secret path
	authCalls   atomic.Int32
	secretCalls atomic.Int32
}

func newFakeDSVServer() *fakeDSVServer {
	f := &fakeDSVServer{secrets: make(map[string]map[string]any)}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, _ *http.Request) {
		f.authCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken": "test-token",
			"expiresIn":   3600,
		})
	})

	mux.HandleFunc("/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		f.secretCalls.Add(1)
		path := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
		f.mu.Lock()
		data, ok := f.secrets[path]
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path": path,
			"data": data,
		})
	})

	f.Server = httptest.NewServer(mux)
	return f
}

func (f *fakeDSVServer) setSecret(path string, data map[string]any) {
	f.mu.Lock()
	f.secrets[path] = data
	f.mu.Unlock()
}

// urlTemplate returns a URLTemplate that routes the SDK at this fake server.
// The explicit %[3]s%[4]s indices consume only the resource and path arguments
// (ignoring the tenant and TLD that urlFor also passes); Go's fmt suppresses
// the "extra arguments" annotation when explicit argument indices are used, so
// this renders cleanly to "<srv>/v1/token" and "<srv>/v1/secrets/<path>".
func (f *fakeDSVServer) urlTemplate() string {
	return f.URL + "/v1/%[3]s%[4]s"
}

// newTestDSVManager builds and Starts a dsvManager pointed at the fake server.
// It resets the SDK's process-global DSV_AT token cache first so each test
// forces a fresh /v1/token call and is isolated from its neighbors.
func newTestDSVManager(t *testing.T, srv *fakeDSVServer, mutate func(*config.DSVManager)) *dsvManager {
	t.Helper()
	t.Setenv("DSV_AT", "")

	cfg := config.DSVManager{
		Tenant:       "test-tenant",
		ClientID:     "cid",
		ClientSecret: "csecret",
		URLTemplate:  srv.urlTemplate(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	d := &dsvManager{preLogger: newTestLogger(), config: cfg}
	require.NoError(t, d.Start(context.Background()))
	return d
}

func TestDSVSolvePolicySecrets_HappyPathAndTokenReuse(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"password": "s3cr3t"})
	srv.setSecret("staging/api", map[string]any{"token": "abc123"})

	d := newTestDSVManager(t, srv, nil)

	out, err := d.SolvePolicySecrets(config.PolicyPayload{
		ID: "policy-1",
		Data: map[string]any{
			"pw":  "${dsv://servers/prod-db/password}",
			"tok": "${dsv://staging/api/token}",
		},
	})
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "s3cr3t", data["pw"])
	assert.Equal(t, "abc123", data["tok"])

	// Two secret fetches, but the token is fetched once and reused via DSV_AT.
	assert.Equal(t, int32(1), srv.authCalls.Load())
	assert.Equal(t, int32(2), srv.secretCalls.Load())
}

func TestDSVSolvePolicySecrets_CacheHit(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"password": "s3cr3t"})

	d := newTestDSVManager(t, srv, nil)
	payload := config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${dsv://servers/prod-db/password}"}}

	_, err := d.SolvePolicySecrets(payload)
	require.NoError(t, err)
	first := srv.secretCalls.Load()

	_, err = d.SolvePolicySecrets(payload)
	require.NoError(t, err)
	assert.Equal(t, first, srv.secretCalls.Load(), "second resolve should hit cache, not server")
}

func TestDSVSolvePolicySecrets_FieldMissing(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"password": "s3cr3t"})

	d := newTestDSVManager(t, srv, nil)
	_, err := d.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${dsv://servers/prod-db/username}"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `field "username" not found`)
}

func TestDSVSolvePolicySecrets_FieldNotString(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"port": 5432})

	d := newTestDSVManager(t, srv, nil)
	_, err := d.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${dsv://servers/prod-db/port}"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not a string")
}

func TestDSVSolvePolicySecrets_FieldEmpty(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"password": ""})

	d := newTestDSVManager(t, srv, nil)
	_, err := d.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${dsv://servers/prod-db/password}"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
}

func TestDSVSolvePolicySecrets_SecretNotFound(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)

	d := newTestDSVManager(t, srv, nil)
	_, err := d.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${dsv://does/not-exist/password}"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get secret")
}

func TestDSVFetch_BadGrammar(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)

	d := newTestDSVManager(t, srv, nil)
	for _, body := range []string{"", "mysecret", "/password", "mysecret/"} {
		_, err := d.fetch(body)
		require.Errorf(t, err, "body %q should be rejected", body)
		assert.Contains(t, err.Error(), "invalid dsv reference")
	}
	// Grammar is rejected before any HTTP call is made.
	assert.Equal(t, int32(0), srv.secretCalls.Load())
	assert.Equal(t, int32(0), srv.authCalls.Load())
}

func TestDSVStart_Validation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*config.DSVManager)
		wantErr string
	}{
		{"missing tenant", func(c *config.DSVManager) { c.Tenant = "" }, "tenant is required"},
		{"missing client_id", func(c *config.DSVManager) { c.ClientID = "" }, "client_id is required"},
		{"missing client_secret", func(c *config.DSVManager) { c.ClientSecret = "" }, "client_secret is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DSVManager{Tenant: "t", ClientID: "c", ClientSecret: "s"}
			tc.mutate(&cfg)
			d := &dsvManager{preLogger: newTestLogger(), config: cfg}
			err := d.Start(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestDSVStart_ResolvesEnvSecret(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"password": "s3cr3t"})

	t.Setenv("DSV_AT", "")
	t.Setenv("DSV_CLIENT_SECRET", "csecret-from-env")

	d := &dsvManager{
		preLogger: newTestLogger(),
		config: config.DSVManager{
			Tenant:       "test-tenant",
			ClientID:     "cid",
			ClientSecret: "${DSV_CLIENT_SECRET}",
			URLTemplate:  srv.urlTemplate(),
		},
	}
	require.NoError(t, d.Start(context.Background()))
	assert.Equal(t, "csecret-from-env", d.config.ClientSecret)

	out, err := d.SolvePolicySecrets(config.PolicyPayload{ID: "p", Data: map[string]any{"c": "${dsv://servers/prod-db/password}"}})
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", out.Data.(map[string]any)["c"])
}

func TestDSVStart_UnsetEnvFailsClearly(t *testing.T) {
	d := &dsvManager{
		preLogger: newTestLogger(),
		config: config.DSVManager{
			Tenant:       "test-tenant",
			ClientID:     "cid",
			ClientSecret: "${DSV_CLIENT_SECRET_DEFINITELY_UNSET}",
		},
	}
	err := d.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolving dsv client_secret from environment")
}

func TestDSVPolling_DetectsRotation(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"password": "old"})

	d := newTestDSVManager(t, srv, nil)

	// Prime the cache through the standard resolve path.
	got, err := d.resolveBody("servers/prod-db/password", "policy-1")
	require.NoError(t, err)
	assert.Equal(t, "old", got)

	changed := make(chan map[string]bool, 1)
	d.RegisterUpdatePoliciesCallback(func(ids map[string]bool) { changed <- ids })

	// Rotate the stored value, then trigger a poll directly.
	srv.setSecret("servers/prod-db", map[string]any{"password": "new"})
	d.pollSecrets()

	select {
	case ids := <-changed:
		assert.Equal(t, true, ids["policy-1"])
	default:
		t.Fatal("expected update callback for rotated secret")
	}
}
