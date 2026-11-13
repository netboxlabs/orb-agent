package secretsmgr

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// fakeDSVServer emulates the two DSV endpoints a read calls:
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
	return newFakeDSVServerWith(nil)
}

// newFakeDSVServerWith is newFakeDSVServer with its endpoints wrapped by wrap,
// which may answer a request itself.
func newFakeDSVServerWith(wrap func(endpoints http.Handler) http.Handler) *fakeDSVServer {
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

	var h http.Handler = mux
	if wrap != nil {
		h = wrap(mux)
	}
	f.Server = httptest.NewServer(h)
	return f
}

func (f *fakeDSVServer) setSecret(path string, data map[string]any) {
	f.mu.Lock()
	f.secrets[path] = data
	f.mu.Unlock()
}

// urlTemplate returns a URLTemplate that routes the reads at this fake server.
// The explicit %[3]s%[4]s indices consume only the resource and path arguments
// (ignoring the tenant and TLD that urlFor also passes); Go's fmt suppresses
// the "extra arguments" annotation when explicit argument indices are used, so
// this renders cleanly to "<srv>/v1/token" and "<srv>/v1/secrets/<path>".
func (f *fakeDSVServer) urlTemplate() string {
	return f.URL + "/v1/%[3]s%[4]s"
}

// newTestDSVManager builds and Starts a dsvManager pointed at the fake server.
func newTestDSVManager(t *testing.T, srv *fakeDSVServer, mutate func(*config.DSVManager)) *dsvManager {
	t.Helper()
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

func TestDSVSolvePolicySecrets_HappyPathLeavesNoToken(t *testing.T) {
	srv := newFakeDSVServer()
	t.Cleanup(srv.Close)
	srv.setSecret("servers/prod-db", map[string]any{"password": "s3cr3t"})
	srv.setSecret("staging/api", map[string]any{"token": "abc123"})

	d := newTestDSVManager(t, srv, nil)
	envBefore := os.Environ()

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

	// Each read requests its own token and keeps it no longer than the read,
	// as the agent did with the SDK's, which it dropped after every read.
	assert.Equal(t, int32(2), srv.authCalls.Load())
	assert.Equal(t, int32(2), srv.secretCalls.Load())

	// The token is not left in the process environment for later-launched
	// backend subprocesses to inherit: the SDK cached it in DSV_AT.
	assert.ElementsMatch(t, envBefore, os.Environ(), "a read leaves the environment as it was")
	_, ok := os.LookupEnv("DSV_AT")
	assert.False(t, ok, "DSV_AT is not set")
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

	changed := make(chan map[string]error, 1)
	d.RegisterUpdatePoliciesCallback(func(ids map[string]error) { changed <- ids })

	// Rotate the stored value, then trigger a poll directly.
	srv.setSecret("servers/prod-db", map[string]any{"password": "new"})
	d.pollSecrets()

	select {
	case ids := <-changed:
		require.Contains(t, ids, "policy-1")
		assert.NoError(t, ids["policy-1"])
	default:
		t.Fatal("expected update callback for rotated secret")
	}
}

// dsvRequest is one request as a DSV server receives it.
type dsvRequest struct {
	Method     string
	RequestURI string
	Header     http.Header
	Body       string
}

// TestDSVFetch_RequestShape pins the requests dsv-sdk-go v2.2.0 sent, which
// the agent sends itself now: for each read, a token request and then the
// secret request, with the configured URL template filled in with the
// tenant, the TLD, the resource and the secret path, the path inserted as
// written. It passed against the SDK before the agent stopped using it.
func TestDSVFetch_RequestShape(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantURI  string
		wantData string
	}{
		{"plain path", "servers/prod-db/password", "/acme/eu/v1/secrets/servers/prod-db", "s3cr3t"},
		{"leading slashes trimmed", "//servers/prod-db/password", "/acme/eu/v1/secrets/servers/prod-db", "s3cr3t"},
		{"space escaped", "team a/db/password", "/acme/eu/v1/secrets/team%20a/db", "spaced"},
		{"plus and escapes kept", "x+y/a%2Fb/password", "/acme/eu/v1/secrets/x+y/a%2Fb", "kept"},
		{"question mark starts a query", "q/a?b/password", "/acme/eu/v1/secrets/q/a?b", "query"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu   sync.Mutex
				seen []dsvRequest
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				seen = append(seen, dsvRequest{r.Method, r.RequestURI, r.Header.Clone(), string(b)})
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/acme/eu/v1/token" {
					_, _ = w.Write([]byte(`{"accessToken":"tok-123","tokenType":"bearer","expiresIn":3600}`))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "8e7a", "path": "x", "attributes": map[string]any{"owner": "orb"},
					"data":    map[string]any{"password": tc.wantData, "port": 5432},
					"created": "2026-01-02T03:04:05Z", "lastModified": "2026-01-02T03:04:05Z", "version": "1",
				})
			}))
			t.Cleanup(srv.Close)

			d := &dsvManager{preLogger: newTestLogger(), config: config.DSVManager{
				Tenant:       "acme",
				ClientID:     "client-id-1",
				ClientSecret: `s3cr3t<&>"`,
				TLD:          "eu",
				URLTemplate:  srv.URL + "/%s/%s/v1/%s%s",
			}}
			require.NoError(t, d.Start(context.Background()))

			val, err := d.fetch(tc.body)
			require.NoError(t, err)
			assert.Equal(t, tc.wantData, val)

			mu.Lock()
			defer mu.Unlock()
			require.Len(t, seen, 2)

			token := seen[0]
			assert.Equal(t, http.MethodPost, token.Method)
			assert.Equal(t, "/acme/eu/v1/token", token.RequestURI)
			wantBody := `{"grant_type":"client_credentials","client_id":"client-id-1","client_secret":"s3cr3t\u003c\u0026\u003e\""}`
			assert.Equal(t, wantBody, token.Body)
			assert.Equal(t, http.Header{
				"Accept-Encoding": {"gzip"},
				"Content-Length":  {strconv.Itoa(len(wantBody))},
				"Content-Type":    {"application/json"},
				"User-Agent":      {"Go-http-client/1.1"},
			}, token.Header)

			secret := seen[1]
			assert.Equal(t, http.MethodGet, secret.Method)
			assert.Equal(t, tc.wantURI, secret.RequestURI)
			assert.Empty(t, secret.Body)
			assert.Equal(t, http.Header{
				"Accept-Encoding": {"gzip"},
				"Authorization":   {"Bearer tok-123"},
				"User-Agent":      {"Go-http-client/1.1"},
			}, secret.Header)
		})
	}
}

// dsvFetchWithin runs d.fetch(body) and fails the test if it has not returned
// within limit, so a read that hangs fails instead of stalling the suite.
func dsvFetchWithin(t *testing.T, d *dsvManager, body string, limit time.Duration) (time.Duration, error) {
	t.Helper()
	done := make(chan error, 1)
	began := time.Now()
	go func() {
		_, err := d.fetch(body)
		done <- err
	}()
	select {
	case err := <-done:
		return time.Since(began), err
	case <-time.After(limit):
		t.Fatalf("read of %q did not return within %s", body, limit)
		return 0, nil
	}
}

// A DSV that accepts a request and never answers fails the read after the
// configured timeout, whether it is the token or the secret request.
func TestDSVFetch_SilentServerTimesOut(t *testing.T) {
	for _, silent := range []string{"/v1/token", "/v1/secrets/servers/prod-db"} {
		t.Run(silent, func(t *testing.T) {
			release := make(chan struct{})
			srv := newFakeDSVServerWith(func(endpoints http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == silent {
						select {
						case <-r.Context().Done():
						case <-release:
						}
						return
					}
					endpoints.ServeHTTP(w, r)
				})
			})
			t.Cleanup(srv.Close)
			srv.setSecret("servers/prod-db", map[string]any{"password": "s3cr3t"})
			t.Cleanup(func() { close(release) }) // runs before srv.Close

			const timeout = 300 * time.Millisecond
			d := &dsvManager{
				preLogger: newTestLogger(),
				config:    config.DSVManager{Tenant: "t", ClientID: "cid", ClientSecret: "csecret", URLTemplate: srv.urlTemplate()},
				timeout:   timeout,
			}
			require.NoError(t, d.Start(context.Background()))

			took, err := dsvFetchWithin(t, d, "servers/prod-db/password", 5*time.Second)
			require.Error(t, err)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.GreaterOrEqual(t, took, timeout)
			assert.Less(t, took, 3*time.Second, "the token and the secret request share one limit")
		})
	}
}

// A non-2xx answer carries its HTTP status in a typed error.
func TestDSVFetch_ErrorCarriesTheStatus(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		status     int
		answer     string
		wantStatus int
		wantText   string
	}{
		{"token refused", "/v1/token", http.StatusUnauthorized, `{"code":401,"message":"invalid client"}`, 401, `fetching token: 401 Unauthorized: {"code":401,"message":"invalid client"}`},
		{"secret missing", "/v1/secrets/servers/prod-db", http.StatusNotFound, `{"code":404,"message":"unable to find item"}`, 404, `404 Not Found: {"code":404,"message":"unable to find item"}`},
		{"html page", "/v1/secrets/servers/prod-db", http.StatusBadGateway, `<html><body>bad gateway</body></html>`, 502, `502 Bad Gateway`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeDSVServerWith(func(endpoints http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == tc.path {
						if strings.HasPrefix(tc.answer, "<") {
							w.Header().Set("Content-Type", "text/html")
						}
						w.WriteHeader(tc.status)
						_, _ = w.Write([]byte(tc.answer))
						return
					}
					endpoints.ServeHTTP(w, r)
				})
			})
			t.Cleanup(srv.Close)
			srv.setSecret("servers/prod-db", map[string]any{"password": "s3cr3t"})

			d := newTestDSVManager(t, srv, nil)
			_, err := d.fetch("servers/prod-db/password")
			var httpErr *dsvHTTPError
			require.ErrorAs(t, err, &httpErr)
			assert.Equal(t, tc.wantStatus, httpErr.StatusCode)
			assert.Contains(t, err.Error(), tc.wantText)
			assert.NotContains(t, err.Error(), "<html>")
		})
	}
}

func TestDSVStart_Timeout(t *testing.T) {
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
			d := &dsvManager{preLogger: newTestLogger(), config: config.DSVManager{Tenant: "t", ClientID: "c", ClientSecret: "s", Timeout: tc.timeout}}
			require.NoError(t, d.Start(context.Background()))
			assert.Equal(t, tc.want, d.timeout)
		})
	}
}

// Without tld and url_template, the URLs are dsv-sdk-go v2.2.0's defaults:
// https://<tenant>.secretsvaultcloud.com/v1/<resource><path>.
func TestDSVStart_DefaultURLs(t *testing.T) {
	d := &dsvManager{preLogger: newTestLogger(), config: config.DSVManager{Tenant: "acme", ClientID: "c", ClientSecret: "s"}}
	require.NoError(t, d.Start(context.Background()))
	assert.Equal(t, "https://acme.secretsvaultcloud.com/v1/token", d.urlFor("token", ""))
	assert.Equal(t, "https://acme.secretsvaultcloud.com/v1/secrets/servers/prod-db", d.urlFor("secrets", "servers/prod-db"))

	d = &dsvManager{preLogger: newTestLogger(), config: config.DSVManager{Tenant: "acme", ClientID: "c", ClientSecret: "s", TLD: "eu"}}
	require.NoError(t, d.Start(context.Background()))
	assert.Equal(t, "https://acme.secretsvaultcloud.eu/v1/secrets/servers/prod-db", d.urlFor("secrets", "/servers/prod-db"))
}
