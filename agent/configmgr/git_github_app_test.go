package configmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// testAppKey is shared across the package: RSA key generation costs ~100ms and
// the key is read-only, so sharing it keeps `go test -race` fast and stays
// race-free.
var testAppKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func pkcs1PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// fakeClock drives githubAppAuth.now so the refresh-margin behaviour can be
// tested deterministically without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestGitHubApp builds a githubAppAuth pointed at a test server, with the
// clock and API base swapped out.
func newTestGitHubApp(t *testing.T, apiBase string, clock *fakeClock) *githubAppAuth {
	t.Helper()
	auth, err := newGitHubAppAuth(testLogger(), config.GitHubAppAuth{
		ClientID:       "Iv23liTestClientID",
		InstallationID: "78901234",
		PrivateKey:     string(pkcs1PEM(t, testAppKey())),
	}, false)
	require.NoError(t, err)
	auth.apiBase = apiBase
	auth.now = clock.Now
	return auth
}

// tokenServer is an httptest server standing in for api.github.com. It counts
// hits and computes expires_at from the *same* fake clock the auth method uses -
// using time.Now() here would make the caching tests nondeterministic.
type tokenServer struct {
	*httptest.Server
	hits   atomic.Int32
	status atomic.Int32 // when non-zero, respond with this status instead of 201
	ttl    time.Duration
}

func newTokenServer(t *testing.T, clock *fakeClock) *tokenServer {
	t.Helper()
	ts := &tokenServer{ttl: time.Hour}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := ts.hits.Add(1)
		if s := ts.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			_, _ = w.Write([]byte(`{"message":"forced failure"}`))
			return
		}
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/app/installations/78901234/access_tokens", r.URL.Path)
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
		assert.Equal(t, githubAPIVersion, r.Header.Get("X-GitHub-Api-Version"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // the endpoint returns 201, not 200
		_ = json.NewEncoder(w).Encode(githubInstallationToken{
			Token:     fmt.Sprintf("ghs_token_%d", n),
			ExpiresAt: clock.Now().Add(ts.ttl).Format(time.RFC3339),
		})
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestParseGitHubAppKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encryptedPKCS1 := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123"},
		Bytes:   []byte("not-really-encrypted"),
	})

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "pkcs1", data: pkcs1PEM(t, testAppKey())},
		{name: "pkcs8", data: pkcs8PEM(t, testAppKey())},
		{name: "pkcs8 ecdsa", data: pkcs8PEM(t, ecKey), wantErr: "always RSA"},
		{name: "garbage", data: []byte("not a pem file"), wantErr: "no PEM block found"},
		{name: "passphrase protected", data: encryptedPKCS1, wantErr: "passphrase-protected"},
		{
			name:    "openssh",
			data:    pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("x")}),
			wantErr: "OpenSSH key, not a GitHub App key",
		},
		{
			name:    "encrypted pkcs8",
			data:    pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}),
			wantErr: "encrypted PKCS#8 key",
		},
		{
			name:    "certificate",
			data:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
			wantErr: `holds a "CERTIFICATE" PEM block`,
		},
		{
			name:    "corrupt pkcs1",
			data:    pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("corrupt")}),
			wantErr: "failed to parse the PKCS#1 private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseGitHubAppKey(tt.data, "the test key")
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Contains(t, err.Error(), "github_app: ")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testAppKey().N, key.N)
		})
	}
}

func TestLoadGitHubAppKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.pem")
	require.NoError(t, os.WriteFile(path, pkcs1PEM(t, testAppKey()), 0o600))

	t.Run("from file path", func(t *testing.T) {
		key, err := loadGitHubAppKey(path)
		require.NoError(t, err)
		assert.Equal(t, testAppKey().N, key.N)
	})

	t.Run("from inline PEM", func(t *testing.T) {
		key, err := loadGitHubAppKey(string(pkcs1PEM(t, testAppKey())))
		require.NoError(t, err)
		assert.Equal(t, testAppKey().N, key.N)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadGitHubAppKey(filepath.Join(t.TempDir(), "absent.pem"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read private_key")
	})
}

func TestGitHubAppJWT(t *testing.T) {
	clock := newFakeClock()
	auth := newTestGitHubApp(t, "https://api.github.com", clock)

	assertion, err := auth.appJWT()
	require.NoError(t, err)

	parsed, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)
	assert.Equal(t, "JWT", parsed.Headers[0].ExtraHeaders[jose.HeaderType])

	var claims jwt.Claims
	require.NoError(t, parsed.Claims(&testAppKey().PublicKey, &claims))

	assert.Equal(t, "Iv23liTestClientID", claims.Issuer)
	require.NotNil(t, claims.IssuedAt)
	require.NotNil(t, claims.Expiry)

	iat, exp := claims.IssuedAt.Time(), claims.Expiry.Time()
	// iat is backdated to absorb clock drift; GitHub rejects a future iat.
	assert.GreaterOrEqual(t, clock.Now().Sub(iat), 59*time.Second)
	// GitHub rejects an exp more than 10 minutes ahead of its own clock.
	assert.LessOrEqual(t, exp.Sub(iat), 600*time.Second)
}

func TestMintInstallationToken_Success(t *testing.T) {
	clock := newFakeClock()
	var gotAuthHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/app/installations/78901234/access_tokens", r.URL.Path)
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
		assert.Equal(t, githubAPIVersion, r.Header.Get("X-GitHub-Api-Version"))
		assert.Equal(t, "orb-agent", r.Header.Get("User-Agent"))

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_abc123","expires_at":"2026-03-10T13:00:00Z"}`))
	}))
	defer srv.Close()

	auth := newTestGitHubApp(t, srv.URL, clock)
	tok, expiresAt, err := auth.mintInstallationToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ghs_abc123", tok)
	assert.Equal(t, time.Date(2026, 3, 10, 13, 0, 0, 0, time.UTC), expiresAt.UTC())

	// The Authorization header must carry a JWT that verifies against the app key.
	require.True(t, len(gotAuthHeader) > 7 && gotAuthHeader[:7] == "Bearer ")
	parsed, err := jwt.ParseSigned(gotAuthHeader[7:], []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	var claims jwt.Claims
	require.NoError(t, parsed.Claims(&testAppKey().PublicKey, &claims))
	assert.Equal(t, "Iv23liTestClientID", claims.Issuer)
}

func TestMintInstallationToken_Errors(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantErrs []string
	}{
		{
			name: "401 names clock skew", status: http.StatusUnauthorized,
			body:     `{"message":"'Expiration time' claim ('exp') is invalid"}`,
			wantErrs: []string{"host clock", "GitHub time", "agent time", "Iv23liTestClientID"},
		},
		{
			name: "403 names suspension", status: http.StatusForbidden,
			body:     `{"message":"Resource not accessible by integration"}`,
			wantErrs: []string{"suspended", "rate limited"},
		},
		{
			name: "404 names installation_id", status: http.StatusNotFound,
			body:     `{"message":"Not Found"}`,
			wantErrs: []string{"installation settings page", "not the app id", "78901234"},
		},
		{
			name: "422", status: http.StatusUnprocessableEntity,
			body:     `{"message":"Invalid request"}`,
			wantErrs: []string{"HTTP 422", "Invalid request"},
		},
		{
			name: "500 falls through to the default", status: http.StatusInternalServerError,
			body:     `upstream exploded`,
			wantErrs: []string{"status 500", "upstream exploded"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			auth := newTestGitHubApp(t, srv.URL, newFakeClock())
			_, _, err := auth.mintInstallationToken(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "github_app: ")
			for _, want := range tt.wantErrs {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

func TestMintInstallationToken_EmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"","expires_at":"2026-03-10T13:00:00Z"}`))
	}))
	defer srv.Close()

	auth := newTestGitHubApp(t, srv.URL, newFakeClock())
	_, _, err := auth.mintInstallationToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty installation token")
}

func TestMintInstallationToken_UnparsableExpiry(t *testing.T) {
	clock := newFakeClock()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"ghs_abc","expires_at":"whenever"}`))
	}))
	defer srv.Close()

	auth := newTestGitHubApp(t, srv.URL, clock)
	tok, expiresAt, err := auth.mintInstallationToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ghs_abc", tok)
	assert.Equal(t, clock.Now().Add(githubAppFallbackTTL), expiresAt)
}

// TestTokenCachingAndRefreshMargin is the core test for the caching behaviour: a
// token must be re-minted once it is within githubAppRefreshMargin of expiry,
// because a single git fetch spans several HTTP requests.
func TestTokenCachingAndRefreshMargin(t *testing.T) {
	clock := newFakeClock()
	srv := newTokenServer(t, clock)
	auth := newTestGitHubApp(t, srv.URL, clock)
	ctx := context.Background()

	tok, err := auth.token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ghs_token_1", tok)
	assert.EqualValues(t, 1, srv.hits.Load())

	// Immediately again: served from cache.
	tok, err = auth.token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ghs_token_1", tok)
	assert.EqualValues(t, 1, srv.hits.Load())

	// 6 minutes of validity left - outside the 5 minute margin, still cached.
	clock.Advance(time.Hour - 6*time.Minute)
	tok, err = auth.token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ghs_token_1", tok)
	assert.EqualValues(t, 1, srv.hits.Load())

	// 4 minutes left - inside the margin, must re-mint.
	clock.Advance(2 * time.Minute)
	tok, err = auth.token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ghs_token_2", tok)
	assert.EqualValues(t, 2, srv.hits.Load())

	// Past expiry of the second token - re-mint again.
	clock.Advance(time.Hour)
	tok, err = auth.token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ghs_token_3", tok)
	assert.EqualValues(t, 3, srv.hits.Load())
}

func TestSetAuthAppliesBasicAuth(t *testing.T) {
	clock := newFakeClock()
	srv := newTokenServer(t, clock)
	auth := newTestGitHubApp(t, srv.URL, clock)

	// Lazy mint: SetAuth is the first call, no eager token() beforehand.
	r := httptest.NewRequest(http.MethodGet, "https://github.com/org/repo.git/info/refs", nil)
	auth.SetAuth(r)

	user, pass, ok := r.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, githubAppTokenUser, user)
	assert.Equal(t, "ghs_token_1", pass)
	assert.EqualValues(t, 1, srv.hits.Load())

	// A second request within the token's life reuses the cached value.
	r2 := httptest.NewRequest(http.MethodPost, "https://github.com/org/repo.git/git-upload-pack", nil)
	auth.SetAuth(r2)
	_, pass2, ok := r2.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "ghs_token_1", pass2)
	assert.EqualValues(t, 1, srv.hits.Load())
}

func TestSetAuthFallsBackToStaleToken(t *testing.T) {
	clock := newFakeClock()
	srv := newTokenServer(t, clock)
	auth := newTestGitHubApp(t, srv.URL, clock)

	require.NoError(t, func() error { _, err := auth.token(context.Background()); return err }())
	assert.EqualValues(t, 1, srv.hits.Load())

	// Refresh starts failing, and the clock moves into the refresh margin.
	srv.status.Store(http.StatusInternalServerError)
	clock.Advance(time.Hour - 4*time.Minute)

	r := httptest.NewRequest(http.MethodGet, "https://github.com/org/repo.git/info/refs", nil)
	auth.SetAuth(r)
	_, pass, ok := r.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "ghs_token_1", pass, "the previously minted token should still be sent")
	require.Error(t, auth.lastError())
	assert.EqualValues(t, 2, srv.hits.Load())

	// A second attempt inside the retry cooldown must not hit the API again.
	r2 := httptest.NewRequest(http.MethodPost, "https://github.com/org/repo.git/git-upload-pack", nil)
	auth.SetAuth(r2)
	_, pass2, ok := r2.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "ghs_token_1", pass2)
	assert.EqualValues(t, 2, srv.hits.Load(), "the retry cooldown should suppress a second mint")
}

func TestSetAuthWithNoTokenSendsNothing(t *testing.T) {
	clock := newFakeClock()
	srv := newTokenServer(t, clock)
	srv.status.Store(http.StatusUnauthorized)
	auth := newTestGitHubApp(t, srv.URL, clock)

	r := httptest.NewRequest(http.MethodGet, "https://github.com/org/repo.git/info/refs", nil)
	auth.SetAuth(r)

	assert.Empty(t, r.Header.Get("Authorization"))
	require.Error(t, auth.lastError())
}

func TestGitHubAppNameAndStringDoNotLeak(t *testing.T) {
	clock := newFakeClock()
	srv := newTokenServer(t, clock)
	auth := newTestGitHubApp(t, srv.URL, clock)

	tok, err := auth.token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "http-github-app-auth", auth.Name())
	assert.Contains(t, auth.String(), "Iv23liTestClientID")
	assert.Contains(t, auth.String(), "78901234")
	assert.NotContains(t, auth.String(), tok)
}

// TestConcurrentSetAuth proves the mutex collapses concurrent callers into a
// single token exchange. Run under -race.
func TestConcurrentSetAuth(t *testing.T) {
	clock := newFakeClock()
	srv := newTokenServer(t, clock)
	auth := newTestGitHubApp(t, srv.URL, clock)

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			r := httptest.NewRequest(http.MethodGet, "https://github.com/org/repo.git/info/refs", nil)
			auth.SetAuth(r)
			_ = auth.String()
		})
	}
	wg.Wait()

	assert.EqualValues(t, 1, srv.hits.Load())
}

func TestNewGitHubAppAuthValidation(t *testing.T) {
	validKey := string(pkcs1PEM(t, testAppKey()))

	tests := []struct {
		name    string
		cfg     config.GitHubAppAuth
		wantErr string
	}{
		{
			name:    "missing client_id",
			cfg:     config.GitHubAppAuth{InstallationID: "78901234", PrivateKey: validKey},
			wantErr: "client_id is required",
		},
		{
			name:    "missing installation_id",
			cfg:     config.GitHubAppAuth{ClientID: "Iv23li", PrivateKey: validKey},
			wantErr: "installation_id is required",
		},
		{
			name:    "missing private_key",
			cfg:     config.GitHubAppAuth{ClientID: "Iv23li", InstallationID: "78901234"},
			wantErr: "private_key is required",
		},
		{
			name:    "non-numeric installation_id",
			cfg:     config.GitHubAppAuth{ClientID: "Iv23li", InstallationID: "Iv23li", PrivateKey: validKey},
			wantErr: "is not numeric",
		},
		{
			name:    "unresolvable env var",
			cfg:     config.GitHubAppAuth{ClientID: "${ORB_TEST_UNSET_CLIENT_ID}", InstallationID: "1", PrivateKey: validKey},
			wantErr: "github_app: client_id",
		},
		{
			name:    "bad key",
			cfg:     config.GitHubAppAuth{ClientID: "Iv23li", InstallationID: "78901234", PrivateKey: "/nonexistent.pem"},
			wantErr: "failed to read private_key",
		},
		{
			// A numeric Client ID is still accepted; the client id is only preferred.
			name: "numeric client_id is accepted",
			cfg:  config.GitHubAppAuth{ClientID: "123456", InstallationID: "78901234", PrivateKey: validKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := newGitHubAppAuth(testLogger(), tt.cfg, false)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, githubAPIBase, auth.apiBase)
		})
	}
}

func TestRequireGitHubHTTPSURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr string
	}{
		{url: "https://github.com/org/repo"},
		{url: "https://github.com/org/repo.git"},
		{url: "https://www.github.com/org/repo"},
		{url: "HTTPS://GitHub.com/org/repo"},
		{url: "git@github.com:org/repo.git", wantErr: "scp-style and ssh URLs"},
		{url: "ssh://git@github.com/org/repo.git", wantErr: `scheme "ssh"`},
		{url: "http://github.com/org/repo", wantErr: `scheme "http"`},
		{url: "https://github.example.com/org/repo", wantErr: "is not github.com"},
		{url: "https://gitlab.com/org/repo", wantErr: "is not github.com"},
		{url: "https://dev.azure.com/org/proj/_git/repo", wantErr: "is not github.com"},
		{url: "file:///tmp/repo", wantErr: `scheme "file"`},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := requireGitHubHTTPSURL(tt.url)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Contains(t, err.Error(), "github_app: ")
		})
	}
}

// TestGitStartGitHubAppValidation checks that every github_app misconfiguration
// fails during Start, before any git I/O - so none of these cases touch the
// network.
func TestGitStartGitHubAppValidation(t *testing.T) {
	validKey := filepath.Join(t.TempDir(), "app.pem")
	require.NoError(t, os.WriteFile(validKey, pkcs1PEM(t, testAppKey()), 0o600))

	tests := []struct {
		name    string
		git     config.GitManager
		wantErr string
	}{
		{
			name: "non-github url",
			git: config.GitManager{
				URL:  "file:///tmp/repo",
				Auth: "github_app",
				GitHubApp: config.GitHubAppAuth{
					ClientID: "Iv23li", InstallationID: "78901234", PrivateKey: validKey,
				},
			},
			wantErr: `scheme "file"`,
		},
		{
			name: "ssh url",
			git: config.GitManager{
				URL:  "git@github.com:org/repo.git",
				Auth: "github_app",
				GitHubApp: config.GitHubAppAuth{
					ClientID: "Iv23li", InstallationID: "78901234", PrivateKey: validKey,
				},
			},
			wantErr: "scp-style and ssh URLs",
		},
		{
			name: "missing client_id",
			git: config.GitManager{
				URL:       "https://github.com/org/repo",
				Auth:      "github_app",
				GitHubApp: config.GitHubAppAuth{InstallationID: "78901234", PrivateKey: validKey},
			},
			wantErr: "client_id is required",
		},
		{
			name: "client id in installation_id",
			git: config.GitManager{
				URL:  "https://github.com/org/repo",
				Auth: "github_app",
				GitHubApp: config.GitHubAppAuth{
					ClientID: "Iv23li", InstallationID: "Iv23li", PrivateKey: validKey,
				},
			},
			wantErr: "is not numeric",
		},
		{
			name: "unreadable key",
			git: config.GitManager{
				URL:  "https://github.com/org/repo",
				Auth: "github_app",
				GitHubApp: config.GitHubAppAuth{
					ClientID: "Iv23li", InstallationID: "78901234", PrivateKey: "/nonexistent.pem",
				},
			},
			wantErr: "failed to read private_key",
		},
		{
			name: "invalid www url",
			git: config.GitManager{
				URL:  "https://www.github.com/org/repo",
				Auth: "github_app",
				GitHubApp: config.GitHubAppAuth{
					ClientID: "Iv23li", InstallationID: "78901234", PrivateKey: validKey,
				},
			},
			wantErr: "must be github.com, not www.github.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gc := &gitConfigManager{logger: testLogger()}
			cfg := config.Config{}
			cfg.OrbAgent.ConfigManager.Sources.Git = tt.git

			err := gc.Start(context.Background(), cfg, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestAnnotateAuthError(t *testing.T) {
	baseErr := fmt.Errorf("authentication required")

	t.Run("nil error passes through", func(t *testing.T) {
		gc := &gitConfigManager{logger: testLogger()}
		assert.NoError(t, gc.annotateAuthError(nil))
	})

	t.Run("no github app configured", func(t *testing.T) {
		gc := &gitConfigManager{logger: testLogger()}
		assert.Equal(t, baseErr, gc.annotateAuthError(baseErr))
	})

	t.Run("annotates with the mint failure", func(t *testing.T) {
		clock := newFakeClock()
		srv := newTokenServer(t, clock)
		srv.status.Store(http.StatusNotFound)
		auth := newTestGitHubApp(t, srv.URL, clock)
		_, err := auth.token(context.Background())
		require.Error(t, err)

		gc := &gitConfigManager{logger: testLogger(), githubApp: auth}
		got := gc.annotateAuthError(baseErr)
		require.Error(t, got)
		assert.Contains(t, got.Error(), "authentication required")
		assert.Contains(t, got.Error(), "github_app token refresh also failed")
		assert.ErrorIs(t, got, baseErr)
	})
}
