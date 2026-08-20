package configmgr

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/netboxlabs/orb-agent/agent/config"
)

const (
	// githubAPIBase is the REST API for github.com. GitHub App auth is
	// deliberately github.com-only; GitHub Enterprise Server and GitHub
	// Enterprise Cloud with data residency use different API hosts.
	githubAPIBase = "https://api.github.com"

	// githubAPIVersion pins the REST API version for the token exchange.
	githubAPIVersion = "2026-03-10"

	// githubAppTokenUser is the username GitHub expects for git-over-HTTPS basic
	// auth when the password is an installation access token.
	githubAppTokenUser = "x-access-token"

	// githubAppJWTTTL and githubAppJWTBackdate bound the app JWT. GitHub rejects
	// a JWT whose exp is more than 10 minutes ahead, and rejects an iat in the
	// future - backdating absorbs modest host clock drift.
	githubAppJWTTTL      = 9 * time.Minute
	githubAppJWTBackdate = 60 * time.Second

	// githubAppRefreshMargin is the validity that must remain on a cached
	// installation token for it to be reused. A single git fetch is several HTTP
	// requests, so a token that merely has not expired yet must not be handed to
	// the first of them.
	githubAppRefreshMargin = 5 * time.Minute

	// githubAppTokenTimeout bounds one token-exchange request. go-git applies
	// auth to a request before attaching the operation's context, so SetAuth has
	// no context to inherit and this timeout is the only thing preventing a hung
	// api.github.com connection from stalling a scheduler tick.
	githubAppTokenTimeout = 30 * time.Second

	// githubAppRetryCooldown throttles re-minting so a persistent failure does
	// not turn every git request into an API call and an error log line.
	githubAppRetryCooldown = 30 * time.Second

	// githubAppMinMintInterval is a floor on mint frequency even after a success,
	// guarding against a response whose expires_at is already inside the refresh
	// margin.
	githubAppMinMintInterval = 10 * time.Second

	// githubAppFallbackTTL is assumed when expires_at is missing or unparsable.
	// GitHub's documented lifetime is one hour.
	githubAppFallbackTTL = 30 * time.Minute

	// githubAppMaxResponseBytes caps how much of a token response is read.
	githubAppMaxResponseBytes = 1 << 20
)

// githubAppAuth authenticates git-over-HTTPS to github.com as a GitHub App
// installation. It implements go-git's http.AuthMethod; go-git calls SetAuth
// once per HTTP request, so the cached installation token is re-checked - and
// re-minted when close to expiry - per request rather than per fetch.
type githubAppAuth struct {
	logger *slog.Logger

	// Immutable after construction; read without the mutex.
	clientID       string
	installationID string
	privateKey     *rsa.PrivateKey
	apiBase        string // overridden in tests
	skipTLS        bool
	now            func() time.Time // overridden in tests

	// mu guards the token cache. Minting happens while holding mu so concurrent
	// callers collapse into a single API call: the loser blocks, re-checks the
	// cache, and gets the fresh token for free.
	mu          sync.Mutex
	cachedToken string
	expiresAt   time.Time
	lastErr     error
	nextAttempt time.Time
}

// Compile-time proof that go-git will accept this as an HTTP auth method.
// Without SetAuth, go-git returns the opaque transport.ErrInvalidAuthMethod.
var _ githttp.AuthMethod = (*githubAppAuth)(nil)

// newGitHubAppAuth validates the configuration and loads the private key. It
// performs no network I/O; call token() to mint eagerly.
func newGitHubAppAuth(logger *slog.Logger, cfg config.GitHubAppAuth, skipTLS bool) (*githubAppAuth, error) {
	clientID, err := config.ResolveEnv(cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("github_app: client_id: %w", err)
	}
	installationID, err := config.ResolveEnv(cfg.InstallationID)
	if err != nil {
		return nil, fmt.Errorf("github_app: installation_id: %w", err)
	}
	keyRef, err := config.ResolveEnv(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("github_app: private_key: %w", err)
	}

	switch {
	case clientID == "":
		return nil, errors.New("github_app: client_id is required when auth is github_app")
	case installationID == "":
		return nil, errors.New("github_app: installation_id is required when auth is github_app")
	case keyRef == "":
		return nil, errors.New("github_app: private_key is required when auth is github_app")
	}

	// installation_id is interpolated into an API path, and confusing it with the
	// app id is the most common misconfiguration. Requiring digits both prevents
	// path injection and catches a client id pasted into the wrong key. app_id is
	// deliberately not checked: the preferred value is a client id (Iv23li...).
	if _, err := strconv.ParseUint(installationID, 10, 64); err != nil {
		return nil, fmt.Errorf("github_app: installation_id %q is not numeric; it is the id in the URL of "+
			"the app's installation settings page, not the app id or client id", installationID)
	}

	key, err := loadGitHubAppKey(keyRef)
	if err != nil {
		return nil, err
	}

	return &githubAppAuth{
		logger:         logger,
		clientID:       clientID,
		installationID: installationID,
		privateKey:     key,
		apiBase:        githubAPIBase,
		skipTLS:        skipTLS,
		now:            time.Now,
	}, nil
}

// token returns a valid installation access token, minting one if the cache is
// empty or within githubAppRefreshMargin of expiry.
func (a *githubAppAuth) token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokenLocked(ctx)
}

// tokenLocked implements token(); the caller must hold a.mu.
func (a *githubAppAuth) tokenLocked(ctx context.Context) (string, error) {
	now := a.now()
	if a.cachedToken != "" && now.Add(githubAppRefreshMargin).Before(a.expiresAt) {
		return a.cachedToken, nil
	}

	tok, expiresAt, err := a.mintInstallationToken(ctx)
	if err != nil {
		a.lastErr = err
		a.nextAttempt = now.Add(githubAppRetryCooldown)
		return "", err
	}

	a.cachedToken, a.expiresAt, a.lastErr = tok, expiresAt, nil
	// Floor the mint rate even on success, in case GitHub ever returns a token
	// that is already inside the refresh margin.
	a.nextAttempt = now.Add(githubAppMinMintInterval)

	a.logger.Debug("github_app: minted installation access token",
		"installation_id", a.installationID, "expires_at", expiresAt)
	return tok, nil
}

// lastError returns the most recent mint failure, or nil. The git config manager
// uses it to annotate go-git errors: a failed refresh surfaces from go-git as a
// bare transport.ErrAuthenticationRequired, which says nothing about the cause.
func (a *githubAppAuth) lastError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

// SetAuth implements go-git's http.AuthMethod.
//
// It cannot return an error, so a failed mint is handled three ways at once: it
// is logged with the underlying cause; it is recorded on the struct so
// lastError() can annotate the go-git error the caller ultimately sees; and,
// when a previously minted token is still cached, that token is sent anyway.
// Sending the stale token is the right fallback because the refresh margin is
// conservative - a token due for refresh normally still has minutes of validity
// - so a transient api.github.com blip does not become a failed poll.
//
// Note the context: go-git attaches the operation's context to the request only
// after calling this, so r.Context() is context.Background() here and the mint
// must supply its own timeout.
func (a *githubAppAuth) SetAuth(r *http.Request) {
	if a == nil || r == nil {
		return
	}

	a.mu.Lock()
	now := a.now()
	needsMint := a.cachedToken == "" || !now.Add(githubAppRefreshMargin).Before(a.expiresAt)
	if needsMint && !now.Before(a.nextAttempt) {
		ctx, cancel := context.WithTimeout(context.Background(), githubAppTokenTimeout)
		_, _ = a.tokenLocked(ctx) // failure is recorded in a.lastErr
		cancel()
	}
	// Re-read the cache rather than using tokenLocked's return value: that is
	// what makes the stale-token fallback work in both the failed-mint and the
	// in-cooldown cases.
	tok, lastErr := a.cachedToken, a.lastErr
	a.mu.Unlock()

	switch {
	case tok == "":
		a.logger.Error("github_app: no installation access token available; sending the git request "+
			"unauthenticated, which will fail with HTTP 401",
			"url", r.URL.Redacted(), "error", lastErr)
		return
	case lastErr != nil:
		a.logger.Warn("github_app: token refresh failed; retrying the git request with the previously "+
			"minted token, which may already have expired",
			"url", r.URL.Redacted(), "error", lastErr)
	}

	// GitHub accepts installation tokens on the git HTTPS endpoints as basic auth
	// with the fixed username x-access-token. It does not accept them as
	// Authorization: Bearer there - that form is for the REST API only.
	r.SetBasicAuth(githubAppTokenUser, tok)
}

// Name implements transport.AuthMethod.
func (a *githubAppAuth) Name() string { return "http-github-app-auth" }

// String implements transport.AuthMethod. go-git surfaces this in debug and
// error output, so it must never contain the access token. It reads only
// immutable fields and therefore takes no lock - a locking String() would
// deadlock if go-git logged the auth method from inside a locked section.
func (a *githubAppAuth) String() string {
	return fmt.Sprintf("%s - client_id: %s, installation_id: %s", a.Name(), a.clientID, a.installationID)
}

// appJWT signs the short-lived RS256 assertion that authenticates the app itself
// to the GitHub API. iat is backdated so modest clock drift on the agent host
// does not make GitHub reject the assertion as issued in the future, and exp
// stays inside GitHub's 10-minute ceiling.
func (a *githubAppAuth) appJWT() (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: a.privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("github_app: failed to create JWT signer: %w", err)
	}

	now := a.now()
	assertion, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   a.clientID,
		IssuedAt: jwt.NewNumericDate(now.Add(-githubAppJWTBackdate)),
		Expiry:   jwt.NewNumericDate(now.Add(githubAppJWTTTL)),
	}).Serialize()
	if err != nil {
		return "", fmt.Errorf("github_app: failed to sign app JWT: %w", err)
	}
	return assertion, nil
}

// githubInstallationToken is the access_tokens endpoint response.
type githubInstallationToken struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// githubAPIError is the error envelope the GitHub REST API returns.
type githubAPIError struct {
	Message string `json:"message"`
}

// mintInstallationToken exchanges a freshly signed app JWT for an installation
// access token.
func (a *githubAppAuth) mintInstallationToken(ctx context.Context) (string, time.Time, error) {
	assertion, err := a.appJWT()
	if err != nil {
		return "", time.Time{}, err
	}

	endpoint := fmt.Sprintf("%s/app/installations/%s/access_tokens", a.apiBase, a.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github_app: failed to create the token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+assertion)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", "orb-agent")

	client := &http.Client{
		Timeout: githubAppTokenTimeout,
		Transport: &http.Transport{
			// Proxy must be set explicitly: a bare &http.Transport{} does not
			// inherit ProxyFromEnvironment from DefaultTransport. go-git's own
			// client uses DefaultTransport, so omitting this would send the git
			// traffic through HTTP_PROXY but not the token exchange around it.
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: a.skipTLS}, //nolint:gosec // opt-in via skip_tls
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github_app: installation token request to %s failed: %w", endpoint, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			a.logger.Warn("github_app: failed to close response body", "error", cerr)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, githubAppMaxResponseBytes))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github_app: failed to read the installation token response: %w", err)
	}

	// The endpoint returns 201 Created, not 200.
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", time.Time{}, a.tokenStatusError(resp, body)
	}

	var payload githubInstallationToken
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", time.Time{}, fmt.Errorf("github_app: failed to parse the installation token response: %w", err)
	}
	if payload.Token == "" {
		return "", time.Time{}, errors.New("github_app: GitHub returned an empty installation token")
	}

	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		a.logger.Warn("github_app: could not parse expires_at; assuming a short lifetime",
			"expires_at", payload.ExpiresAt, "assumed_ttl", githubAppFallbackTTL)
		expiresAt = a.now().Add(githubAppFallbackTTL)
	}
	return payload.Token, expiresAt, nil
}

// tokenStatusError names the likely misconfiguration for each status GitHub
// returns here. The alternative - letting the operator see a bare HTTP 401 from
// git - tells them nothing about which of three settings is wrong.
func (a *githubAppAuth) tokenStatusError(resp *http.Response, body []byte) error {
	var apiErr githubAPIError
	_ = json.Unmarshal(body, &apiErr)
	detail := apiErr.Message
	if detail == "" {
		detail = strings.TrimSpace(string(body))
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		// Clock skew is the most common cause and the hardest to guess, so echo
		// GitHub's Date header next to ours.
		return fmt.Errorf("github_app: GitHub rejected the app JWT (HTTP 401: %s); check that app_id %q "+
			"matches the private key, and check the host clock (GitHub time: %q, agent time: %q)",
			detail, a.clientID, resp.Header.Get("Date"), a.now().UTC().Format(http.TimeFormat))
	case http.StatusForbidden:
		return fmt.Errorf("github_app: GitHub refused the token request (HTTP 403: %s); the app may be "+
			"suspended, blocked by an org policy, or rate limited", detail)
	case http.StatusNotFound:
		return fmt.Errorf("github_app: installation %s was not found (HTTP 404: %s); check installation_id - "+
			"it is the id in the URL of the app's installation settings page, not the app id - and check "+
			"that the app is still installed on the account that owns the repository", a.installationID, detail)
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("github_app: GitHub rejected the token request (HTTP 422: %s)", detail)
	default:
		return fmt.Errorf("github_app: installation token request failed with status %d: %s", resp.StatusCode, detail)
	}
}

// loadGitHubAppKey reads a GitHub App private key. ref is either a path to a PEM
// file or - when ${VAR} or a secrets manager injected the key material directly
// - the PEM document itself.
func loadGitHubAppKey(ref string) (*rsa.PrivateKey, error) {
	if strings.Contains(ref, "-----BEGIN") {
		return parseGitHubAppKey([]byte(ref), "the inline private_key value")
	}
	data, err := os.ReadFile(ref)
	if err != nil {
		return nil, fmt.Errorf("github_app: failed to read private_key: %w", err)
	}
	return parseGitHubAppKey(data, ref)
}

// parseGitHubAppKey accepts the PKCS#1 ("RSA PRIVATE KEY") PEM that GitHub
// issues, and the PKCS#8 ("PRIVATE KEY") PEM produced by
// `openssl pkcs8 -topk8 -nocrypt`. Every other input gets an error naming what
// was actually found and what to do about it.
func parseGitHubAppKey(data []byte, source string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("github_app: no PEM block found in %s; expected the .pem file downloaded "+
			"from the GitHub App settings page", source)
	}

	if _, encrypted := block.Headers["DEK-Info"]; encrypted {
		return nil, fmt.Errorf("github_app: the key in %s is passphrase-protected, which is not supported; "+
			"decrypt it first with `openssl rsa -in key.pem -out key-decrypted.pem`", source)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("github_app: failed to parse the PKCS#1 private key in %s: %w", source, err)
		}
		return key, nil

	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("github_app: failed to parse the PKCS#8 private key in %s: %w", source, err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("github_app: the private key in %s is %T; GitHub App keys are always RSA",
				source, parsed)
		}
		return key, nil

	case "ENCRYPTED PRIVATE KEY":
		return nil, fmt.Errorf("github_app: the key in %s is an encrypted PKCS#8 key, which is not supported; "+
			"provide an unencrypted key", source)

	case "OPENSSH PRIVATE KEY":
		return nil, fmt.Errorf("github_app: %s holds an OpenSSH key, not a GitHub App key; download the app "+
			"private key from Settings > Developer settings > GitHub Apps > Private keys", source)

	default:
		return nil, fmt.Errorf("github_app: %s holds a %q PEM block; expected \"RSA PRIVATE KEY\" (PKCS#1, "+
			"what GitHub issues) or \"PRIVATE KEY\" (PKCS#8)", source, block.Type)
	}
}

// requireGitHubHTTPSURL rejects configurations that cannot work with github_app
// auth, before any credential or network work happens. An installation token is
// an HTTPS-only credential scoped to github.com: go-git's SSH transport rejects
// a non-ssh.AuthMethod with the opaque transport.ErrInvalidAuthMethod, and any
// other host answers with an unexplained 401.
func requireGitHubHTTPSURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" {
		// scp-style remotes such as git@github.com:org/repo.git land here:
		// url.Parse rejects them with "first path segment cannot contain colon".
		return fmt.Errorf("github_app: url %q must be an https://github.com/... URL "+
			"(scp-style and ssh URLs cannot use installation tokens)", rawURL)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("github_app: url uses scheme %q; github_app auth requires https", u.Scheme)
	}
	if host := strings.ToLower(u.Hostname()); host != "github.com" && host != "www.github.com" {
		return fmt.Errorf("github_app: url host %q is not github.com; github_app auth supports github.com "+
			"only (for GitHub Enterprise Server use auth: basic with a personal access token)", host)
	}
	return nil
}
