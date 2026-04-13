package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/netboxlabs/orb-agent/agent/redact"
)

// AuthError indicates a non-retriable authentication failure (e.g. HTTP 401/403).
// Callers should not retry when they receive this error — the credentials are wrong.
type AuthError struct {
	StatusCode int
	Body       string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authentication failed (HTTP %d)", e.StatusCode)
}

// AuthTokenManager manages auth tokens
type AuthTokenManager struct {
	mu             sync.RWMutex
	logger         *slog.Logger
	tokenURL       string
	skipTLS        bool
	timeout        time.Duration
	clientID       string
	clientSecret   string
	lastToken      *TokenResponse
	tokenExpiresAt time.Time
}

// NewAuthTokenManager creates a new AuthTokenManager
func NewAuthTokenManager(logger *slog.Logger) *AuthTokenManager {
	return &AuthTokenManager{
		logger: logger,
	}
}

// TokenResponse is the response from the auth token endpoint
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	MQTTURL     string `json:"mqtt_url"`
	ExpiresIn   int    `json:"expires_in"`
}

// GetToken gets an auth token from the auth token endpoint
func (fleetManager *AuthTokenManager) GetToken(ctx context.Context, tokenURL string, skipTLS bool, timeout time.Duration, clientID string, clientSecret string) (*TokenResponse, error) {
	// Input validation
	if tokenURL == "" {
		return nil, fmt.Errorf("token URL cannot be empty")
	}
	if clientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("client secret cannot be empty")
	}

	fleetManager.logger.Debug("requesting access token", "token_url", tokenURL, "client_id", clientID)

	scopes := []string{
		"orb.mqtt:agent",
		"orb.mqtt:group",
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", strings.Join(scopes, " "))
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("audience", "orb")

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		fleetManager.logger.Error("failed to create token request", "error", err, "token_url", tokenURL)
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// HTTP client with configurable timeout and TLS settings
	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
		},
	}

	fleetManager.logger.Debug("sending token request", "url", tokenURL, "data", redact.SensitiveData(data), "client_id", clientID)

	// Note that errors below are logged with Warn level, but returned as errors to allow callers
	// to distinguish between transient errors (e.g. network issues) and auth failures
	// (e.g. invalid credentials). The caller can choose to retry on transient errors,
	// but should not retry on auth failures without fixing the credentials.
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		fleetManager.logger.Warn("failed to send token request", "error", err, "token_url", tokenURL)
		return nil, fmt.Errorf("failed to send request to %s: %w", tokenURL, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fleetManager.logger.Warn("failed to close response body", "error", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fleetManager.logger.Warn("failed to read response body", "error", err, "status_code", resp.StatusCode)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		fleetManager.logger.Warn("token request failed",
			"status_code", resp.StatusCode,
			"response", string(body),
			"token_url", tokenURL,
			"client_id", clientID)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &AuthError{StatusCode: resp.StatusCode, Body: string(body)}
		}
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		fleetManager.logger.Error("failed to parse token response", "error", err, "response", string(body))
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Validate token response
	if tokenResp.AccessToken == "" {
		fleetManager.logger.Error("received empty access token", "response", string(body))
		return nil, fmt.Errorf("received empty access token from server")
	}

	fleetManager.logger.Debug("successfully obtained access token",
		"token_url", tokenURL,
		"expires_in", tokenResp.ExpiresIn,
		"mqtt_url", tokenResp.MQTTURL)

	// Calculate expiration time before taking the lock
	var expiryTime time.Time
	if parsedExpiry, err := parseJWTExpiry(tokenResp.AccessToken); err == nil && !parsedExpiry.IsZero() {
		// Use JWT exp claim with a proportional buffer: 10% of TTL, capped at 5 minutes.
		// A hardcoded 5-minute buffer breaks when the server TTL is short (e.g. 5 minutes),
		// causing the token to be considered expired immediately upon receipt.
		ttl := time.Until(parsedExpiry)
		buffer := ttl / 10
		if buffer > 5*time.Minute {
			buffer = 5 * time.Minute
		}
		expiryTime = parsedExpiry.Add(-buffer)
		fleetManager.logger.Debug("using JWT exp claim for token expiry", "expiry", parsedExpiry, "ttl", ttl, "buffer_applied", buffer, "effective_expiry", expiryTime)
	} else if tokenResp.ExpiresIn > 0 {
		// Fallback to ExpiresIn from response with the same proportional buffer.
		ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
		buffer := ttl / 10
		if buffer > 5*time.Minute {
			buffer = 5 * time.Minute
		}
		expiryTime = time.Now().Add(ttl - buffer)
		fleetManager.logger.Debug("using ExpiresIn for token expiry", "expires_in", tokenResp.ExpiresIn, "ttl", ttl, "buffer_applied", buffer, "effective_expiry", expiryTime)
	}

	if effectiveLifetime := time.Until(expiryTime); effectiveLifetime <= 0 {
		fleetManager.logger.Warn("token effective lifetime is zero or negative after applying buffer — token will be treated as expired immediately",
			"effective_expiry", expiryTime,
			"expires_in_field", tokenResp.ExpiresIn)
	}

	// Store credentials and token state under write lock; the HTTP call above is intentionally
	// outside the lock to avoid holding it during I/O.
	fleetManager.mu.Lock()
	fleetManager.tokenURL = tokenURL
	fleetManager.skipTLS = skipTLS
	fleetManager.timeout = timeout
	fleetManager.clientID = clientID
	fleetManager.clientSecret = clientSecret
	fleetManager.lastToken = &tokenResp
	fleetManager.tokenExpiresAt = expiryTime
	fleetManager.mu.Unlock()

	return &tokenResp, nil
}

// RefreshToken refreshes the auth token using stored credentials
func (fleetManager *AuthTokenManager) RefreshToken(ctx context.Context) (*TokenResponse, error) {
	fleetManager.mu.RLock()
	tokenURL := fleetManager.tokenURL
	skipTLS := fleetManager.skipTLS
	timeout := fleetManager.timeout
	clientID := fleetManager.clientID
	clientSecret := fleetManager.clientSecret
	fleetManager.mu.RUnlock()

	if tokenURL == "" {
		return nil, fmt.Errorf("cannot refresh token: credentials not initialized")
	}

	fleetManager.logger.Debug("refreshing JWT token")
	return fleetManager.GetToken(ctx, tokenURL, skipTLS, timeout, clientID, clientSecret)
}

// GetFreshToken returns the cached access token if it is still valid, otherwise
// performs an HTTP refresh and returns the new token. This avoids redundant HTTP
// calls when the token monitor has already refreshed proactively.
func (fleetManager *AuthTokenManager) GetFreshToken(ctx context.Context) (string, error) {
	fleetManager.mu.RLock()
	token := fleetManager.lastToken
	expired := fleetManager.lastToken == nil || time.Now().After(fleetManager.tokenExpiresAt)
	fleetManager.mu.RUnlock()

	if !expired {
		return token.AccessToken, nil
	}

	resp, err := fleetManager.RefreshToken(ctx)
	if err != nil {
		return "", err
	}
	return resp.AccessToken, nil
}

// IsTokenExpired checks if the current token is expired or will expire soon
func (fleetManager *AuthTokenManager) IsTokenExpired() bool {
	fleetManager.mu.RLock()
	lastToken := fleetManager.lastToken
	tokenExpiresAt := fleetManager.tokenExpiresAt
	fleetManager.mu.RUnlock()

	if lastToken == nil {
		return true
	}
	return time.Now().After(tokenExpiresAt)
}

// IsTokenExpiringSoon checks if the token will expire within the specified duration
func (fleetManager *AuthTokenManager) IsTokenExpiringSoon(buffer time.Duration) bool {
	fleetManager.mu.RLock()
	lastToken := fleetManager.lastToken
	tokenExpiresAt := fleetManager.tokenExpiresAt
	fleetManager.mu.RUnlock()

	if lastToken == nil {
		return true
	}
	if tokenExpiresAt.IsZero() {
		return true
	}
	return time.Now().Add(buffer).After(tokenExpiresAt)
}

// GetTokenExpiryTime returns the time when the current token expires (with buffer already applied)
func (fleetManager *AuthTokenManager) GetTokenExpiryTime() time.Time {
	fleetManager.mu.RLock()
	defer fleetManager.mu.RUnlock()
	return fleetManager.tokenExpiresAt
}

// parseJWTExpiry extracts the exp claim from a JWT token
func parseJWTExpiry(tokenString string) (time.Time, error) {
	if tokenString == "" {
		return time.Time{}, fmt.Errorf("empty token string")
	}

	// Parse the JWT token without verification
	token, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	var claims jwt.Claims

	// Extract standard claims without verification
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return time.Time{}, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}

	// Check if exp claim exists
	if claims.Expiry == nil {
		return time.Time{}, fmt.Errorf("exp claim not found in JWT token")
	}

	return claims.Expiry.Time(), nil
}
