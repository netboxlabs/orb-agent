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
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/netboxlabs/orb-agent/agent/redact"
)

// AuthTokenManager manages auth tokens
type AuthTokenManager struct {
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

	// Store credentials for future refresh
	fleetManager.tokenURL = tokenURL
	fleetManager.skipTLS = skipTLS
	fleetManager.timeout = timeout
	fleetManager.clientID = clientID
	fleetManager.clientSecret = clientSecret

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

	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		fleetManager.logger.Error("failed to send token request", "error", err, "token_url", tokenURL)
		return nil, fmt.Errorf("failed to send request to %s: %w", tokenURL, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fleetManager.logger.Error("failed to close response body", "error", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fleetManager.logger.Error("failed to read response body", "error", err, "status_code", resp.StatusCode)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		fleetManager.logger.Error("token request failed",
			"status_code", resp.StatusCode,
			"response", string(body),
			"token_url", tokenURL,
			"client_id", clientID)
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var TokenResponse TokenResponse
	if err := json.Unmarshal(body, &TokenResponse); err != nil {
		fleetManager.logger.Error("failed to parse token response", "error", err, "response", string(body))
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Validate token response
	if TokenResponse.AccessToken == "" {
		fleetManager.logger.Error("received empty access token", "response", string(body))
		return nil, fmt.Errorf("received empty access token from server")
	}

	fleetManager.logger.Debug("successfully obtained access token",
		"token_url", tokenURL,
		"expires_in", TokenResponse.ExpiresIn,
		"mqtt_url", TokenResponse.MQTTURL)

	// Store token and calculate expiration time
	fleetManager.lastToken = &TokenResponse

	// Try to parse JWT exp claim for more accurate expiry tracking
	var expiryTime time.Time
	if parsedExpiry, err := parseJWTExpiry(TokenResponse.AccessToken); err == nil && !parsedExpiry.IsZero() {
		// Use JWT exp claim with 5-minute buffer for safety
		expiryTime = parsedExpiry.Add(-5 * time.Minute)
		fleetManager.logger.Debug("using JWT exp claim for token expiry", "expiry", parsedExpiry, "buffer_applied", expiryTime)
	} else if TokenResponse.ExpiresIn > 0 {
		// Fallback to ExpiresIn from response (with 5-minute buffer)
		expiryTime = time.Now().Add(time.Duration(TokenResponse.ExpiresIn)*time.Second - 5*time.Minute)
		fleetManager.logger.Debug("using ExpiresIn for token expiry", "expires_in", TokenResponse.ExpiresIn, "buffer_applied", expiryTime)
	}

	fleetManager.tokenExpiresAt = expiryTime

	return &TokenResponse, nil
}

// RefreshToken refreshes the auth token using stored credentials
func (fleetManager *AuthTokenManager) RefreshToken(ctx context.Context) (*TokenResponse, error) {
	if fleetManager.tokenURL == "" {
		return nil, fmt.Errorf("cannot refresh token: credentials not initialized")
	}

	fleetManager.logger.Debug("refreshing JWT token")
	return fleetManager.GetToken(ctx, fleetManager.tokenURL, fleetManager.skipTLS, fleetManager.timeout, fleetManager.clientID, fleetManager.clientSecret)
}

// IsTokenExpired checks if the current token is expired or will expire soon
func (fleetManager *AuthTokenManager) IsTokenExpired() bool {
	if fleetManager.lastToken == nil {
		return true
	}
	return time.Now().After(fleetManager.tokenExpiresAt)
}

// IsTokenExpiringSoon checks if the token will expire within the specified duration
func (fleetManager *AuthTokenManager) IsTokenExpiringSoon(buffer time.Duration) bool {
	if fleetManager.lastToken == nil {
		return true
	}
	if fleetManager.tokenExpiresAt.IsZero() {
		return true
	}
	return time.Now().Add(buffer).After(fleetManager.tokenExpiresAt)
}

// GetTokenExpiryTime returns the time when the current token expires (with buffer already applied)
func (fleetManager *AuthTokenManager) GetTokenExpiryTime() time.Time {
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
