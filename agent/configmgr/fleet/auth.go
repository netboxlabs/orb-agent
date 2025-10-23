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

	fleetManager.logger.Debug("sending token request", "url", tokenURL, "data", data, "client_id", clientID) //, "client_secret", clientSecret)

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

	fleetManager.logger.Debug("sending token request", "url", tokenURL)
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

	fleetManager.logger.Info("successfully obtained access token",
		"token_url", tokenURL,
		"expires_in", TokenResponse.ExpiresIn,
		"mqtt_url", TokenResponse.MQTTURL)

	// Store token and calculate expiration time (with 5-minute buffer)
	fleetManager.lastToken = &TokenResponse
	if TokenResponse.ExpiresIn > 0 {
		fleetManager.tokenExpiresAt = time.Now().Add(time.Duration(TokenResponse.ExpiresIn)*time.Second - 5*time.Minute)
	}

	return &TokenResponse, nil
}

// RefreshToken refreshes the auth token using stored credentials
func (fleetManager *AuthTokenManager) RefreshToken(ctx context.Context) (*TokenResponse, error) {
	if fleetManager.tokenURL == "" {
		return nil, fmt.Errorf("cannot refresh token: credentials not initialized")
	}

	fleetManager.logger.Info("refreshing JWT token")
	return fleetManager.GetToken(ctx, fleetManager.tokenURL, fleetManager.skipTLS, fleetManager.timeout, fleetManager.clientID, fleetManager.clientSecret)
}

// IsTokenExpired checks if the current token is expired or will expire soon
func (fleetManager *AuthTokenManager) IsTokenExpired() bool {
	if fleetManager.lastToken == nil {
		return true
	}
	return time.Now().After(fleetManager.tokenExpiresAt)
}
