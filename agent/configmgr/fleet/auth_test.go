package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFleetConfigManager_GetToken_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Create mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and headers
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		// Verify request body
		err := r.ParseForm()
		assert.NoError(t, err)
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		assert.Contains(t, r.Form.Get("scope"), "orb.mqtt:agent")

		// Return valid token response (no longer includes topics)
		response := TokenResponse{
			AccessToken: "test_access_token",
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Act
	ctx := context.Background()
	token, err := authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client_id", "test_client_secret")

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "test_access_token", token.AccessToken)
	assert.Equal(t, "mqtt://test.example.com:1883", token.MQTTURL)
	assert.Equal(t, 3600, token.ExpiresIn)
}

func TestFleetConfigManager_GetToken_HTTPError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Create mock HTTP server that returns error
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	// Act
	ctx := context.Background()
	token, err := authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "invalid_client", "invalid_secret")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "token request failed")
}

func TestFleetConfigManager_GetToken_InvalidJSON(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Create mock HTTP server that returns invalid JSON
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	// Act
	ctx := context.Background()
	token, err := authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client", "test_secret")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to parse token response")
}

func TestFleetConfigManager_GetToken_NetworkError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Act with invalid URL
	ctx := context.Background()
	token, err := authTokenManager.GetToken(ctx, "http://invalid.nonexistent.url:99999", false, 60*time.Second, "test", "test")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to send request")
}

func TestFleetConfigManager_GetToken_InvalidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Act with malformed URL
	ctx := context.Background()
	token, err := authTokenManager.GetToken(ctx, "://invalid-url", false, 60*time.Second, "test", "test")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to create request")
}

func TestTokenResponse_Marshaling(t *testing.T) {
	// Arrange
	original := TokenResponse{
		AccessToken: "test_token_123",
		MQTTURL:     "mqtt://test.example.com:1883",
		ExpiresIn:   7200,
	}

	// Act - Marshal to JSON
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Act - Unmarshal back
	var unmarshaled TokenResponse
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	// Assert
	assert.Equal(t, original.AccessToken, unmarshaled.AccessToken)
	assert.Equal(t, original.MQTTURL, unmarshaled.MQTTURL)
	assert.Equal(t, original.ExpiresIn, unmarshaled.ExpiresIn)
}
