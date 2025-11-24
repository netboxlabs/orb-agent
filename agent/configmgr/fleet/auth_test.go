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

func TestAuthTokenManager_GetToken_WithJWTExpClaim(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Create a JWT token with exp claim
	futureExpiry := time.Now().Add(1 * time.Hour)
	jwtToken := RawJWTWithClaims(map[string]any{
		"exp": futureExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	// Create mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600, // This should be ignored if JWT exp is present
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

	// Verify expiry time is set (should be futureExpiry - 5 minutes buffer)
	expiryTime := authTokenManager.GetTokenExpiryTime()
	assert.False(t, expiryTime.IsZero())
	assert.WithinDuration(t, futureExpiry.Add(-5*time.Minute), expiryTime, 1*time.Second)
}

func TestAuthTokenManager_GetToken_WithExpiresInFallback(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Create a JWT token without exp claim
	jwtToken := RawJWTWithClaims(map[string]any{
		"iat": time.Now().Unix(),
		// No exp claim
	})

	// Create mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600, // Should use this
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Act
	ctx := context.Background()
	beforeTime := time.Now()
	token, err := authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	afterTime := time.Now()

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, token)

	// Verify expiry time is set using ExpiresIn (3600 seconds - 5 minutes buffer)
	expiryTime := authTokenManager.GetTokenExpiryTime()
	assert.False(t, expiryTime.IsZero())
	expectedExpiry := beforeTime.Add(3600*time.Second - 5*time.Minute)
	assert.True(t, expiryTime.After(expectedExpiry.Add(-1*time.Second)) && expiryTime.Before(afterTime.Add(3600*time.Second-5*time.Minute).Add(1*time.Second)))
}

func TestAuthTokenManager_GetTokenExpiryTime(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Test with no token
	expiryTime := authTokenManager.GetTokenExpiryTime()
	assert.True(t, expiryTime.IsZero())

	// Get a token
	futureExpiry := time.Now().Add(1 * time.Hour)
	jwtToken := RawJWTWithClaims(map[string]any{
		"exp": futureExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// Test with token
	expiryTime = authTokenManager.GetTokenExpiryTime()
	assert.False(t, expiryTime.IsZero())
	assert.WithinDuration(t, futureExpiry.Add(-5*time.Minute), expiryTime, 1*time.Second)
}

func TestAuthTokenManager_IsTokenExpired_ExpiredCases(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Test with no token
	assert.True(t, authTokenManager.IsTokenExpired())

	// Test with expired token
	pastExpiry := time.Now().Add(-1 * time.Hour)
	jwtTokenExpired := RawJWTWithClaims(map[string]any{
		"exp": pastExpiry.Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	serverExpired := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtTokenExpired,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   1,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer serverExpired.Close()

	ctx := context.Background()
	_, err := authTokenManager.GetToken(ctx, serverExpired.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// Token is already expired (pastExpiry is 1 hour ago), so no wait needed
	assert.True(t, authTokenManager.IsTokenExpired())
}

func TestAuthTokenManager_IsTokenExpired_ValidToken(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Test with valid token
	futureExpiry := time.Now().Add(1 * time.Hour)
	jwtTokenValid := RawJWTWithClaims(map[string]any{
		"exp": futureExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	serverValid := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtTokenValid,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer serverValid.Close()

	ctx := context.Background()
	_, err := authTokenManager.GetToken(ctx, serverValid.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	assert.False(t, authTokenManager.IsTokenExpired())
}

func TestAuthTokenManager_IsTokenExpiringSoon(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Test with no token
	assert.True(t, authTokenManager.IsTokenExpiringSoon(2*time.Minute))

	// Test with token expiring soon (within buffer)
	soonExpiry := time.Now().Add(1 * time.Minute) // Will expire in 1 minute, buffer is 2 minutes
	jwtTokenSoon := RawJWTWithClaims(map[string]any{
		"exp": soonExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	serverSoon := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtTokenSoon,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   60,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer serverSoon.Close()

	ctx := context.Background()
	_, err := authTokenManager.GetToken(ctx, serverSoon.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// With 2 minute buffer, token expiring in 1 minute should be considered expiring soon
	// But note: GetToken applies a 5-minute buffer, so the actual expiry check is against (soonExpiry - 5 minutes)
	// So if soonExpiry is 1 minute from now, tokenExpiresAt will be (1 minute - 5 minutes) = -4 minutes ago
	// So IsTokenExpiringSoon(2 minutes) should return true
	assert.True(t, authTokenManager.IsTokenExpiringSoon(2*time.Minute))

	// Test with token not expiring soon
	futureExpiry := time.Now().Add(1 * time.Hour)
	jwtTokenFuture := RawJWTWithClaims(map[string]any{
		"exp": futureExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	serverFuture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtTokenFuture,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer serverFuture.Close()

	authTokenManager2 := NewAuthTokenManager(logger)
	_, err = authTokenManager2.GetToken(ctx, serverFuture.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// With 2 minute buffer, token expiring in ~55 minutes should not be considered expiring soon
	assert.False(t, authTokenManager2.IsTokenExpiringSoon(2*time.Minute))
}

func TestAuthTokenManager_RefreshToken(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	authTokenManager := NewAuthTokenManager(logger)

	// Test refresh without initial token
	ctx := context.Background()
	_, err := authTokenManager.RefreshToken(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot refresh token")

	// Get initial token
	futureExpiry := time.Now().Add(1 * time.Hour)
	jwtToken := RawJWTWithClaims(map[string]any{
		"exp": futureExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: jwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	_, err = authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// Test refresh with stored credentials
	newFutureExpiry := time.Now().Add(2 * time.Hour)
	newJwtToken := RawJWTWithClaims(map[string]any{
		"exp": newFutureExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := TokenResponse{
			AccessToken: newJwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   7200,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server2.Close()

	// Update the token URL to point to new server
	authTokenManager.tokenURL = server2.URL

	// Refresh token
	token, err := authTokenManager.RefreshToken(ctx)
	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, newJwtToken, token.AccessToken)

	// Verify expiry time was updated
	newExpiryTime := authTokenManager.GetTokenExpiryTime()
	assert.WithinDuration(t, newFutureExpiry.Add(-5*time.Minute), newExpiryTime, 1*time.Second)
}
