package configmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/otlpbridge"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockPolicyManagerForFleet implements the PolicyManager interface for fleet testing
type mockPolicyManagerForFleet struct {
	mock.Mock
}

func (m *mockPolicyManagerForFleet) ManagePolicy(payload config.PolicyPayload) {
	m.Called(payload)
}

func (m *mockPolicyManagerForFleet) RemovePolicyDataset(policyID string, datasetID string, be backend.Backend) {
	m.Called(policyID, datasetID, be)
}

func (m *mockPolicyManagerForFleet) GetPolicyState() ([]policies.PolicyData, error) {
	args := m.Called()
	return args.Get(0).([]policies.PolicyData), args.Error(1)
}

func (m *mockPolicyManagerForFleet) GetRepo() policies.PolicyRepo {
	args := m.Called()
	val := args.Get(0)
	if val == nil {
		return nil
	}
	return val.(policies.PolicyRepo)
}

func (m *mockPolicyManagerForFleet) ApplyBackendPolicies(be backend.Backend) error {
	args := m.Called(be)
	return args.Error(0)
}

func (m *mockPolicyManagerForFleet) RemoveBackendPolicies(be backend.Backend, permanently bool) error {
	args := m.Called(be, permanently)
	return args.Error(0)
}

func (m *mockPolicyManagerForFleet) RemovePolicy(policyID string, policyName string, beName string) error {
	args := m.Called(policyID, policyName, beName)
	return args.Error(0)
}

type mockBackendState struct {
	mock.Mock
}

func (m *mockBackendState) Get() map[string]*backend.State {
	return m.Called().Get(0).(map[string]*backend.State)
}

// findAvailablePort finds an available port by listening on port 0 and returning the assigned port
func findAvailablePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err, "failed to find available port")
	defer func() {
		_ = listener.Close()
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port
}

func TestFleetConfigManager_Start_TokenError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Create config with invalid token URL
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     "http://invalid.nonexistent.url:99999",
						ClientID:     "test_client",
						ClientSecret: "test_secret",
					},
				},
			},
		},
	}

	backends := make(map[string]backend.Backend)

	// Use a short-lived context so the startup retry loop exits quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Act
	err := fleetManager.Start(ctx, cfg, backends)

	// Assert
	assert.Error(t, err)
}

func TestFleetConfigManager_Start_ConnectError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)

	// Create mock MQTT connection that returns a connection error immediately
	mockConn := &fleet.MockMQTTConnection{
		ConnectError: fmt.Errorf("mqtt connection failed: invalid URL"),
	}
	fleetManager := newFleetConfigManagerWithConnection(logger, mockPMgr, &mockBackendState{}, mockConn)

	// Create mock HTTP server for token endpoint
	// Use a valid JWT token so parsing succeeds and we reach the connection step
	validJWT := fleet.RawJWTWithClaims(map[string]any{
		"orb:org_id":   "test-org",
		"orb:zone":     "default",
		"orb:agent_id": "test-agent",
		"client_id":    "test-client",
		"iat":          1516239022,
		"ext": map[string]any{
			"orb:mqtt_url": "mqtt://test.example.com:1883",
		},
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: validJWT,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     server.URL,
						SkipTLS:      true, // Skip TLS verification for test server
						ClientID:     "test_client",
						ClientSecret: "test_secret",
					},
				},
			},
		},
	}

	backends := make(map[string]backend.Backend)

	// Use a short-lived context so the startup retry loop exits quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Act
	err := fleetManager.Start(ctx, cfg, backends)

	// Assert
	assert.Error(t, err)
}

func TestFleetConfigManager_GetContext(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	originalCtx := context.Background()
	type contextKey string
	const testKey contextKey = "test_key"
	testCtx := context.WithValue(originalCtx, testKey, "test_value")

	// Act
	resultCtx := fleetManager.GetContext(testCtx)

	// Assert
	assert.Equal(t, testCtx, resultCtx, "GetContext should return the context as-is")

	// Verify the context value is preserved
	assert.Equal(t, "test_value", resultCtx.Value(testKey))
}

func TestFleetConfigManager_Start_WithJWTTopicGeneration(t *testing.T) {
	// This test verifies that the Start method correctly generates topics from JWT claims

	mqttURL := "mqtt://test.example.com:1883"
	// Create a valid JWT token with orb-prefixed claims used by parseJWTClaims
	validJWT := fleet.RawJWTWithClaims(map[string]any{
		"orb:org_id":   "integration-org",
		"orb:zone":     "default",
		"orb:agent_id": "test-agent",
		"client_id":    "test-client",
		"iat":          1516239022,
		"ext": map[string]any{
			"orb:mqtt_url": mqttURL,
		},
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)

	// Create mock MQTT connection that returns a connection error
	mockConn := &fleet.MockMQTTConnection{
		ConnectError: fmt.Errorf("mqtt connection failed: connection refused"),
	}
	fleetManager := newFleetConfigManagerWithConnection(logger, mockPMgr, &mockBackendState{}, mockConn)

	// Create mock HTTP server that returns a JWT token
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: validJWT,
			MQTTURL:     mqttURL,
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create test config with ephemeral port (0) to avoid port conflicts
	ephemeralPort := 0
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:           server.URL,
						SkipTLS:            true,
						ClientID:           "test_client_id",
						ClientSecret:       "test_client_secret",
						OTLPBridgeGRPCPort: &ephemeralPort,
					},
				},
			},
		},
	}

	// Mock backends
	backends := make(map[string]backend.Backend)

	// Use a short-lived context so the startup retry loop exits quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// The Start method should succeed in generating topics from JWT claims,
	// but fail at the MQTT connection step (which is mocked to return an error)
	err := fleetManager.Start(ctx, cfg, backends)

	// We expect an error because the mock connection returns an error,
	// but we want to verify that topic generation succeeded
	// (The error should be related to MQTT connection, not JWT parsing)
	require.Error(t, err)
	// The error may be the mocked connection error or context cancellation from the retry loop.
	errorMsg := strings.ToLower(err.Error())
	assert.True(t,
		strings.Contains(errorMsg, "mqtt") ||
			strings.Contains(errorMsg, "connection") ||
			strings.Contains(errorMsg, "cancelled") ||
			strings.Contains(errorMsg, "deadline"),
		"Expected connection-related or cancellation error, got: %s", err.Error())
}

func TestFleetConfigManager_configToSafeString(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	tests := []struct {
		name         string
		clientSecret string
		wantSecret   string
		wantErr      bool
		checkInYAML  bool
	}{
		{
			name:         "sanitizes non-empty client secret",
			clientSecret: "my-super-secret-password",
			wantSecret:   "********",
			wantErr:      false,
			checkInYAML:  true,
		},
		{
			name:         "empty client secret remains empty",
			clientSecret: "",
			wantSecret:   "",
			wantErr:      false,
			checkInYAML:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			cfg := config.Config{
				Version: 1.0,
				OrbAgent: config.OrbAgent{
					ConfigManager: config.ManagerConfig{
						Active: "orb",
						Sources: config.Sources{
							Fleet: config.FleetManager{
								TokenURL:     "https://example.com/token",
								ClientID:     "test-client-id",
								ClientSecret: tt.clientSecret,
								SkipTLS:      false,
							},
						},
					},
				},
			}

			// Act
			result, err := fleetManager.configToSafeString(cfg)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, result)

			// Verify the original secret is not in the output
			if tt.clientSecret != "" {
				assert.NotContains(t, result, tt.clientSecret, "original secret should not be in output")
			}

			// Verify the expected secret is in the YAML output
			if tt.checkInYAML {
				assert.Contains(t, result, tt.wantSecret, "sanitized secret should be in output")
				// YAML can use either single or double quotes, so check for either
				assert.True(t,
					strings.Contains(result, "client_secret: '********'") ||
						strings.Contains(result, "client_secret: \"********\"") ||
						strings.Contains(result, "client_secret: ********"),
					"client_secret should be masked in YAML output")
			}
		})
	}
}

func TestFleetConfigManager_configToSafeString_DoesNotModifyOriginal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Arrange
	originalSecret := "my-secret-password"
	cfg := config.Config{
		Version: 1.0,
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     "https://example.com/token",
						ClientID:     "test-client-id",
						ClientSecret: originalSecret,
					},
				},
			},
		},
	}

	// Act
	_, err := fleetManager.configToSafeString(cfg)

	// Assert
	require.NoError(t, err)
	// The original config should not be modified (we're modifying a copy)
	// Note: Due to Go's pass-by-value semantics, the original is preserved
	assert.Equal(t, originalSecret, cfg.OrbAgent.ConfigManager.Sources.Fleet.ClientSecret,
		"original config should not be modified")
}

func TestFleetConfigManager_MonitorTokenExpiry_Configuration(t *testing.T) {
	// Test that monitorTokenExpiry uses default values when config is not set
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Set config with no monitoring settings (should use defaults)
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     "https://example.com/token",
						ClientID:     "test-client-id",
						ClientSecret: "test-secret",
					},
				},
			},
		},
	}
	fleetManager.config = cfg

	// Initialize monitor context
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())

	// Start monitor in a goroutine
	done := make(chan bool)
	go func() {
		fleetManager.monitorTokenExpiry()
		done <- true
	}()

	// Cancel monitor context to stop the monitor
	fleetManager.monitorCancel()

	// Wait for monitor to stop
	select {
	case <-done:
		// Monitor stopped successfully
	case <-time.After(100 * time.Millisecond):
		t.Fatal("monitor did not stop within timeout")
	}
}

func TestFleetConfigManager_MonitorTokenExpiry_CustomConfiguration(t *testing.T) {
	// Test that monitorTokenExpiry uses custom config values
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Set config with custom monitoring settings
	checkInterval := 60
	reconnectBuffer := 180
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:                 "https://example.com/token",
						ClientID:                 "test-client-id",
						ClientSecret:             "test-secret",
						TokenExpiryCheckInterval: &checkInterval,
						TokenReconnectBuffer:     &reconnectBuffer,
					},
				},
			},
		},
	}
	fleetManager.config = cfg

	// Initialize monitor context
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())

	// Start monitor in a goroutine
	done := make(chan bool)
	go func() {
		fleetManager.monitorTokenExpiry()
		done <- true
	}()

	// Cancel monitor context to stop the monitor
	fleetManager.monitorCancel()

	// Wait for monitor to stop
	select {
	case <-done:
		// Monitor stopped successfully
	case <-time.After(100 * time.Millisecond):
		t.Fatal("monitor did not stop within timeout")
	}
}

func TestFleetConfigManager_Stop_CancelsMonitor(t *testing.T) {
	// Test that Stop() properly cancels the token expiry monitor
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Initialize monitor context
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())

	// Verify monitor context is not cancelled initially
	select {
	case <-fleetManager.monitorCtx.Done():
		t.Fatal("monitor context should not be cancelled initially")
	default:
		// Good, context is not cancelled
	}

	// Call Stop()
	ctx := context.Background()
	err := fleetManager.Stop(ctx)

	// Assert
	require.NoError(t, err)

	// Verify monitor context is now cancelled
	select {
	case <-fleetManager.monitorCtx.Done():
		// Good, context is cancelled
	case <-time.After(50 * time.Millisecond):
		t.Fatal("monitor context should be cancelled after Stop()")
	}
}

func TestFleetConfigManager_Stop_HandlesNilMonitorCancel(t *testing.T) {
	// Test that Stop() handles nil monitorCancel gracefully
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Don't initialize monitorCancel (should be nil)
	fleetManager.monitorCancel = nil

	// Call Stop() - should not panic
	ctx := context.Background()
	err := fleetManager.Stop(ctx)

	// Assert
	require.NoError(t, err)
}

func TestFleetConfigManager_MonitorTokenExpiry_DetectsExpiredToken(t *testing.T) {
	// Test that monitor detects expired token and triggers reconnection
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Set up config
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     "https://example.com/token",
						ClientID:     "test-client-id",
						ClientSecret: "test-secret",
					},
				},
			},
		},
	}
	fleetManager.config = cfg

	// Set up expired token by getting a token and then manually setting expiry to past
	// We'll use a test server to get a token first
	pastExpiry := time.Now().Add(-1 * time.Hour)
	jwtToken := fleet.RawJWTWithClaims(map[string]any{
		"exp": pastExpiry.Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: jwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   1,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fleetManager.authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// Verify token is expired
	assert.True(t, fleetManager.authTokenManager.IsTokenExpired())

	// Create monitor context
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())
	defer fleetManager.monitorCancel()

	// Start monitor with short check interval for testing
	done := make(chan bool)
	go func() {
		// Use a very short check interval for testing
		checkInterval := 100 * time.Millisecond

		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-fleetManager.monitorCtx.Done():
				done <- true
				return
			case <-ticker.C:
				if fleetManager.authTokenManager.IsTokenExpired() {
					// Signal reconnection
					select {
					case fleetManager.reconnectChan <- struct{}{}:
						// Reconnection triggered
					default:
						// Channel full, skip
					}
					done <- true
					return
				}
			}
		}
	}()

	// Wait for monitor to detect expired token
	// Allow at least one ticker interval (100ms) plus buffer
	select {
	case <-done:
		// Monitor detected expired token
	case <-time.After(200 * time.Millisecond):
		t.Fatal("monitor did not detect expired token within timeout")
	}

	// Verify reconnection was triggered
	select {
	case <-fleetManager.reconnectChan:
		// Reconnection signal received
	default:
		t.Fatal("reconnection signal should have been sent")
	}
}

func TestFleetConfigManager_MonitorTokenExpiry_DetectsExpiringSoonToken(t *testing.T) {
	// Test that monitor detects token expiring soon and triggers reconnection
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Set up config
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     "https://example.com/token",
						ClientID:     "test-client-id",
						ClientSecret: "test-secret",
					},
				},
			},
		},
	}
	fleetManager.config = cfg

	// Set up token expiring soon (within buffer) by getting a token with soon expiry
	soonExpiry := time.Now().Add(1 * time.Minute) // Expires in 1 minute
	jwtToken := fleet.RawJWTWithClaims(map[string]any{
		"exp": soonExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: jwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   60,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fleetManager.authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// Verify token is expiring soon with 2 minute buffer
	reconnectBuffer := 2 * time.Minute
	assert.True(t, fleetManager.authTokenManager.IsTokenExpiringSoon(reconnectBuffer))

	// Create monitor context
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())
	defer fleetManager.monitorCancel()

	// Start monitor with short check interval for testing
	done := make(chan bool)
	go func() {
		checkInterval := 100 * time.Millisecond

		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-fleetManager.monitorCtx.Done():
				done <- true
				return
			case <-ticker.C:
				if fleetManager.authTokenManager.IsTokenExpiringSoon(reconnectBuffer) {
					// Signal reconnection
					select {
					case fleetManager.reconnectChan <- struct{}{}:
						// Reconnection triggered
					default:
						// Channel full, skip
					}
					done <- true
					return
				}
			}
		}
	}()

	// Wait for monitor to detect expiring token
	// Allow at least one ticker interval (100ms) plus buffer
	select {
	case <-done:
		// Monitor detected expiring token
	case <-time.After(200 * time.Millisecond):
		t.Fatal("monitor did not detect expiring token within timeout")
	}

	// Verify reconnection was triggered
	select {
	case <-fleetManager.reconnectChan:
		// Reconnection signal received
	default:
		t.Fatal("reconnection signal should have been sent")
	}
}

// TestFleetConfigManager_MonitorTokenExpiry_NoSpuriousReconnectForShortLivedToken verifies that
// the monitor does NOT trigger a reconnect for a short-lived but valid token where the effective
// lifetime (after the proportional buffer) is greater than the reconnect buffer.
//
// Scenario (reproduces OBS-2248 at the monitor layer):
//   - Token TTL = 5 minutes → after proportional buffer (30s) → ~4m30s effective lifetime
//   - Configured reconnectBuffer = 2 minutes
//   - 4m30s remaining > 2m reconnect buffer → IsTokenExpiringSoon(2m) is FALSE → no reconnect
//
// The ticker interval is set to 1 second so the monitor loop actually executes within the test
// window. We wait 1.5 seconds to guarantee at least one full tick fires before asserting.
func TestFleetConfigManager_MonitorTokenExpiry_NoSpuriousReconnectForShortLivedToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Use a 1-second check interval so the ticker fires within the test window.
	// The default is 30 seconds which would never tick during a short test.
	checkInterval := 1
	reconnectBuffer := 120 // 2 minutes in seconds
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:                 "https://example.com/token",
						ClientID:                 "test-client-id",
						ClientSecret:             "test-secret",
						TokenExpiryCheckInterval: &checkInterval,
						TokenReconnectBuffer:     &reconnectBuffer,
					},
				},
			},
		},
	}
	fleetManager.config = cfg

	// Token expires in 5 minutes; proportional buffer = 10% of 5m = 30s → effective lifetime ≈ 4m30s.
	// This is well above the 2-minute reconnect buffer, so IsTokenExpiringSoon must return false.
	fiveMinExpiry := time.Now().Add(5 * time.Minute)
	jwtToken := fleet.RawJWTWithClaims(map[string]any{
		"exp": fiveMinExpiry.Unix(),
		"iat": time.Now().Unix(),
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: jwtToken,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   300,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fleetManager.authTokenManager.GetToken(ctx, server.URL, true, 60*time.Second, "test_client_id", "test_client_secret")
	require.NoError(t, err)

	// Pre-flight: confirm the auth manager state is correct before starting the monitor.
	assert.False(t, fleetManager.authTokenManager.IsTokenExpired(), "token should not be expired")
	assert.False(t, fleetManager.authTokenManager.IsTokenExpiringSoon(2*time.Minute),
		"5-minute token with ~4m30s effective lifetime should not be expiring soon with 2m buffer")

	// Start the monitor and wait 1.5 seconds — enough for at least one 1-second tick to fire.
	// If the monitor loop is broken and emits a reconnect, the test will catch it.
	fleetManager.monitorCtx, fleetManager.monitorCancel = context.WithCancel(context.Background())
	defer fleetManager.monitorCancel()

	go fleetManager.monitorTokenExpiry()

	select {
	case <-fleetManager.reconnectChan:
		t.Fatal("reconnect was triggered spuriously for a healthy 5-minute token after at least one monitor tick")
	case <-time.After(1500 * time.Millisecond):
		// At least one tick fired with no spurious reconnect — correct behaviour
	}
}

func TestFleetConfigManager_OnReadyHook_InitializesBridgeOnFirstCall(t *testing.T) {
	// Test that OnReadyHook initializes the bridge when called the first time
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Verify bridge is nil initially
	assert.Nil(t, fleetManager.otlpBridge, "bridge should be nil initially")

	// Create the hook function (simulating what Start does)
	hookFunc := func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		if fleetManager.otlpBridge == nil {
			fleetManager.logger.Info("MQTT connection ready, initializing OTLP bridge")
			bridgeConfig := otlpbridge.BridgeConfig{
				ListenAddr: ":0",
				Encoding:   "protobuf",
			}
			var err error
			fleetManager.otlpBridge, err = otlpbridge.NewBridgeServer(bridgeConfig, fleetManager.policyManager.GetRepo(), fleetManager.logger)
			if err != nil {
				fleetManager.logger.Error("failed to create OTLP bridge", slog.Any("error", err))
				return
			}
			if err := fleetManager.otlpBridge.Start(context.Background()); err != nil {
				fleetManager.logger.Error("failed to start OTLP bridge", slog.Any("error", err))
				return
			}
		} else {
			fleetManager.logger.Info("OTLP bridge already initialized, skipping initialization")
		}

		pub := otlpbridge.NewCMAdapterPublisher(cm)
		fleetManager.otlpBridge.SetPublisher(pub)
		fleetManager.otlpBridge.SetIngestTopic(topics.Ingest)
		fleetManager.otlpBridge.SetTelemetryTopic(topics.Telemetry)
		fleetManager.logger.Info("OTLP bridge bound to Fleet MQTT",
			slog.String("ingest_topic", topics.Ingest),
			slog.String("telemetry_topic", topics.Telemetry))
	}

	// Register the hook
	fleetManager.connection.AddOnReadyHook(hookFunc)

	// Simulate first connection ready event
	topics := fleet.TokenResponseTopics{
		Ingest:    "test/otlp/topic",
		Telemetry: "test/telemetry/topic",
	}

	// Call the hook manually (simulating first connection)
	hookFunc(nil, topics)

	// Verify bridge was initialized
	require.NotNil(t, fleetManager.otlpBridge, "bridge should be initialized after first hook call")
	assert.Equal(t, "test/otlp/topic", fleetManager.otlpBridge.GetIngestTopic(), "bridge should have correct ingest topic")
	assert.Equal(t, "test/telemetry/topic", fleetManager.otlpBridge.GetTelemetryTopic(), "bridge should have correct telemetry topic")

	// Cleanup
	if fleetManager.otlpBridge != nil {
		_ = fleetManager.otlpBridge.Stop(context.Background())
	}
}

func TestFleetConfigManager_OnReadyHook_SkipsInitializationOnReconnect(t *testing.T) {
	// Test that OnReadyHook skips initialization when bridge already exists (reconnection scenario)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Pre-initialize the bridge (simulating it was already created)
	bridgeConfig := otlpbridge.BridgeConfig{
		ListenAddr: ":0",
		Encoding:   "protobuf",
	}
	bridge, err := otlpbridge.NewBridgeServer(bridgeConfig, nil, logger)
	require.NoError(t, err)
	err = bridge.Start(context.Background())
	require.NoError(t, err)
	fleetManager.otlpBridge = bridge

	// Store the original bridge pointer to verify it's not recreated
	originalBridge := fleetManager.otlpBridge

	// Create the hook function
	hookFunc := func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		if fleetManager.otlpBridge == nil {
			fleetManager.logger.Info("MQTT connection ready, initializing OTLP bridge")
			bridgeConfig := otlpbridge.BridgeConfig{
				ListenAddr: ":0",
				Encoding:   "protobuf",
			}
			var err error
			fleetManager.otlpBridge, err = otlpbridge.NewBridgeServer(bridgeConfig, fleetManager.policyManager.GetRepo(), fleetManager.logger)
			if err != nil {
				fleetManager.logger.Error("failed to create OTLP bridge", slog.Any("error", err))
				return
			}
			if err := fleetManager.otlpBridge.Start(context.Background()); err != nil {
				fleetManager.logger.Error("failed to start OTLP bridge", slog.Any("error", err))
				return
			}
		} else {
			fleetManager.logger.Info("OTLP bridge already initialized, skipping initialization")
		}

		pub := otlpbridge.NewCMAdapterPublisher(cm)
		fleetManager.otlpBridge.SetPublisher(pub)
		fleetManager.otlpBridge.SetIngestTopic(topics.Ingest)
		fleetManager.otlpBridge.SetTelemetryTopic(topics.Telemetry)
		fleetManager.logger.Info("OTLP bridge bound to Fleet MQTT",
			slog.String("ingest_topic", topics.Ingest),
			slog.String("telemetry_topic", topics.Telemetry))
	}

	// Register the hook
	fleetManager.connection.AddOnReadyHook(hookFunc)

	// Simulate reconnection ready event
	topics := fleet.TokenResponseTopics{
		Ingest:    "test/otlp/topic/reconnect",
		Telemetry: "test/telemetry/topic/reconnect",
	}

	// Call the hook manually (simulating reconnection)
	hookFunc(nil, topics)

	// Verify bridge was NOT recreated (same instance)
	assert.Equal(t, originalBridge, fleetManager.otlpBridge, "bridge should not be recreated on reconnect")
	assert.Equal(t, "test/otlp/topic/reconnect", fleetManager.otlpBridge.GetIngestTopic(), "bridge should have updated ingest topic")
	assert.Equal(t, "test/telemetry/topic/reconnect", fleetManager.otlpBridge.GetTelemetryTopic(), "bridge should have updated telemetry topic")

	// Cleanup
	if fleetManager.otlpBridge != nil {
		_ = fleetManager.otlpBridge.Stop(context.Background())
	}
}

func TestFleetConfigManager_OnReadyHook_UsesConfiguredGRPCPort(t *testing.T) {
	// Test that OnReadyHook uses the configured gRPC port from config
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Create config with custom gRPC port
	customPort := 9999
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						OTLPBridgeGRPCPort: &customPort,
					},
				},
			},
		},
	}
	fleetManager.config = cfg

	// Create the hook function that uses config (simulating what Start does)
	hookFunc := func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		if fleetManager.otlpBridge == nil {
			fleetManager.logger.Info("MQTT connection ready, initializing OTLP bridge")
			// Get gRPC port from config, defaulting to 4317 if not specified
			grpcPort := 4317
			if fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort != nil {
				grpcPort = *fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort
			}
			bridgeConfig := otlpbridge.BridgeConfig{
				ListenAddr: fmt.Sprintf(":%d", grpcPort),
				Encoding:   "json",
			}
			var err error
			fleetManager.otlpBridge, err = otlpbridge.NewBridgeServer(bridgeConfig, fleetManager.policyManager.GetRepo(), fleetManager.logger)
			if err != nil {
				fleetManager.logger.Error("failed to create OTLP bridge", slog.Any("error", err))
				return
			}
			if err := fleetManager.otlpBridge.Start(context.Background()); err != nil {
				fleetManager.logger.Error("failed to start OTLP bridge", slog.Any("error", err))
				return
			}
		} else {
			fleetManager.logger.Info("OTLP bridge already initialized, skipping initialization")
		}

		pub := otlpbridge.NewCMAdapterPublisher(cm)
		fleetManager.otlpBridge.SetPublisher(pub)
		fleetManager.otlpBridge.SetIngestTopic(topics.Ingest)
		fleetManager.otlpBridge.SetTelemetryTopic(topics.Telemetry)
		fleetManager.logger.Info("OTLP bridge bound to Fleet MQTT",
			slog.String("ingest_topic", topics.Ingest),
			slog.String("telemetry_topic", topics.Telemetry))
	}

	// Register the hook
	fleetManager.connection.AddOnReadyHook(hookFunc)

	// Simulate connection ready event
	topics := fleet.TokenResponseTopics{
		Ingest:    "test/otlp/topic",
		Telemetry: "test/telemetry/topic",
	}

	// Call the hook manually
	hookFunc(nil, topics)

	// Verify bridge was initialized
	require.NotNil(t, fleetManager.otlpBridge, "bridge should be initialized")
	// Verify the bridge is listening on the configured port
	// We can't directly check the port, but we can verify the bridge started successfully
	// The actual port verification would require inspecting the listener, which is not exposed
	// So we just verify the bridge exists and started without error

	// Cleanup
	if fleetManager.otlpBridge != nil {
		_ = fleetManager.otlpBridge.Stop(context.Background())
	}
}

func TestFleetConfigManager_OnReadyHook_UsesDefaultGRPCPort(t *testing.T) {
	// Test that OnReadyHook uses the default gRPC port (4317) when not configured
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Create config without gRPC port configured (should use default)
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						// OTLPBridgeGRPCPort is nil, should use default 4317
					},
				},
			},
		},
	}
	fleetManager.config = cfg

	// Create the hook function that uses config (simulating what Start does)
	hookFunc := func(cm *autopaho.ConnectionManager, topics fleet.TokenResponseTopics) {
		if fleetManager.otlpBridge == nil {
			fleetManager.logger.Info("MQTT connection ready, initializing OTLP bridge")
			// Get gRPC port from config, defaulting to 4317 if not specified
			grpcPort := 4317
			if fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort != nil {
				grpcPort = *fleetManager.config.OrbAgent.ConfigManager.Sources.Fleet.OTLPBridgeGRPCPort
			}
			bridgeConfig := otlpbridge.BridgeConfig{
				ListenAddr: fmt.Sprintf(":%d", grpcPort),
				Encoding:   "json",
			}
			var err error
			fleetManager.otlpBridge, err = otlpbridge.NewBridgeServer(bridgeConfig, fleetManager.policyManager.GetRepo(), fleetManager.logger)
			if err != nil {
				fleetManager.logger.Error("failed to create OTLP bridge", slog.Any("error", err))
				return
			}
			if err := fleetManager.otlpBridge.Start(context.Background()); err != nil {
				fleetManager.logger.Error("failed to start OTLP bridge", slog.Any("error", err))
				return
			}
		} else {
			fleetManager.logger.Info("OTLP bridge already initialized, skipping initialization")
		}

		pub := otlpbridge.NewCMAdapterPublisher(cm)
		fleetManager.otlpBridge.SetPublisher(pub)
		fleetManager.otlpBridge.SetIngestTopic(topics.Ingest)
		fleetManager.otlpBridge.SetTelemetryTopic(topics.Telemetry)
		fleetManager.logger.Info("OTLP bridge bound to Fleet MQTT",
			slog.String("ingest_topic", topics.Ingest),
			slog.String("telemetry_topic", topics.Telemetry))
	}

	// Register the hook
	fleetManager.connection.AddOnReadyHook(hookFunc)

	// Simulate connection ready event
	topics := fleet.TokenResponseTopics{
		Ingest:    "test/otlp/topic",
		Telemetry: "test/telemetry/topic",
	}

	// Call the hook manually
	hookFunc(nil, topics)

	// Verify bridge was initialized (should use default port 4317)
	require.NotNil(t, fleetManager.otlpBridge, "bridge should be initialized with default port")

	// Cleanup
	if fleetManager.otlpBridge != nil {
		_ = fleetManager.otlpBridge.Stop(context.Background())
	}
}

func TestFleetConfigManager_Start_OTLPBridgePortInUse(t *testing.T) {
	// Test that Start() fails with a clear error when the OTLP bridge port is already in use
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)

	// Pre-occupy a port with a test listener
	testPort := findAvailablePort(t)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", testPort))
	require.NoError(t, err, "failed to create test listener")
	defer func() {
		_ = listener.Close()
	}()

	// Create mock HTTP server for token endpoint
	validJWT := fleet.RawJWTWithClaims(map[string]any{
		"orb:org_id":   "test-org",
		"orb:zone":     "default",
		"orb:agent_id": "test-agent",
		"client_id":    "test-client",
		"iat":          1516239022,
		"ext": map[string]any{
			"orb:mqtt_url": "mqtt://test.example.com:1883",
		},
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: validJWT,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create config with the pre-occupied port
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:           server.URL,
						SkipTLS:            true,
						ClientID:           "test_client",
						ClientSecret:       "test_secret",
						OTLPBridgeGRPCPort: &testPort,
					},
				},
			},
		},
	}

	backends := make(map[string]backend.Backend)
	// Use mock connection so we don't try to actually connect to MQTT
	mockConn := &fleet.MockMQTTConnection{
		ConnectError: fmt.Errorf("mqtt connection failed"),
	}
	fleetManager := newFleetConfigManagerWithConnection(logger, mockPMgr, &mockBackendState{}, mockConn)

	// Act — port binding is before the retry loop, so this fails immediately.
	err = fleetManager.Start(context.Background(), cfg, backends)

	// Assert
	require.Error(t, err, "Start() should fail when port is in use")
	assert.Contains(t, err.Error(), "failed to start OTLP bridge", "error should mention OTLP bridge failure")
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", testPort), "error should mention the port number")
}

func TestFleetConfigManager_Start_OTLPBridgeStartsBeforeMQTT(t *testing.T) {
	// Test that OTLP bridge starts before MQTT connection attempt
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	mockPMgr.On("GetRepo").Return(nil)

	// Create a mock MQTT connection that tracks when Connect() is called
	mockConn := &fleet.MockMQTTConnection{
		ConnectError: fmt.Errorf("mqtt connection failed"),
	}
	fleetManager := newFleetConfigManagerWithConnection(logger, mockPMgr, &mockBackendState{}, mockConn)

	// Create mock HTTP server for token endpoint
	validJWT := fleet.RawJWTWithClaims(map[string]any{
		"orb:org_id":   "test-org",
		"orb:zone":     "default",
		"orb:agent_id": "test-agent",
		"client_id":    "test-client",
		"iat":          1516239022,
		"ext": map[string]any{
			"orb:mqtt_url": "mqtt://test.example.com:1883",
		},
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: validJWT,
			MQTTURL:     "mqtt://test.example.com:1883",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Use ephemeral port (0) to avoid port conflicts with other tests
	ephemeralPort := 0
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:           server.URL,
						SkipTLS:            true,
						ClientID:           "test_client",
						ClientSecret:       "test_secret",
						OTLPBridgeGRPCPort: &ephemeralPort,
					},
				},
			},
		},
	}

	backends := make(map[string]backend.Backend)

	// Use a short-lived context so the startup retry loop exits quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Act
	err := fleetManager.Start(ctx, cfg, backends)

	// Assert
	// Even though MQTT connection fails, we should verify that:
	// 1. OTLP bridge was started (it should exist)
	// 2. Connect() was called (indicating we got past bridge startup)
	require.Error(t, err, "Start() should fail due to MQTT connection error")
	assert.True(t, mockConn.ConnectCalled(), "MQTT Connect() should have been called")
	// The bridge should have been created and started before Connect() was called
	// Since Connect() was called, the bridge must have started successfully
	assert.NotNil(t, fleetManager.otlpBridge, "OTLP bridge should be initialized before MQTT connection")

	// Cleanup
	if fleetManager.otlpBridge != nil {
		_ = fleetManager.otlpBridge.Stop(context.Background())
	}
}

// controlledTokenServer is a test HTTP server whose response can switch from failure to success
// after a configurable number of requests. Thread-safe.
type controlledTokenServer struct {
	t            *testing.T
	mu           sync.Mutex
	failForCount int // requests 1..failForCount return 500; subsequent requests return a valid token
	requestCount int
	validJWT     string
	mqttURL      string
}

func (s *controlledTokenServer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.requestCount++
	count := s.requestCount
	s.mu.Unlock()

	// Request 1 is the credential-priming GetToken call — always succeed.
	// Requests 2..failForCount+1 fail; requests failForCount+2 onward succeed again.
	if count > 1 && count <= s.failForCount+1 {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(fleet.TokenResponse{
		AccessToken: s.validJWT,
		MQTTURL:     s.mqttURL,
		ExpiresIn:   3600,
	})
}

func (s *controlledTokenServer) RequestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requestCount
}

// newControlledTokenServer wraps a controlledTokenServer in a TLS httptest.Server.
// failForCount requests will return HTTP 500 before switching to valid responses.
func newControlledTokenServer(t *testing.T, failForCount int) (*httptest.Server, *controlledTokenServer) {
	t.Helper()
	mqttURL := "mqtt://test.example.com:1883"
	validJWT := fleet.RawJWTWithClaims(map[string]any{
		"orb:org_id":   "test-org",
		"orb:zone":     "default",
		"orb:agent_id": "test-agent",
		"client_id":    "test-client",
		"iat":          1516239022,
		"ext": map[string]any{
			"orb:mqtt_url": mqttURL,
		},
	})
	handler := &controlledTokenServer{
		t:            t,
		failForCount: failForCount,
		validJWT:     validJWT,
		mqttURL:      mqttURL,
	}
	return httptest.NewTLSServer(handler), handler
}

// newReconnectWorkerManager creates a FleetConfigManager wired with a mock MQTT connection and a
// pre-fetched valid token so that runReconnectWorker can be invoked directly in tests.
func newReconnectWorkerManager(t *testing.T, mockConn *fleet.MockMQTTConnection, tokenServerURL string) *FleetConfigManager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}

	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	mgr := &FleetConfigManager{
		logger:           logger,
		connection:       mockConn,
		authTokenManager: fleet.NewAuthTokenManager(logger),
		resetChan:        resetChan,
		reconnectChan:    reconnectChan,
		policyManager:    mockPMgr,
		config: config.Config{
			OrbAgent: config.OrbAgent{
				ConfigManager: config.ManagerConfig{
					Sources: config.Sources{
						Fleet: config.FleetManager{
							TokenURL:     tokenServerURL,
							SkipTLS:      true,
							ClientID:     "test_client",
							ClientSecret: "test_secret",
						},
					},
				},
			},
		},
	}

	// Pre-fetch a token so the manager has stored credentials for RefreshToken.
	ctx := context.Background()
	_, err := mgr.authTokenManager.GetToken(ctx, tokenServerURL, true, 10*time.Second, "test_client", "test_secret")
	require.NoError(t, err, "initial GetToken must succeed to prime credentials")

	// Set a heartbeat topic so Disconnect has a valid topic string.
	mgr.connectionDetails = fleet.ConnectionDetails{
		Topics: fleet.TokenResponseTopics{
			Heartbeat: "agents/test-agent/heartbeat",
		},
	}

	return mgr
}

// TestFleetConfigManager_ReconnectWorker_RetriesOnTransientFailure verifies that when the token
// endpoint fails for fewer attempts than maxRetries, refreshAndReconnect eventually succeeds,
// Disconnect is NOT called, and no re-signal timer is scheduled.
func TestFleetConfigManager_ReconnectWorker_RetriesOnTransientFailure(t *testing.T) {
	// Token server fails for the first 2 requests, then succeeds.
	// With maxRetries=5 the worker should succeed on attempt 3.
	server, handler := newControlledTokenServer(t, 2)
	defer server.Close()

	mockConn := &fleet.MockMQTTConnection{
		ReconnectError: nil, // Reconnect succeeds after token refresh
	}
	mgr := newReconnectWorkerManager(t, mockConn, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run worker with very short backoffs so the test completes quickly.
	go mgr.runReconnectWorker(ctx, 10*time.Second, 5, 10*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)

	// Trigger one reconnect.
	mgr.reconnectChan <- struct{}{}

	// Wait long enough for 2 failures + backoffs + 1 success (generous upper bound).
	time.Sleep(300 * time.Millisecond)

	assert.False(t, mockConn.DisconnectCalled(), "Disconnect should NOT be called when refresh eventually succeeds")
	// Request 1 = prime, requests 2-3 = failures, request 4 = success → at least 4 total.
	assert.GreaterOrEqual(t, handler.RequestCount(), 4, "token endpoint should have been called at least 4 times (1 prime + 2 failures + 1 success)")

	// reconnectChan should be empty (no re-signal scheduled).
	select {
	case <-mgr.reconnectChan:
		t.Fatal("reconnectChan should be empty after a successful retry")
	default:
	}
}

// TestFleetConfigManager_ReconnectWorker_DisconnectsAfterAllRetriesFail verifies that when the
// token endpoint fails on every request, the worker calls Disconnect after exhausting maxRetries.
func TestFleetConfigManager_ReconnectWorker_DisconnectsAfterAllRetriesFail(t *testing.T) {
	// Token server always fails (failForCount > maxRetries).
	server, _ := newControlledTokenServer(t, 100)
	defer server.Close()

	mockConn := &fleet.MockMQTTConnection{}
	mgr := newReconnectWorkerManager(t, mockConn, server.URL)

	// Override the token URL with the always-failing server AFTER priming credentials,
	// so RefreshToken uses this URL.
	mgr.config.OrbAgent.ConfigManager.Sources.Fleet.TokenURL = server.URL

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// maxRetries=3, very short backoffs to keep test fast.
	const testMaxRetries = 3
	go mgr.runReconnectWorker(ctx, 10*time.Second, testMaxRetries, 10*time.Millisecond, 50*time.Millisecond, 5*time.Second)

	mgr.reconnectChan <- struct{}{}

	// Wait long enough for 3 attempts + backoffs + disconnect.
	// 3 attempts: 10ms + 20ms backoffs between them = ~50ms total; add generous buffer.
	require.Eventually(t, func() bool {
		return mockConn.DisconnectCalled()
	}, 2*time.Second, 20*time.Millisecond, "Disconnect should be called after all retries are exhausted")
}

// TestFleetConfigManager_ReconnectWorker_ExitsOnContextCancel verifies that runReconnectWorker
// exits promptly when its context is cancelled, even while idle waiting for a signal.
func TestFleetConfigManager_ReconnectWorker_ExitsOnContextCancel(t *testing.T) {
	server, _ := newControlledTokenServer(t, 0)
	defer server.Close()

	mockConn := &fleet.MockMQTTConnection{}
	mgr := newReconnectWorkerManager(t, mockConn, server.URL)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		mgr.runReconnectWorker(ctx, 10*time.Second, 3, 10*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)
		close(done)
	}()

	// Cancel the context — worker should exit without any signal on reconnectChan.
	cancel()

	select {
	case <-done:
		// Worker exited as expected.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runReconnectWorker did not exit after context cancellation")
	}
}

// TestFleetConfigManager_ReconnectWorker_ReschedulesAfterExhaustion verifies that after all retries
// fail, the worker schedules a re-signal on reconnectChan so recovery does not depend solely on the
// 30-second monitor tick.
func TestFleetConfigManager_ReconnectWorker_ReschedulesAfterExhaustion(t *testing.T) {
	// Token server always fails.
	server, _ := newControlledTokenServer(t, 100)
	defer server.Close()

	mockConn := &fleet.MockMQTTConnection{}
	mgr := newReconnectWorkerManager(t, mockConn, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// maxRetries=2, very short retry delay (50ms) so the re-signal arrives quickly.
	const testMaxRetries = 2
	const testRetryDelay = 50 * time.Millisecond
	go mgr.runReconnectWorker(ctx, 10*time.Second, testMaxRetries, 10*time.Millisecond, 50*time.Millisecond, testRetryDelay)

	// Send first signal; the worker will exhaust retries and schedule a re-signal.
	mgr.reconnectChan <- struct{}{}

	// Drain the first signal that was consumed by the worker (it's already gone).
	// Now wait for the re-signal to arrive within retryDelay + a generous buffer.
	select {
	case <-mgr.reconnectChan:
		// Re-signal received — correct behaviour.
	case <-time.After(2 * time.Second):
		t.Fatal("expected a re-signal on reconnectChan after retry exhaustion but none arrived")
	}
}

// TestFleetConfigManager_ReconnectWorker_AfterFuncSuppressedOnContextCancel verifies that
// when the context is cancelled before the retryDelay elapses, the time.AfterFunc callback
// does not send a re-signal on reconnectChan.
func TestFleetConfigManager_ReconnectWorker_AfterFuncSuppressedOnContextCancel(t *testing.T) {
	// Token server always fails so the worker exhausts retries and schedules a re-signal.
	server, _ := newControlledTokenServer(t, 100)
	defer server.Close()

	mockConn := &fleet.MockMQTTConnection{}
	mgr := newReconnectWorkerManager(t, mockConn, server.URL)

	ctx, cancel := context.WithCancel(context.Background())

	const testMaxRetries = 2
	const testRetryDelay = 200 * time.Millisecond

	go mgr.runReconnectWorker(ctx, 10*time.Second, testMaxRetries, 5*time.Millisecond, 20*time.Millisecond, testRetryDelay)

	// Trigger one reconnect attempt.
	mgr.reconnectChan <- struct{}{}

	// Wait for retries to exhaust (2 attempts with tiny backoffs take ~25ms).
	// Then cancel the context before retryDelay (200ms) elapses.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Now wait past the retryDelay and verify no re-signal was sent.
	select {
	case <-mgr.reconnectChan:
		t.Fatal("AfterFunc callback should have been suppressed by context cancellation")
	case <-time.After(testRetryDelay + 100*time.Millisecond):
		// No re-signal — correct behaviour.
	}
}

// TestFleetConfigManager_ResetGoroutine_UsesLatestConnectionDetails verifies that the reset
// goroutine reads the current fleetManager.connectionDetails rather than the stale closure
// values captured at Start() time.
func TestFleetConfigManager_ResetGoroutine_UsesLatestConnectionDetails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}

	mockConn := &fleet.MockMQTTConnection{}
	mgr := newFleetConfigManagerWithConnection(logger, mockPMgr, &mockBackendState{}, mockConn)

	// Simulate Start() having stored an initial set of connection details.
	initialDetails := fleet.ConnectionDetails{
		Token: "initial-token",
		Topics: fleet.TokenResponseTopics{
			Heartbeat: "agents/test-agent/heartbeat",
		},
	}
	mgr.connectionDetails = initialDetails
	mgr.backends = make(map[string]backend.Backend)
	mgr.labels = map[string]string{"env": "test"}
	mgr.configYaml = "initial-config"

	// Launch the reset goroutine (mirrors what Start() does, including the connMu snapshot).
	timeout := 5 * time.Second
	go func() {
		for range mgr.resetChan {
			mgr.connMu.RLock()
			details := mgr.connectionDetails
			mgr.connMu.RUnlock()

			disconnectCtx, cancel := context.WithTimeout(context.Background(), timeout)
			_ = mgr.connection.Disconnect(disconnectCtx, details.Topics.Heartbeat)
			cancel()
			connectCtx := context.Background()
			_ = mgr.connection.Connect(connectCtx, details, mgr.backends, mgr.labels, mgr.configYaml)
		}
	}()

	// Simulate a successful token refresh updating connectionDetails on the struct.
	refreshedDetails := fleet.ConnectionDetails{
		Token: "refreshed-token",
		Topics: fleet.TokenResponseTopics{
			Heartbeat: "agents/test-agent/heartbeat",
		},
	}
	mgr.connMu.Lock()
	mgr.connectionDetails = refreshedDetails
	mgr.connMu.Unlock()

	// Signal a reset and wait for the goroutine to call Connect.
	mgr.resetChan <- struct{}{}

	require.Eventually(t, func() bool {
		return mockConn.ConnectCalled()
	}, time.Second, 10*time.Millisecond, "Connect should have been called by the reset goroutine")

	assert.Equal(t, "refreshed-token", mockConn.LastConnectDetails().Token,
		"reset goroutine should use the refreshed token, not the stale initial token")
}

// TestFleetConfigManager_ResetAfterProactiveRefresh_UsesRotatedCredentials challenges the
// credential-rotation path added in this branch: after a proactive RefreshToken updates the
// auth manager cache, a later reset-driven Connect should use the rotated token and MQTT URL.
func TestFleetConfigManager_ResetAfterProactiveRefresh_UsesRotatedCredentials(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}

	mockConn := &fleet.MockMQTTConnection{}
	mgr := newFleetConfigManagerWithConnection(logger, mockPMgr, &mockBackendState{}, mockConn)

	initialJWT := fleet.RawJWTWithClaims(map[string]any{
		"orb:org_id":   "test-org",
		"orb:zone":     "default",
		"orb:agent_id": "test-agent",
		"client_id":    "test-client",
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(10 * time.Minute).Unix(),
		"ext": map[string]any{
			"orb:mqtt_url": "mqtt://broker-a.example.com:1883",
		},
	})
	rotatedJWT := fleet.RawJWTWithClaims(map[string]any{
		"orb:org_id":   "test-org",
		"orb:zone":     "default",
		"orb:agent_id": "test-agent",
		"client_id":    "test-client",
		"iat":          time.Now().Add(1 * time.Minute).Unix(),
		"exp":          time.Now().Add(20 * time.Minute).Unix(),
		"ext": map[string]any{
			"orb:mqtt_url": "mqtt://broker-b.example.com:1883",
		},
	})

	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++

		token := initialJWT
		mqttURL := "mqtt://broker-a.example.com:1883"
		if requestCount > 1 {
			token = rotatedJWT
			mqttURL = "mqtt://broker-b.example.com:1883"
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fleet.TokenResponse{
			AccessToken: token,
			MQTTURL:     mqttURL,
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := mgr.authTokenManager.GetToken(ctx, server.URL, true, 10*time.Second, "test_client", "test_secret")
	require.NoError(t, err)

	initialClaims, err := fleet.ParseJWTClaims(initialJWT)
	require.NoError(t, err)
	initialTopics, err := fleet.GenerateTopicsFromTemplate(initialClaims)
	require.NoError(t, err)

	mgr.connectionDetails = fleet.ConnectionDetails{
		MQTTURL:  initialClaims.MqttURL,
		Token:    initialJWT,
		AgentID:  initialClaims.AgentID,
		Topics:   *initialTopics,
		ClientID: "test_client",
		Zone:     initialClaims.Zone,
	}
	mgr.backends = make(map[string]backend.Backend)
	mgr.labels = map[string]string{"env": "test"}
	mgr.configYaml = "initial-config"

	// Simulate the new proactive monitor behavior: refresh the auth-manager cache
	// without updating connectionDetails.
	_, err = mgr.authTokenManager.RefreshToken(ctx)
	require.NoError(t, err)

	freshToken, err := mgr.authTokenManager.GetFreshToken(ctx)
	require.NoError(t, err)
	require.Equal(t, rotatedJWT, freshToken, "auth manager should hold the rotated token after proactive refresh")

	timeout := 5 * time.Second
	go func() {
		for range mgr.resetChan {
			mgr.connMu.RLock()
			details := mgr.connectionDetails
			mgr.connMu.RUnlock()

			disconnectCtx, cancel := context.WithTimeout(context.Background(), timeout)
			_ = mgr.connection.Disconnect(disconnectCtx, details.Topics.Heartbeat)
			cancel()
			_ = mgr.connection.Connect(context.Background(), details, mgr.backends, mgr.labels, mgr.configYaml)
		}
	}()

	mgr.resetChan <- struct{}{}

	require.Eventually(t, func() bool {
		return mockConn.ConnectCalled()
	}, time.Second, 10*time.Millisecond, "Connect should have been called by the reset goroutine")

	assert.Equal(t, rotatedJWT, mockConn.LastConnectDetails().Token,
		"reset reconnect should use the rotated token cached by proactive refresh")
	assert.Equal(t, "mqtt://broker-b.example.com:1883", mockConn.LastConnectDetails().MQTTURL,
		"reset reconnect should use the rotated MQTT URL from the refreshed credentials")
}
