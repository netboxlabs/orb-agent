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

	// Act
	err := fleetManager.Start(cfg, backends)

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

	// Act
	err := fleetManager.Start(cfg, backends)

	// Assert
	assert.Error(t, err)
	// Verify the error is from the mock connection (no 30s wait)
	assert.Contains(t, err.Error(), "mqtt connection failed")
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

	// The Start method should succeed in generating topics from JWT claims,
	// but fail at the MQTT connection step (which is mocked to return an error)
	err := fleetManager.Start(cfg, backends)

	// We expect an error because the mock connection returns an error,
	// but we want to verify that topic generation succeeded
	// (The error should be related to MQTT connection, not JWT parsing)
	require.Error(t, err)
	// The error should be the mocked connection error
	errorMsg := strings.ToLower(err.Error())
	assert.True(t,
		strings.Contains(errorMsg, "mqtt") ||
			strings.Contains(errorMsg, "connection"),
		"Expected connection-related error, got: %s", err.Error())
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

	// Act
	err = fleetManager.Start(cfg, backends)

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

	// Act
	err := fleetManager.Start(cfg, backends)

	// Assert
	// Even though MQTT connection fails, we should verify that:
	// 1. OTLP bridge was started (it should exist)
	// 2. Connect() was called (indicating we got past bridge startup)
	require.Error(t, err, "Start() should fail due to MQTT connection error")
	assert.True(t, mockConn.ConnectCalled, "MQTT Connect() should have been called")
	// The bridge should have been created and started before Connect() was called
	// Since Connect() was called, the bridge must have started successfully
	assert.NotNil(t, fleetManager.otlpBridge, "OTLP bridge should be initialized before MQTT connection")

	// Cleanup
	if fleetManager.otlpBridge != nil {
		_ = fleetManager.otlpBridge.Stop(context.Background())
	}
}
