package configmgr

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
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
	return args.Get(0).(policies.PolicyRepo)
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

func TestFleetConfigManager_Start_TokenError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
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
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

	// Create mock HTTP server for token endpoint
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := fleet.TokenResponse{
			AccessToken: "test_access_token",
			MQTTURL:     "://invalid-mqtt-url", // Invalid MQTT URL
			ExpiresIn:   3600,
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     server.URL,
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
	fleetManager := newFleetConfigManager(logger, mockPMgr, &mockBackendState{})

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

	// Create test config
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{
				Sources: config.Sources{
					Fleet: config.FleetManager{
						TokenURL:     server.URL,
						SkipTLS:      true,
						ClientID:     "test_client_id",
						ClientSecret: "test_client_secret",
					},
				},
			},
		},
	}

	// Mock backends
	backends := make(map[string]backend.Backend)

	// Since we can't easily mock the MQTT connection in this test,
	// we expect the Start method to fail at the MQTT connection step,
	// but succeed in generating topics from JWT claims
	err := fleetManager.Start(cfg, backends)

	// We expect an error because we can't actually connect to MQTT,
	// but we want to verify that topic generation succeeded
	// (The error should be related to MQTT connection, not JWT parsing)
	require.Error(t, err)
	// The error could be connection-related (mqtt, tcp, timeout, etc.)
	errorMsg := strings.ToLower(err.Error())
	assert.True(t,
		strings.Contains(errorMsg, "mqtt") ||
			strings.Contains(errorMsg, "connection") ||
			strings.Contains(errorMsg, "timeout") ||
			strings.Contains(errorMsg, "deadline"),
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
			wantSecret:   "******",
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
					strings.Contains(result, "client_secret: '******'") ||
						strings.Contains(result, "client_secret: \"******\"") ||
						strings.Contains(result, "client_secret: ******"),
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
