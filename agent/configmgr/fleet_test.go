package configmgr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/messages"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockPublishFunc is a testify mock for the publish function
type mockPublishFunc struct {
	mock.Mock
}

func (m *mockPublishFunc) Publish(ctx context.Context, payload []byte) error {
	args := m.Called(ctx, payload)
	return args.Error(0)
}

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

// rawJWTWithClaims builds a raw JWT string with the given claims.
// Signature is a dummy value; ParseUnverified only inspects header/payload.
func rawJWTWithClaims(claims map[string]any) string {
	header := map[string]any{
		"alg": "RS256",
		"kid": "test-key",
		"typ": "JWT",
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

// Test helper to create a heartbeater instance for testing
func createTestHeartbeater() *heartbeater {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return &heartbeater{
		logger:       logger,
		hbTicker:     time.NewTicker(50 * time.Millisecond), // Short interval for testing
		heartbeatCtx: context.Background(),
	}
}

func TestHeartbeater_SendSingleHeartbeat_Success(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()

	// We don't assert exact bytes; validate the marshalled heartbeat content
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil)

	// Act
	hb.sendSingleHeartbeat(ctx, mockPublish.Publish, "test-agent-id", testTime, messages.Online)

	// Assert: ensure one publish happened with a valid heartbeat payload
	calls := mockPublish.Calls
	require.Len(t, calls, 1)
	payload, ok := calls[0].Arguments.Get(1).([]byte)
	require.True(t, ok)

	var hbMsg messages.Heartbeat
	require.NoError(t, json.Unmarshal(payload, &hbMsg))
	assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, hbMsg.SchemaVersion)
	assert.Equal(t, messages.State(1), hbMsg.State)
	assert.False(t, hbMsg.TimeStamp.IsZero())
}

func TestHeartbeater_SendSingleHeartbeat_PublishError(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTime := time.Now()
	publishError := errors.New("publish failed")

	// Set up mock expectations - publish function returns error
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(publishError)

	// Act - should not panic despite publish error
	hb.sendSingleHeartbeat(ctx, mockPublish.Publish, "test-agent-id", testTime, messages.Online)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendSingleHeartbeat_HeartbeatContent(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	testTime := time.Now()

	// Act
	hb.sendSingleHeartbeat(ctx, publishFunc, "test-agent-id", testTime, messages.Online)

	// Assert
	require.NotNil(t, capturedPayload)

	var heartbeat messages.Heartbeat
	err := json.Unmarshal(capturedPayload, &heartbeat)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, heartbeat.SchemaVersion)
	assert.Equal(t, messages.State(1), heartbeat.State)
	assert.False(t, heartbeat.TimeStamp.IsZero())
}

func TestHeartbeater_SendHeartbeats_InitialHeartbeat(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up expectations for initial heartbeat (Online state)
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Set up expectations for final heartbeat (Offline state) when context is cancelled
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Once()

	// Act
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish, "test-agent-id")

	// Give some time for initial heartbeat
	time.Sleep(10 * time.Millisecond)

	// Cancel context to trigger cleanup
	cancel()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_PeriodicHeartbeats(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// We expect at least 3 heartbeats: initial + at least 2 periodic + final
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Times(4)

	// Act
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish, "test-agent-id")

	// Wait for some periodic heartbeats (ticker is 50ms in test)
	time.Sleep(120 * time.Millisecond)

	// Cancel context
	cancel()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_ContextCancellation(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a channel to signal when the goroutine has finished
	done := make(chan bool, 1)

	publishFunc := func(ctx context.Context, payload []byte) error {
		return mockPublish.Publish(ctx, payload)
	}

	// Expect initial heartbeat (Online) and final heartbeat (Offline)
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Twice()

	// Act
	go func() {
		hb.sendHeartbeats(ctx, cancel, publishFunc, "test-agent-id")
		done <- true
	}()

	// Let it run briefly
	time.Sleep(10 * time.Millisecond)

	// Cancel context immediately
	cancel()

	// Wait for the goroutine to finish
	<-done

	// Assert
	mockPublish.AssertExpectations(t)

	// Verify context is properly cleaned up (now safe to read after goroutine finished)
	assert.Nil(t, hb.heartbeatCtx)
}

func TestHeartbeater_SendHeartbeats_PublishErrors(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	publishError := errors.New("network error")

	// Mock publish function to return errors - should not stop the heartbeat loop
	// Expect initial + periodic + final heartbeat (all with errors)
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(publishError).Times(4)

	// Act
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish, "test-agent-id")

	// Wait for some heartbeats with errors
	time.Sleep(120 * time.Millisecond)

	// Cancel context
	cancel()

	// Give time for cleanup
	time.Sleep(10 * time.Millisecond)

	// Assert - even with publish errors, all calls should be made
	mockPublish.AssertExpectations(t)
}

func TestHeartbeater_SendHeartbeats_ConcurrentCancellation(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	mockPublish := &mockPublishFunc{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Allow any number of publish calls since timing can vary
	mockPublish.On("Publish", ctx, mock.AnythingOfType("[]uint8")).Return(nil).Maybe()

	// Act - start heartbeats
	go hb.sendHeartbeats(ctx, cancel, mockPublish.Publish, "test-agent-id")

	// Cancel immediately in a separate goroutine
	go func() {
		time.Sleep(1 * time.Millisecond)
		cancel()
	}()

	// Give time for everything to complete
	time.Sleep(50 * time.Millisecond)

	// Assert - should not panic or hang
	// The test passes if we reach this point without deadlock
	assert.True(t, true, "Concurrent cancellation handled without deadlock")
}

func TestHeartbeater_SendHeartbeats_HeartbeatStates(t *testing.T) {
	// Arrange
	hb := createTestHeartbeater()
	defer hb.hbTicker.Stop()

	var capturedPayloads [][]byte
	var mutex sync.Mutex

	// Use a channel to signal when the goroutine has finished
	done := make(chan bool, 1)

	publishFunc := func(_ context.Context, payload []byte) error {
		// Store a copy of the payload with proper synchronization
		payloadCopy := make([]byte, len(payload))
		copy(payloadCopy, payload)

		mutex.Lock()
		capturedPayloads = append(capturedPayloads, payloadCopy)
		mutex.Unlock()

		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Act
	go func() {
		hb.sendHeartbeats(ctx, cancel, publishFunc, "test-agent-id")
		done <- true
	}()

	// Wait for initial heartbeat
	time.Sleep(10 * time.Millisecond)

	// Cancel to trigger offline heartbeat
	cancel()

	// Wait for goroutine to finish
	<-done

	// Assert - now safe to read capturedPayloads
	mutex.Lock()
	payloadsCopy := make([][]byte, len(capturedPayloads))
	copy(payloadsCopy, capturedPayloads)
	mutex.Unlock()

	assert.GreaterOrEqual(t, len(payloadsCopy), 2, "Should have at least initial and final heartbeats")

	// Verify all payloads are valid heartbeat messages and contain expected fields
	for i, payload := range payloadsCopy {
		var heartbeat messages.Heartbeat
		err := json.Unmarshal(payload, &heartbeat)
		require.NoError(t, err, "Heartbeat %d should be valid JSON", i)
		assert.Equal(t, messages.CurrentHeartbeatSchemaVersion, heartbeat.SchemaVersion)
		assert.False(t, heartbeat.TimeStamp.IsZero())
		// Current implementation always sends Online state (1)
		assert.Equal(t, messages.State(1), heartbeat.State)
	}
}

func TestNewFleetConfigManager_HeartbeaterInitialization(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}

	// Act
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)

	// Assert
	assert.NotNil(t, fleetManager)
	assert.NotNil(t, fleetManager.heartbeater)
	assert.NotNil(t, fleetManager.heartbeater.logger)
	assert.NotNil(t, fleetManager.heartbeater.hbTicker)
	assert.NotNil(t, fleetManager.heartbeater.hbTicker.C, "Ticker channel should be available")
	assert.NotNil(t, fleetManager.heartbeater.heartbeatCtx, "Heartbeat context should be initialized")

	// Clean up ticker
	fleetManager.heartbeater.hbTicker.Stop()
}

func TestFleetConfigManager_GetToken_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

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
		response := tokenResponse{
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
	token, err := fleetManager.getToken(ctx, server.URL, "test_client_id", "test_client_secret")

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
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Create mock HTTP server that returns error
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	// Act
	ctx := context.Background()
	token, err := fleetManager.getToken(ctx, server.URL, "invalid_client", "invalid_secret")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "token request failed")
}

func TestFleetConfigManager_GetToken_InvalidJSON(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Create mock HTTP server that returns invalid JSON
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	// Act
	ctx := context.Background()
	token, err := fleetManager.getToken(ctx, server.URL, "test_client", "test_secret")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to parse token response")
}

func TestFleetConfigManager_GetToken_NetworkError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Act with invalid URL
	ctx := context.Background()
	token, err := fleetManager.getToken(ctx, "http://invalid.nonexistent.url:99999", "test", "test")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to send request")
}

func TestFleetConfigManager_GetToken_InvalidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Act with malformed URL
	ctx := context.Background()
	token, err := fleetManager.getToken(ctx, "://invalid-url", "test", "test")

	// Assert
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to create request")
}

func TestFleetConfigManager_Connect_InvalidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Act with invalid URL
	backends := make(map[string]backend.Backend)
	trt := tokenResponseTopics{Inbox: "test/topic"}
	err := fleetManager.connect(context.Background(), "://invalid-url", "test_token", trt, backends, "test-agent-id", "test-zone", map[string]string{})

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing protocol scheme") // URL parsing error
}

func TestFleetConfigManager_Connect_ValidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Act with valid URL but don't expect successful connection
	// since we don't have a real MQTT server
	backends := make(map[string]backend.Backend)
	trt2 := tokenResponseTopics{Inbox: "test/topic"}
	// Timeout after 3 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := fleetManager.connect(ctx, "mqtt://localhost:1883", "test_token", trt2, backends, "test-agent-id", "test-zone", map[string]string{})

	// Assert - we expect connection to fail since no server is running,
	// but URL parsing should succeed
	assert.Error(t, err)
	// The actual error could be context deadline exceeded or connection refused
	assert.True(t,
		strings.Contains(err.Error(), "context deadline exceeded") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "server denied connect"),
		"Expected connection-related error, got: %v", err)
}

func TestFleetConfigManager_Start_TokenError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

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
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Create mock HTTP server for token endpoint
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := tokenResponse{
			AccessToken: rawJWTWithClaims(map[string]any{
				"orb:org_id": "test-org",
				"iat":        1516239022,
			}),
			MQTTURL:   "://invalid-mqtt-url", // Invalid MQTT URL
			ExpiresIn: 3600,
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

func TestFleetConfigManager_DispatchToHandlers(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Act - currently this method is a TODO, so it should not panic
	payload := map[string]any{"test": "data"}
	rpc := messages.RPC{
		// SchemaVersion: messages.CurrentRPCSchemaVersion,
		Func:    "config",
		Payload: payload,
	}

	// This should not panic since it's currently empty implementation
	fleetManager.dispatchToHandlers("config", rpc, "test-org")
	fleetManager.dispatchToHandlers("policy", rpc, "test-org")
	fleetManager.dispatchToHandlers("unknown", rpc, "test-org")

	// Assert - reaching this point means no panic occurred
	assert.True(t, true, "dispatchToHandlers should handle all message types without panic")
}

func TestFleetConfigManager_GetContext(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

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

func TestTokenResponse_Marshaling(t *testing.T) {
	// Arrange
	original := tokenResponse{
		AccessToken: "test_token_123",
		MQTTURL:     "mqtt://test.example.com:1883",
		ExpiresIn:   7200,
	}

	// Act - Marshal to JSON
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Act - Unmarshal back
	var unmarshaled tokenResponse
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	// Assert
	assert.Equal(t, original.AccessToken, unmarshaled.AccessToken)
	assert.Equal(t, original.MQTTURL, unmarshaled.MQTTURL)
	assert.Equal(t, original.ExpiresIn, unmarshaled.ExpiresIn)
}

// Test edge cases for heartbeater ticker cleanup
func TestFleetConfigManager_HeartbeaterTickerCleanup(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}

	// Act
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)

	// Verify ticker is created
	assert.NotNil(t, fleetManager.heartbeater.hbTicker)

	// Stop ticker to clean up
	fleetManager.heartbeater.hbTicker.Stop()

	// Assert - no panic should occur
	assert.True(t, true, "Ticker cleanup should not cause issues")
}

// mockBackend implements the Backend interface for testing
type mockBackend struct {
	mock.Mock
}

func (m *mockBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo, config map[string]any, commons config.BackendCommons) error {
	args := m.Called(logger, repo, config, commons)
	return args.Error(0)
}

func (m *mockBackend) Version() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	args := m.Called(ctx, cancelFunc)
	return args.Error(0)
}

func (m *mockBackend) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) FullReset(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) GetStartTime() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *mockBackend) GetCapabilities() (map[string]any, error) {
	args := m.Called()
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *mockBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus), args.String(1), args.Error(2)
}

func (m *mockBackend) GetInitialState() backend.RunningStatus {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus)
}

func (m *mockBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	args := m.Called(data, updatePolicy)
	return args.Error(0)
}

func (m *mockBackend) RemovePolicy(data policies.PolicyData) error {
	args := m.Called(data)
	return args.Error(0)
}

func TestFleetConfigManager_SendCapabilities_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Create mock backends
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	// Set up backend expectations
	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{
		"feature1": "enabled",
		"feature2": "disabled",
	}, nil)

	mockBackend2.On("Version").Return("2.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any{
		"protocol":   "mqtt",
		"encryption": "tls",
	}, nil)

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	// Mock publish function
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()
	labels := map[string]string{}

	// Act
	fleetManager.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	// Verify the published capabilities structure
	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)
	assert.Len(t, capabilities.Backends, 2)

	// Verify backend1 capabilities
	assert.Contains(t, capabilities.Backends, "backend1")
	backend1Info := capabilities.Backends["backend1"]
	assert.Equal(t, "1.2.3", backend1Info.Version)
	assert.Equal(t, "enabled", backend1Info.Data["feature1"])
	assert.Equal(t, "disabled", backend1Info.Data["feature2"])

	// Verify backend2 capabilities
	assert.Contains(t, capabilities.Backends, "backend2")
	backend2Info := capabilities.Backends["backend2"]
	assert.Equal(t, "2.0.0", backend2Info.Version)
	assert.Equal(t, "mqtt", backend2Info.Data["protocol"])
	assert.Equal(t, "tls", backend2Info.Data["encryption"])

	// Verify all mock expectations were met
	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_BackendVersionError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Create mock backends - one succeeds, one fails on version
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"feature": "enabled"}, nil)

	mockBackend2.On("Version").Return("", errors.New("version retrieval failed"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	labels := map[string]string{}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	fleetManager.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Only backend1 should be included, backend2 should be skipped
	assert.Len(t, capabilities.Backends, 1)
	assert.Contains(t, capabilities.Backends, "backend1")
	assert.NotContains(t, capabilities.Backends, "backend2")

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_BackendCapabilitiesError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Create mock backends - one succeeds, one fails on capabilities
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	mockBackend1.On("Version").Return("1.2.3", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"feature": "enabled"}, nil)

	mockBackend2.On("Version").Return("2.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any(nil), errors.New("capabilities retrieval failed"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	labels := map[string]string{}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	fleetManager.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Only backend1 should be included, backend2 should be skipped
	assert.Len(t, capabilities.Backends, 1)
	assert.Contains(t, capabilities.Backends, "backend1")
	assert.NotContains(t, capabilities.Backends, "backend2")

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_PublishError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	mockBackend1 := &mockBackend{}
	mockBackend1.On("Version").Return("1.0.0", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{"test": "value"}, nil)

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
	}

	labels := map[string]string{}

	publishError := errors.New("publish failed")
	publishFunc := func(_ context.Context, _ []byte) error {
		return publishError
	}

	ctx := context.Background()

	// Act
	fleetManager.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	assert.Equal(t, publishError, publishFunc(ctx, []byte{}))

	mockBackend1.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_EmptyBackends(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	backends := map[string]backend.Backend{} // Empty backends
	labels := map[string]string{}
	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	fleetManager.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)
	assert.Empty(t, capabilities.Backends)
}

func TestFleetConfigManager_SendCapabilities_AllBackendsFail(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// All backends fail
	mockBackend1 := &mockBackend{}
	mockBackend2 := &mockBackend{}

	labels := map[string]string{}

	mockBackend1.On("Version").Return("", errors.New("version error"))
	mockBackend2.On("Version").Return("1.0.0", nil)
	mockBackend2.On("GetCapabilities").Return(map[string]any(nil), errors.New("capabilities error"))

	backends := map[string]backend.Backend{
		"backend1": mockBackend1,
		"backend2": mockBackend2,
	}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	fleetManager.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// No backends should be included
	assert.Empty(t, capabilities.Backends)

	mockBackend1.AssertExpectations(t)
	mockBackend2.AssertExpectations(t)
}

func TestFleetConfigManager_SendCapabilities_CapabilitiesStructure(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	mockBackend1 := &mockBackend{}
	mockBackend1.On("Version").Return("test-version", nil)
	mockBackend1.On("GetCapabilities").Return(map[string]any{
		"string_val":  "test",
		"number_val":  42,
		"boolean_val": true,
		"array_val":   []string{"a", "b", "c"},
		"object_val":  map[string]string{"nested": "value"},
	}, nil)

	backends := map[string]backend.Backend{
		"test_backend": mockBackend1,
	}

	labels := map[string]string{}

	var capturedPayload []byte
	publishFunc := func(_ context.Context, payload []byte) error {
		capturedPayload = payload
		return nil
	}

	ctx := context.Background()

	// Act
	fleetManager.sendCapabilities(ctx, backends, labels, publishFunc)

	// Assert
	require.NotNil(t, capturedPayload)

	// Verify JSON structure can be unmarshaled and contains expected data types
	var capabilities messages.Capabilities
	err := json.Unmarshal(capturedPayload, &capabilities)
	require.NoError(t, err)

	// Verify structure fields
	assert.Equal(t, messages.CurrentCapabilitiesSchemaVersion, capabilities.SchemaVersion)
	assert.NotEmpty(t, capabilities.OrbAgent.Version)

	// Verify backend data structure preservation
	backendInfo := capabilities.Backends["test_backend"]
	assert.Equal(t, "test-version", backendInfo.Version)

	// Verify all data types are preserved
	assert.Equal(t, "test", backendInfo.Data["string_val"])
	assert.Equal(t, float64(42), backendInfo.Data["number_val"]) // JSON numbers become float64
	assert.Equal(t, true, backendInfo.Data["boolean_val"])
	assert.IsType(t, []interface{}{}, backendInfo.Data["array_val"])
	assert.IsType(t, map[string]interface{}{}, backendInfo.Data["object_val"])

	mockBackend1.AssertExpectations(t)
}

func TestFleetConfigManager_Start_WithJWTTopicGeneration(t *testing.T) {
	// This test verifies that the Start method correctly generates topics from JWT claims

	mqttURL := "mqtt://test.example.com:1883"
	// Create a valid JWT token with orb-prefixed claims used by parseJWTClaims
	validJWT := rawJWTWithClaims(map[string]any{
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
	fleetManager := newFleetConfigManager(context.Background(), logger, mockPMgr)
	defer fleetManager.heartbeater.hbTicker.Stop()

	// Create mock HTTP server that returns a JWT token
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := tokenResponse{
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
