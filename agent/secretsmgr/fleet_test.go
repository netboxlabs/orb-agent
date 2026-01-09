package secretsmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

func TestFleetSecretsManager_processString(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("no fleet reference", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(1)})
		fm.ctx = ctx

		result, err := fm.processString("plain text", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "plain text", result)
	})

	t.Run("valid fleet reference", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(5)})
		fm.ctx = ctx
		fm.requestTopic = "test/request"
		fm.responseTopic = "test/response"
		fm.updatedTopic = "test/updated"

		// Create a mock publisher that simulates async responses
		mockPub := &asyncMockPublisher{
			fm: fm,
			responseSecrets: []messages.SecretValue{
				{
					Path:    "orb/agents/database/password",
					Value:   "secretvalue",
					Version: 1,
				},
			},
		}
		fm.publisher = mockPub
		fm.subscriber = &mockSubscriber{}

		result, err := fm.processString("${fleet://orb/agents/database/password}", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "secretvalue", result)
	})

	t.Run("cached secret", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(1)})
		fm.ctx = ctx
		// Pre-cache a secret
		fm.usedVars["orb/agents/cached/secret"] = fleetCachedSecret{
			Value:     "cachedvalue",
			Version:   1,
			policyIDs: map[string]bool{"policy1": true},
		}

		result, err := fm.processString("${fleet://orb/agents/cached/secret}", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "cachedvalue", result)
	})

	t.Run("malformed reference", func(t *testing.T) {
		fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{Timeout: intPtr(1)})
		fm.ctx = ctx

		result, err := fm.processString("${fleet:/malformed}", "policy1")
		assert.NoError(t, err)
		assert.Equal(t, "${fleet:/malformed}", result)
	})
}

func TestFleetSecretsManager_handleResponse(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{})
	fm.pendingReqs = make(map[string]chan *messages.SecretResponseMsg)

	requestID := uuid.New().String()
	responseCh := make(chan *messages.SecretResponseMsg, 1)
	fm.pendingReqs[requestID] = responseCh

	response := messages.SecretResponseMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		RequestID:     requestID,
		Timestamp:     time.Now(),
		Status:        "success",
		Secrets: []messages.SecretValue{
			{
				Path:    "test/path",
				Value:   "testvalue",
				Version: 1,
			},
		},
	}

	payload, err := json.Marshal(response)
	require.NoError(t, err)

	err = fm.handleResponse(payload)
	assert.NoError(t, err)

	// Check that response was sent to channel
	select {
	case received := <-responseCh:
		assert.Equal(t, requestID, received.RequestID)
		assert.Equal(t, "success", received.Status)
		assert.Len(t, received.Secrets, 1)
		assert.Equal(t, "testvalue", received.Secrets[0].Value)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}

func TestFleetSecretsManager_handleUpdateNotification(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{})
	fm.usedVars = make(map[string]fleetCachedSecret)
	fm.usedVars["test/path"] = fleetCachedSecret{
		Value:     "oldvalue",
		Version:   1,
		policyIDs: map[string]bool{"policy1": true},
	}

	var callbackCalled bool
	var callbackPolicyIDs map[string]bool
	fm.callback = func(policyIDs map[string]bool) {
		callbackCalled = true
		callbackPolicyIDs = policyIDs
	}

	notification := messages.SecretUpdateNotificationMsg{
		SchemaVersion: messages.CurrentSecretsSchemaVersion,
		Timestamp:     time.Now(),
		Updates: []messages.SecretUpdate{
			{
				Path:     "test/path",
				Version:  2,
				Contexts: []string{"policy1"},
			},
		},
	}

	payload, err := json.Marshal(notification)
	require.NoError(t, err)

	// Note: This test doesn't fully test the update flow since requestSecret
	// requires a real MQTT connection. But we can test the notification parsing.
	// handleUpdateNotification logs errors from requestSecret but returns nil
	err = fm.handleUpdateNotification(payload)
	assert.NoError(t, err) // Function returns nil even when requestSecret fails (it logs the error)

	// Verify the callback was called with the policy marked as failed (false)
	assert.True(t, callbackCalled)
	assert.Contains(t, callbackPolicyIDs, "policy1")
	assert.False(t, callbackPolicyIDs["policy1"]) // false because requestSecret failed
}

func TestNewFleetSecretsManager(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name         string
		config       config.FleetSecretsManager
		expectedType string
	}{
		{
			name: "with timeout",
			config: config.FleetSecretsManager{
				Timeout: intPtr(60),
			},
			expectedType: "*secretsmgr.FleetSecretsManager",
		},
		{
			name:         "without timeout",
			config:       config.FleetSecretsManager{},
			expectedType: "*secretsmgr.FleetSecretsManager",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewFleetSecretsManager(logger, tt.config)
			assert.NotNil(t, manager)
			assert.Equal(t, tt.expectedType, fmt.Sprintf("%T", manager))
		})
	}
}

func TestFleetSecretsManager_RegisterUpdatePoliciesCallback(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	fm := NewFleetSecretsManager(logger, config.FleetSecretsManager{})

	called := false
	callback := func(_ map[string]bool) {
		called = true
	}

	fm.RegisterUpdatePoliciesCallback(callback)
	assert.NotNil(t, fm.callback)

	// Manually call the callback to verify it works
	fm.callback(map[string]bool{"policy1": true})
	assert.True(t, called)
}

// Helper functions and mocks

// asyncMockPublisher simulates async MQTT responses for testing
type asyncMockPublisher struct {
	fm              *FleetSecretsManager
	responseSecrets []messages.SecretValue
}

func (m *asyncMockPublisher) Publish(_ context.Context, _ string, payload []byte) error {
	// Parse the request to get the request ID
	var req messages.SecretRequestMsg
	if err := json.Unmarshal(payload, &req); err != nil {
		return err
	}

	// Simulate async response in a goroutine
	go func() {
		time.Sleep(10 * time.Millisecond) // Small delay to simulate network

		response := messages.SecretResponseMsg{
			SchemaVersion: messages.CurrentSecretsSchemaVersion,
			RequestID:     req.RequestID,
			Timestamp:     time.Now(),
			Status:        "success",
			Secrets:       m.responseSecrets,
		}

		responsePayload, _ := json.Marshal(response)
		_ = m.fm.handleResponse(responsePayload)
	}()

	return nil
}

type mockSubscriber struct{}

func (m *mockSubscriber) Subscribe(_ context.Context, _ *paho.Subscribe) error {
	return nil
}

func intPtr(i int) *int {
	return &i
}
