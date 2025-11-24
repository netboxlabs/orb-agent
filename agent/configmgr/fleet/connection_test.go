package fleet

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
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
	backendState map[string]*backend.State
}

func (m *mockBackendState) Get() map[string]*backend.State {
	if m.backendState == nil {
		return map[string]*backend.State{}
	}
	return m.backendState
}

func TestFleetConfigManager_Connect_InvalidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Act with invalid URL
	backends := make(map[string]backend.Backend)
	trt := TokenResponseTopics{Inbox: "test/topic"}
	err := connection.Connect(
		context.Background(),
		ConnectionDetails{MQTTURL: "://invalid-url", Token: "test_token", AgentID: "test-agent-id", Topics: trt, ClientID: "test-agent-id", Zone: "test-zone"},
		backends,
		map[string]string{},
		"",
	)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing protocol scheme") // URL parsing error
}

func TestFleetConfigManager_Connect_ValidURL(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManagerForFleet{}
	resetChan := make(chan struct{}, 1)
	reconnectChan := make(chan struct{}, 1)
	connection := NewMQTTConnection(logger, mockPMgr, resetChan, reconnectChan, &mockBackendState{})

	// Act with valid URL but don't expect successful connection
	// since we don't have a real MQTT server
	backends := make(map[string]backend.Backend)
	trt2 := TokenResponseTopics{Inbox: "test/topic"}
	// Timeout after 100ms for faster test execution (connection will fail quickly)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := connection.Connect(ctx,
		ConnectionDetails{MQTTURL: "mqtt://localhost:1883", Token: "test_token", AgentID: "test-agent-id", Topics: trt2, ClientID: "test-agent-id", Zone: "test-zone"},
		backends,
		map[string]string{},
		"",
	)

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
