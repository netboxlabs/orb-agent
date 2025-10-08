package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockPolicyManager implements the PolicyManager interface for testing
type mockPolicyManager struct {
	mock.Mock
}

func (m *mockPolicyManager) ManagePolicy(payload config.PolicyPayload) {
	m.Called(payload)
}

func (m *mockPolicyManager) RemovePolicyDataset(policyID string, datasetID string, be backend.Backend) {
	m.Called(policyID, datasetID, be)
}

func (m *mockPolicyManager) GetPolicyState() ([]policies.PolicyData, error) {
	args := m.Called()
	return args.Get(0).([]policies.PolicyData), args.Error(1)
}

func (m *mockPolicyManager) GetRepo() policies.PolicyRepo {
	args := m.Called()
	return args.Get(0).(policies.PolicyRepo)
}

func (m *mockPolicyManager) ApplyBackendPolicies(be backend.Backend) error {
	args := m.Called(be)
	return args.Error(0)
}

func (m *mockPolicyManager) RemoveBackendPolicies(be backend.Backend, permanently bool) error {
	args := m.Called(be, permanently)
	return args.Error(0)
}

func (m *mockPolicyManager) RemovePolicy(policyID string, policyName string, beName string) error {
	args := m.Called(policyID, policyName, beName)
	return args.Error(0)
}

func TestMessageHandlers_DispatchToHandlers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}

	tests := []struct {
		name           string
		messageType    string
		rpc            messages.RPC
		orgID          string
		expectedTopics []string
		expectedError  bool
	}{
		{
			name:        "group_membership message type",
			messageType: "group_membership",
			rpc: messages.RPC{
				SchemaVersion: "1.0",
				Func:          "group_membership",
				Payload: map[string]any{
					"full_list": true,
					"groups": []map[string]any{
						{"group_id": "group1", "name": "Group 1"},
						{"group_id": "group2", "name": "Group 2"},
					},
				},
			},
			orgID:          "org123",
			expectedTopics: []string{"orgs/org123/groups/group1", "orgs/org123/groups/group2"},
			expectedError:  false,
		},
		{
			name:        "unknown message type",
			messageType: "unknown_type",
			rpc: messages.RPC{
				SchemaVersion: "1.0",
				Func:          "unknown_func",
				Payload:       map[string]any{},
			},
			orgID:          "org123",
			expectedTopics: []string{},
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset subscribed topics for each test
			subscribedTopics = []string{}
			agentID := "agent123"
			mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
				return nil
			}
			// Act
			handlers.DispatchToHandlers(tt.messageType, tt.rpc, tt.orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

			// Assert
			assert.Equal(t, tt.expectedTopics, subscribedTopics)
		})
	}
}

func TestMessageHandlers_handleGroupMemberships_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}
	agentID := "agent123"
	orgID := "org123"
	groupMemberships := messages.GroupMemberships{
		FullList: true,
		Groups: []messages.GroupMembership{
			{GroupID: "group1", Name: "Group 1"},
			{GroupID: "group2", Name: "Group 2"},
		},
	}

	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       groupMemberships,
	}

	// Act
	handlers.handleGroupMemberships(rpc, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert
	expectedTopics := []string{"orgs/org123/groups/group1", "orgs/org123/groups/group2"}
	assert.Equal(t, expectedTopics, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_InvalidPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}
	agentID := "agent123"
	orgID := "org123"
	// Create an RPC with invalid payload that can't be unmarshaled to GroupMemberships
	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       "invalid_payload_string",
	}

	// Act - This should not panic, just log an error
	handlers.handleGroupMemberships(rpc, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert - should not subscribe to any topics due to invalid payload
	assert.Empty(t, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_EmptyGroups(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}
	agentID := "agent123"
	orgID := "org123"
	groupMemberships := messages.GroupMemberships{
		FullList: true,
		Groups:   []messages.GroupMembership{}, // Empty groups
	}

	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       groupMemberships,
	}

	// Act
	handlers.handleGroupMemberships(rpc, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert - should not subscribe to any topics due to empty groups
	assert.Empty(t, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_JSONMarshalError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}
	agentID := "agent123"
	orgID := "org123"
	// Create an RPC with payload that can't be marshaled (e.g., function)
	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       func() {}, // Functions can't be marshaled to JSON
	}

	// Act
	handlers.handleGroupMemberships(rpc, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert - should not subscribe to any topics due to JSON marshal error
	assert.Empty(t, subscribedTopics)
}

func TestGroupTopic(t *testing.T) {
	tests := []struct {
		name     string
		orgID    string
		groupID  string
		expected string
	}{
		{
			name:     "valid org and group IDs",
			orgID:    "org123",
			groupID:  "group456",
			expected: "orgs/org123/groups/group456",
		},
		{
			name:     "empty org ID",
			orgID:    "",
			groupID:  "group456",
			expected: "orgs//groups/group456",
		},
		{
			name:     "empty group ID",
			orgID:    "org123",
			groupID:  "",
			expected: "orgs/org123/groups/",
		},
		{
			name:     "both empty",
			orgID:    "",
			groupID:  "",
			expected: "orgs//groups/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := groupTopic(tt.orgID, tt.groupID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMessageHandlers_handleGroupMemberships_ComplexPayload(t *testing.T) {
	// Test with a more complex payload structure
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}

	agentID := "agent123"
	orgID := "org123"
	// Create a complex payload with nested structures
	complexPayload := map[string]any{
		"full_list": true,
		"groups": []map[string]any{
			{
				"group_id": "group1",
				"name":     "Group 1",
				"metadata": map[string]any{
					"description": "Test group 1",
					"tags":        []string{"tag1", "tag2"},
				},
			},
			{
				"group_id": "group2",
				"name":     "Group 2",
				"metadata": map[string]any{
					"description": "Test group 2",
					"tags":        []string{"tag3", "tag4"},
				},
			},
		},
	}

	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       complexPayload,
	}

	// Act
	handlers.handleGroupMemberships(rpc, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert
	expectedTopics := []string{"orgs/org123/groups/group1", "orgs/org123/groups/group2"}
	assert.Equal(t, expectedTopics, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_SendsAgentPoliciesRequest(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}

	// Track published messages
	publishedMessages := []struct {
		topic   string
		payload []byte
	}{}
	mockPublishToTopic := func(_ context.Context, topic string, payload []byte) error {
		publishedMessages = append(publishedMessages, struct {
			topic   string
			payload []byte
		}{topic, payload})
		return nil
	}

	agentID := "agent123"
	orgID := "org123"
	groupMemberships := messages.GroupMemberships{
		FullList: true,
		Groups: []messages.GroupMembership{
			{GroupID: "group1", Name: "Group 1"},
			{GroupID: "group2", Name: "Group 2"},
		},
	}

	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       groupMemberships,
	}

	// Act
	handlers.handleGroupMemberships(rpc, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert
	expectedTopics := []string{"orgs/org123/groups/group1", "orgs/org123/groups/group2"}
	assert.Equal(t, expectedTopics, subscribedTopics)

	// Verify that an agent policies request was published
	assert.Len(t, publishedMessages, 1, "Expected exactly one published message")

	publishedMsg := publishedMessages[0]
	expectedTopic := "agents/agent123/outbox"
	assert.Equal(t, expectedTopic, publishedMsg.topic, "Expected agent policies request to be published to agent outbox topic")

	// Verify the payload structure
	var rpcPayload messages.RPC
	err := json.Unmarshal(publishedMsg.payload, &rpcPayload)
	assert.NoError(t, err, "Published payload should be valid JSON RPC")
	assert.Equal(t, "agent_policies_req", rpcPayload.Func, "Expected RPC function to be 'agent_policies_req'")

	// Verify the payload is a SendAgentPoliciesRequest
	payloadBytes, err := json.Marshal(rpcPayload.Payload)
	assert.NoError(t, err, "RPC payload should be marshallable")

	var agentPoliciesReq messages.SendAgentPoliciesRequest
	err = json.Unmarshal(payloadBytes, &agentPoliciesReq)
	assert.NoError(t, err, "RPC payload should be a SendAgentPoliciesRequest")
}

func TestNewMessageHandlers(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}

	// Act
	handlers := NewMessaging(logger, mockPMgr)

	// Assert
	assert.NotNil(t, handlers)
	assert.Equal(t, logger, handlers.logger)
	assert.Equal(t, mockPMgr, handlers.policyManager)
}
