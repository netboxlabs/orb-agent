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

// mockPolicyRepo implements the PolicyRepo interface for testing
type mockPolicyRepo struct {
	mock.Mock
}

func (m *mockPolicyRepo) Exists(policyID string) bool {
	args := m.Called(policyID)
	return args.Bool(0)
}

func (m *mockPolicyRepo) Get(policyID string) (policies.PolicyData, error) {
	args := m.Called(policyID)
	return args.Get(0).(policies.PolicyData), args.Error(1)
}

func (m *mockPolicyRepo) Remove(policyID string) error {
	args := m.Called(policyID)
	return args.Error(0)
}

func (m *mockPolicyRepo) Update(data policies.PolicyData) error {
	args := m.Called(data)
	return args.Error(0)
}

func (m *mockPolicyRepo) GetAll() ([]policies.PolicyData, error) {
	// Return empty slice for basic mocking
	return []policies.PolicyData{}, nil
}

func (m *mockPolicyRepo) GetByName(policyName string) (policies.PolicyData, error) {
	args := m.Called(policyName)
	return args.Get(0).(policies.PolicyData), args.Error(1)
}

func (m *mockPolicyRepo) EnsureDataset(policyID string, datasetID string) error {
	args := m.Called(policyID, datasetID)
	return args.Error(0)
}

func (m *mockPolicyRepo) RemoveDataset(policyID string, datasetID string) (bool, error) {
	args := m.Called(policyID, datasetID)
	return args.Bool(0), args.Error(1)
}

func (m *mockPolicyRepo) EnsureGroupID(policyID string, agentGroupID string) error {
	args := m.Called(policyID, agentGroupID)
	return args.Error(0)
}

func TestMessageHandlers_DispatchToHandlers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}

	tests := []struct {
		name                  string
		messageType           string
		rpc                   messages.RPC
		orgID                 string
		expectedTopics        []string
		expectedUnsubscribe   []string
		setupMocks            func(*mockPolicyManager)
		expectedError         bool
		expectedPolicyMgrCall bool
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
			setupMocks: func(_ *mockPolicyManager) {
				// No policy manager calls expected for group membership
			},
			expectedError:         false,
			expectedPolicyMgrCall: false,
		},
		{
			name:        "agent_policy message type",
			messageType: "agent_policy",
			rpc: messages.RPC{
				SchemaVersion: "1.0",
				Func:          "agent_policy",
				Payload: []any{
					map[string]any{
						"action":         "apply",
						"id":             "policy1",
						"dataset_id":     "dataset1",
						"agent_group_id": "group1",
						"name":           "Test Policy",
						"backend":        "pktvisor",
						"format":         "yaml",
						"version":        int32(1),
						"data":           map[string]any{},
					},
				},
			},
			orgID:          "org123",
			expectedTopics: []string{},
			setupMocks: func(m *mockPolicyManager) {
				m.On("ManagePolicy", mock.Anything).Return()
			},
			expectedError:         false,
			expectedPolicyMgrCall: true,
		},
		{
			name:        "group_removed message type",
			messageType: "group_removed",
			rpc: messages.RPC{
				SchemaVersion: "1.0",
				Func:          "group_removed",
				Payload: map[string]any{
					"agent_group_id": "group1",
					"datasets":       []any{"dataset1", "dataset2"},
				},
			},
			orgID:               "org123",
			expectedTopics:      []string{},
			expectedUnsubscribe: []string{"group1"},
			setupMocks: func(m *mockPolicyManager) {
				m.On("GetRepo").Return(&mockPolicyRepo{})
			},
			expectedError:         false,
			expectedPolicyMgrCall: true,
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
			setupMocks: func(_ *mockPolicyManager) {
				// No policy manager calls expected
			},
			expectedError:         false,
			expectedPolicyMgrCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset subscribed topics for each test
			subscribedTopics = []string{}
			unsubscribedTopics := []string{}

			// Create a fresh mock policy manager for each test
			mockPMgr := &mockPolicyManager{}
			if tt.setupMocks != nil {
				tt.setupMocks(mockPMgr)
			}
			handlers := NewMessaging(logger, mockPMgr)

			agentID := "agent123"
			mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
				return nil
			}
			mockUnsubscribeFromTopic := func(topic string) error {
				unsubscribedTopics = append(unsubscribedTopics, topic)
				return nil
			}
			// Marshal RPC to bytes
			payload, err := json.Marshal(tt.rpc)
			assert.NoError(t, err)

			// Act
			ctx := context.Background()
			err = handlers.DispatchToHandlers(ctx, payload, tt.orgID, agentID, TopicActions{
				Subscribe:   mockSubscribeToTopic,
				Publish:     mockPublishToTopic,
				Unsubscribe: mockUnsubscribeFromTopic,
			})

			// Assert
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedTopics, subscribedTopics)
			if tt.expectedUnsubscribe != nil {
				assert.Equal(t, tt.expectedUnsubscribe, unsubscribedTopics)
			}
			if tt.expectedPolicyMgrCall {
				mockPMgr.AssertExpectations(t)
			}
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
	groupMemberships := messages.GroupMembershipRPCPayload{
		FullList: true,
		Groups: []messages.GroupMembershipData{
			{GroupID: "group1", Name: "Group 1"},
			{GroupID: "group2", Name: "Group 2"},
		},
	}

	// Act
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

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
	// Create an invalid payload - empty groups is the closest we can get to testing invalid data
	// since handleGroupMemberships expects a typed GroupMembershipRPCPayload struct
	groupMemberships := messages.GroupMembershipRPCPayload{
		FullList: false,
		Groups:   []messages.GroupMembershipData{},
	}

	// Act - This should not panic, just handle gracefully
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert - should not subscribe to any topics due to empty groups
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
	groupMemberships := messages.GroupMembershipRPCPayload{
		FullList: true,
		Groups:   []messages.GroupMembershipData{}, // Empty groups
	}

	// Act
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

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
	// Create a minimal payload - this test is now similar to EmptyGroups test
	// since handleGroupMemberships now accepts typed struct
	groupMemberships := messages.GroupMembershipRPCPayload{
		FullList: false,
		Groups:   []messages.GroupMembershipData{},
	}

	// Act
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert - should not subscribe to any topics due to empty groups
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
	groupMemberships := messages.GroupMembershipRPCPayload{
		FullList: true,
		Groups: []messages.GroupMembershipData{
			{GroupID: "group1", Name: "Group 1"},
			{GroupID: "group2", Name: "Group 2"},
		},
	}

	// Act
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

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
	groupMemberships := messages.GroupMembershipRPCPayload{
		FullList: true,
		Groups: []messages.GroupMembershipData{
			{GroupID: "group1", Name: "Group 1"},
			{GroupID: "group2", Name: "Group 2"},
		},
	}

	// Act
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, mockSubscribeToTopic, mockPublishToTopic)

	// Assert
	expectedTopics := []string{"orgs/org123/groups/group1", "orgs/org123/groups/group2"}
	assert.Equal(t, expectedTopics, subscribedTopics)

	// Verify that an agent policies request was published
	assert.Len(t, publishedMessages, 1, "Expected exactly one published message")

	publishedMsg := publishedMessages[0]
	expectedTopic := "orgs/org123/agents/agent123/outbox"
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
