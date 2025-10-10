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
	args := m.Called()
	if args.Get(0) == nil {
		return []policies.PolicyData{}, args.Error(1)
	}
	return args.Get(0).([]policies.PolicyData), args.Error(1)
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
				mockRepo := &mockPolicyRepo{}
				mockRepo.On("GetAll").Return([]policies.PolicyData{}, nil)
				m.On("GetRepo").Return(mockRepo)
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

// Test handleAgentPolicies with fullList=false
func TestMessageHandlers_handleAgentPolicies_NotFullList(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Setup mock expectations
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		return p.ID == "policy1" && p.Action == "apply"
	})).Return()

	// Create policy payload
	policies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "apply",
			ID:           "policy1",
			DatasetID:    "dataset1",
			AgentGroupID: "group1",
			Name:         "Test Policy",
			Backend:      "pktvisor",
			Format:       "yaml",
			Version:      1,
			Data:         map[string]any{},
		},
	}

	// Act
	handlers.handleAgentPolicies(policies, false)

	// Assert
	mockPMgr.AssertExpectations(t)
}

// Test handleAgentPolicies with fullList=true and policies to remove
func TestMessageHandlers_handleAgentPolicies_FullList_RemovesOldPolicies(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	handlers := NewMessaging(logger, mockPMgr)

	// Setup existing policies in repo
	existingPolicies := []policies.PolicyData{
		{
			ID:      "policy1",
			Name:    "Old Policy 1",
			Backend: "pktvisor",
		},
		{
			ID:      "policy2",
			Name:    "Old Policy 2",
			Backend: "pktvisor",
		},
	}

	// Setup mock expectations
	mockPMgr.On("GetRepo").Return(mockRepo)
	mockRepo.On("GetAll").Return(existingPolicies, nil)

	// Expect policy2 to be retrieved for removal
	mockRepo.On("Get", "policy2").Return(policies.PolicyData{
		ID:      "policy2",
		Name:    "Old Policy 2",
		Backend: "pktvisor",
	}, nil)

	// Expect policy2 to be removed (not in new list)
	mockPMgr.On("RemovePolicy", "policy2", "Old Policy 2", "pktvisor").Return(nil)

	// Expect policy1 to be applied (in new list)
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		return p.ID == "policy1" && p.Action == "apply"
	})).Return()

	// Create new policy list (only policy1, so policy2 should be removed)
	newPolicies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "apply",
			ID:           "policy1",
			DatasetID:    "dataset1",
			AgentGroupID: "group1",
			Name:         "Updated Policy 1",
			Backend:      "pktvisor",
			Format:       "yaml",
			Version:      2,
			Data:         map[string]any{},
		},
	}

	// Act
	handlers.handleAgentPolicies(newPolicies, true)

	// Assert
	mockPMgr.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

// Test handleAgentPolicies with sanitize action
func TestMessageHandlers_handleAgentPolicies_SkipsSanitizeAction(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Create policy payload with sanitize action
	policies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "sanitize",
			ID:           "policy1",
			DatasetID:    "dataset1",
			AgentGroupID: "group1",
			Name:         "Test Policy",
			Backend:      "pktvisor",
			Format:       "yaml",
			Version:      1,
			Data:         map[string]any{},
		},
	}

	// Act
	handlers.handleAgentPolicies(policies, false)

	// Assert - ManagePolicy should NOT be called for sanitize action
	mockPMgr.AssertNotCalled(t, "ManagePolicy", mock.Anything)
}

// Test handleAgentPolicies with fullList=true but GetAll fails
func TestMessageHandlers_handleAgentPolicies_FullList_GetAllFails(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	handlers := NewMessaging(logger, mockPMgr)

	// Setup mock expectations - GetAll fails
	mockPMgr.On("GetRepo").Return(mockRepo)
	mockRepo.On("GetAll").Return([]policies.PolicyData{}, assert.AnError)

	// Create new policy list
	newPolicies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "apply",
			ID:           "policy1",
			DatasetID:    "dataset1",
			AgentGroupID: "group1",
			Name:         "Test Policy",
			Backend:      "pktvisor",
			Format:       "yaml",
			Version:      1,
			Data:         map[string]any{},
		},
	}

	// Act
	handlers.handleAgentPolicies(newPolicies, true)

	// Assert - should return early, not call ManagePolicy
	mockPMgr.AssertNotCalled(t, "ManagePolicy", mock.Anything)
	mockPMgr.AssertNotCalled(t, "RemovePolicy", mock.Anything, mock.Anything, mock.Anything)
}

// Test handleAgentGroupRemoval with policy that has no remaining groups
func TestMessageHandlers_handleAgentGroupRemoval_RemovesPolicyWhenNoGroupsRemain(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	handlers := NewMessaging(logger, mockPMgr)

	unsubscribedTopics := []string{}
	mockUnsubscribeFromTopic := func(topic string) error {
		unsubscribedTopics = append(unsubscribedTopics, topic)
		return nil
	}

	// Setup existing policies with only the group being removed
	existingPolicies := []policies.PolicyData{
		{
			ID:       "policy1",
			Name:     "Test Policy",
			Backend:  "pktvisor",
			GroupIDs: map[string]bool{"group1": true}, // Only this group
		},
	}

	// Setup mock expectations
	mockPMgr.On("GetRepo").Return(mockRepo)
	mockRepo.On("GetAll").Return(existingPolicies, nil)
	mockPMgr.On("RemovePolicy", "policy1", "Test Policy", "pktvisor").Return(nil)

	// Create group removal payload
	groupRemoval := messages.GroupRemovedRPCPayload{
		AgentGroupID: "group1",
		Datasets:     []string{"dataset1"},
	}

	// Act
	handlers.handleAgentGroupRemoval(groupRemoval, mockUnsubscribeFromTopic)

	// Assert
	assert.Equal(t, []string{"group1"}, unsubscribedTopics)
	mockPMgr.AssertExpectations(t)
}

// Test handleAgentGroupRemoval with policy that has remaining groups
func TestMessageHandlers_handleAgentGroupRemoval_RemovesDatasetsWhenGroupsRemain(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	handlers := NewMessaging(logger, mockPMgr)

	unsubscribedTopics := []string{}
	mockUnsubscribeFromTopic := func(topic string) error {
		unsubscribedTopics = append(unsubscribedTopics, topic)
		return nil
	}

	// Setup backend registry for testing
	// Note: This test assumes backend.HaveBackend and backend.GetBackend work
	// In real scenario, you'd need to register a backend first

	// Setup existing policies with multiple groups
	existingPolicies := []policies.PolicyData{
		{
			ID:      "policy1",
			Name:    "Test Policy",
			Backend: "pktvisor",
			GroupIDs: map[string]bool{
				"group1": true,
				"group2": true, // Has another group
			},
		},
	}

	// Setup mock expectations
	mockPMgr.On("GetRepo").Return(mockRepo)
	mockRepo.On("GetAll").Return(existingPolicies, nil)
	mockPMgr.On("RemovePolicyDataset", "policy1", "dataset1", mock.Anything).Return()
	mockPMgr.On("RemovePolicyDataset", "policy1", "dataset2", mock.Anything).Return()

	// Create group removal payload
	groupRemoval := messages.GroupRemovedRPCPayload{
		AgentGroupID: "group1",
		Datasets:     []string{"dataset1", "dataset2"},
	}

	// Act
	handlers.handleAgentGroupRemoval(groupRemoval, mockUnsubscribeFromTopic)

	// Assert
	assert.Equal(t, []string{"group1"}, unsubscribedTopics)
	// Should NOT call RemovePolicy since group2 remains
	mockPMgr.AssertNotCalled(t, "RemovePolicy", mock.Anything, mock.Anything, mock.Anything)
}

// Test handleAgentGroupRemoval when unsubscribe fails
func TestMessageHandlers_handleAgentGroupRemoval_UnsubscribeFails(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	mockUnsubscribeFromTopic := func(_ string) error {
		return assert.AnError
	}

	// Create group removal payload
	groupRemoval := messages.GroupRemovedRPCPayload{
		AgentGroupID: "group1",
		Datasets:     []string{"dataset1"},
	}

	// Act
	handlers.handleAgentGroupRemoval(groupRemoval, mockUnsubscribeFromTopic)

	// Assert - should return early without calling GetRepo
	mockPMgr.AssertNotCalled(t, "GetRepo")
}

// Test DispatchToHandlers with invalid JSON
func TestMessageHandlers_DispatchToHandlers_InvalidJSON(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	invalidPayload := []byte("invalid json {")

	// Act
	ctx := context.Background()
	err := handlers.DispatchToHandlers(ctx, invalidPayload, "org123", "agent123", TopicActions{
		Subscribe:   func(_ string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(_ string) error { return nil },
	})

	// Assert
	assert.Error(t, err)
}

// Test DispatchToHandlers with missing Func field
func TestMessageHandlers_DispatchToHandlers_MissingFunc(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Create RPC with empty Func
	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "", // Empty func
		Payload:       map[string]any{},
	}
	payload, _ := json.Marshal(rpc)

	// Act
	ctx := context.Background()
	err := handlers.DispatchToHandlers(ctx, payload, "org123", "agent123", TopicActions{
		Subscribe:   func(_ string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(_ string) error { return nil },
	})

	// Assert
	assert.Error(t, err)
	assert.Equal(t, messages.ErrSchemaMalformed, err)
}

// Test DispatchToHandlers with nil Payload
func TestMessageHandlers_DispatchToHandlers_NilPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Create RPC with nil Payload
	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "test_func",
		Payload:       nil, // Nil payload
	}
	payload, _ := json.Marshal(rpc)

	// Act
	ctx := context.Background()
	err := handlers.DispatchToHandlers(ctx, payload, "org123", "agent123", TopicActions{
		Subscribe:   func(_ string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(_ string) error { return nil },
	})

	// Assert
	assert.Error(t, err)
	assert.Equal(t, messages.ErrSchemaMalformed, err)
}

// Test DispatchToHandlers with malformed group_membership payload
func TestMessageHandlers_DispatchToHandlers_MalformedGroupMembershipPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Create malformed payload - using string instead of proper structure
	malformedPayload := []byte(`{"schema_version":"1.0","func":"group_membership","payload":"not_a_valid_structure"}`)

	// Act
	ctx := context.Background()
	err := handlers.DispatchToHandlers(ctx, malformedPayload, "org123", "agent123", TopicActions{
		Subscribe:   func(_ string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(_ string) error { return nil },
	})

	// Assert
	assert.Error(t, err)
}

// Test DispatchToHandlers with malformed agent_policy payload
func TestMessageHandlers_DispatchToHandlers_MalformedAgentPolicyPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Create malformed payload
	malformedPayload := []byte(`{"schema_version":"1.0","func":"agent_policy","payload":"not_an_array"}`)

	// Act
	ctx := context.Background()
	err := handlers.DispatchToHandlers(ctx, malformedPayload, "org123", "agent123", TopicActions{
		Subscribe:   func(_ string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(_ string) error { return nil },
	})

	// Assert
	assert.Error(t, err)
}

// Test DispatchToHandlers with malformed group_removed payload
func TestMessageHandlers_DispatchToHandlers_MalformedGroupRemovedPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	handlers := NewMessaging(logger, mockPMgr)

	// Create malformed payload
	malformedPayload := []byte(`{"schema_version":"1.0","func":"group_removed","payload":"not_a_structure"}`)

	// Act
	ctx := context.Background()
	err := handlers.DispatchToHandlers(ctx, malformedPayload, "org123", "agent123", TopicActions{
		Subscribe:   func(_ string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(_ string) error { return nil },
	})

	// Assert
	assert.Error(t, err)
}
