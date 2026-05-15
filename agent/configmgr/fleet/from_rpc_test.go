package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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

func (m *mockPolicyRepo) UpdateRuns(policyName string, runs []policies.RunData) error {
	args := m.Called(policyName, runs)
	return args.Error(0)
}

func (m *mockPolicyRepo) FailNonTerminalRuns(reason string) error {
	args := m.Called(reason)
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
				m.On("GetPolicyState").Return([]policies.PolicyData{}, nil)
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
			name:        "dataset_removed message type",
			messageType: "dataset_removed",
			rpc: messages.RPC{
				SchemaVersion: "1.0",
				Func:          "dataset_removed",
				Payload: map[string]any{
					"dataset_id": "dataset1",
					"policy_id":  "policy1",
				},
			},
			orgID:          "org123",
			expectedTopics: []string{},
			setupMocks: func(m *mockPolicyManager) {
				// Register a test backend if not already registered
				if !backend.HaveBackend("test_backend_dispatch") {
					mockBe := &mockBackend{}
					backend.Register("test_backend_dispatch", mockBe)
				}
				mockRepo := &mockPolicyRepo{}
				mockRepo.On("Get", "policy1").Return(policies.PolicyData{
					ID:      "policy1",
					Backend: "test_backend_dispatch",
				}, nil)
				m.On("GetRepo").Return(mockRepo)
				m.On("RemovePolicyDataset", "policy1", "dataset1", mock.Anything).Return()
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
			resetChan := make(chan struct{}, 1)
			groupManager := newGroupManager()
			handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}
	mockUnsubscribeFromTopic := func(_ string) error {
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
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, TopicActions{
		Subscribe:   mockSubscribeToTopic,
		Publish:     mockPublishToTopic,
		Unsubscribe: mockUnsubscribeFromTopic,
	})

	// Assert
	expectedTopics := []string{"orgs/org123/groups/group1", "orgs/org123/groups/group2"}
	assert.Equal(t, expectedTopics, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_InvalidPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}
	mockUnsubscribeFromTopic := func(_ string) error {
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
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, TopicActions{
		Subscribe:   mockSubscribeToTopic,
		Publish:     mockPublishToTopic,
		Unsubscribe: mockUnsubscribeFromTopic,
	})

	// Assert - should not subscribe to any topics due to empty groups
	assert.Empty(t, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_EmptyGroups(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	mockUnsubscribeFromTopic := func(_ string) error {
		return nil
	}
	// Act
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, TopicActions{
		Subscribe:   mockSubscribeToTopic,
		Publish:     mockPublishToTopic,
		Unsubscribe: mockUnsubscribeFromTopic,
	})

	// Assert - should not subscribe to any topics due to empty groups
	assert.Empty(t, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_JSONMarshalError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	mockUnsubscribeFromTopic := func(_ string) error {
		return nil
	}
	// Act
	ctx := context.Background()
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, TopicActions{
		Subscribe:   mockSubscribeToTopic,
		Publish:     mockPublishToTopic,
		Unsubscribe: mockUnsubscribeFromTopic,
	})

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Mock subscribeToTopic function
	subscribedTopics := []string{}
	mockSubscribeToTopic := func(topic string) error {
		subscribedTopics = append(subscribedTopics, topic)
		return nil
	}
	mockPublishToTopic := func(_ context.Context, _ string, _ []byte) error {
		return nil
	}
	mockUnsubscribeFromTopic := func(_ string) error {
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
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, TopicActions{
		Subscribe:   mockSubscribeToTopic,
		Publish:     mockPublishToTopic,
		Unsubscribe: mockUnsubscribeFromTopic,
	})

	// Assert
	expectedTopics := []string{"orgs/org123/groups/group1", "orgs/org123/groups/group2"}
	assert.Equal(t, expectedTopics, subscribedTopics)
}

func TestMessageHandlers_handleGroupMemberships_SendsAgentPoliciesRequest(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	mockUnsubscribeFromTopic := func(_ string) error {
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
	handlers.handleGroupMemberships(ctx, groupMemberships, orgID, agentID, TopicActions{
		Subscribe:   mockSubscribeToTopic,
		Publish:     mockPublishToTopic,
		Unsubscribe: mockUnsubscribeFromTopic,
	})

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		return p.ID == "policy1" && p.Action == "apply"
	})).Return()
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{{ID: "policy1"}}, nil)

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
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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

// Test that handleAgentPolicies emits the DEBUG RPC-shape line with
// applied/skipped counters and the INFO "agent managed policies" line reflecting
// the repo state after handling.
func TestMessageHandlers_handleAgentPolicies_LogCounters(t *testing.T) {
	tests := []struct {
		name             string
		payloads         []messages.AgentPolicyRPCPayload
		wantApplied      float64
		wantSkipped      float64
		wantManageCalls  int
		repoState        []policies.PolicyData
		wantManagedCount float64
	}{
		{
			name:             "sanitize-only payload: applied=0, skipped=1, no managed policies",
			payloads:         []messages.AgentPolicyRPCPayload{{Action: "sanitize", ID: "p1", Name: "n1", Backend: "pktvisor"}},
			wantApplied:      0,
			wantSkipped:      1,
			wantManageCalls:  0,
			repoState:        []policies.PolicyData{},
			wantManagedCount: 0,
		},
		{
			name: "apply-only payloads: skipped=0, repo reflects applied policies",
			payloads: []messages.AgentPolicyRPCPayload{
				{Action: "apply", ID: "p1", Name: "n1", Backend: "pktvisor", Data: map[string]any{}},
				{Action: "apply", ID: "p2", Name: "n2", Backend: "pktvisor", Data: map[string]any{}},
			},
			wantApplied:      2,
			wantSkipped:      0,
			wantManageCalls:  2,
			repoState:        []policies.PolicyData{{ID: "p1"}, {ID: "p2"}},
			wantManagedCount: 2,
		},
		{
			name: "mixed payloads: both counters present, repo reflects only applied",
			payloads: []messages.AgentPolicyRPCPayload{
				{Action: "apply", ID: "p1", Name: "n1", Backend: "pktvisor", Data: map[string]any{}},
				{Action: "sanitize", ID: "p2", Name: "n2", Backend: "pktvisor"},
				{Action: "sanitize", ID: "p3", Name: "n3", Backend: "pktvisor"},
			},
			wantApplied:      1,
			wantSkipped:      2,
			wantManageCalls:  1,
			repoState:        []policies.PolicyData{{ID: "p1"}},
			wantManagedCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			mockPMgr := &mockPolicyManager{}
			mockPMgr.On("ManagePolicy", mock.Anything).Return()
			mockPMgr.On("GetPolicyState").Return(tc.repoState, nil)
			resetChan := make(chan struct{}, 1)
			groupManager := newGroupManager()
			handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

			handlers.handleAgentPolicies(tc.payloads, false)

			// DEBUG line: RPC shape, applied + skipped always emitted.
			var debugRec map[string]any
			require.NoError(t, findLogRecord(buf.Bytes(), "agent_policy RPC handled", &debugRec))
			assert.Equal(t, "DEBUG", debugRec["level"], "RPC line must be DEBUG")
			assert.Equal(t, tc.wantApplied, debugRec["applied"], "applied counter mismatch")
			assert.Equal(t, tc.wantSkipped, debugRec["skipped"], "skipped counter mismatch")

			// INFO line: managed policy count from repo state.
			var infoRec map[string]any
			require.NoError(t, findLogRecord(buf.Bytes(), "agent managed policies", &infoRec))
			assert.Equal(t, "INFO", infoRec["level"], "managed-policies line must be INFO")
			assert.Equal(t, tc.wantManagedCount, infoRec["count"], "managed policy count mismatch")

			// Legacy combined log message must not be re-introduced.
			var legacy map[string]any
			assert.Error(t, findLogRecord(buf.Bytes(), "successfully processed agent policies", &legacy),
				"legacy combined log message must not be emitted")

			assert.Equal(t, tc.wantManageCalls, mockCallCount(mockPMgr, "ManagePolicy"), "ManagePolicy call count mismatch")
		})
	}
}

// mockCallCount returns the number of times the given method was invoked on a
// testify mock.
func mockCallCount(m *mockPolicyManager, method string) int {
	n := 0
	for _, call := range m.Calls {
		if call.Method == method {
			n++
		}
	}
	return n
}

// findLogRecord scans newline-delimited JSON slog output and returns the first
// record whose msg matches the given message.
func findLogRecord(out []byte, msg string, dst *map[string]any) error {
	for _, line := range bytes.Split(bytes.TrimRight(out, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		rec := map[string]any{}
		if err := json.Unmarshal(line, &rec); err != nil {
			return err
		}
		if rec["msg"] == msg {
			*dst = rec
			return nil
		}
	}
	return fmt.Errorf("no log record matching message %q", msg)
}

// Test handleAgentPolicies with fullList=true but GetAll fails
func TestMessageHandlers_handleAgentPolicies_FullList_GetAllFails(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

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

// Test DispatchToHandlers with malformed dataset_removed payload
func TestMessageHandlers_DispatchToHandlers_MalformedDatasetRemovedPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Create malformed payload
	malformedPayload := []byte(`{"schema_version":"1.0","func":"dataset_removed","payload":"not_a_structure"}`)

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

// Test handleDatasetRemoval with successful dataset removal
func TestMessageHandlers_handleDatasetRemoval_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Register a mock backend for testing
	mockBe := &mockBackend{}
	backend.Register("test_backend", mockBe)
	defer func() {
		// Clean up - manually remove from registry
		// Note: There's no Unregister function, but for isolated tests this is fine
		// In a real scenario, we would want an Unregister function
	}()

	// Setup mock expectations
	mockPMgr.On("GetRepo").Return(mockRepo)
	mockRepo.On("Get", "policy1").Return(policies.PolicyData{
		ID:      "policy1",
		Name:    "Test Policy",
		Backend: "test_backend",
	}, nil)
	mockPMgr.On("RemovePolicyDataset", "policy1", "dataset1", mockBe).Return()

	// Create dataset removal payload
	datasetRemoval := messages.DatasetRemovedRPCPayload{
		DatasetID: "dataset1",
		PolicyID:  "policy1",
	}

	// Act
	handlers.handleDatasetRemoval(datasetRemoval)

	// Assert
	mockPMgr.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

// Test handleDatasetRemoval when policy retrieval fails
func TestMessageHandlers_handleDatasetRemoval_PolicyRetrievalFails(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations - Get fails
	mockPMgr.On("GetRepo").Return(mockRepo)
	mockRepo.On("Get", "policy1").Return(policies.PolicyData{}, assert.AnError)

	// Create dataset removal payload
	datasetRemoval := messages.DatasetRemovedRPCPayload{
		DatasetID: "dataset1",
		PolicyID:  "policy1",
	}

	// Act
	handlers.handleDatasetRemoval(datasetRemoval)

	// Assert - should return early without calling RemovePolicyDataset
	mockPMgr.AssertNotCalled(t, "RemovePolicyDataset", mock.Anything, mock.Anything, mock.Anything)
	mockPMgr.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

// Test handleDatasetRemoval when backend not found
func TestMessageHandlers_handleDatasetRemoval_BackendNotFound(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockRepo := &mockPolicyRepo{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations - policy exists but with nonexistent backend
	mockPMgr.On("GetRepo").Return(mockRepo)
	mockRepo.On("Get", "policy1").Return(policies.PolicyData{
		ID:      "policy1",
		Name:    "Test Policy",
		Backend: "nonexistent_backend",
	}, nil)

	// Create dataset removal payload
	datasetRemoval := messages.DatasetRemovedRPCPayload{
		DatasetID: "dataset1",
		PolicyID:  "policy1",
	}

	// Act
	handlers.handleDatasetRemoval(datasetRemoval)

	// Assert - should return early without calling RemovePolicyDataset
	mockPMgr.AssertNotCalled(t, "RemovePolicyDataset", mock.Anything, mock.Anything, mock.Anything)
	mockPMgr.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

// Test handleAgentReset with FullReset=false
func TestMessageHandlers_handleAgentReset_NoFullReset(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	ctx := context.Background()

	// Create agent reset payload with FullReset=false
	resetPayload := messages.AgentResetRPCPayload{
		FullReset: false,
		Reason:    "test reset without full reset",
	}

	// Act
	handlers.handleAgentReset(ctx, resetPayload)

	// Assert
	// Verify no reset signal was sent to channel
	select {
	case <-resetChan:
		t.Error("Did not expect reset signal to be sent to channel when FullReset=false")
	default:
		// Expected - no signal sent
	}
}

// Test DispatchToHandlers with agent_reset RPC
func TestMessageHandlers_DispatchToHandlers_AgentReset(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	ctx := context.Background()

	// Create agent_reset RPC message with FullReset=false to avoid backend registry issues
	rpc := messages.AgentResetRPC{
		SchemaVersion: "1.0",
		Func:          messages.AgentResetRPCFunc,
		Payload: messages.AgentResetRPCPayload{
			FullReset: false, // Set to false to avoid calling backend.RestartAll
			Reason:    "test dispatch",
		},
	}

	payload, err := json.Marshal(rpc)
	assert.NoError(t, err)

	// Act
	err = handlers.DispatchToHandlers(ctx, payload, "org123", "agent123", TopicActions{
		Subscribe:   func(_ string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(_ string) error { return nil },
	})

	// Assert
	assert.NoError(t, err)
	// With FullReset=false, no reset signal should be sent to channel
}

// Test DispatchToHandlers with malformed agent_reset payload
func TestMessageHandlers_DispatchToHandlers_MalformedAgentResetPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Create malformed payload
	malformedPayload := []byte(`{"schema_version":"1.0","func":"agent_reset","payload":"not_a_structure"}`)

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

// Test DispatchToHandlers with agent_stop RPC
func TestMessageHandlers_DispatchToHandlers_AgentStop(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	_ = NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Create agent_stop RPC message
	rpc := messages.AgentStopRPC{
		SchemaVersion: "1.0",
		Func:          messages.AgentStopRPCFunc,
		Payload: messages.AgentStopRPCPayload{
			Reason: "test stop",
		},
	}

	payload, err := json.Marshal(rpc)
	assert.NoError(t, err)

	// Note: We can't easily test os.Exit() behavior without special setup
	// This test verifies the dispatch works, but handleAgentStop will call os.Exit(0)
	// In a real scenario, you might want to make os.Exit injectable for testing
	// For this test, we'll just verify the payload can be marshaled and dispatched
	// without testing the actual handler execution

	// Instead of calling DispatchToHandlers which would exit,
	// we'll just verify the RPC can be properly unmarshaled
	var unmarshaledRPC messages.AgentStopRPC
	err = json.Unmarshal(payload, &unmarshaledRPC)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, messages.AgentStopRPCFunc, unmarshaledRPC.Func)
	assert.Equal(t, "test stop", unmarshaledRPC.Payload.Reason)
}

// Test DispatchToHandlers with malformed agent_stop payload
func TestMessageHandlers_DispatchToHandlers_MalformedAgentStopPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Create malformed payload
	malformedPayload := []byte(`{"schema_version":"1.0","func":"agent_stop","payload":"not_a_structure"}`)

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

// Test handleAgentPolicies with YAML string data
func TestMessageHandlers_handleAgentPolicies_YAMLStringData(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations - verify that the data is converted to a map
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		if p.ID != "policy1" || p.Action != "manage" {
			return false
		}
		// Verify that Data is now a map, not a string
		dataMap, ok := p.Data.(map[string]any)
		if !ok {
			return false
		}
		// Verify the structure of the unmarshaled YAML
		scope, ok := dataMap["scope"].(map[string]any)
		if !ok {
			return false
		}
		targets, ok := scope["targets"].([]any)
		return ok && len(targets) == 1 && targets[0] == "192.168.12.190/32"
	})).Return()

	// Create policy payload with YAML string data
	yamlString := "scope:\n  targets: [192.168.12.190/32]\n"
	policies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "manage",
			ID:           "policy1",
			DatasetID:    "dataset1",
			AgentGroupID: "group1",
			Name:         "Network Discovery Policy",
			Backend:      "network-discovery",
			Format:       "yaml",
			Version:      1,
			Data:         yamlString,
		},
	}

	// Act
	handlers.handleAgentPolicies(policies, false)

	// Assert
	mockPMgr.AssertExpectations(t)
}

// Test handleAgentPolicies with structured data (backwards compatibility)
func TestMessageHandlers_handleAgentPolicies_StructuredData(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations - verify that structured data is passed through unchanged
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		if p.ID != "policy2" || p.Action != "manage" {
			return false
		}
		// Verify that Data remains as a map
		dataMap, ok := p.Data.(map[string]any)
		if !ok {
			return false
		}
		scope, ok := dataMap["scope"].(map[string]any)
		if !ok {
			return false
		}
		targets, ok := scope["targets"].([]any)
		return ok && len(targets) == 1 && targets[0] == "192.168.1.1/32"
	})).Return()

	// Create policy payload with already structured data
	structuredData := map[string]any{
		"scope": map[string]any{
			"targets": []any{"192.168.1.1/32"},
		},
	}
	policies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "manage",
			ID:           "policy2",
			DatasetID:    "dataset2",
			AgentGroupID: "group1",
			Name:         "Device Discovery Policy",
			Backend:      "device-discovery",
			Format:       "yaml",
			Version:      1,
			Data:         structuredData,
		},
	}

	// Act
	handlers.handleAgentPolicies(policies, false)

	// Assert
	mockPMgr.AssertExpectations(t)
}

// Test handleAgentPolicies with empty YAML string
func TestMessageHandlers_handleAgentPolicies_EmptyYAMLString(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations - empty string should be passed through
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		if p.ID != "policy3" {
			return false
		}
		// Empty string should remain as empty string
		_, ok := p.Data.(string)
		return ok
	})).Return()

	// Create policy payload with empty YAML string
	policies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "manage",
			ID:           "policy3",
			DatasetID:    "dataset3",
			AgentGroupID: "group1",
			Name:         "Empty Policy",
			Backend:      "worker",
			Format:       "yaml",
			Version:      1,
			Data:         "",
		},
	}

	// Act
	handlers.handleAgentPolicies(policies, false)

	// Assert
	mockPMgr.AssertExpectations(t)
}

// Test handleAgentPolicies with invalid YAML string
func TestMessageHandlers_handleAgentPolicies_InvalidYAMLString(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations - invalid YAML should be passed through as-is
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		if p.ID != "policy4" {
			return false
		}
		// Invalid YAML should remain as string (unmarshal fails, original data used)
		_, ok := p.Data.(string)
		return ok
	})).Return()

	// Create policy payload with invalid YAML string
	invalidYAML := "this is not valid YAML: [[[{"
	policies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "manage",
			ID:           "policy4",
			DatasetID:    "dataset4",
			AgentGroupID: "group1",
			Name:         "Invalid YAML Policy",
			Backend:      "pktvisor",
			Format:       "yaml",
			Version:      1,
			Data:         invalidYAML,
		},
	}

	// Act
	handlers.handleAgentPolicies(policies, false)

	// Assert
	mockPMgr.AssertExpectations(t)
}

// Test handleAgentPolicies with non-yaml format
func TestMessageHandlers_handleAgentPolicies_NonYAMLFormat(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mockPMgr := &mockPolicyManager{}
	mockPMgr.On("GetPolicyState").Return([]policies.PolicyData{}, nil)
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, mockPMgr, resetChan, &groupManager)

	// Setup mock expectations - non-yaml format should pass data through unchanged
	mockPMgr.On("ManagePolicy", mock.MatchedBy(func(p config.PolicyPayload) bool {
		if p.ID != "policy5" {
			return false
		}
		// Data should remain as string since format is not yaml
		_, ok := p.Data.(string)
		return ok
	})).Return()

	// Create policy payload with non-yaml format
	policies := []messages.AgentPolicyRPCPayload{
		{
			Action:       "manage",
			ID:           "policy5",
			DatasetID:    "dataset5",
			AgentGroupID: "group1",
			Name:         "JSON Policy",
			Backend:      "pktvisor",
			Format:       "json",
			Version:      1,
			Data:         "{\"key\": \"value\"}",
		},
	}

	// Act
	handlers.handleAgentPolicies(policies, false)

	// Assert
	mockPMgr.AssertExpectations(t)
}
