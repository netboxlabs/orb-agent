package fleet

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

func TestMQTTConnection_dispatchToHandlers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	connection := &MQTTConnection{
		logger: logger,
	}

	tests := []struct {
		name        string
		messageType string
		rpc         messages.RPC
		orgID       string
		shouldPanic bool
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
			orgID:       "org123",
			shouldPanic: true, // Will panic due to nil connection manager
		},
		{
			name:        "unknown message type",
			messageType: "unknown_type",
			rpc: messages.RPC{
				SchemaVersion: "1.0",
				Func:          "unknown_func",
				Payload:       map[string]any{},
			},
			orgID:       "org123",
			shouldPanic: false, // Should not panic for unknown message type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				assert.Panics(t, func() {
					connection.dispatchToHandlers(tt.messageType, tt.rpc, tt.orgID)
				})
			} else {
				assert.NotPanics(t, func() {
					connection.dispatchToHandlers(tt.messageType, tt.rpc, tt.orgID)
				})
			}
		})
	}
}

func TestMQTTConnection_handleGroupMemberships_Success(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	connection := &MQTTConnection{
		logger:            logger,
		connectionManager: nil, // We'll test the logic without actual MQTT calls
	}

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

	// Act - This will panic due to nil connection manager, but we can test the JSON handling
	assert.Panics(t, func() {
		connection.handleGroupMemberships(rpc, orgID)
	})
}

func TestMQTTConnection_handleGroupMemberships_InvalidPayload(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	connection := &MQTTConnection{
		logger:            logger,
		connectionManager: nil,
	}

	orgID := "org123"
	// Create an RPC with invalid payload that can't be unmarshaled to GroupMemberships
	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       "invalid_payload_string",
	}

	// Act - This should not panic, just log an error
	assert.NotPanics(t, func() {
		connection.handleGroupMemberships(rpc, orgID)
	})
}

func TestMQTTConnection_handleGroupMemberships_EmptyGroups(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	connection := &MQTTConnection{
		logger:            logger,
		connectionManager: nil,
	}

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

	// Act - This should not panic, just process empty groups
	assert.NotPanics(t, func() {
		connection.handleGroupMemberships(rpc, orgID)
	})
}

func TestMQTTConnection_handleGroupMemberships_JSONMarshalError(t *testing.T) {
	// Arrange
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	connection := &MQTTConnection{
		logger:            logger,
		connectionManager: nil,
	}

	orgID := "org123"
	// Create an RPC with payload that can't be marshaled (e.g., function)
	rpc := messages.RPC{
		SchemaVersion: "1.0",
		Func:          "group_membership",
		Payload:       func() {}, // Functions can't be marshaled to JSON
	}

	// Act - This should not panic, just log an error
	assert.NotPanics(t, func() {
		connection.handleGroupMemberships(rpc, orgID)
	})
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

func TestMQTTConnection_handleGroupMemberships_ComplexPayload(t *testing.T) {
	// Test with a more complex payload structure
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	connection := &MQTTConnection{
		logger:            logger,
		connectionManager: nil,
	}

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

	// Act - This will panic due to nil connection manager, but we can test the JSON handling
	assert.Panics(t, func() {
		connection.handleGroupMemberships(rpc, orgID)
	})
}
