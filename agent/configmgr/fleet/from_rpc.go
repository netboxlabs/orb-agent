package fleet

import (
	"context"
	"encoding/json"

	"github.com/eclipse/paho.golang/paho"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

func (connection *MQTTConnection) dispatchToHandlers(messageType string, rpc messages.RPC, orgID string) {
	switch messageType {
	case "group_membership":
		connection.handleGroupMemberships(rpc, orgID)
	default:
		connection.logger.Debug("unknown message type", "message_type", messageType)
	}
}

func (connection *MQTTConnection) handleGroupMemberships(rpc messages.RPC, orgID string) {
	connection.logger.Debug("handling group memberships", "payload", rpc.Payload)
	payloadJSON, err := json.Marshal(rpc.Payload)
	if err != nil {
		connection.logger.Error("failed to marshal payload", "error", err)
		return
	}
	groupMeberships := messages.GroupMemberships{}
	if err := json.Unmarshal(payloadJSON, &groupMeberships); err != nil {
		connection.logger.Error("failed to unmarshal payload", "error", err)
		return
	}

	for _, group := range groupMeberships.Groups {
		connection.logger.Info("subscribing to group", "group", group)
		_, err := connection.connectionManager.Subscribe(context.Background(), &paho.Subscribe{
			Subscriptions: []paho.SubscribeOptions{
				{Topic: groupTopic(orgID, group.GroupID), QoS: 1},
			},
		})
		if err != nil {
			connection.logger.Error("failed to subscribe to group", "error", err)
		}
		connection.logger.Info("subscribed to group topic for group ID", "group_id", group.GroupID)
	}
}
