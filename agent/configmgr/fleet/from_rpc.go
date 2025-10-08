package fleet

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Messaging handles the messages from the MQTT broker
type Messaging struct {
	logger        *slog.Logger
	policyManager policymgr.PolicyManager
}

// NewMessaging creates a new Messaging
func NewMessaging(logger *slog.Logger, policyManager policymgr.PolicyManager) *Messaging {
	return &Messaging{
		logger:        logger,
		policyManager: policyManager,
	}
}

// DispatchToHandlers dispatches the message to the appropriate handler
func (messaging *Messaging) DispatchToHandlers(ctx context.Context, payload []byte, orgID string, agentID string, subscribeToTopic func(topic string) error, publishToTopic func(ctx context.Context, topic string, payload []byte) error) error {
	var rpc messages.RPC
	if err := json.Unmarshal(payload, &rpc); err != nil {
		messaging.logger.Error("failed to unmarshal RPC", "error", err)
		return err
	}
	// if rpc.SchemaVersion != messages.CurrentRPCSchemaVersion {
	// 	messaging.logger.Error("error decoding RPC message from core", "error", messages.ErrSchemaVersion)
	// 	return messages.ErrSchemaVersion
	// }
	if rpc.Func == "" || rpc.Payload == nil {
		messaging.logger.Error("error decoding RPC message from core", "error", messages.ErrSchemaMalformed)
		return messages.ErrSchemaMalformed
	}

	switch rpc.Func {
	case messages.GroupMembershipRPCFunc:
		groupMemberships := messages.GroupMembershipRPC{}
		if err := json.Unmarshal(payload, &groupMemberships); err != nil {
			messaging.logger.Error("failed to unmarshal payload", "error", err)
			return err
		}
		messaging.handleGroupMemberships(ctx, groupMemberships.Payload, orgID, agentID, subscribeToTopic, publishToTopic)
	case messages.AgentPolicyRPCFunc:
		agentPolicies := messages.AgentPolicyRPC{}
		if err := json.Unmarshal(payload, &agentPolicies); err != nil {
			messaging.logger.Error("failed to unmarshal payload", "error", err)
			return err
		}
		messaging.handleAgentPolicies(agentPolicies.Payload, agentPolicies.FullList)
	default:
		messaging.logger.Debug("unknown rpc function", "func", rpc.Func)
	}
	return nil
}

func (messaging *Messaging) handleGroupMemberships(ctx context.Context, groupMemberships messages.GroupMembershipRPCPayload, orgID string, agentID string, subscribeFunc func(topic string) error, publishFunc func(ctx context.Context, topic string, payload []byte) error) {
	messaging.logger.Debug("handling group memberships", "payload", groupMemberships)

	// if groupMemberships.FullList {
	// 	// TODO: handle when this is the full list. We'll need to
	// 	// - unsubscribe from all group topics not included in this request
	// 	// - subscribe to all group topics
	// }
	for _, group := range groupMemberships.Groups {
		messaging.logger.Info("subscribing to group", "group", group)
		topic := groupTopic(orgID, group.GroupID)
		err := subscribeFunc(topic)
		if err != nil {
			messaging.logger.Error("failed to subscribe to group", "error", err)
		} else {
			messaging.logger.Info("subscribed to group topic for group ID", "group_id", group.GroupID)
		}
	}
	err := messaging.sendAgentPoliciesRequest(ctx, orgID, agentID, publishFunc)
	if err != nil {
		messaging.logger.Error("failed to send agent policies request", "error", err)
	}
}

func (messaging *Messaging) handleAgentPolicies(rpc []messages.AgentPolicyRPCPayload, fullList bool) {
	if fullList {
		policies, err := messaging.policyManager.GetRepo().GetAll()
		if err != nil {
			messaging.logger.Error("failed to retrieve policies on handle subscriptions")
			return
		}
		// Create a map with all the old policies
		policyRemove := map[string]bool{}
		for _, p := range policies {
			policyRemove[p.ID] = true
		}
		for _, payload := range rpc {
			if ok := policyRemove[payload.ID]; ok {
				policyRemove[payload.ID] = false
			}
		}
		// Remove only the policy which should be removed
		for k, v := range policyRemove {
			if v {
				policy, err := messaging.policyManager.GetRepo().Get(k)
				if err != nil {
					messaging.logger.Warn("failed to retrieve policy", "policy_id", k, "error", err)
					continue
				}
				err = messaging.policyManager.RemovePolicy(policy.ID, policy.Name, policy.Backend)
				if err != nil {
					messaging.logger.Warn("failed to remove a policy, ignoring", "policy_id", policy.ID, "policy_name", policy.Name, "error", err)
					continue
				}
			}
		}
	}

	for _, payload := range rpc {
		if payload.Action != "sanitize" {
			messaging.policyManager.ManagePolicy(config.PolicyPayload(payload))
		}
	}
	messaging.logger.Info("successfully processed agent policies", "count", len(rpc))
}
