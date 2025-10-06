package fleet

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Messaging handles the messages from the MQTT broker
type Messaging struct {
	logger *slog.Logger
	pMgr   policymgr.PolicyManager
}

// NewMessaging creates a new Messaging
func NewMessaging(logger *slog.Logger, pMgr policymgr.PolicyManager) *Messaging {
	return &Messaging{
		logger: logger,
		pMgr:   pMgr,
	}
}

// DispatchToHandlers dispatches the message to the appropriate handler
func (handlers *Messaging) DispatchToHandlers(messageType string, rpc messages.RPC, orgID string, agentID string, subscribeToTopic func(topic string) error, publishToTopic func(ctx context.Context, topic string, payload []byte) error) {
	switch messageType {
	case "group_membership":
		handlers.handleGroupMemberships(rpc, orgID, agentID, subscribeToTopic, publishToTopic)
	default:
		handlers.logger.Debug("unknown message type", "message_type", messageType)
	}
}

func (handlers *Messaging) handleGroupMemberships(rpc messages.RPC, orgID string, agentID string, subscribeFunc func(topic string) error, publishFunc func(ctx context.Context, topic string, payload []byte) error) {
	handlers.logger.Debug("handling group memberships", "payload", rpc.Payload)
	payloadJSON, err := json.Marshal(rpc.Payload)
	if err != nil {
		handlers.logger.Error("failed to marshal payload", "error", err)
		return
	}
	groupMeberships := messages.GroupMemberships{}
	if err := json.Unmarshal(payloadJSON, &groupMeberships); err != nil {
		handlers.logger.Error("failed to unmarshal payload", "error", err)
		return
	}

	for _, group := range groupMeberships.Groups {
		handlers.logger.Info("subscribing to group", "group", group)
		topic := groupTopic(orgID, group.GroupID)
		err := subscribeFunc(topic)
		if err != nil {
			handlers.logger.Error("failed to subscribe to group", "error", err)
		} else {
			handlers.logger.Info("subscribed to group topic for group ID", "group_id", group.GroupID)
		}
	}
	err = handlers.sendAgentPoliciesRequest(agentID, publishFunc)
	if err != nil {
		handlers.logger.Error("failed to send agent policies request", "error", err)
	}
}

// func (a *orbAgent) handleAgentPolicies(ctx context.Context, rpc []fleet.AgentPolicyRPCPayload, fullList bool) {
// 	ctx, _ = a.extendContext("handleAgentPolicies")
// 	if fullList {
// 		policies, err := a.policyManager.GetRepo().GetAll()
// 		if err != nil {
// 			a.logger.Error("failed to retrieve policies on handle subscriptions")
// 			return
// 		}
// 		// Create a map with all the old policies
// 		policyRemove := map[string]bool{}
// 		for _, p := range policies {
// 			policyRemove[p.ID] = true
// 		}
// 		for _, payload := range rpc {
// 			if ok := policyRemove[payload.ID]; ok {
// 				policyRemove[payload.ID] = false
// 			}
// 		}
// 		// Remove only the policy which should be removed
// 		for k, v := range policyRemove {
// 			if v == true {
// 				policy, err := a.policyManager.GetRepo().Get(k)
// 				if err != nil {
// 					a.logger.Warn("failed to retrieve policy", zap.String("policy_id", k), zap.Error(err))
// 					continue
// 				}
// 				err = a.policyManager.RemovePolicy(policy.ID, policy.Name, policy.Backend)
// 				if err != nil {
// 					a.logger.Warn("failed to remove a policy, ignoring", zap.String("policy_id", policy.ID), zap.String("policy_name", policy.Name), zap.Error(err))
// 					continue
// 				}
// 			}
// 		}
// 	}

// 	for _, payload := range rpc {
// 		if payload.Action != "sanitize" {
// 			a.policyManager.ManagePolicy(payload)
// 		}
// 	}

// 	// heart beat with new policy status after application
// 	if a.heartbeatCtx == nil {
// 		a.logonWithHeartbeat()
// 	}
// }
