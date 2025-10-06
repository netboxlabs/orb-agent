package fleet

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/version"
)

func (handler *Messaging) sendGroupMembershipsRequest(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error) {
	body, err := json.Marshal(messages.RPC{
		// SchemaVersion: messages.CurrentRPCSchemaVersion, // TODO: add schema version check later
		Func:    "group_membership_req",
		Payload: messages.SendGroupMembershipsRequest{},
	})
	if err != nil {
		handler.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	handler.logger.Info("sending group memberships request", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		handler.logger.Error("error sending group memberships request", "error", err)
	}
	handler.logger.Info("group memberships request sent", "value", string(body))
}

func (handler *Messaging) sendCapabilities(ctx context.Context, backends map[string]backend.Backend, labels map[string]string, publishFunc func(ctx context.Context, payload []byte) error) {
	capabilities := messages.Capabilities{
		SchemaVersion: messages.CurrentCapabilitiesSchemaVersion,
		AgentLabels:   labels,
		OrbAgent: messages.OrbAgentInfo{
			Version: version.GetBuildVersion(),
		},
	}

	capabilities.Backends = make(map[string]messages.BackendInfo)
	for name, be := range backends {
		ver, err := be.Version()
		if err != nil {
			handler.logger.Error("backend failed to retrieve version, skipping", "backend", name, "error", err)
			continue
		}
		cp, err := be.GetCapabilities()
		if err != nil {
			handler.logger.Error("backend failed to retrieve capabilities, skipping", "backend", name, "error", err)
			continue
		}
		capabilities.Backends[name] = messages.BackendInfo{
			Version: ver,
			Data:    cp,
		}
	}

	body, err := json.Marshal(capabilities)
	if err != nil {
		handler.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	handler.logger.Info("sending capabilities", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		handler.logger.Error("error sending capabilities", "error", err)
	}
}

func (handlers *Messaging) sendAgentPoliciesRequest(agentID string, publishFunc func(ctx context.Context, topic string, payload []byte) error) error {
	handlers.logger.Debug("sending agent policies request")
	payload := messages.SendAgentPoliciesRequest{}

	data := messages.RPC{
		// SchemaVersion: fleet.CurrentRPCSchemaVersion,
		Func:    "agent_policies_req",
		Payload: payload,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	err = publishFunc(context.Background(), fmt.Sprintf("agents/%s/outbox", agentID), body)
	if err != nil {
		return err
	}

	return nil
}
