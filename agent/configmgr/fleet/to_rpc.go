package fleet

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/version"
)

func (messaging *Messaging) sendGroupMembershipsRequest(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error) {
	body, err := json.Marshal(messages.RPC{
		// SchemaVersion: messages.CurrentRPCSchemaVersion, // TODO: add schema version check later
		Func:    "group_membership_req",
		Payload: messages.SendGroupMembershipsRequest{},
	})
	if err != nil {
		messaging.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	messaging.logger.Debug("sending group memberships request", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		messaging.logger.Error("error sending group memberships request", "error", err)
	}
	messaging.logger.Debug("group memberships request sent", "value", string(body))
}

func (messaging *Messaging) sendCapabilities(ctx context.Context, backends map[string]backend.Backend, labels map[string]string, config string, publishFunc func(ctx context.Context, payload []byte) error) {
	backendsInfo := make(map[string]messages.BackendInfo)
	for name, be := range backends {
		ver, err := be.Version()
		if err != nil {
			messaging.logger.Error("backend failed to retrieve version, skipping", "backend", name, "error", err)
			continue
		}
		cp, err := be.GetCapabilities()
		if err != nil {
			messaging.logger.Error("backend failed to retrieve capabilities, skipping", "backend", name, "error", err)
			continue
		}
		backendsInfo[name] = messages.BackendInfo{
			Version: ver,
			Data:    cp,
		}
	}

	capabilities := messages.Capabilities{
		SchemaVersion: messages.CurrentCapabilitiesSchemaVersion,
		AgentLabels:   labels,
		OrbAgent: messages.OrbAgentInfo{
			Version:   version.GetBuildVersion(),
			Branch:    version.GetBuildBranch(),
			Commit:    version.GetBuildCommit(),
			Modified:  version.GetBuildModified(),
			BuildTime: version.GetBuildTime(),
		},
		Backends:    backendsInfo,
		AgentConfig: config,
	}

	body, err := json.Marshal(capabilities)
	if err != nil {
		messaging.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	messaging.logger.Debug("sending capabilities", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		messaging.logger.Error("error sending capabilities", "error", err)
	}
}

func (messaging *Messaging) sendAgentPoliciesRequest(ctx context.Context, orgID string, agentID string, publishFunc func(ctx context.Context, topic string, payload []byte) error) error {
	messaging.logger.Debug("sending agent policies request")
	payload := messages.SendAgentPoliciesRequest{}

	data := messages.RPC{
		SchemaVersion: messages.CurrentRPCSchemaVersion,
		Func:          "agent_policies_req",
		Payload:       payload,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	topic := fmt.Sprintf("orgs/%s/agents/%s/outbox", orgID, agentID)
	messaging.logger.Debug("sending agent policies request", "value", string(body), "topic", topic)
	err = publishFunc(ctx, topic, body)
	if err != nil {
		return err
	}

	return nil
}

func (messaging *Messaging) sendBundleListRequest(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error) {
	body, err := json.Marshal(messages.RPC{
		SchemaVersion: messages.CurrentRPCSchemaVersion,
		Func:          messages.BundleListReqRPCFunc,
		Payload:       messages.BundleListReqRPCPayload{},
	})
	if err != nil {
		messaging.logger.Error("failed to marshal bundle_list_req, skipping", "error", err)
		return
	}
	messaging.logger.Debug("sending bundle_list_req", "value", string(body))
	if err := publishFunc(ctx, body); err != nil {
		messaging.logger.Error("error sending bundle_list_req", "error", err)
		return
	}
	messaging.logger.Debug("bundle_list_req sent")
}
