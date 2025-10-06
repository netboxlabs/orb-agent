package fleet

import (
	"context"
	"encoding/json"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/version"
)

func (connection *MQTTConnection) sendGroupMembershipsRequest(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error) {
	body, err := json.Marshal(messages.RPC{
		// SchemaVersion: messages.CurrentRPCSchemaVersion, // TODO: add schema version check later
		Func:    "group_membership_req",
		Payload: messages.SendGroupMembershipsRequest{},
	})
	if err != nil {
		connection.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	connection.logger.Info("sending group memberships request", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		connection.logger.Error("error sending group memberships request", "error", err)
	}
	connection.logger.Info("group memberships request sent", "value", string(body))
}

func (connection *MQTTConnection) sendCapabilities(ctx context.Context, backends map[string]backend.Backend, labels map[string]string, publishFunc func(ctx context.Context, payload []byte) error) {
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
			connection.logger.Error("backend failed to retrieve version, skipping", "backend", name, "error", err)
			continue
		}
		cp, err := be.GetCapabilities()
		if err != nil {
			connection.logger.Error("backend failed to retrieve capabilities, skipping", "backend", name, "error", err)
			continue
		}
		capabilities.Backends[name] = messages.BackendInfo{
			Version: ver,
			Data:    cp,
		}
	}

	body, err := json.Marshal(capabilities)
	if err != nil {
		connection.logger.Error("backend failed to marshal capabilities, skipping", "error", err)
		return
	}

	connection.logger.Info("sending capabilities", "value", string(body))
	err = publishFunc(ctx, body)
	if err != nil {
		connection.logger.Error("error sending capabilities", "error", err)
	}
}
