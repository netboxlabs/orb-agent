package fleet

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Messaging handles the messages from the MQTT broker
type Messaging struct {
	logger        *slog.Logger
	policyManager policymgr.PolicyManager
	groupManager  *GroupManager
	resetChan     chan struct{}
	filesManager  filesmgr.Manager
	stopCtx       context.Context
	stopCancel    context.CancelFunc
}

// NewMessaging creates a new Messaging
func NewMessaging(logger *slog.Logger, policyManager policymgr.PolicyManager, resetChan chan struct{}, groupManager *GroupManager, filesManager filesmgr.Manager) *Messaging {
	stopCtx, stopCancel := context.WithCancel(context.Background())
	return &Messaging{
		logger:        logger,
		policyManager: policyManager,
		groupManager:  groupManager,
		resetChan:     resetChan,
		filesManager:  filesManager,
		stopCtx:       stopCtx,
		stopCancel:    stopCancel,
	}
}

// Stop cancels any in-flight bundle installations.
func (messaging *Messaging) Stop() {
	messaging.stopCancel()
}

// DispatchToHandlers dispatches the message to the appropriate handler
func (messaging *Messaging) DispatchToHandlers(ctx context.Context, payload []byte, orgID string, agentID string, topicActions TopicActions) error {
	var rpc messages.RPC
	if err := json.Unmarshal(payload, &rpc); err != nil {
		messaging.logger.Error("failed to unmarshal RPC", "error", err)
		return err
	}

	// TODO: add schema version check later

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
		messaging.handleGroupMemberships(ctx, groupMemberships.Payload, orgID, agentID, topicActions)
	case messages.AgentPolicyRPCFunc:
		agentPolicies := messages.AgentPolicyRPC{}
		if err := json.Unmarshal(payload, &agentPolicies); err != nil {
			messaging.logger.Error("failed to unmarshal payload", "error", err)
			return err
		}
		messaging.handleAgentPolicies(agentPolicies.Payload, agentPolicies.FullList)
	case messages.GroupRemovedRPCFunc:
		groupRemoved := messages.GroupRemovedRPC{}
		if err := json.Unmarshal(payload, &groupRemoved); err != nil {
			messaging.logger.Error("failed to unmarshal payload", "error", err)
			return err
		}
		messaging.handleAgentGroupRemoval(groupRemoved.Payload, topicActions.Unsubscribe)
	case messages.DatasetRemovedRPCFunc:
		var r messages.DatasetRemovedRPC
		if err := json.Unmarshal(payload, &r); err != nil {
			messaging.logger.Error("error decoding dataset removal message from core", "error", messages.ErrSchemaMalformed)
			return err
		}
		messaging.handleDatasetRemoval(r.Payload)
	case messages.AgentStopRPCFunc:
		var r messages.AgentStopRPC
		if err := json.Unmarshal(payload, &r); err != nil {
			messaging.logger.Error("error decoding agent stop message from core", "error", messages.ErrSchemaMalformed)
			return err
		}
		messaging.handleAgentStop(r.Payload)
	case messages.AgentResetRPCFunc:
		var r messages.AgentResetRPC
		if err := json.Unmarshal(payload, &r); err != nil {
			messaging.logger.Error("error decoding agent reset message from core", "error", messages.ErrSchemaMalformed)
			return err
		}
		messaging.handleAgentReset(ctx, r.Payload)
	case messages.PackagesCredentialsRPCFunc:
		var r messages.PackagesCredentialsRPC
		if err := json.Unmarshal(payload, &r); err != nil {
			messaging.logger.Error("error decoding packages credentials message from core", "error", messages.ErrSchemaMalformed)
			return err
		}
		messaging.handlePackages(ctx, r.Payload)
	default:
		messaging.logger.Debug("unknown rpc function", "func", rpc.Func)
	}
	return nil
}

// handlePackages installs each bundle delivered by filesmgr.Manager.
// Failures are non-fatal: a failed bundle is logged and skipped so that
// other bundles in the same delivery are still installed.
func (messaging *Messaging) handlePackages(_ context.Context, payload messages.PackagesCredentialsRPCPayload) {
	if messaging.filesManager == nil {
		messaging.logger.Error("filesManager is nil, cannot install bundles")
		return
	}
	if len(payload.Bundles) == 0 {
		messaging.logger.Debug("packages_credentials received with empty bundle list, nothing to do")
		return
	}
	messaging.logger.Info("installing bundles", "count", len(payload.Bundles))
	for _, bundle := range payload.Bundles {
		// TODO: check bundle.ExpiresAt before calling Ensure to avoid
		// unnecessary download attempts with expired presigned URLs.
		installCtx, cancel := context.WithTimeout(messaging.stopCtx, 10*time.Minute)
		spec := filesmgr.FileSpec{
			Name:       bundle.Name,
			Version:    bundle.Version,
			URL:        bundle.URL,
			SHA256:     bundle.SHA256,
			Extract:    bundle.Extract,
			TargetPath: bundle.TargetPath,
			Mode:       bundle.Mode,
		}
		path, err := messaging.filesManager.Ensure(installCtx, spec)
		cancel()
		if err != nil {
			messaging.logger.Error("failed to install bundle",
				"name", bundle.Name,
				"version", bundle.Version,
				"error", err)
			continue
		}
		messaging.logger.Info("bundle installed",
			"name", bundle.Name,
			"version", bundle.Version,
			"path", path)
	}
}

func (messaging *Messaging) handleGroupMemberships(ctx context.Context, groupMemberships messages.GroupMembershipRPCPayload, orgID string, agentID string, topicActions TopicActions) {
	messaging.logger.Debug("handling group memberships", "payload", groupMemberships)

	if groupMemberships.FullList {
		for _, group := range messaging.groupManager.GetAll() {
			if err := topicActions.Unsubscribe(groupTopic(orgID, group.GroupID)); err != nil {
				messaging.logger.Error("failed to unsubscribe from group topic", "group_id", group.GroupID, "error", err)
			}
			messaging.groupManager.Remove(group.GroupID)
		}
	}
	for _, group := range groupMemberships.Groups {
		messaging.groupManager.Add(group)
		messaging.logger.Info("subscribing to group", "group", group)
		topic := groupTopic(orgID, group.GroupID)
		err := topicActions.Subscribe(topic)
		if err != nil {
			messaging.logger.Error("failed to subscribe to group", "error", err)
		} else {
			messaging.logger.Info("subscribed to group topic for group ID", "group_id", group.GroupID)
		}
	}
	err := messaging.sendAgentPoliciesRequest(ctx, orgID, agentID, topicActions.Publish)
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

	applied := 0
	skipped := 0
	for _, payload := range rpc {
		if payload.Action == "sanitize" {
			skipped++
			continue
		}
		// If the policy data is a string and Format is "yaml" (or empty), try to unmarshal it as YAML
		// This handles cases where Format="yaml" or where the backend sends YAML without setting Format
		if dataStr, ok := payload.Data.(string); ok && dataStr != "" && (payload.Format == "yaml" || payload.Format == "") {
			var structuredData map[string]any
			if err := yaml.Unmarshal([]byte(dataStr), &structuredData); err != nil {
				// If unmarshaling fails, log a warning only if Format was explicitly set to yaml
				if payload.Format == "yaml" {
					messaging.logger.Warn("failed to unmarshal YAML policy data",
						"policy_id", payload.ID,
						"policy_name", payload.Name,
						"error", err)
				}
				// Continue with original string data - let the backend handle it
			} else {
				// Successfully unmarshaled - use the structured data
				payload.Data = structuredData
			}
		}
		messaging.policyManager.ManagePolicy(config.PolicyPayload(payload))
		applied++
	}
	messaging.logger.Debug("agent_policy RPC handled", "applied", applied, "skipped", skipped)

	managed, err := messaging.policyManager.GetPolicyState()
	if err != nil {
		messaging.logger.Warn("failed to read agent managed policy count after RPC", "error", err)
		return
	}
	messaging.logger.Info("agent managed policies", "count", len(managed))
}

func (messaging *Messaging) handleAgentGroupRemoval(rpc messages.GroupRemovedRPCPayload, unsubscribeFromTopic func(topic string) error) {
	err := unsubscribeFromTopic(rpc.AgentGroupID)
	if err != nil {
		messaging.logger.Error("failed to unsubscribe from group topic", "error", err)
		return
	}

	policies, err := messaging.policyManager.GetRepo().GetAll()
	if err != nil {
		return
	}

	for _, policy := range policies {
		delete(policy.GroupIDs, rpc.AgentGroupID)

		if len(policy.GroupIDs) == 0 {
			messaging.logger.Info("policy no longer used by any group, removing", "policy_id", policy.ID, "policy_name", policy.Name)

			err = messaging.policyManager.RemovePolicy(policy.ID, policy.Name, policy.Backend)
			if err != nil {
				messaging.logger.Warn("failed to remove a policy, ignoring", "policy_id", policy.ID, "policy_name", policy.Name, "error", err)
				continue
			}
		} else {
			for _, datasetID := range rpc.Datasets {
				if backend.HaveBackend(policy.Backend) {
					messaging.policyManager.RemovePolicyDataset(policy.ID, datasetID, backend.GetBackend(policy.Backend))
				}
			}
		}
	}
}

func (messaging *Messaging) handleDatasetRemoval(rpc messages.DatasetRemovedRPCPayload) {
	messaging.logger.Info("handling dataset removal", "dataset_id", rpc.DatasetID, "policy_id", rpc.PolicyID)
	policy, err := messaging.policyManager.GetRepo().Get(rpc.PolicyID)
	if err != nil {
		messaging.logger.Error("failed to retrieve policy", "policy_id", rpc.PolicyID, "error", err)
		return
	}
	if !backend.HaveBackend(policy.Backend) {
		messaging.logger.Error("policy backend not found", "policy_id", rpc.PolicyID, "policy_backend", policy.Backend)
		return
	}
	be := backend.GetBackend(policy.Backend)
	messaging.policyManager.RemovePolicyDataset(rpc.PolicyID, rpc.DatasetID, be)
}

func (messaging *Messaging) handleAgentReset(ctx context.Context, payload messages.AgentResetRPCPayload) {
	messaging.logger.Info("handling agent reset", "reason", payload.Reason, "full_reset", payload.FullReset)
	if payload.FullReset {
		err := backend.RestartAll(ctx)
		if err != nil {
			messaging.logger.Error("RestartAll failure", "error", err)
		}
		// Send reset message to channel
		select {
		case messaging.resetChan <- struct{}{}:
			messaging.logger.Info("sent reset signal to channel")
		default:
			messaging.logger.Warn("reset channel is full, skipping reset signal")
		}
	}
	// TODO backend specific restart
	// a.RestartBackend()
}

func (messaging *Messaging) handleAgentStop(payload messages.AgentStopRPCPayload) {
	messaging.logger.Error("handling agent stop", "reason", payload.Reason)
	os.Exit(0)
}
