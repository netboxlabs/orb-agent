package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

// Resetter restarts every backend the agent started; the supervisor
// implements it and the agent installs it after construction, before the
// connection that dispatches resets exists, so the field is read without
// a lock on the dispatch worker.
type Resetter interface {
	// RestartAll restarts every started backend. A sweep that did not
	// complete, because ctx was cancelled or because the agent is
	// shutting down, returns an error satisfying
	// errors.Is(err, context.Canceled); no reconnect signal follows it.
	RestartAll(ctx context.Context, reason string) error
}

// bundleInstaller is implemented by the fleet files-manager type
// (*filesmgr.FleetFilesManager): it installs bundles delivered via
// packages_credentials. A non-fleet files manager (the dummy) does not
// implement it, so bundle delivery is a no-op when files delivery is inactive.
type bundleInstaller interface {
	HandlePackages(ctx context.Context, payload messages.PackagesCredentialsRPCPayload)
}

// Messaging handles the messages from the MQTT broker
type Messaging struct {
	logger        *slog.Logger
	policyManager policymgr.PolicyManager
	groupManager  *GroupManager
	resetChan     chan struct{}
	filesManager  filesmgr.Manager

	// resetter restarts every backend for a full agent reset; SetResetter
	// installs it once, before the dispatch worker that calls
	// handleAgentReset is reachable, so it is read here without a lock.
	resetter Resetter
	// resetMu guards resetRunning, resetPending and resetPendingReason. A
	// reset RPC that arrives while one is already running is not dropped: it
	// is remembered here and the same goroutine runs it once more, for the
	// last reason queued, after the current run finishes.
	resetMu            sync.Mutex
	resetRunning       bool
	resetPending       bool
	resetPendingReason string
}

// SetResetter installs the resetter a full agent reset restarts through.
func (messaging *Messaging) SetResetter(r Resetter) {
	messaging.resetter = r
}

// NewMessaging creates a new Messaging
func NewMessaging(logger *slog.Logger, policyManager policymgr.PolicyManager, resetChan chan struct{}, groupManager *GroupManager, filesManager filesmgr.Manager) *Messaging {
	return &Messaging{
		logger:        logger,
		policyManager: policyManager,
		groupManager:  groupManager,
		resetChan:     resetChan,
		filesManager:  filesManager,
	}
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
		messaging.handleAgentGroupRemoval(groupRemoved.Payload, orgID, topicActions.Unsubscribe)

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
		if installer, ok := messaging.filesManager.(bundleInstaller); ok {
			installer.HandlePackages(ctx, r.Payload)
		} else {
			messaging.logger.Warn("received fleet bundles but files_manager.active != fleet; ignoring (set files_manager.active: fleet to install)")
		}
	default:
		messaging.logger.Debug("unknown rpc function", "func", rpc.Func)
	}
	return nil
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

func (messaging *Messaging) handleAgentGroupRemoval(rpc messages.GroupRemovedRPCPayload, orgID string, unsubscribeFromTopic func(topic string) error) {
	// Must unsubscribe the same fully-qualified topic we subscribed to in
	// handleGroupMemberships (orgs/<org>/groups/<id>). Passing the bare group ID
	// here is an MQTT filter mismatch and silently leaves the subscription live.
	err := unsubscribeFromTopic(groupTopic(orgID, rpc.AgentGroupID))
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
					messaging.policyManager.RemovePolicyDataset(policy.ID, datasetID, policy.Backend, backend.GetBackend(policy.Backend))
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
	messaging.policyManager.RemovePolicyDataset(rpc.PolicyID, rpc.DatasetID, policy.Backend, be)
}

func (messaging *Messaging) handleAgentReset(ctx context.Context, payload messages.AgentResetRPCPayload) {
	messaging.logger.Info("handling agent reset", "reason", payload.Reason, "full_reset", payload.FullReset)
	if !payload.FullReset {
		return
	}
	if messaging.resetter == nil {
		messaging.logger.Warn("agent reset requested but no resetter is installed; ignoring")
		return
	}
	messaging.resetMu.Lock()
	if messaging.resetRunning {
		messaging.resetPending = true
		messaging.resetPendingReason = payload.Reason
		messaging.resetMu.Unlock()
		messaging.logger.Info("agent reset already running; queued", "reason", payload.Reason)
		return
	}
	messaging.resetRunning = true
	messaging.resetMu.Unlock()
	// Off the dispatch worker: restarting every backend takes minutes and
	// the worker must keep serving policies meanwhile. ctx is
	// context.Background() from the worker; shutdown interrupts the
	// restarts through the supervisor's own stop context.
	go messaging.runResets(ctx, payload.Reason)
}

// runResets runs the resetter for reason, sends the reconnect signal (so the
// capabilities republished on reconnect see every backend answering), then
// checks whether another full reset arrived while this one ran: if so, it
// runs once more, for the last reason queued, with its own reconnect signal;
// otherwise it clears resetRunning and returns. One reconnect signal follows
// each run, never one for a run that was itself replaced by a later one
// before it started.
func (messaging *Messaging) runResets(ctx context.Context, reason string) {
	for {
		err := messaging.resetter.RestartAll(ctx, reason)
		switch {
		case errors.Is(err, context.Canceled):
			// Shutdown (or a cancelled request) aborted the sweep: there is
			// no connection to refresh, and the reset handler the signal
			// wakes is on its way down and could sit in Disconnect for its
			// whole timeout, holding the config manager's stop.
			messaging.logger.Info("agent reset did not complete; no reconnect signal", "error", err)
		default:
			if err != nil {
				messaging.logger.Error("RestartAll failure", "error", err)
			}
			select {
			case messaging.resetChan <- struct{}{}:
				messaging.logger.Info("sent reset signal to channel")
			default:
				messaging.logger.Warn("reset channel is full, skipping reset signal")
			}
		}
		messaging.resetMu.Lock()
		if !messaging.resetPending {
			messaging.resetRunning = false
			messaging.resetMu.Unlock()
			return
		}
		reason = messaging.resetPendingReason
		messaging.resetPending = false
		messaging.resetPendingReason = ""
		messaging.resetMu.Unlock()
	}
}

func (messaging *Messaging) handleAgentStop(payload messages.AgentStopRPCPayload) {
	messaging.logger.Error("handling agent stop", "reason", payload.Reason)
	os.Exit(0)
}
