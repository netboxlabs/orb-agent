package messages

import (
	"errors"
	"time"
)

// CurrentHeartbeatSchemaVersion defines the current version of the heartbeat schema
const CurrentHeartbeatSchemaVersion = "1.0"

var (
	// ErrSchemaVersion a message was received indicating a version we don't support
	ErrSchemaVersion = errors.New("unsupported schema version")
	// ErrSchemaMalformed a message contained a schema we couldn't parse
	ErrSchemaMalformed = errors.New("schema malformed")
	// ErrPayloadTooBig a message contained a payload that was abnormally large
	ErrPayloadTooBig = errors.New("payload too big")
)

// State represents the current state of an agent in the system
type State int

// BackendStateInfo contains state information for a backend
type BackendStateInfo struct {
	State             string    `json:"state"`
	Error             string    `json:"error,omitempty"`
	RestartCount      int64     `json:"restart_count,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	LastRestartTS     time.Time `json:"last_restart_ts,omitempty"`
	LastRestartReason string    `json:"last_restart_reason,omitempty"`
}

// RunStateInfo contains state information for a run
type RunStateInfo struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount *int64    `json:"entity_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PolicyStateInfo contains state information for a policy
type PolicyStateInfo struct {
	Name     string         `json:"name"`
	Datasets []string       `json:"datasets,omitempty"`
	State    string         `json:"state"`
	Error    string         `json:"error,omitempty"`
	Version  int32          `json:"version,omitempty"`
	Backend  string         `json:"backend,omitempty"`
	Runs     []RunStateInfo `json:"runs,omitempty"`
}

// GroupStateInfo contains state information for a group
type GroupStateInfo struct {
	GroupName string `json:"name"`
	GroupID   string `json:"id"`
}

// Heartbeat represents an agent heartbeat message
type Heartbeat struct {
	SchemaVersion string                      `json:"schema_version"`
	TimeStamp     time.Time                   `json:"ts"`
	State         State                       `json:"state"`
	BackendState  map[string]BackendStateInfo `json:"backend_state"`
	PolicyState   map[string]PolicyStateInfo  `json:"policy_state"`
	GroupState    map[string]GroupStateInfo   `json:"group_state"`
}

// HeartbeatState represents the current state of an agent in the system
type HeartbeatState int

const (
	// New represents an agent that has been created but not yet activated
	New HeartbeatState = iota
	// Online represents an agent that is currently online and active
	Online
	// Offline represents an agent that is currently offline or disconnected
	Offline
	// Stale represents an agent that has not sent a heartbeat for a long time
	Stale
	// Removed represents an agent that has been removed from the system
	Removed
	// UpgradeRequired represents an agent that needs to be upgraded to a newer version
	UpgradeRequired
)

// OrbAgentInfo contains information about the Orb agent itself
type OrbAgentInfo struct {
	Version string `json:"version"`
}

// BackendInfo contains version and configuration data for a specific backend
type BackendInfo struct {
	Version string         `json:"version"`
	Data    map[string]any `json:"data"`
}

// CurrentCapabilitiesSchemaVersion defines the current version of the capabilities schema
const CurrentCapabilitiesSchemaVersion = "1.0"

// Capabilities represents the complete set of capabilities and information about an agent
type Capabilities struct {
	SchemaVersion string                 `json:"schema_version"`
	OrbAgent      OrbAgentInfo           `json:"orb_agent"`
	AgentLabels   map[string]string      `json:"agent_labels"`
	Backends      map[string]BackendInfo `json:"backends"`
	AgentConfig   string                 `json:"agent_config"`
}

// GroupMemberships represents the group memberships of an agent
type GroupMemberships struct {
	FullList bool              `json:"full_list"`
	Groups   []GroupMembership `json:"groups"`
}

// GroupMembership represents a group membership of an agent
type GroupMembership struct {
	GroupID string `json:"group_id"`
	Name    string `json:"name"`
}

// RPC represents a request to or from the fleet manager
type RPC struct {
	SchemaVersion string `json:"schema_version"`
	Func          string `json:"func"`
	Payload       any    `json:"payload"`
}

// SendGroupMembershipsRequest represents a request to send group memberships to the fleet manager
type SendGroupMembershipsRequest struct{}

// SendAgentPoliciesRequest represents a request to send agent policies to the fleet manager
type SendAgentPoliciesRequest struct{}

// CurrentRPCSchemaVersion defines the current version of the RPC schema
const CurrentRPCSchemaVersion = "1.0"

// GroupMembershipRPCFunc is the function name for group membership RPC calls
const GroupMembershipRPCFunc = "group_membership"

// GroupMembershipRPC represents an RPC message for group membership operations
type GroupMembershipRPC struct {
	SchemaVersion string                    `json:"schema_version"`
	Func          string                    `json:"func"`
	Payload       GroupMembershipRPCPayload `json:"payload"`
}

// GroupMembershipData contains information about a single group membership
type GroupMembershipData struct {
	GroupID string `json:"group_id"`
	Name    string `json:"name"`
}

// GroupMembershipRPCPayload is the payload for group membership RPC messages
type GroupMembershipRPCPayload struct {
	Groups   []GroupMembershipData `json:"groups"`
	FullList bool                  `json:"full_list"`
}

// AgentPolicyRPCFunc is the function name for agent policy RPC calls
const AgentPolicyRPCFunc = "agent_policy"

// AgentPolicyRPC represents an RPC message for agent policy operations
type AgentPolicyRPC struct {
	SchemaVersion string                  `json:"schema_version"`
	Func          string                  `json:"func"`
	Payload       []AgentPolicyRPCPayload `json:"payload"`
	FullList      bool                    `json:"full_list"`
}

// AgentPolicyRPCPayload is the payload for agent policy RPC messages
type AgentPolicyRPCPayload struct {
	Action       string `json:"action"`
	ID           string `json:"id"`
	DatasetID    string `json:"dataset_id"`
	AgentGroupID string `json:"agent_group_id"`
	Name         string `json:"name"`
	Backend      string `json:"backend"`
	Format       string `json:"format"`
	Version      int32  `json:"version"`
	Data         any    `json:"data"`
}

// GroupRemovedRPCFunc is the function name for group removed RPC calls
const GroupRemovedRPCFunc = "group_removed"

// GroupRemovedRPC represents an RPC message for group removal operations
type GroupRemovedRPC struct {
	SchemaVersion string                 `json:"schema_version"`
	Func          string                 `json:"func"`
	Payload       GroupRemovedRPCPayload `json:"payload"`
}

// GroupRemovedRPCPayload is the payload for group removed RPC messages
type GroupRemovedRPCPayload struct {
	AgentGroupID string   `json:"agent_group_id"`
	Datasets     []string `json:"datasets"`
}

// DatasetRemovedRPCFunc is the function name for dataset removed RPC calls
const DatasetRemovedRPCFunc = "dataset_removed"

// DatasetRemovedRPC represents an RPC message for dataset removal operations
type DatasetRemovedRPC struct {
	SchemaVersion string                   `json:"schema_version"`
	Func          string                   `json:"func"`
	Payload       DatasetRemovedRPCPayload `json:"payload"`
}

// DatasetRemovedRPCPayload is the payload for dataset removed RPC messages
type DatasetRemovedRPCPayload struct {
	DatasetID string `json:"dataset_id"`
	PolicyID  string `json:"policy_id"`
}

// GroupMembershipReqRPCFunc is the function name for group membership request RPC calls
const GroupMembershipReqRPCFunc = "group_membership_req"

// GroupMembershipReqRPCPayload is the payload for group membership request RPC messages
type GroupMembershipReqRPCPayload struct {
	// empty
}

// AgentPoliciesReqRPCFunc is the function name for agent policies request RPC calls
const AgentPoliciesReqRPCFunc = "agent_policies_req"

// AgentPoliciesReqRPCPayload is the payload for agent policies request RPC messages
type AgentPoliciesReqRPCPayload struct {
	// empty
}

// AgentStopRPCFunc is the function name for agent stop RPC calls
const AgentStopRPCFunc = "agent_stop"

// AgentStopRPCPayload is the payload for agent stop RPC messages
type AgentStopRPCPayload struct {
	Reason string `json:"reason"`
}

// AgentStopRPC represents an RPC message for agent stop operations
type AgentStopRPC struct {
	SchemaVersion string              `json:"schema_version"`
	Func          string              `json:"func"`
	Payload       AgentStopRPCPayload `json:"payload"`
}

// AgentResetRPCFunc is the function name for agent reset RPC calls
const AgentResetRPCFunc = "agent_reset"

// AgentResetRPCPayload is the payload for agent reset RPC messages
type AgentResetRPCPayload struct {
	FullReset bool   `json:"full_reset"`
	Reason    string `json:"reason"`
}

// AgentResetRPC represents an RPC message for agent reset operations
type AgentResetRPC struct {
	SchemaVersion string               `json:"schema_version"`
	Func          string               `json:"func"`
	Payload       AgentResetRPCPayload `json:"payload"`
}
