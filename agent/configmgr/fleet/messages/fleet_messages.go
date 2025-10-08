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

// PolicyStateInfo contains state information for a policy
type PolicyStateInfo struct {
	Name            string    `json:"name"`
	Datasets        []string  `json:"datasets,omitempty"`
	State           string    `json:"state"`
	Error           string    `json:"error,omitempty"`
	Version         int32     `json:"version"`
	LastScrapeBytes int64     `json:"last_scrape_bytes,omitempty"`
	LastScrapeTS    time.Time `json:"last_scrape_ts,omitempty"`
	Backend         string    `json:"backend,omitempty"`
}

// GroupStateInfo contains state information for a group
type GroupStateInfo struct {
	GroupName    string `json:"name"`
	GroupChannel string `json:"channel"`
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

// ##########################################

const CurrentRPCSchemaVersion = "1.0"

const GroupMembershipRPCFunc = "group_membership"

type GroupMembershipRPC struct {
	SchemaVersion string                    `json:"schema_version"`
	Func          string                    `json:"func"`
	Payload       GroupMembershipRPCPayload `json:"payload"`
}

type GroupMembershipData struct {
	GroupID   string `json:"group_id"`
	Name      string `json:"name"`
	ChannelID string `json:"channel_id"`
}

type GroupMembershipRPCPayload struct {
	Groups   []GroupMembershipData `json:"groups"`
	FullList bool                  `json:"full_list"`
}

const AgentPolicyRPCFunc = "agent_policy"

type AgentPolicyRPC struct {
	SchemaVersion string                  `json:"schema_version"`
	Func          string                  `json:"func"`
	Payload       []AgentPolicyRPCPayload `json:"payload"`
	FullList      bool                    `json:"full_list"`
}

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

const GroupRemovedRPCFunc = "group_removed"

type GroupRemovedRPC struct {
	SchemaVersion string                 `json:"schema_version"`
	Func          string                 `json:"func"`
	Payload       GroupRemovedRPCPayload `json:"payload"`
}

type GroupRemovedRPCPayload struct {
	AgentGroupID string   `json:"agent_group_id"`
	ChannelID    string   `json:"channel_id"`
	Datasets     []string `json:"datasets"`
}

const DatasetRemovedRPCFunc = "dataset_removed"

type DatasetRemovedRPC struct {
	SchemaVersion string                   `json:"schema_version"`
	Func          string                   `json:"func"`
	Payload       DatasetRemovedRPCPayload `json:"payload"`
}

type DatasetRemovedRPCPayload struct {
	DatasetID string `json:"dataset_id"`
	PolicyID  string `json:"policy_id"`
}

const GroupMembershipReqRPCFunc = "group_membership_req"

type GroupMembershipReqRPCPayload struct {
	// empty
}

const AgentPoliciesReqRPCFunc = "agent_policies_req"

type AgentPoliciesReqRPCPayload struct {
	// empty
}
