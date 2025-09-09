package messages

import "time"

// Heartbeat represents a periodic message sent by an agent to indicate it's alive and active
// CurrentHeartbeatSchemaVersion defines the current version of the heartbeat schema
const CurrentHeartbeatSchemaVersion = "1.0"

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
	AgentTags     map[string]string      `json:"agent_tags"`
	Backends      map[string]BackendInfo `json:"backends"`
}
