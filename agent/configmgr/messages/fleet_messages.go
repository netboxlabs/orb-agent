package messages

// Heartbeat represents a periodic message sent by an agent to indicate it's alive and active
type Heartbeat struct {
	AgentID string `json:"agent_id"`
	Version string `json:"version"`
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
	Version string                 `json:"version"`
	Data    map[string]interface{} `json:"data"`
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
