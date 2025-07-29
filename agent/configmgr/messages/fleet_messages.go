package messages

type Heartbeat struct {
	AgentID string `json:"agent_id"`
	Version string `json:"version"`
}

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

// State represents the current state of an agent in the system
type HeartbeatState int
