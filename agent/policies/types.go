package policies

import (
	"database/sql/driver"
	"time"
)

// RunData represents run information for a policy
type RunData struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id,omitempty"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	EntityCount int64     `json:"entity_count,omitzero"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Targets     []string  `json:"targets,omitempty"`
	Driver      string    `json:"driver,omitempty"`
}

// PolicyData represents a policy
type PolicyData struct {
	ID                 string
	Datasets           map[string]bool
	GroupIDs           map[string]bool
	Name               string
	Backend            string
	Version            int32
	Data               any
	State              PolicyState
	BackendErr         string
	PreviousPolicyData *PolicyData
	Runs               []RunData
}

// GetDatasetIDs returns the dataset IDs
func (d *PolicyData) GetDatasetIDs() []string {
	keys := make([]string, len(d.Datasets))

	i := 0
	for k := range d.Datasets {
		keys[i] = k
		i++
	}
	return keys
}

// Policy state types
const (
	Unknown PolicyState = iota
	Running
	FailedToApply
	Offline
)

// PolicyState represents the state of a policy
type PolicyState int

var policyStateMap = [...]string{
	"unknown",
	"running",
	"failed_to_apply",
	"offline",
}

var policyStateRevMap = map[string]PolicyState{
	"unknown":         Unknown,
	"running":         Running,
	"failed_to_apply": FailedToApply,
	"offline":         Offline,
}

func (s PolicyState) String() string {
	return policyStateMap[s]
}

// Scan scans the value into the PolicyState
func (s *PolicyState) Scan(value any) error {
	*s = policyStateRevMap[string(value.([]byte))]
	return nil
}

// Value returns the value of the PolicyState
func (s PolicyState) Value() (driver.Value, error) { return s.String(), nil }

// RunFailureReasonAgentStopped is reported when non-terminal runs are finalized
// because the agent shut down intentionally (e.g. SIGTERM/SIGINT).
const RunFailureReasonAgentStopped = "Run interrupted: agent was intentionally stopped"

// IsTerminalRunStatus returns true if the run status represents a finished run
// whose timestamps should no longer be updated.
func IsTerminalRunStatus(status string) bool {
	switch status {
	case "completed", "failed":
		return true
	default:
		return false
	}
}
