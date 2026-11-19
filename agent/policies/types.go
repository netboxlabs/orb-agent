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
	// PolicyVersion is the policy version the run started under, worked out
	// by the agent from when it applied each version (see
	// PolicyData.Applied). 0 when unknown.
	PolicyVersion int32 `json:"policy_version,omitempty"`
	// Kind distinguishes runs describing different work, for a backend that
	// emits more than one shape. See backend.PolicyStatusRun.Kind.
	Kind string `json:"kind,omitempty"`
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
	// NotOnBackend is set while the agent knows the backend holds nothing of
	// the policy. Applying it is then a fresh apply rather than an update,
	// which would remove it first, and removing it does not call the backend.
	// A manage stores a new policy with it set: one that found the backend
	// starting, unavailable or not answering, or failed on its secrets or its
	// name, stores the policy before any apply reaches the backend. It is set
	// again once the backend confirms the removal of a policy the agent keeps,
	// to stop it for a secret that no longer resolves or for a restart, and
	// for every policy of a backend whose process was replaced. Asking the backend
	// to apply the policy clears it, unless the backend refused the policy
	// before sending its process anything.
	NotOnBackend bool
	// Applied lists the last versions the agent sent to the backend, oldest
	// first, with when it sent each. A new run gets the last version sent at
	// or before the run's created_at. It lives on the record, and every
	// write of the record carries it over, because a new version replaces
	// the record and drops its runs: the backend still holds the old runs,
	// and they come back as new runs that must still get the old version.
	Applied []AppliedVersion
}

// AppliedVersion is one policy version and the time the agent began
// sending it to the backend.
type AppliedVersion struct {
	Version int32
	At      time.Time
}

// maxAppliedVersions bounds PolicyData.Applied. Only a run that started
// before the last few applies and is first seen after them needs an older
// entry, and it then gets no version, so Fleet falls back as before.
const maxAppliedVersions = 5

// RecordApplied adds version, sent to the backend at at, to Applied. A
// version of 0 (a config manager with no versions) and a re-apply of the
// last version add nothing. Applied is rebuilt rather than appended to, so a
// copy of the record read from the repo never shares its storage.
func (d *PolicyData) RecordApplied(version int32, at time.Time) {
	if version == 0 {
		return
	}
	if n := len(d.Applied); n > 0 && d.Applied[n-1].Version == version {
		return
	}
	kept := d.Applied
	if len(kept) >= maxAppliedVersions {
		kept = kept[len(kept)-maxAppliedVersions+1:]
	}
	applied := make([]AppliedVersion, 0, len(kept)+1)
	applied = append(applied, kept...)
	d.Applied = append(applied, AppliedVersion{Version: version, At: at})
}

// VersionAt returns the version a run created at createdAt started under:
// the last one applied at or before it. It returns 0 when createdAt is zero
// or before every entry, or there are none.
func (d *PolicyData) VersionAt(createdAt time.Time) int32 {
	if createdAt.IsZero() {
		return 0
	}
	for i := len(d.Applied) - 1; i >= 0; i-- {
		if !d.Applied[i].At.After(createdAt) {
			return d.Applied[i].Version
		}
	}
	return 0
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
