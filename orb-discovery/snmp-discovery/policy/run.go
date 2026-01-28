package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RunStatus represents the status of a run
type RunStatus string

const (
	// RunStatusRunning indicates the run is currently running
	RunStatusRunning RunStatus = "running"
	// RunStatusCompleted indicates the run completed successfully
	RunStatusCompleted RunStatus = "completed"
	// RunStatusFailed indicates the run failed with an error
	RunStatusFailed RunStatus = "failed"
)

// Run represents a single run execution
type Run struct {
	ID          string            `json:"id"`
	PolicyID    string            `json:"policy_id"`
	Status      RunStatus         `json:"status"`
	Reason      string            `json:"reason,omitempty"`
	EntityCount int               `json:"entity_count"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   int64             `json:"created_at"`
	UpdatedAt   int64             `json:"updated_at"`
}

// RunStore manages runs in memory with per-target tracking
type RunStore struct {
	mu   sync.RWMutex
	runs map[string]map[string][]*Run // policyName -> target -> runs (max 3 per target)
}

const maxRunsPerTarget = 3

// NewRunStore creates a new RunStore
func NewRunStore() *RunStore {
	return &RunStore{
		runs: make(map[string]map[string][]*Run),
	}
}

// normalizeTarget normalizes target strings to canonical form and includes port
// Returns format "host:port" (e.g., "192.168.1.10:161")
func normalizeTarget(host string, port uint16) string {
	normalizedHost := host
	// Try to parse as IP address
	if addr, err := netip.ParseAddr(host); err == nil {
		normalizedHost = addr.String()
	} else if prefix, err := netip.ParsePrefix(host); err == nil {
		// Try to parse as IP prefix (CIDR)
		normalizedHost = prefix.String()
	}
	// Return composite identifier "host:port"
	return fmt.Sprintf("%s:%d", normalizedHost, port)
}

// copyRun creates a deep copy of a Run to avoid race conditions
func copyRun(r *Run) *Run {
	if r == nil {
		return nil
	}

	// Copy metadata map, preserving nil vs empty map semantics
	var metadataCopy map[string]string
	if r.Metadata != nil {
		metadataCopy = make(map[string]string)
		for k, v := range r.Metadata {
			metadataCopy[k] = v
		}
	}

	return &Run{
		ID:          r.ID,
		PolicyID:    r.PolicyID,
		Status:      r.Status,
		Reason:      r.Reason,
		EntityCount: r.EntityCount,
		Metadata:    metadataCopy,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// CreateRun creates a new run for the given policy and target, and returns it
func (rs *RunStore) CreateRun(policyName string, target string, port uint16, parentTarget string) *Run {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	now := time.Now()

	// Normalize target for consistent storage (includes port)
	normalizedTarget := normalizeTarget(target, port)

	// Create metadata with target and port information
	metadata := make(map[string]string)
	metadata["target"] = target // Store original host, not normalized
	metadata["port"] = strconv.FormatUint(uint64(port), 10)
	if parentTarget != "" {
		metadata["parent_target"] = parentTarget
	}

	run := &Run{
		ID:        uuid.New().String(),
		PolicyID:  policyName,
		Status:    RunStatusRunning,
		Metadata:  metadata,
		CreatedAt: now.UTC().UnixNano(),
		UpdatedAt: now.UTC().UnixNano(),
	}

	// Initialize policy map if needed
	if rs.runs[policyName] == nil {
		rs.runs[policyName] = make(map[string][]*Run)
	}

	// Add run to the target's run list
	runs := rs.runs[policyName][normalizedTarget]
	runs = append(runs, run)

	// Keep only the last maxRunsPerTarget runs
	if len(runs) > maxRunsPerTarget {
		runs = runs[len(runs)-maxRunsPerTarget:]
	}

	rs.runs[policyName][normalizedTarget] = runs
	// Return a deep copy to prevent race conditions
	return copyRun(run)
}

// UpdateRun updates the status of a run
func (rs *RunStore) UpdateRun(policyName, target string, port uint16, runID string, status RunStatus, err error, entityCount int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.runs[policyName] == nil {
		return
	}

	// Normalize target for lookup (includes port)
	normalizedTarget := normalizeTarget(target, port)

	runs := rs.runs[policyName][normalizedTarget]
	for _, run := range runs {
		if run.ID == runID {
			run.Status = status
			run.EntityCount = entityCount
			run.UpdatedAt = time.Now().UTC().UnixNano()
			if err != nil {
				run.Reason = err.Error()
			} else {
				run.Reason = "" // Clear reason when no error
			}
			return
		}
	}
}

// GetRunsForTarget returns all runs for a given policy and target
func (rs *RunStore) GetRunsForTarget(policyName string, target string, port uint16) []*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.runs[policyName] == nil {
		return []*Run{} // Return empty slice, not nil, for consistent JSON serialization
	}

	// Normalize target for lookup (includes port)
	normalizedTarget := normalizeTarget(target, port)

	runs := rs.runs[policyName][normalizedTarget]
	// Return deep copies to avoid race conditions
	result := make([]*Run, len(runs))
	for i, run := range runs {
		result[i] = copyRun(run)
	}
	return result
}

// GetRunsForPolicy returns all runs for a given policy (flattened across all targets)
func (rs *RunStore) GetRunsForPolicy(policyName string) []*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	if rs.runs[policyName] == nil {
		return []*Run{} // Return empty slice, not nil, for consistent JSON serialization
	}

	// Aggregate runs from all targets into a flat list (deep copy to avoid race conditions)
	result := make([]*Run, 0) // Initialize as empty slice, not nil
	for _, targetRuns := range rs.runs[policyName] {
		for _, run := range targetRuns {
			result = append(result, copyRun(run))
		}
	}

	// Sort by CreatedAt descending (newest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt > result[j].CreatedAt
	})

	return result
}

// GetAllPoliciesWithRuns returns all policies with their runs (flattened per policy)
func (rs *RunStore) GetAllPoliciesWithRuns() map[string][]*Run {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	result := make(map[string][]*Run)
	for policyName, targets := range rs.runs {
		// Flatten all targets' runs into a single array (deep copy to avoid race conditions)
		runs := make([]*Run, 0) // Initialize as empty slice, not nil
		for _, targetRuns := range targets {
			for _, run := range targetRuns {
				runs = append(runs, copyRun(run))
			}
		}

		// Sort runs for consistent ordering (newest first)
		sort.Slice(runs, func(i, j int) bool {
			return runs[i].CreatedAt > runs[j].CreatedAt
		})

		result[policyName] = runs
	}
	return result
}
