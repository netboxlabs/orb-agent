package backend

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// MinRestartTime is the minimum time to wait between restarts
const MinRestartTime = 5 * time.Minute

// BackendMonitorInterval is the interval at which to monitor backends
const BackendMonitorInterval = 10 * time.Second

// newMonitorTicker is a seam for tests: production code gets a real ticker,
// tests install a function that hands back a channel they control.
var newMonitorTicker = func(interval time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(interval)
	return t.C, t.Stop
}

// StateRetriever provides an interface for accessing backend state information
type StateRetriever interface {
	Get() map[string]*State
}

// StateManager provides an interface for managing backend state information
type StateManager interface {
	StateRetriever
	StartBackendMonitor(name string, be Backend)
	RegisterError(name string, errMessage string)
	RegisterRestart(name string, reason string)
}

// StateManager manages the state and monitoring of backends
type stateManager struct {
	backendState       map[string]*State
	mu                 sync.RWMutex
	logger             *slog.Logger
	restartBackendChan chan string
	policyRepo         policies.PolicyRepo
}

// NewStateManager creates a new StateManager with the given logger and restart channel
func NewStateManager(activeConfigMgr string, logger *slog.Logger, restartBackendChan chan string, policyRepo policies.PolicyRepo) StateManager {
	if configMgrSupportsStateMonitoring(activeConfigMgr) {
		return &stateManager{
			backendState:       make(map[string]*State),
			logger:             logger,
			restartBackendChan: restartBackendChan,
			policyRepo:         policyRepo,
		}
	}
	return nullStateManager{}
}

func configMgrSupportsStateMonitoring(activeConfigMgr string) bool {
	return activeConfigMgr == "fleet"
}

type nullStateManager struct{}

var _ StateManager = nullStateManager{}

func (n nullStateManager) Get() map[string]*State {
	return make(map[string]*State)
}

func (n nullStateManager) StartBackendMonitor(_ string, _ Backend) {}

func (n nullStateManager) RegisterError(_ string, _ string) {}

func (n nullStateManager) RegisterRestart(_ string, _ string) {}

// StartBackendMonitor starts monitoring a backend and manages its state
func (manager *stateManager) StartBackendMonitor(name string, be Backend) {
	manager.mu.Lock()
	manager.backendState[name] = &State{
		Status:        be.GetInitialState(),
		LastRestartTS: time.Now(),
	}
	manager.mu.Unlock()

	ticks, stop := newMonitorTicker(BackendMonitorInterval)
	go func() {
		defer stop()
		for range ticks {
			// The status call is an HTTP request for several backends, so it runs
			// outside the lock; a RegisterError landing between this read and the
			// write below is overwritten until the next tick, which is accepted.
			backendStatus, errMsg, err := be.GetRunningStatus()
			restart := false
			manager.mu.Lock()
			manager.backendState[name].Status = backendStatus
			if backendStatus != Running {
				if err != nil {
					manager.backendState[name].LastError = fmt.Sprintf("failed to retrieve backend status: %v", err)
				} else if errMsg != "" {
					manager.backendState[name].LastError = errMsg
				}
				// status is not running so we have a current error
				if time.Since(be.GetStartTime()) >= MinRestartTime {
					restart = true
				} else {
					remainingSecondsUntilRestart := MinRestartTime - time.Since(be.GetStartTime())
					manager.logger.Info("waiting to attempt backend restart due to failed status", "remaining_secs", remainingSecondsUntilRestart, "backend", name)
				}
			}
			manager.mu.Unlock()

			if restart {
				// Outside the lock, and never blocking: a consumer that has
				// fallen behind must not freeze every reader of the state.
				select {
				case manager.restartBackendChan <- name:
				default:
					manager.logger.Debug("restart already queued for this backend, request dropped until the next tick", "backend", name)
				}
				if err != nil {
					manager.logger.Error("failed to read backend status", "error", err, "backend", name)
				}
			}

			// Poll policy status if backend supports it
			if provider, ok := be.(PolicyStatusProvider); ok && manager.policyRepo != nil {
				statuses, err := provider.GetPolicyStatus()
				if err != nil {
					manager.logger.Debug("failed to get policy status", "backend", name, "error", err)
				} else {
					for _, ps := range statuses {
						runs := convertToRunData(ps.Runs)
						if err := manager.policyRepo.UpdateRuns(ps.Name, runs); err != nil {
							manager.logger.Debug("failed to update runs for policy", "policy", ps.Name, "error", err)
						}
					}
				}
			}
		}
	}()
}

// RegisterError records a failure on a backend's entry. A new entry is
// stamped with the time, as before, since the failure is the first thing
// known about the backend; an existing one keeps its restart count, time
// and reason, which belong to RegisterRestart, so a failed retry does not
// erase the restarts before it.
func (manager *stateManager) RegisterError(name string, errMessage string) {
	manager.logger.Error(errMessage, "backend", name)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state, ok := manager.backendState[name]
	if !ok {
		state = &State{LastRestartTS: time.Now()}
		manager.backendState[name] = state
	}
	state.Status = BackendError
	state.LastError = errMessage
}

// RegisterRestart registers a restart event for a backend
func (manager *stateManager) RegisterRestart(name string, reason string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	// A restart can be asked for before the monitor registered the backend.
	if manager.backendState[name] == nil {
		manager.backendState[name] = &State{Status: Unknown}
	}
	manager.backendState[name].RestartCount++
	manager.backendState[name].LastRestartTS = time.Now()
	manager.backendState[name].LastRestartReason = reason
}

// Get returns the current state of all backends
func (manager *stateManager) Get() map[string]*State {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	// Return a copy of the map to prevent external modification
	result := make(map[string]*State, len(manager.backendState))
	for k, v := range manager.backendState {
		// Copy the state to prevent external modification
		stateCopy := *v
		result[k] = &stateCopy
	}
	return result
}

// nsToTime converts a nanosecond Unix timestamp to time.Time.
// A zero value is treated as "not provided" and returns the zero time.Time,
// so that downstream IsZero() checks (e.g. in UpdateRuns) still fire correctly.
func nsToTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

// convertToRunData converts backend PolicyStatusRun to policies.RunData.
// All discovery backends emit created_at/updated_at as nanoseconds since epoch;
// convert them to time.Time here so the rest of the agent works with time.Time.
func convertToRunData(statusRuns []PolicyStatusRun) []policies.RunData {
	runs := make([]policies.RunData, len(statusRuns))
	for i, sr := range statusRuns {
		targets := sr.Targets
		if sr.Targets == nil {
			targets = targetsFromMetadata(sr.Metadata)
		}
		runs[i] = policies.RunData{
			ID:          sr.ID,
			Status:      sr.Status,
			Reason:      sr.Reason,
			EntityCount: sr.EntityCount,
			CreatedAt:   nsToTime(sr.CreatedAt),
			UpdatedAt:   nsToTime(sr.UpdatedAt),
			Targets:     targets,
			Driver:      sr.Driver,
			Kind:        sr.Kind,
		}
	}
	return runs
}

// targetsFromMetadata extracts a targets list from the metadata map emitted by
// discovery backends that have not yet adopted the top-level targets field.
// network-discovery v1.x encodes targets as a JSON array string at metadata["targets"].
func targetsFromMetadata(meta map[string]string) []string {
	if len(meta) == 0 {
		return nil
	}
	raw, ok := meta["targets"]
	if !ok || raw == "" {
		return nil
	}
	var targets []string
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		return nil
	}
	return targets
}
