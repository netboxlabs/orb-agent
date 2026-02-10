package backend

import (
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
	ticker             *time.Ticker
	logger             *slog.Logger
	restartBackendChan chan string
	policyRepo         policies.PolicyRepo
}

// NewStateManager creates a new StateManager with the given logger and restart channel
func NewStateManager(activeConfigMgr string, logger *slog.Logger, restartBackendChan chan string, policyRepo policies.PolicyRepo) StateManager {
	if configMgrSupportsStateMonitoring(activeConfigMgr) {
		return &stateManager{
			backendState:       make(map[string]*State),
			ticker:             time.NewTicker(BackendMonitorInterval),
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

	go func() {
		for range manager.ticker.C {
			manager.mu.Lock()
			backendStatus, errMsg, err := be.GetRunningStatus()
			manager.backendState[name].Status = backendStatus
			if backendStatus != Running {
				if err != nil {
					manager.backendState[name].LastError = fmt.Sprintf("failed to retrieve backend status: %v", err)
				} else if errMsg != "" {
					manager.backendState[name].LastError = errMsg
				}

				// status is not running so we have a current error
				if time.Since(be.GetStartTime()) >= MinRestartTime {
					manager.restartBackendChan <- name
					if err != nil {
						manager.logger.Error("failed to restart backend", "error", err, "backend", name)
					}
				} else {
					remainingSecondsUntilRestart := MinRestartTime - time.Since(be.GetStartTime())
					manager.logger.Info("waiting to attempt backend restart due to failed status", "remaining_secs", remainingSecondsUntilRestart)
				}
			}
			manager.mu.Unlock()

			// Poll policy status if backend supports it
			if provider, ok := be.(PolicyStatusProvider); ok && manager.policyRepo != nil {
				statuses, err := provider.GetPolicyStatus()
				if err != nil {
					manager.logger.Debug("failed to get policy status", "backend", name, "error", err)
				} else {
					for _, ps := range statuses {
						existingRuns, err := getExistingRuns(manager.policyRepo, ps.Name)
						if err != nil {
							manager.logger.Debug("failed to get existing runs for policy", "policy", ps.Name, "error", err)
						}
						runs := convertToRunData(ps.Runs, existingRuns)
						if err := manager.policyRepo.UpdateRuns(ps.Name, runs); err != nil {
							manager.logger.Debug("failed to update runs for policy", "policy", ps.Name, "error", err)
						}
					}
				}
			}
		}
	}()
}

// RegisterError registers an error for a backend and updates its state
func (manager *stateManager) RegisterError(name string, errMessage string) {
	manager.logger.Error(errMessage, "backend", name)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.backendState[name] = &State{
		Status:        BackendError,
		LastError:     errMessage,
		LastRestartTS: time.Now(),
	}
}

// RegisterRestart registers a restart event for a backend
func (manager *stateManager) RegisterRestart(name string, reason string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
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

// getExistingRuns returns the existing runs for a policy by name.
// Returns nil runs and an error if the policy lookup fails.
func getExistingRuns(repo policies.PolicyRepo, policyName string) ([]policies.RunData, error) {
	policy, err := repo.GetByName(policyName)
	if err != nil {
		return nil, err
	}
	return policy.Runs, nil
}

// entityCountEqual compares two entity count pointers for equality
func entityCountEqual(a, b *int64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// convertToRunData converts backend PolicyStatusRun to policies.RunData.
// UpdatedAt is only updated when status, reason, or entity count have changed.
func convertToRunData(statusRuns []PolicyStatusRun, existingRuns []policies.RunData) []policies.RunData {
	existingByID := make(map[string]policies.RunData)
	for _, r := range existingRuns {
		existingByID[r.ID] = r
	}

	runs := make([]policies.RunData, len(statusRuns))
	for i, sr := range statusRuns {
		updatedAt := sr.UpdatedAt
		if existing, ok := existingByID[sr.ID]; ok {
			if sr.Status == existing.Status &&
				sr.Reason == existing.Reason &&
				entityCountEqual(sr.EntityCount, existing.EntityCount) {
				updatedAt = existing.UpdatedAt
			}
		}

		runs[i] = policies.RunData{
			ID:          sr.ID,
			Status:      sr.Status,
			Reason:      sr.Reason,
			EntityCount: sr.EntityCount,
			CreatedAt:   sr.CreatedAt,
			UpdatedAt:   updatedAt,
		}
	}
	return runs
}
