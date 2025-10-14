package backend

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// MinRestartTime is the minimum time to wait between restarts
const MinRestartTime = 5 * time.Minute

// BackendMonitorInterval is the interval at which to monitor backends
const BackendMonitorInterval = 10 * time.Second

// StateRetriever provides an interface for accessing backend state information
type StateRetriever interface {
	Get() map[string]*State
}

// StateManager manages the state and monitoring of backends
type StateManager struct {
	backendState       map[string]*State
	mu                 sync.RWMutex
	ticker             *time.Ticker
	logger             *slog.Logger
	restartBackendChan chan string
}

// NewStateManager creates a new StateManager with the given logger and restart channel
func NewStateManager(logger *slog.Logger, restartBackendChan chan string) *StateManager {
	return &StateManager{
		backendState:       make(map[string]*State),
		ticker:             time.NewTicker(BackendMonitorInterval),
		logger:             logger,
		restartBackendChan: restartBackendChan,
	}
}

// StartBackendMonitor starts monitoring a backend and manages its state
func (manager *StateManager) StartBackendMonitor(name string, be Backend) {
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
		}
	}()
}

// RegisterError registers an error for a backend and updates its state
func (manager *StateManager) RegisterError(name string, errMessage string) {
	manager.logger.Error(errMessage, slog.String("backend", name))
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.backendState[name] = &State{
		Status:        BackendError,
		LastError:     errMessage,
		LastRestartTS: time.Now(),
	}
}

// RegisterRestart registers a restart event for a backend
func (manager *StateManager) RegisterRestart(name string, reason string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.backendState[name].RestartCount++
	manager.backendState[name].LastRestartTS = time.Now()
	manager.backendState[name].LastRestartReason = reason
}

// Get returns the current state of all backends
func (manager *StateManager) Get() map[string]*State {
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
