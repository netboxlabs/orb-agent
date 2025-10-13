package backend

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// MinRestartTime is the minimum time to wait between restarts
const MinRestartTime = 5 * time.Minute

// BackendState provides an interface for accessing backend state information
//
//nolint:revive // BackendState is intentionally named to distinguish from the State struct
type BackendState interface {
	Get() map[string]*State
}

// BackendStateManager manages the state and monitoring of backends
//
//nolint:revive // BackendStateManager is intentionally named to distinguish from the State struct
type BackendStateManager struct {
	backendState       map[string]*State
	mu                 sync.RWMutex
	ticker             *time.Ticker
	logger             *slog.Logger
	restartBackendChan chan string
}

// NewBackendStateManager creates a new BackendStateManager with the given logger and restart channel
func NewBackendStateManager(logger *slog.Logger, restartBackendChan chan string) *BackendStateManager {
	return &BackendStateManager{
		backendState:       make(map[string]*State),
		ticker:             time.NewTicker(10 * time.Second),
		logger:             logger,
		restartBackendChan: restartBackendChan,
	}
}

// StartBackendMonitor starts monitoring a backend and manages its state
func (manager *BackendStateManager) StartBackendMonitor(name string, be Backend) {
	manager.mu.Lock()
	manager.backendState[name] = &State{
		Status:        be.GetInitialState(),
		LastRestartTS: time.Now(),
	}
	manager.mu.Unlock()

	go func() {
		for range manager.ticker.C {
			backendStatus, errMsg, err := be.GetRunningStatus()

			manager.mu.Lock()
			manager.backendState[name].Status = backendStatus
			if backendStatus != Running {
				if err != nil {
					manager.backendState[name].LastError = fmt.Sprintf("failed to retrieve backend status: %v", err)
				} else if errMsg != "" {
					manager.backendState[name].LastError = errMsg
				}
				manager.mu.Unlock()

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
			} else {
				manager.mu.Unlock()
			}
		}
	}()
}

// RegisterError registers an error for a backend and updates its state
func (manager *BackendStateManager) RegisterError(name string, errMessage string) {
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
func (manager *BackendStateManager) RegisterRestart(name string, reason string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.backendState[name].RestartCount++
	manager.backendState[name].LastRestartTS = time.Now()
	manager.backendState[name].LastRestartReason = reason
}

// Get returns the current state of all backends
func (manager *BackendStateManager) Get() map[string]*State {
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
