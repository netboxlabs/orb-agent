package backend

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// PolicyStatusRun represents a run in the backend status response
type PolicyStatusRun struct {
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Reason      string            `json:"reason"`
	EntityCount int64             `json:"entity_count,omitzero"`
	CreatedAt   int64             `json:"created_at"` // nanoseconds since epoch
	UpdatedAt   int64             `json:"updated_at"` // nanoseconds since epoch
	Targets     []string          `json:"targets,omitempty"`
	Driver      string            `json:"driver,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PolicyStatus represents policy status from backend status endpoint
type PolicyStatus struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Runs   []PolicyStatusRun `json:"runs"`
}

// StatusResponse represents the full status response from backend
type StatusResponse struct {
	Version       string         `json:"version"`
	StartTime     time.Time      `json:"start_time"`
	UpTimeSeconds float64        `json:"up_time_seconds"`
	Policies      []PolicyStatus `json:"policies"`
}

// PolicyStatusProvider is an optional interface for backends that support policy status polling
type PolicyStatusProvider interface {
	GetPolicyStatus() ([]PolicyStatus, error)
}

// Running Status types
const (
	Unknown RunningStatus = iota
	Running
	BackendError
	AgentError
	Offline
	Waiting
)

// RunningStatus is the status of the backend
type RunningStatus int

var runningStatusMap = [...]string{
	"unknown",
	"running",
	"backend_error",
	"agent_error",
	"offline",
	"waiting",
}

// State represents the state of the backend
type State struct {
	Status            RunningStatus
	RestartCount      int64
	LastError         string
	LastRestartTS     time.Time
	LastRestartReason string
}

func (s RunningStatus) String() string {
	return runningStatusMap[s]
}

// Backend is the interface that all backends must implement
type Backend interface {
	Configure(*slog.Logger, policies.PolicyRepo, map[string]any, config.BackendCommons, filesmgr.Manager) error
	Version() (string, error)
	Start(ctx context.Context, cancelFunc context.CancelFunc) error
	Stop(ctx context.Context) error
	FullReset(ctx context.Context) error

	GetStartTime() time.Time
	GetCapabilities() (map[string]any, error)
	GetRunningStatus() (RunningStatus, string, error)
	GetInitialState() RunningStatus

	ApplyPolicy(data policies.PolicyData, updatePolicy bool) error
	RemovePolicy(data policies.PolicyData) error
}

var registry = make(map[string]Backend)

// Register registers backend
func Register(name string, b Backend) {
	registry[name] = b
}

// GetList returns list of registered backends
func GetList() []string {
	keys := make([]string, 0, len(registry))
	for k := range registry {
		keys = append(keys, k)
	}
	return keys
}

// HaveBackend checks if backend is registered
func HaveBackend(name string) bool {
	_, prs := registry[name]
	return prs
}

// GetBackend returns a registered backend
func GetBackend(name string) Backend {
	return registry[name]
}

// RestartAll restarts all backends
func RestartAll(ctx context.Context) error {
	errs := make([]error, 0)
	for _, be := range registry {
		err := be.FullReset(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
