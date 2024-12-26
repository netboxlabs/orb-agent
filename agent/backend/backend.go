package backend

import (
	"context"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

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
	Configure(*zap.Logger, policies.PolicyRepo, map[string]interface{}, config.BackendCommons) error
	SetCommsClient(string, *mqtt.Client, string)
	Version() (string, error)
	Start(ctx context.Context, cancelFunc context.CancelFunc) error
	Stop(ctx context.Context) error
	FullReset(ctx context.Context) error

	GetStartTime() time.Time
	GetCapabilities() (map[string]interface{}, error)
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
