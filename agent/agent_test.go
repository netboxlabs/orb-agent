package agent

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
)

// mockConfigManager implements configmgr.Manager for testing Stop delegation
type mockConfigManager struct {
	stopCalled bool
}

func (m *mockConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	return nil
}
func (m *mockConfigManager) GetContext(ctx context.Context) context.Context { return ctx }
func (m *mockConfigManager) Stop(ctx context.Context) error                 { m.stopCalled = true; return nil }

func TestSetCommonConfigOverrides_FleetOverridesWhenEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a := &orbAgent{logger: logger, config: config.Config{OrbAgent: config.OrbAgent{ConfigManager: config.ManagerConfig{Active: "fleet"}}}}

	// commons without OTLP gRPC set
	commons := config.BackendCommons{}
	a.backendsCommon = commons

	a.setCommonConfigOverrides()

	// Expect override to local bridge address when fleet and empty
	assert.Equal(t, "grpc://localhost:4317", a.backendsCommon.Otlp.Grpc)
}

func TestSetCommonConfigOverrides_DoesNotOverrideWhenProvided(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a := &orbAgent{logger: logger, config: config.Config{OrbAgent: config.OrbAgent{ConfigManager: config.ManagerConfig{Active: "fleet"}}}}

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "grpc://remote:4317"
	a.backendsCommon = commons

	a.setCommonConfigOverrides()

	// Expect original value preserved
	assert.Equal(t, "grpc://remote:4317", a.backendsCommon.Otlp.Grpc)
}

func TestSetCommonConfigOverrides_NonFleet_NoOverride(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a := &orbAgent{logger: logger, config: config.Config{OrbAgent: config.OrbAgent{ConfigManager: config.ManagerConfig{Active: "local"}}}}

	commons := config.BackendCommons{}
	a.backendsCommon = commons

	a.setCommonConfigOverrides()

	// Expect unchanged (still empty)
	assert.Equal(t, "", a.backendsCommon.Otlp.Grpc)
}

func TestAgentStop_DelegatesToConfigManagerStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a := &orbAgent{logger: logger}

	mockMgr := &mockConfigManager{}
	// type assertion to satisfy compile-time check for interface
	var _ configmgr.Manager = mockMgr
	a.configManager = mockMgr

	// no backends running
	a.backends = map[string]backend.Backend{}

	a.Stop(context.Background())

	assert.True(t, mockMgr.stopCalled, "expected configManager.Stop to be called")
}
