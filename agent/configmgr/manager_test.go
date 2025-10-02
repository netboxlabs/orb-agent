package configmgr_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// Mock implementations for testing

type mockPolicyManager struct {
	mock.Mock
}

func (m *mockPolicyManager) ManagePolicy(payload config.PolicyPayload) {
	m.Called(payload)
}

func (m *mockPolicyManager) RemovePolicyDataset(policyID string, datasetID string, be backend.Backend) {
	m.Called(policyID, datasetID, be)
}

func (m *mockPolicyManager) GetPolicyState() ([]policies.PolicyData, error) {
	args := m.Called()
	return args.Get(0).([]policies.PolicyData), args.Error(1)
}

func (m *mockPolicyManager) GetRepo() policies.PolicyRepo {
	args := m.Called()
	return args.Get(0).(policies.PolicyRepo)
}

func (m *mockPolicyManager) ApplyBackendPolicies(be backend.Backend) error {
	args := m.Called(be)
	return args.Error(0)
}

func (m *mockPolicyManager) RemoveBackendPolicies(be backend.Backend, permanently bool) error {
	args := m.Called(be, permanently)
	return args.Error(0)
}

func (m *mockPolicyManager) RemovePolicy(policyID string, policyName string, beName string) error {
	args := m.Called(policyID, policyName, beName)
	return args.Error(0)
}

type mockBackend struct {
	mock.Mock
	name string
}

func (m *mockBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo, cfg map[string]any, commons config.BackendCommons) error {
	args := m.Called(logger, repo, cfg, commons)
	return args.Error(0)
}

func (m *mockBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	args := m.Called(ctx, cancelFunc)
	return args.Error(0)
}

func (m *mockBackend) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) GetStartTime() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *mockBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus), args.String(1), args.Error(2)
}

func (m *mockBackend) GetInitialState() backend.RunningStatus {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus)
}

func (m *mockBackend) Version() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockBackend) GetName() string {
	return m.name
}

func (m *mockBackend) GetCapabilities() (map[string]any, error) {
	args := m.Called()
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *mockBackend) FullReset(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) ApplyPolicy(policy policies.PolicyData, updatePolicy bool) error {
	args := m.Called(policy, updatePolicy)
	return args.Error(0)
}

func (m *mockBackend) RemovePolicy(policy policies.PolicyData) error {
	args := m.Called(policy)
	return args.Error(0)
}

// Test the manager.New function
func TestManagerNew(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	pMgr := new(mockPolicyManager)

	t.Run("LocalManager", func(t *testing.T) {
		cfg := config.ManagerConfig{
			Active: "local",
			Sources: config.Sources{
				Local: config.LocalManager{},
			},
		}

		mgr := configmgr.New(logger, pMgr, cfg.Active)
		assert.NotNil(t, mgr)
		// Check we got the expected implementation
		ctx := context.Background()
		resultCtx := mgr.GetContext(ctx)
		assert.Equal(t, ctx, resultCtx)
	})

	t.Run("GitManager", func(t *testing.T) {
		cfg := config.ManagerConfig{
			Active: "git",
			Sources: config.Sources{
				Git: config.GitManager{
					URL: "https://github.com/example/repo.git",
				},
			},
		}

		mgr := configmgr.New(logger, pMgr, cfg.Active)
		assert.NotNil(t, mgr)
		// Check we got the expected implementation
		ctx := context.Background()
		resultCtx := mgr.GetContext(ctx)
		assert.Equal(t, ctx, resultCtx)
	})

	t.Run("DefaultToLocalManager", func(t *testing.T) {
		cfg := config.ManagerConfig{
			Active: "unknown",
		}

		mgr := configmgr.New(logger, pMgr, cfg.Active)
		assert.NotNil(t, mgr)
		// Check we got the local implementation
		ctx := context.Background()
		resultCtx := mgr.GetContext(ctx)
		assert.Equal(t, ctx, resultCtx)
	})
}
