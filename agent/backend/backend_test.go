package backend_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockBackend implements the Backend interface for testing
type mockBackend struct {
	mock.Mock
}

func (m *mockBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo, config map[string]any, commons config.BackendCommons) error {
	args := m.Called(logger, repo, config, commons)
	return args.Error(0)
}

func (m *mockBackend) Version() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	args := m.Called(ctx, cancelFunc)
	return args.Error(0)
}

func (m *mockBackend) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) FullReset(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBackend) GetStartTime() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *mockBackend) GetCapabilities() (map[string]any, error) {
	args := m.Called()
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *mockBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus), args.String(1), args.Error(2)
}

func (m *mockBackend) GetInitialState() backend.RunningStatus {
	args := m.Called()
	return args.Get(0).(backend.RunningStatus)
}

func (m *mockBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	args := m.Called(data, updatePolicy)
	return args.Error(0)
}

func (m *mockBackend) RemovePolicy(data policies.PolicyData) error {
	args := m.Called(data)
	return args.Error(0)
}

func (m *mockBackend) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]backend.PolicyStatus), args.Error(1)
}

func TestRestartAll_NoBackends(t *testing.T) {
	// This test assumes no backends are registered
	// In a real scenario, we'd need to clear the registry first
	// For now, we'll test with a fresh context
	ctx := context.Background()

	// Act
	err := backend.RestartAll(ctx)

	// Assert
	// Should succeed even with no backends or with existing backends
	// The function handles empty registry gracefully
	assert.NoError(t, err)
}

func TestRestartAll_MultipleBackendsSuccess(t *testing.T) {
	// Arrange
	ctx := context.Background()

	mockBe1 := &mockBackend{}
	mockBe2 := &mockBackend{}
	mockBe3 := &mockBackend{}

	// Register test backends
	backend.Register("test_backend_restart_1", mockBe1)
	backend.Register("test_backend_restart_2", mockBe2)
	backend.Register("test_backend_restart_3", mockBe3)

	// Setup expectations - all succeed
	mockBe1.On("FullReset", ctx).Return(nil)
	mockBe2.On("FullReset", ctx).Return(nil)
	mockBe3.On("FullReset", ctx).Return(nil)

	// Act
	err := backend.RestartAll(ctx)

	// Assert
	assert.NoError(t, err)
	mockBe1.AssertExpectations(t)
	mockBe2.AssertExpectations(t)
	mockBe3.AssertExpectations(t)
}

func TestRestartAll_OneBackendFails(t *testing.T) {
	// Arrange
	ctx := context.Background()

	mockBe1 := &mockBackend{}
	mockBe2 := &mockBackend{}
	mockBe3 := &mockBackend{}

	// Register test backends
	backend.Register("test_backend_fail_1", mockBe1)
	backend.Register("test_backend_fail_2", mockBe2)
	backend.Register("test_backend_fail_3", mockBe3)

	expectedErr := errors.New("backend reset failed")

	// Setup expectations - one fails
	mockBe1.On("FullReset", ctx).Return(nil)
	mockBe2.On("FullReset", ctx).Return(expectedErr)
	mockBe3.On("FullReset", ctx).Return(nil)

	// Act
	err := backend.RestartAll(ctx)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend reset failed")
	mockBe1.AssertExpectations(t)
	mockBe2.AssertExpectations(t)
	mockBe3.AssertExpectations(t)
}

func TestRestartAll_MultipleBackendsFail(t *testing.T) {
	// Arrange
	ctx := context.Background()

	mockBe1 := &mockBackend{}
	mockBe2 := &mockBackend{}
	mockBe3 := &mockBackend{}

	// Register test backends
	backend.Register("test_backend_multifail_1", mockBe1)
	backend.Register("test_backend_multifail_2", mockBe2)
	backend.Register("test_backend_multifail_3", mockBe3)

	err1 := errors.New("backend 1 reset failed")
	err2 := errors.New("backend 2 reset failed")

	// Setup expectations - two fail
	mockBe1.On("FullReset", ctx).Return(err1)
	mockBe2.On("FullReset", ctx).Return(err2)
	mockBe3.On("FullReset", ctx).Return(nil)

	// Act
	err := backend.RestartAll(ctx)

	// Assert
	assert.Error(t, err)
	// errors.Join creates an error that contains all errors
	assert.Contains(t, err.Error(), "backend 1 reset failed")
	assert.Contains(t, err.Error(), "backend 2 reset failed")
	mockBe1.AssertExpectations(t)
	mockBe2.AssertExpectations(t)
	mockBe3.AssertExpectations(t)
}

func TestBackendRegistry_GetList(t *testing.T) {
	// Test that GetList returns registered backends
	list := backend.GetList()
	assert.NotNil(t, list)
	// Should contain at least the backends we registered in previous tests
	assert.Greater(t, len(list), 0)
}

func TestBackendRegistry_HaveBackend(t *testing.T) {
	// Arrange
	mockBe := &mockBackend{}
	backend.Register("test_backend_exists", mockBe)

	// Act & Assert
	assert.True(t, backend.HaveBackend("test_backend_exists"))
	assert.False(t, backend.HaveBackend("nonexistent_backend"))
}

func TestBackendRegistry_GetBackend(t *testing.T) {
	// Arrange
	mockBe := &mockBackend{}
	backend.Register("test_backend_get", mockBe)

	// Act
	retrievedBackend := backend.GetBackend("test_backend_get")

	// Assert
	assert.NotNil(t, retrievedBackend)
	assert.Equal(t, mockBe, retrievedBackend)
}

func TestRunningStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   backend.RunningStatus
		expected string
	}{
		{
			name:     "Unknown status",
			status:   backend.Unknown,
			expected: "unknown",
		},
		{
			name:     "Running status",
			status:   backend.Running,
			expected: "running",
		},
		{
			name:     "BackendError status",
			status:   backend.BackendError,
			expected: "backend_error",
		},
		{
			name:     "AgentError status",
			status:   backend.AgentError,
			expected: "agent_error",
		},
		{
			name:     "Offline status",
			status:   backend.Offline,
			expected: "offline",
		},
		{
			name:     "Waiting status",
			status:   backend.Waiting,
			expected: "waiting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.status.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	os.Exit(code)
}
