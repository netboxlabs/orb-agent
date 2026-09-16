package backend_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockBackend implements the Backend interface for testing
type mockBackend struct {
	mock.Mock
}

func (m *mockBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo, config map[string]any, commons config.BackendCommons, _ filesmgr.Manager) error {
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

func TestBackendRegistry_GetList(t *testing.T) {
	// Test that GetList returns registered backends. Register one of its own
	// rather than relying on registrations left behind by tests that happen
	// to run earlier in the same package.
	mockBe := &mockBackend{}
	backend.Register("test_backend_get_list", mockBe)
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	list := backend.GetList()
	assert.NotNil(t, list)
	assert.Greater(t, len(list), 0)
}

func TestBackendRegistry_HaveBackend(t *testing.T) {
	// Arrange
	mockBe := &mockBackend{}
	backend.Register("test_backend_exists", mockBe)
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

	// Act & Assert
	assert.True(t, backend.HaveBackend("test_backend_exists"))
	assert.False(t, backend.HaveBackend("nonexistent_backend"))
}

func TestBackendRegistry_GetBackend(t *testing.T) {
	// Arrange
	mockBe := &mockBackend{}
	backend.Register("test_backend_get", mockBe)
	mockBe.On("GetRunningStatus").Return(backend.Running, "", nil).Maybe()

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

// A second StopProcess call against a mock whose one status was already
// delivered must return at once: SetupSuccessfulProcess closes its status
// channel after sending, mirroring CmdWrapper.Start, so a stale receive
// never makes a caller wait out the real grace period or attempt to SIGKILL
// a fabricated PID.
func TestStopProcessReturnsAtOnceOnASecondCallAgainstAClosedMockChannel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)
	statusCh := mockCmd.Start()

	backend.StopProcess(logger, mockCmd, statusCh, 5*time.Second, "test-backend")

	done := make(chan struct{})
	go func() {
		backend.StopProcess(logger, mockCmd, statusCh, 5*time.Second, "test-backend")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("second StopProcess call did not return within 100ms; the mock's status channel is still open")
	}
}
