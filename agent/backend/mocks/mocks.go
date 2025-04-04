package mocks

import (
	"errors"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

// MockCmd is a testify-based mock implementation of backend.CmdInterface
type MockCmd struct {
	mock.Mock
}

// Start mocks the Start method
func (m *MockCmd) Start() <-chan backend.CmdStatus {
	args := m.Called()
	return args.Get(0).(<-chan backend.CmdStatus)
}

// Stop mocks the Stop method
func (m *MockCmd) Stop() error {
	args := m.Called()
	return args.Error(0)
}

// Status mocks the Status method
func (m *MockCmd) Status() backend.CmdStatus {
	args := m.Called()
	return args.Get(0).(backend.CmdStatus)
}

// GetStdout mocks the GetStdout method
func (m *MockCmd) GetStdout() <-chan string {
	args := m.Called()
	return args.Get(0).(<-chan string)
}

// GetStderr mocks the GetStderr method
func (m *MockCmd) GetStderr() <-chan string {
	args := m.Called()
	return args.Get(0).(<-chan string)
}

// SetupSuccessfulProcess configures the mock for a successful running process
func SetupSuccessfulProcess(mockCmd *MockCmd, pid int) (<-chan string, <-chan string) {
	// Create status channel - create it as bidirectional first
	statusCh := make(chan backend.CmdStatus, 1)
	// Create a receive-only channel to return from the mock
	var readOnlyStatusCh <-chan backend.CmdStatus = statusCh

	status := backend.CmdStatus{
		PID:      pid,
		Complete: false,
		Exit:     -1, // Not completed yet
		Error:    nil,
	}

	// Create stdout/stderr channels
	stdoutCh := make(chan string, 10)
	stderrCh := make(chan string, 10)

	// Create read-only versions of stdout/stderr channels
	var readOnlyStdoutCh <-chan string = stdoutCh
	var readOnlyStderrCh <-chan string = stderrCh

	// Configure mock behavior - pass the read-only channels
	mockCmd.On("Start").Return(readOnlyStatusCh)
	mockCmd.On("Status").Return(status)
	mockCmd.On("GetStdout").Return(readOnlyStdoutCh)
	mockCmd.On("GetStderr").Return(readOnlyStderrCh)
	mockCmd.On("Stop").Return(nil)

	// Send the status in another goroutine to simulate async behavior
	go func() {
		// Delay before sending to simulate process startup
		time.Sleep(10 * time.Millisecond)
		statusCh <- status
	}()

	return readOnlyStdoutCh, readOnlyStderrCh
}

// SetupCompletedProcess configures the mock for a process that has completed
func SetupCompletedProcess(mockCmd *MockCmd, exitCode int, err error) {
	// Create status channel
	statusCh := make(chan backend.CmdStatus, 1)
	// Create a read-only view of the channel
	var readOnlyStatusCh <-chan backend.CmdStatus = statusCh

	status := backend.CmdStatus{
		PID:      12345, // Example PID
		Complete: true,
		Exit:     exitCode,
		Error:    err,
		StopTs:   time.Now().UnixNano(),
	}

	// Empty channels for stdout/stderr since process is complete
	stdoutCh := make(chan string)
	stderrCh := make(chan string)

	// Create read-only versions
	var readOnlyStdoutCh <-chan string = stdoutCh
	var readOnlyStderrCh <-chan string = stderrCh

	// Configure mock behavior
	mockCmd.On("Start").Return(readOnlyStatusCh)
	mockCmd.On("Status").Return(status)
	mockCmd.On("Stop").Return(nil)

	mockCmd.On("GetStdout").Return(readOnlyStdoutCh)
	mockCmd.On("GetStderr").Return(readOnlyStderrCh)

	// Close the channels
	close(stdoutCh)
	close(stderrCh)

	// Send status immediately
	go func() {
		statusCh <- status
	}()
}

// SetupFailingProcess configures the mock for a process that fails to start
func SetupFailingProcess(mockCmd *MockCmd, errorMsg string) {
	// Create error
	cmdError := errors.New(errorMsg)

	// Create status channel
	statusCh := make(chan backend.CmdStatus, 1)
	// Create a read-only view of the channel
	var readOnlyStatusCh <-chan backend.CmdStatus = statusCh

	status := backend.CmdStatus{
		PID:      0,
		Complete: true,
		Exit:     1,
		Error:    cmdError,
		StopTs:   time.Now().UnixNano(),
	}

	// Empty channels for stdout/stderr
	stdoutCh := make(chan string)
	stderrCh := make(chan string)

	// Create read-only versions
	var readOnlyStdoutCh <-chan string = stdoutCh
	var readOnlyStderrCh <-chan string = stderrCh

	// Configure mock behavior
	mockCmd.On("Start").Return(readOnlyStatusCh)
	mockCmd.On("Status").Return(status)
	mockCmd.On("Stop").Return(nil)
	mockCmd.On("GetStdout").Return(readOnlyStdoutCh)
	mockCmd.On("GetStderr").Return(readOnlyStderrCh)

	// Close the channels
	close(stdoutCh)
	close(stderrCh)

	// Send status immediately
	go func() {
		statusCh <- status
	}()
}
