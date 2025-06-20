package backend

import (
	"github.com/go-cmd/cmd"
)

// Commander abstracts the functionality from go-cmd/cmd package
type Commander interface {
	Start() <-chan CmdStatus
	Stop() error
	Status() CmdStatus

	// For accessing output channels
	GetStdout() <-chan string
	GetStderr() <-chan string
}

// CmdStatus holds the status of a command
type CmdStatus struct {
	PID      int   // Process ID of command
	Complete bool  // Whether the command has completed
	Exit     int   // Exit code of the command
	Error    error // Go error
	StopTs   int64 // Timestamp when the command was stopped
}

// CmdOptions holds the options for command execution
type CmdOptions struct {
	Buffered  bool // Whether to buffer the output
	Streaming bool // Whether to stream the output
}

// NewCmdOptions creates a new command with specific options
var NewCmdOptions = func(options CmdOptions, name string, args ...string) Commander {
	cmdOptions := cmd.Options{
		Buffered:  options.Buffered,
		Streaming: options.Streaming,
	}
	return &CmdWrapper{Cmd: cmd.NewCmdOptions(cmdOptions, name, args...)}
}

// CmdWrapper wraps the cmd.Cmd struct to implement CmdInterface
type CmdWrapper struct {
	*cmd.Cmd
}

// ConvertStatus converts cmd.Status to our Status
func ConvertStatus(status cmd.Status) CmdStatus {
	return CmdStatus{
		PID:      status.PID,
		Complete: status.Complete,
		Exit:     status.Exit,
		Error:    status.Error,
		StopTs:   status.StopTs,
	}
}

// Start starts the command and returns a channel for its status
func (c *CmdWrapper) Start() <-chan CmdStatus {
	statusChan := make(chan CmdStatus, 1)
	origChan := c.Cmd.Start()

	go func() {
		status := <-origChan
		statusChan <- ConvertStatus(status)
		close(statusChan)
	}()

	return statusChan
}

// Stop stops the running command
func (c *CmdWrapper) Stop() error {
	return c.Cmd.Stop()
}

// Status returns the current command status
func (c *CmdWrapper) Status() CmdStatus {
	return ConvertStatus(c.Cmd.Status())
}

// GetStdout returns the stdout channel
func (c *CmdWrapper) GetStdout() <-chan string {
	return c.Cmd.Stdout
}

// GetStderr returns the stderr channel
func (c *CmdWrapper) GetStderr() <-chan string {
	return c.Cmd.Stderr
}
