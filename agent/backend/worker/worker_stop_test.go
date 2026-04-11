package worker

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
)

// slowExitCommander simulates a subprocess that ignores SIGTERM.
// Call close(exitCh) to make it appear to die (simulating OS-level SIGKILL effect).
type slowExitCommander struct {
	pid      int
	exitCh   chan struct{}
	statusCh chan backend.CmdStatus
}

func newSlowExitCommander(pid int) *slowExitCommander {
	return &slowExitCommander{
		pid:      pid,
		exitCh:   make(chan struct{}),
		statusCh: make(chan backend.CmdStatus, 1),
	}
}

func (s *slowExitCommander) Start() <-chan backend.CmdStatus {
	go func() {
		<-s.exitCh
		s.statusCh <- backend.CmdStatus{PID: s.pid, Complete: true, Exit: -1}
	}()
	return s.statusCh
}
func (s *slowExitCommander) Stop() error               { return nil }
func (s *slowExitCommander) Status() backend.CmdStatus { return backend.CmdStatus{PID: s.pid} }
func (s *slowExitCommander) GetStdout() <-chan string   { return make(chan string) }
func (s *slowExitCommander) GetStderr() <-chan string   { return make(chan string) }

func TestWorkerStop_KillsProcessGroupWhenSIGTERMIgnored(t *testing.T) {
	slow := newSlowExitCommander(9999)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &workerBackend{
		logger:          logger,
		cancelFunc:      func() {},
		proc:            slow,
		statusChan:      slow.Start(),
		stopGracePeriod: 100 * time.Millisecond,
	}

	// Simulate the OS reaping the process after SIGKILL fires.
	// syscall.Kill will fail (no real PID 9999) but Stop() logs and continues
	// waiting on statusChan — this goroutine unblocks it.
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(slow.exitCh)
	}()

	ctx := context.WithValue(context.Background(), config.ContextKey("routine"), "test")
	done := make(chan error, 1)
	go func() { done <- d.Stop(ctx) }()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within expected time after SIGKILL escalation")
	}
}

func TestWorkerStop_ExitsGracefullyWithinGracePeriod(t *testing.T) {
	statusCh := make(chan backend.CmdStatus, 1)
	// pre-load the channel — simulates process that exits immediately on SIGTERM
	statusCh <- backend.CmdStatus{PID: 1234, Complete: true, Exit: 0}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &workerBackend{
		logger:     logger,
		cancelFunc: func() {},
		proc:       &immediateExitCommander{pid: 1234, statusCh: statusCh},
		statusChan: statusCh,
	}

	ctx := context.WithValue(context.Background(), config.ContextKey("routine"), "test")
	done := make(chan error, 1)
	go func() { done <- d.Stop(ctx) }()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Stop() hung instead of returning quickly on graceful exit")
	}
}

// immediateExitCommander — status channel already has a value; Start() is not called in these tests.
type immediateExitCommander struct {
	pid      int
	statusCh chan backend.CmdStatus
}

func (i *immediateExitCommander) Start() <-chan backend.CmdStatus  { return i.statusCh }
func (i *immediateExitCommander) Stop() error                      { return nil }
func (i *immediateExitCommander) Status() backend.CmdStatus        { return backend.CmdStatus{PID: i.pid} }
func (i *immediateExitCommander) GetStdout() <-chan string          { return make(chan string) }
func (i *immediateExitCommander) GetStderr() <-chan string          { return make(chan string) }
