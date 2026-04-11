package backend

import (
	"log/slog"
	"os"
	"testing"
	"time"

)

// slowCommander simulates a subprocess that ignores SIGTERM.
// Close exitCh to unblock it (simulates OS-level kill taking effect).
type slowCommander struct {
	pid      int
	exitCh   chan struct{}
	statusCh chan CmdStatus
}

func newSlowCommander(pid int) *slowCommander {
	return &slowCommander{
		pid:      pid,
		exitCh:   make(chan struct{}),
		statusCh: make(chan CmdStatus, 1),
	}
}

func (s *slowCommander) Start() <-chan CmdStatus {
	go func() {
		<-s.exitCh
		s.statusCh <- CmdStatus{PID: s.pid, Complete: true, Exit: -1}
	}()
	return s.statusCh
}
func (s *slowCommander) Stop() error           { return nil } // no-op: process ignores SIGTERM
func (s *slowCommander) Status() CmdStatus     { return CmdStatus{PID: s.pid} }
func (s *slowCommander) GetStdout() <-chan string { return make(chan string) }
func (s *slowCommander) GetStderr() <-chan string { return make(chan string) }

// fastCommander simulates a subprocess that exits immediately on SIGTERM.
type fastCommander struct {
	pid      int
	statusCh chan CmdStatus
}

func (f *fastCommander) Start() <-chan CmdStatus  { return f.statusCh }
func (f *fastCommander) Stop() error              { return nil }
func (f *fastCommander) Status() CmdStatus        { return CmdStatus{PID: f.pid} }
func (f *fastCommander) GetStdout() <-chan string  { return make(chan string) }
func (f *fastCommander) GetStderr() <-chan string  { return make(chan string) }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestStopProcess_GracefulExit(t *testing.T) {
	statusCh := make(chan CmdStatus, 1)
	statusCh <- CmdStatus{PID: 1234, Complete: true, Exit: 0}

	done := make(chan struct{})
	go func() {
		StopProcess(testLogger(), &fastCommander{pid: 1234, statusCh: statusCh}, statusCh, 5*time.Second, "test")
		close(done)
	}()

	select {
	case <-done:
		// passed: returned without waiting for grace period
	case <-time.After(time.Second):
		t.Fatal("StopProcess hung instead of returning quickly on graceful exit")
	}
}

func TestStopProcess_SIGKILLEscalationAfterGracePeriod(t *testing.T) {
	slow := newSlowCommander(9999)
	slow.Start()

	// Unblock statusChan after grace period elapses — simulates OS reaping the process after SIGKILL.
	// syscall.Kill(-9999, SIGKILL) will fail (no such process) but StopProcess logs and continues.
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(slow.exitCh)
	}()

	done := make(chan struct{})
	go func() {
		StopProcess(testLogger(), slow, slow.statusCh, 100*time.Millisecond, "test")
		close(done)
	}()

	select {
	case <-done:
		// passed: returned after SIGKILL escalation
	case <-time.After(2 * time.Second):
		t.Fatal("StopProcess did not return within expected time after SIGKILL escalation")
	}
}
