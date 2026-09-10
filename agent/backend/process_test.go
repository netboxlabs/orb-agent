package backend

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCommander is a controllable Commander for StartProcess tests. Its Status()
// is driven by statusFn (so tests can flip Complete on a chosen iteration), and
// it delivers a final CmdStatus on its status channel when Stop() is called so
// StopProcess's grace-period branch never blocks on the real 5s timer.
type fakeCommander struct {
	pid       int
	statusFn  func() CmdStatus
	statusCh  chan CmdStatus
	stdoutCh  chan string
	stderrCh  chan string
	stopCalls atomic.Int32

	mu          sync.Mutex
	finalSent   bool
	deliverStop bool // when true, Stop() pushes a final status so StopProcess returns promptly
}

func newFakeCommander(pid int) *fakeCommander {
	return &fakeCommander{
		pid:         pid,
		statusCh:    make(chan CmdStatus, 1),
		stdoutCh:    make(chan string, 8),
		stderrCh:    make(chan string, 8),
		deliverStop: true,
		statusFn:    func() CmdStatus { return CmdStatus{PID: pid} },
	}
}

func (f *fakeCommander) Start() <-chan CmdStatus { return f.statusCh }

func (f *fakeCommander) Stop() error {
	f.stopCalls.Add(1)
	if f.deliverStop {
		f.mu.Lock()
		if !f.finalSent {
			f.finalSent = true
			f.statusCh <- CmdStatus{PID: f.pid, Complete: true, Exit: 0}
			close(f.statusCh)
			close(f.stdoutCh)
			close(f.stderrCh)
		}
		f.mu.Unlock()
	}
	return nil
}

func (f *fakeCommander) Status() CmdStatus        { return f.statusFn() }
func (f *fakeCommander) GetStdout() <-chan string { return f.stdoutCh }
func (f *fakeCommander) GetStderr() <-chan string { return f.stderrCh }

// stubProcessTimers stubs the package-level startup wait + readiness sleep to
// no-ops so tests run instantly. NOT t.Parallel-safe — these are package vars,
// which -race would flag under parallel mutation; callers must not parallelize.
// The sleep stub ignores its context and always reports true, so a test that
// needs cancellation during a sleep must not use this helper.
func stubProcessTimers(t *testing.T) {
	t.Helper()
	origWait := startProcessStartupWait
	origSleep := startProcessSleep
	startProcessStartupWait = 0
	startProcessSleep = func(context.Context, time.Duration) bool { return true }
	t.Cleanup(func() {
		startProcessStartupWait = origWait
		startProcessSleep = origSleep
	})
}

// stubNewCmdOptions makes NewCmdOptions return the given Commander and records the
// exec + args it was called with.
func stubNewCmdOptions(t *testing.T, c Commander) *struct {
	exec string
	args []string
} {
	t.Helper()
	captured := &struct {
		exec string
		args []string
	}{}
	orig := NewCmdOptions
	NewCmdOptions = func(_ CmdOptions, name string, args ...string) Commander {
		captured.exec = name
		captured.args = args
		return c
	}
	t.Cleanup(func() { NewCmdOptions = orig })
	return captured
}

func testProcessLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestStartProcess_RequiredFieldsValidated(t *testing.T) {
	noop := func(string, bool) {}
	setProc := func(Commander, <-chan CmdStatus) {}
	ready := func() (string, error) { return "", nil }
	full := StartSpec{Logger: testProcessLogger(), SetProc: setProc, LogLine: noop, ReadinessCheck: ready}

	tests := []struct {
		name string
		spec StartSpec
	}{
		{"missing logger", func() StartSpec { s := full; s.Logger = nil; return s }()},
		{"missing setProc", func() StartSpec { s := full; s.SetProc = nil; return s }()},
		{"missing logLine", func() StartSpec { s := full; s.LogLine = nil; return s }()},
		{"missing readinessCheck", func() StartSpec { s := full; s.ReadinessCheck = nil; return s }()},
		{"zero spec", StartSpec{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := StartProcess(tc.spec)
			require.Error(t, err, "a missing required callback must error, not panic or spawn")
			assert.Contains(t, err.Error(), "required")
		})
	}
}

func TestStartProcess_Success(t *testing.T) {
	stubProcessTimers(t)

	fake := newFakeCommander(4242)
	// Always running.
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 4242} }
	stubNewCmdOptions(t, fake)

	var (
		setProcCalled atomic.Bool
		published     Commander
	)

	// Stream a couple of lines that LogLine must receive.
	fake.stdoutCh <- "hello-stdout"
	fake.stderrCh <- "oops-stderr"

	var (
		logMu       sync.Mutex
		stdoutLines []string
		stderrLines []string
	)

	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		Args:           []string{"--flag"},
		LogLine: func(line string, isStderr bool) {
			logMu.Lock()
			defer logMu.Unlock()
			if isStderr {
				stderrLines = append(stderrLines, line)
			} else {
				stdoutLines = append(stdoutLines, line)
			}
		},
		SetProc: func(c Commander, _ <-chan CmdStatus) {
			setProcCalled.Store(true)
			published = c
		},
		ReadinessCheck: func() (string, error) {
			return "1.2.3", nil
		},
	})

	require.NoError(t, err)
	assert.True(t, setProcCalled.Load(), "SetProc must be invoked")
	assert.Same(t, fake, published, "SetProc must publish the live proc")

	// Give the streaming goroutine a moment to drain the buffered lines.
	require.Eventually(t, func() bool {
		logMu.Lock()
		defer logMu.Unlock()
		return len(stdoutLines) == 1 && len(stderrLines) == 1
	}, time.Second, 5*time.Millisecond, "LogLine must receive streamed stdout+stderr lines")

	logMu.Lock()
	assert.Equal(t, []string{"hello-stdout"}, stdoutLines)
	assert.Equal(t, []string{"oops-stderr"}, stderrLines)
	logMu.Unlock()
}

// TestStartProcess_SetProcBeforeReadiness is the regression guard for the
// nil-proc readiness bug: SetProc MUST publish a non-nil, running Commander
// BEFORE the first ReadinessCheck call. The check records the proc it observes
// (via the SetProc-published value) and asserts it is the live one.
func TestStartProcess_SetProcBeforeReadiness(t *testing.T) {
	stubProcessTimers(t)

	fake := newFakeCommander(7)
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 7} }
	stubNewCmdOptions(t, fake)

	var (
		published      Commander
		procAtFirstChk Commander
		readinessCalls atomic.Int32
	)

	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "guard",
		NameUnderscore: "guard",
		Exec:           "guard-exec",
		LogLine:        func(string, bool) {},
		SetProc: func(c Commander, _ <-chan CmdStatus) {
			published = c
		},
		ReadinessCheck: func() (string, error) {
			if readinessCalls.Add(1) == 1 {
				// Record what SetProc published, observed at the first check.
				procAtFirstChk = published
			}
			return "v", nil
		},
	})

	require.NoError(t, err)
	require.NotNil(t, procAtFirstChk, "SetProc must run before the first ReadinessCheck")
	assert.Same(t, fake, procAtFirstChk, "ReadinessCheck must observe the live published proc, not nil")
	status, _, _ := GetRunningStatus(procAtFirstChk)
	assert.Equal(t, Running, status, "the proc observed by ReadinessCheck must be running")
}

func TestStartProcess_StartupCompleteError(t *testing.T) {
	stubProcessTimers(t)

	fake := newFakeCommander(99)
	// Process completes immediately (before the readiness loop is reached).
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 99, Complete: true, Exit: 1} }
	stubNewCmdOptions(t, fake)

	var readinessCalls atomic.Int32

	done := make(chan error, 1)
	go func() {
		done <- StartProcess(StartSpec{
			Logger:         testProcessLogger(),
			NameDisplay:    "test-backend",
			NameUnderscore: "test_backend",
			Exec:           "test-exec",
			LogLine:        func(string, bool) {},
			SetProc:        func(Commander, <-chan CmdStatus) {},
			ReadinessCheck: func() (string, error) {
				readinessCalls.Add(1)
				return "", nil
			},
		})
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.EqualError(t, err, "test-backend startup error, check log")
	case <-time.After(2 * time.Second):
		t.Fatal("StartProcess did not return promptly — StopProcess likely blocked on the grace period")
	}

	assert.GreaterOrEqual(t, fake.stopCalls.Load(), int32(1), "StopProcess must call proc.Stop on startup-complete")
	assert.Equal(t, int32(0), readinessCalls.Load(), "ReadinessCheck must not run when startup already completed")
}

func TestStartProcess_StartupError(t *testing.T) {
	stubProcessTimers(t)

	startupErr := errors.New("boom")
	fake := newFakeCommander(5)
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 5, Error: startupErr} }
	stubNewCmdOptions(t, fake)

	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		LogLine:        func(string, bool) {},
		SetProc:        func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "", nil },
	})

	// status.Error path returns the raw error (no StopProcess, matching the
	// original inline flow).
	require.ErrorIs(t, err, startupErr)
	assert.Equal(t, int32(0), fake.stopCalls.Load(), "startup-error path returns the raw error without StopProcess")
}

func TestStartProcess_ProcessEndedDuringReadiness(t *testing.T) {
	stubProcessTimers(t)

	fake := newFakeCommander(1234)
	var calls atomic.Int32
	// Running through the startup check + first iteration guard, then Complete on
	// the second iteration's guard.
	fake.statusFn = func() CmdStatus {
		n := calls.Add(1)
		// call 1: startup status check (running)
		// call 2: iteration 0 guard (running)
		// call 3+: iteration 1 guard (complete)
		if n >= 3 {
			return CmdStatus{PID: 1234, Complete: true, Exit: 2}
		}
		return CmdStatus{PID: 1234}
	}
	stubNewCmdOptions(t, fake)

	readinessErr := errors.New("not ready yet")

	done := make(chan error, 1)
	go func() {
		done <- StartProcess(StartSpec{
			Logger:         testProcessLogger(),
			NameDisplay:    "test-backend",
			NameUnderscore: "test_backend",
			Exec:           "test-exec",
			LogLine:        func(string, bool) {},
			SetProc:        func(Commander, <-chan CmdStatus) {},
			ReadinessCheck: func() (string, error) {
				// First iteration fails so the loop proceeds to a second iteration,
				// where the Complete guard fires.
				return "", readinessErr
			},
		})
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.EqualError(t, err, "test-backend process ended unexpectedly, check log")
	case <-time.After(2 * time.Second):
		t.Fatal("StartProcess did not return promptly on process-ended path")
	}

	assert.GreaterOrEqual(t, fake.stopCalls.Load(), int32(1), "StopProcess must call proc.Stop on process-ended")
}

func TestStartProcess_ReadinessTimeout(t *testing.T) {
	stubProcessTimers(t)

	fake := newFakeCommander(2222)
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 2222} } // always running
	stubNewCmdOptions(t, fake)

	readinessErr := errors.New("never ready")
	var readinessCalls atomic.Int32

	done := make(chan error, 1)
	go func() {
		done <- StartProcess(StartSpec{
			Logger:         testProcessLogger(),
			NameDisplay:    "test-backend",
			NameUnderscore: "test_backend",
			Exec:           "test-exec",
			LogLine:        func(string, bool) {},
			SetProc:        func(Commander, <-chan CmdStatus) {},
			ReadinessCheck: func() (string, error) {
				readinessCalls.Add(1)
				return "", readinessErr
			},
		})
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, readinessErr, "persistent readiness failure must return the readiness error")
	case <-time.After(2 * time.Second):
		t.Fatal("StartProcess did not return promptly on readiness-timeout path")
	}

	assert.Equal(t, int32(readinessBackoffCount), readinessCalls.Load(),
		"ReadinessCheck must run once per backoff iteration before giving up")
	assert.GreaterOrEqual(t, fake.stopCalls.Load(), int32(1), "StopProcess must call proc.Stop on readiness timeout")
}

func TestStartProcess_PassesExecAndArgs(t *testing.T) {
	stubProcessTimers(t)

	fake := newFakeCommander(1)
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 1} }
	captured := stubNewCmdOptions(t, fake)

	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "my-binary",
		Args:           []string{"run", "--flag", "value"},
		LogLine:        func(string, bool) {},
		SetProc:        func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "v", nil },
	})

	require.NoError(t, err)
	assert.Equal(t, "my-binary", captured.exec)
	assert.Equal(t, []string{"run", "--flag", "value"}, captured.args)
}

// A context that is already done spawns nothing: the caller has moved on,
// and a child it never sees would run until something else killed it.
func TestStartProcess_ReturnsBeforeSpawningWhenTheContextIsDone(t *testing.T) {
	stubProcessTimers(t)
	fake := newFakeCommander(1)
	captured := stubNewCmdOptions(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := StartProcess(StartSpec{
		Logger: testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "1", nil },
		Ctx:            ctx,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, captured.exec, "no command is built for a start that was cancelled before it began")
	assert.Equal(t, int32(0), fake.stopCalls.Load())
}

// A cancellation during the startup wait stops the child and returns at
// once, with the cancellation as the cause.
func TestStartProcess_CancelledDuringTheStartupWait(t *testing.T) {
	origWait := startProcessStartupWait
	startProcessStartupWait = 5 * time.Second
	t.Cleanup(func() { startProcessStartupWait = origWait })
	fake := newFakeCommander(4242)
	stubNewCmdOptions(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()

	err := StartProcess(StartSpec{
		Logger: testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "1", nil },
		Ctx:            ctx,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, err.Error(), "test-backend start cancelled")
	assert.Less(t, time.Since(start), time.Second, "the startup wait ends with the context")
	assert.Equal(t, int32(1), fake.stopCalls.Load(), "the child is stopped")
}

// A cancellation during a readiness backoff does the same; the readiness
// check itself is not interrupted, so the return is bounded by one check.
func TestStartProcess_CancelledDuringAReadinessBackoff(t *testing.T) {
	origWait := startProcessStartupWait
	startProcessStartupWait = 0
	t.Cleanup(func() { startProcessStartupWait = origWait })
	fake := newFakeCommander(4242)
	stubNewCmdOptions(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	var checks atomic.Int32
	start := time.Now()

	err := StartProcess(StartSpec{
		Logger: testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) {
			if checks.Add(1) == 2 {
				cancel() // the second attempt's backoff is one second; cancel lands inside it
			}
			return "", errors.New("not yet")
		},
		Ctx: ctx,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), time.Second, "the backoff sleep ends with the context")
	assert.Equal(t, int32(2), checks.Load(), "no readiness check after the cancellation")
	assert.Equal(t, int32(1), fake.stopCalls.Load())
}

// A readiness budget bounds the whole readiness phase: the loop never sleeps
// past it and gives up when it is spent, naming the budget.
func TestStartProcess_GivesUpWhenTheReadinessBudgetIsSpent(t *testing.T) {
	origWait := startProcessStartupWait
	startProcessStartupWait = 0
	t.Cleanup(func() { startProcessStartupWait = origWait })
	fake := newFakeCommander(4242)
	stubNewCmdOptions(t, fake)
	var checks atomic.Int32
	start := time.Now()

	err := StartProcess(StartSpec{
		Logger: testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck:  func() (string, error) { checks.Add(1); return "", errors.New("not yet") },
		ReadinessBudget: 40 * time.Millisecond,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "test-backend not ready within 40ms")
	assert.Contains(t, err.Error(), "not yet", "the last readiness error is kept as the cause")
	assert.Less(t, time.Since(start), time.Second, "the one-second backoff was cut to the budget")
	assert.LessOrEqual(t, checks.Load(), int32(3), "attempt 0 sleeps nothing, attempt 1 sleeps the clamped budget, attempt 2 finds it spent")
	assert.Equal(t, int32(1), fake.stopCalls.Load())
}

// A readiness check that completes successfully after the context was
// cancelled must still stop the child: the check itself is not interrupted,
// but its result arrives too late to matter, and the start must not report
// success while leaving an unwanted process running.
func TestStartProcess_StopsTheChildWhenCancelledDuringASuccessfulReadinessCheck(t *testing.T) {
	origWait := startProcessStartupWait
	startProcessStartupWait = 0
	t.Cleanup(func() { startProcessStartupWait = origWait })
	fake := newFakeCommander(4242)
	stubNewCmdOptions(t, fake)
	ctx, cancel := context.WithCancel(context.Background())
	var checks atomic.Int32

	err := StartProcess(StartSpec{
		Logger: testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) {
			checks.Add(1)
			cancel()
			return "1.2.3", nil
		},
		Ctx: ctx,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(1), checks.Load(), "the readiness check ran once")
	assert.Equal(t, int32(1), fake.stopCalls.Load())
}
