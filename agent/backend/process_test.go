package backend

import (
	"context"
	"errors"
	"log/slog"
	"net"
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
	full := StartSpec{Logger: testProcessLogger(), SetProc: setProc, LogLine: noop, ReadinessCheck: ready, ListenAddr: testListenAddr(t)}

	tests := []struct {
		name string
		spec StartSpec
	}{
		{"missing logger", func() StartSpec { s := full; s.Logger = nil; return s }()},
		{"missing setProc", func() StartSpec { s := full; s.SetProc = nil; return s }()},
		{"missing logLine", func() StartSpec { s := full; s.LogLine = nil; return s }()},
		{"missing readinessCheck", func() StartSpec { s := full; s.ReadinessCheck = nil; return s }()},
		{"missing listenAddr", func() StartSpec { s := full; s.ListenAddr = ""; return s }()},
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
		ListenAddr:     testListenAddr(t),
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
		ListenAddr:     testListenAddr(t),
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
			ListenAddr:     testListenAddr(t),
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
		ListenAddr:     testListenAddr(t),
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
			ListenAddr:     testListenAddr(t),
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
			ListenAddr:     testListenAddr(t),
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
		ListenAddr:     testListenAddr(t),
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
	// The address is held: a start cancelled before it began answers with
	// the cancellation, not with the address, so a caller that reads the
	// refusal as the environment's (the upgrade restart) sees a shutdown.
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = holder.Close() }()

	err = StartProcess(StartSpec{
		ListenAddr: holder.Addr().String(),
		Logger:     testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "1", nil },
		Ctx:            ctx,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, errors.Is(err, ErrListenAddrInUse), "a done context returns before the address is probed")
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
		ListenAddr: testListenAddr(t),
		Logger:     testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
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
		ListenAddr: testListenAddr(t),
		Logger:     testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
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
		ListenAddr: testListenAddr(t),
		Logger:     testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
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
		ListenAddr: testListenAddr(t),
		Logger:     testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
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

// A readiness budget attached to the start context bounds the readiness
// phase the same way StartSpec.ReadinessBudget does, so the supervisor can
// bound an on-demand start without every backend threading a field through.
func TestStartProcess_ReadsTheReadinessBudgetFromTheContext(t *testing.T) {
	origWait := startProcessStartupWait
	startProcessStartupWait = 0
	t.Cleanup(func() { startProcessStartupWait = origWait })
	fake := newFakeCommander(4242)
	stubNewCmdOptions(t, fake)
	start := time.Now()

	err := StartProcess(StartSpec{
		ListenAddr: testListenAddr(t),
		Logger:     testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "", errors.New("not yet") },
		Ctx:            WithReadinessBudget(context.Background(), 40*time.Millisecond),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "test-backend not ready within 40ms")
	assert.Less(t, time.Since(start), time.Second, "the backoff was cut to the context's budget")
	assert.Equal(t, int32(1), fake.stopCalls.Load(), "the child is stopped when the budget is spent")
}

// An explicit StartSpec.ReadinessBudget wins over the context's.
func TestStartProcess_SpecBudgetWinsOverTheContextBudget(t *testing.T) {
	origWait := startProcessStartupWait
	startProcessStartupWait = 0
	t.Cleanup(func() { startProcessStartupWait = origWait })
	fake := newFakeCommander(4242)
	stubNewCmdOptions(t, fake)

	err := StartProcess(StartSpec{
		ListenAddr: testListenAddr(t),
		Logger:     testProcessLogger(), NameDisplay: "test-backend", NameUnderscore: "test_backend", Exec: "test-exec",
		LogLine: func(string, bool) {}, SetProc: func(Commander, <-chan CmdStatus) {},
		ReadinessCheck:  func() (string, error) { return "", errors.New("not yet") },
		ReadinessBudget: 40 * time.Millisecond,
		Ctx:             WithReadinessBudget(context.Background(), time.Hour),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not ready within 40ms")
}

// No budget anywhere keeps today's loop: the error names no budget.
func TestReadinessBudgetFromAnUnmarkedContextIsZero(t *testing.T) {
	assert.Equal(t, time.Duration(0), ReadinessBudgetFrom(context.Background()))
	assert.Equal(t, 3*time.Second, ReadinessBudgetFrom(WithReadinessBudget(context.Background(), 3*time.Second)))
}

// A backend's readiness check asks localhost:<port> and takes whatever answers,
// so while another process holds the port, the check would report that
// process's answer as the child's. StartProcess refuses to spawn while the
// address the backend would listen on is held.
func TestStartProcess_RefusesWhileTheListenAddressIsHeld(t *testing.T) {
	stubProcessTimers(t)
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = holder.Close() }()

	fake := newFakeCommander(4242)
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 4242} }
	captured := stubNewCmdOptions(t, fake)
	var setProcCalled atomic.Bool

	err = StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		ListenAddr:     holder.Addr().String(),
		LogLine:        func(string, bool) {},
		SetProc:        func(Commander, <-chan CmdStatus) { setProcCalled.Store(true) },
		ReadinessCheck: func() (string, error) { return "1.0.0", nil },
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrListenAddrInUse), "the refusal is marked as the address being held: %v", err)
	assert.Contains(t, err.Error(), holder.Addr().String(), "the error names the address")
	assert.Contains(t, err.Error(), "in use", "the error says the address is held")
	assert.Empty(t, captured.exec, "nothing is spawned while the address is held")
	assert.False(t, setProcCalled.Load(), "no process is published")
}

// The probe holds the address only for the check: the child must be able to
// bind it right after.
func TestStartProcess_ReleasesTheProbedListenAddress(t *testing.T) {
	stubProcessTimers(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := probe.Addr().String()
	require.NoError(t, probe.Close())

	fake := newFakeCommander(4242)
	fake.statusFn = func() CmdStatus { return CmdStatus{PID: 4242} }
	stubNewCmdOptions(t, fake)

	err = StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		ListenAddr:     addr,
		LogLine:        func(string, bool) {},
		SetProc:        func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "1.0.0", nil },
	})
	require.NoError(t, err, "a free address lets the start proceed")

	child, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the address is free again for the child")
	_ = child.Close()
}

// A readiness check that passed may have been answered by another process on
// the address, with the child dead at its own bind by then: the child's exit
// is checked again after the check passes, before the backend is called ready.
func TestStartProcess_AChildDeadAfterAPassingReadinessCheckIsNotReady(t *testing.T) {
	stubProcessTimers(t)
	fake := newFakeCommander(4242)
	var checked atomic.Bool
	fake.statusFn = func() CmdStatus {
		if checked.Load() {
			return CmdStatus{PID: 4242, Complete: true, Exit: 1}
		}
		return CmdStatus{PID: 4242}
	}
	stubNewCmdOptions(t, fake)

	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		ListenAddr:     testListenAddr(t),
		LogLine:        func(string, bool) {},
		SetProc:        func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) {
			// Answered by another process; the child dies right after.
			checked.Store(true)
			return "1.0.0", nil
		},
	})
	require.Error(t, err, "a child that died is not ready, whatever answered the check")
	assert.Contains(t, err.Error(), "process ended unexpectedly")
}

// testListenAddr is a free loopback address for a spec whose test is not
// about the probe: reserved so it names a real port, released for the probe
// to find free.
func testListenAddr(t *testing.T) string {
	t.Helper()
	addr, err := ReserveListenAddr("127.0.0.1:0")
	require.NoError(t, err)
	return addr
}

// With port 0 the reservation picks a free port and returns it, which is how
// a backend that listens on any open port learns the one to be told; the
// port is released for the child to bind.
func TestReserveListenAddrPicksAFreePort(t *testing.T) {
	addr, err := ReserveListenAddr("127.0.0.1:0")
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.NotEqual(t, "0", port, "the picked port is a concrete one")

	child, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the picked port is released for the child")
	_ = child.Close()
}

// A held address is refused with the sentinel, the same way StartProcess
// reports it.
func TestReserveListenAddrRefusesAHeldAddress(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = holder.Close() }()

	_, err = ReserveListenAddr(holder.Addr().String())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrListenAddrInUse))
}

// A spec still carrying port 0 would probe fine and tell the child to pick a
// port the readiness check cannot know, so it is refused before anything is
// spawned: the port is reserved before the spec is built.
func TestStartProcess_RefusesAnUnreservedPortZero(t *testing.T) {
	// Every spelling net.Listen reads as "any port", including the empty
	// one a `port: ""` config yields, and an address with no port at all.
	for _, addr := range []string{"127.0.0.1:0", "127.0.0.1:", "127.0.0.1:00", "nohostport"} {
		t.Run(addr, func(t *testing.T) {
			stubProcessTimers(t)
			fake := newFakeCommander(4242)
			fake.statusFn = func() CmdStatus { return CmdStatus{PID: 4242} }
			captured := stubNewCmdOptions(t, fake)

			err := StartProcess(StartSpec{
				Logger:         testProcessLogger(),
				NameDisplay:    "test-backend",
				NameUnderscore: "test_backend",
				Exec:           "test-exec",
				ListenAddr:     addr,
				LogLine:        func(string, bool) {},
				SetProc:        func(Commander, <-chan CmdStatus) {},
				ReadinessCheck: func() (string, error) { return "1.0.0", nil },
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ReserveListenAddr")
			assert.Empty(t, captured.exec, "nothing is spawned")
		})
	}
}
