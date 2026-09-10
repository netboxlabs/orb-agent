package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// readinessBackoffCount is the number of readiness attempts. The per-iteration
// sleep is index-scaled (0+1+...+9 = 45s total window), preserving the existing
// backoff behavior the inline loops implemented.
const readinessBackoffCount = 10

// startProcessStartupWait is the one-shot post-spawn wait; startProcessSleep is
// the context-aware sleep used for it and for every readiness backoff. Both are
// package vars so success and timeout paths are unit-testable without
// multi-second waits.
var (
	startProcessStartupWait = time.Second
	startProcessSleep       = sleepUnlessDone
)

// sleepUnlessDone sleeps for d and reports true, or reports false as soon as
// ctx ends. A non-positive d does not sleep and reports whether ctx is still
// live.
func sleepUnlessDone(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// StartSpec describes how to launch and validate a backend subprocess.
type StartSpec struct {
	Logger         *slog.Logger
	NameDisplay    string // hyphen/space form for error strings + lifecycle logs (e.g. "network-discovery")
	NameUnderscore string // underscore form passed only to StopProcess (e.g. "network_discovery")
	Exec           string
	Args           []string
	LogLine        func(line string, isStderr bool)  // per-backend normalizer adapter
	SetProc        func(Commander, <-chan CmdStatus) // publishes proc+statusChan to the backend BEFORE the readiness loop (see CRITICAL below)
	ReadinessCheck func() (string, error)            // returns the version string + err; d.Version fits directly; pktvisor wraps an inline /metrics/app probe returning appMetrics.App.Version
	// Ctx, when set, ends the start: a context already done spawns nothing,
	// and one that ends during the startup wait or a readiness backoff stops
	// the child and returns the cancellation. A readiness check in flight is
	// not interrupted, so a cancellation returns within one check's own
	// timeout; the result of a check that completes after the cancellation is
	// discarded and the child is stopped. Nil means the start cannot be
	// cancelled, as before.
	Ctx context.Context
	// ReadinessBudget bounds the readiness phase after the startup wait: the
	// loop never sleeps past it and gives up when it is spent, overshooting by
	// at most one check. It never adds attempts. Zero keeps the ten-attempt
	// loop as it is.
	ReadinessBudget time.Duration
}

// StartProcess launches the process, streams stdout/stderr to LogLine, then:
//   - builds the Cmd, proc.Start(), and IMMEDIATELY calls spec.SetProc(proc, statusChan)
//     to publish them to the backend (the CRITICAL step — see below), then spawns the
//     stream goroutine.
//   - waits startProcessStartupWait, checks status: status.Error -> Error-log
//     "<NameDisplay> startup error" and return it; status.Complete -> StopProcess +
//     errors.New(NameDisplay+" startup error, check log").
//   - logs "<NameDisplay> process started" (pid), then runs a 0..9 backoff loop;
//     EACH iteration first re-checks proc.Status().Complete and, if complete,
//     StopProcess + returns errors.New(NameDisplay+" process ended unexpectedly,
//     check log"); else calls ReadinessCheck. On success logs "<NameDisplay>
//     readiness ok, got version" with "version" = the returned string; on per-iter
//     failure logs "<NameDisplay> is not ready, trying again with backoff" with attr
//     key "backoff_duration" and sleeps startProcessSleep(time.Duration(backoff) *
//     time.Second) — the existing index-scaled backoff (0+1+...+9 = 45s window); on
//     persistent failure Error-logs "<NameDisplay> error on readiness", StopProcess,
//     and returns the readiness error.
//
// CRITICAL — SetProc ordering. ReadinessCheck is usually d.Version, which calls
// CommonRequest(..., d.proc, ...). If d.proc is still nil during the loop,
// GetRunningStatus(nil) returns (Unknown, _, nil) (utils.go:16-18) so CommonRequest
// returns nil and d.Version returns ("", nil) — readiness "succeeds" instantly with
// an empty version for ALL backends. StartProcess MUST therefore call spec.SetProc
// (which assigns d.proc/d.statusChan) right after proc.Start() and BEFORE the
// readiness loop, so ReadinessCheck observes a live, running proc.
//
// Every lifecycle log + both error strings use NameDisplay; only the internal
// StopProcess call uses NameUnderscore. StartProcess does NOT emit the
// "<name> startup / arguments" line — each backend keeps its own (it owns the
// per-backend redaction). Returns only error — proc/statusChan are published via
// SetProc, not the return (one source of truth). It owns ONLY the Start path;
// callers keep their own Stop. The startup wait and readiness backoff end with
// spec.Ctx when it is set, and the readiness phase is bounded by
// spec.ReadinessBudget; both are optional and their zero values keep the
// historical behaviour.
func StartProcess(spec StartSpec) error {
	if spec.Logger == nil || spec.SetProc == nil || spec.LogLine == nil || spec.ReadinessCheck == nil {
		return errors.New("StartProcess: Logger, SetProc, LogLine, and ReadinessCheck are required")
	}

	ctx := spec.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s start cancelled: %w", spec.NameDisplay, err)
	}

	proc := NewCmdOptions(CmdOptions{
		Buffered:  false,
		Streaming: true,
	}, spec.Exec, spec.Args...)
	statusChan := proc.Start()

	// CRITICAL: publish proc + statusChan to the backend BEFORE the readiness
	// loop so ReadinessCheck (usually d.Version) observes a live, running proc.
	spec.SetProc(proc, statusChan)

	// log STDOUT and STDERR lines streaming from Cmd
	go func() {
		stdout := proc.GetStdout()
		stderr := proc.GetStderr()
		for stdout != nil || stderr != nil {
			select {
			case line, open := <-stdout:
				if !open {
					stdout = nil
					continue
				}
				spec.LogLine(line, false)
			case line, open := <-stderr:
				if !open {
					stderr = nil
					continue
				}
				spec.LogLine(line, true)
			}
		}
	}()

	cancelled := func() error {
		spec.Logger.Info(spec.NameDisplay + " start cancelled")
		StopProcess(spec.Logger, proc, statusChan, DefaultStopGracePeriod, spec.NameUnderscore)
		cause := ctx.Err()
		if cause == nil {
			cause = context.Canceled
		}
		return fmt.Errorf("%s start cancelled: %w", spec.NameDisplay, cause)
	}

	// wait for simple startup errors
	if !startProcessSleep(ctx, startProcessStartupWait) {
		return cancelled()
	}

	status := proc.Status()

	if status.Error != nil {
		spec.Logger.Error(spec.NameDisplay+" startup error", "error", status.Error)
		return status.Error
	}

	if status.Complete {
		StopProcess(spec.Logger, proc, statusChan, DefaultStopGracePeriod, spec.NameUnderscore)
		return errors.New(spec.NameDisplay + " startup error, check log")
	}

	spec.Logger.Info(spec.NameDisplay+" process started", "pid", status.PID)

	var deadline time.Time
	if spec.ReadinessBudget > 0 {
		deadline = time.Now().Add(spec.ReadinessBudget)
	}
	var version string
	var readinessErr error
	for backoff := range readinessBackoffCount {
		if status := proc.Status(); status.Complete {
			StopProcess(spec.Logger, proc, statusChan, DefaultStopGracePeriod, spec.NameUnderscore)
			return errors.New(spec.NameDisplay + " process ended unexpectedly, check log")
		}
		version, readinessErr = spec.ReadinessCheck()
		if readinessErr == nil {
			if ctx.Err() != nil {
				return cancelled()
			}
			spec.Logger.Info(spec.NameDisplay+" readiness ok, got version", "version", version)
			break
		}
		backoffDuration := time.Duration(backoff) * time.Second
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				readinessErr = fmt.Errorf("%s not ready within %s: %w", spec.NameDisplay, spec.ReadinessBudget, readinessErr)
				break
			}
			if backoffDuration > remaining {
				backoffDuration = remaining
			}
		}
		spec.Logger.Info(spec.NameDisplay+" is not ready, trying again with backoff",
			"backoff_duration", backoffDuration.String())
		if !startProcessSleep(ctx, backoffDuration) {
			return cancelled()
		}
	}

	if readinessErr != nil {
		spec.Logger.Error(spec.NameDisplay+" error on readiness", "error", readinessErr)
		StopProcess(spec.Logger, proc, statusChan, DefaultStopGracePeriod, spec.NameUnderscore)
		return readinessErr
	}

	return nil
}
