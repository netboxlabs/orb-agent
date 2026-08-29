package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
)

// stopFunc adapts a function to the stopper the shutdown sequence takes.
type stopFunc func()

func (f stopFunc) Stop() { f() }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The runner contexts derive from the root context, so stopping the server
// first means waiting on work that has not been told to finish: a full series
// of SNMP timeouts can outlast an orchestrator's termination grace period.
func TestShutdownCancelsRootBeforeStoppingTheServer(t *testing.T) {
	rootCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var (
		order      []string
		errAtStop  error
		errAtFlush error
	)

	shutdown(cancel, stopFunc(func() {
		order = append(order, "stop")
		errAtStop = rootCtx.Err()
	}), func() {
		order = append(order, "flush")
		errAtFlush = rootCtx.Err()
	})

	require.Equal(t, []string{"stop", "flush"}, order)
	require.ErrorIs(t, errAtStop, context.Canceled, "the root context must be cancelled before the server is stopped")
	require.ErrorIs(t, errAtFlush, context.Canceled)
}

// The flush runs on its own context, so cancelling the root context first does
// not cost the last export. Nothing speaks gRPC on the listener, so the export
// fails; that it dials at all is the signal, and it is the part a cancelled
// context would skip.
func TestFlushMetricsSurvivesRootCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	dialed := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
		dialed <- struct{}{}
	}()

	rootCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := discardLogger()
	require.NoError(t, metrics.SetupMetricsExport(rootCtx, logger, ln.Addr().String(), 3600))
	t.Cleanup(metrics.ResetMeter)

	// One recorded point, so the final flush has something to export.
	gauge, err := metrics.GetMeter().Int64Gauge("snmp.test.shutdown")
	require.NoError(t, err)
	gauge.Record(context.Background(), 1)

	shutdown(cancel, stopFunc(func() {}), func() { flushMetrics(logger, time.Second) })

	select {
	case <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the final flush did not reach the endpoint after the root context was cancelled")
	}
}

// A server error runs the shutdown sequence from its own goroutine, and that
// sequence cancels the root context on its first step. Releasing main on that
// cancellation lets the process exit through the server stop and the final
// export.
func TestWaitForShutdownWaitsForTheSequenceToFinish(t *testing.T) {
	rootCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	release := make(chan struct{})
	var finished atomic.Bool
	run := func() {
		// The real sequence cancels the root context before it stops the
		// server and flushes metrics.
		cancel()
		<-release
		finished.Store(true)
	}

	serverErrCh := make(chan error, 1)
	serverErrCh <- errors.New("listen tcp 127.0.0.1:8078: address already in use")

	returned := make(chan struct{})
	go func() {
		waitForShutdown(rootCtx, discardLogger(), nil, serverErrCh, run)
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("waitForShutdown returned while the shutdown sequence was still running")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("waitForShutdown did not return once the shutdown sequence had finished")
	}
	assert.True(t, finished.Load(), "the shutdown sequence must have finished before main is released")
}

// A stop signal and a server error can arrive together. The sequence stops the
// server and flushes the meter provider, so it must run once.
func TestWaitForShutdownRunsTheSequenceOnce(t *testing.T) {
	rootCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var runs atomic.Int32
	run := func() {
		runs.Add(1)
		cancel()
	}

	sigs := make(chan os.Signal, 1)
	sigs <- syscall.SIGTERM
	serverErrCh := make(chan error, 1)
	serverErrCh <- errors.New("listen tcp 127.0.0.1:8078: address already in use")

	waitForShutdown(rootCtx, discardLogger(), sigs, serverErrCh, run)

	assert.Never(t, func() bool { return runs.Load() > 1 }, 200*time.Millisecond, 10*time.Millisecond,
		"the shutdown sequence ran more than once")
	assert.Equal(t, int32(1), runs.Load())
}
