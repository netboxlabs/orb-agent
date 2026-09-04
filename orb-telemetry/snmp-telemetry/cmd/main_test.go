package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/traps"
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
// Cancelling that context is also what makes an in-flight collection forget its
// device, so the flush is taken before it, on a root that is still live.
func TestShutdownCancelsRootBetweenTheFlushAndTheServerStop(t *testing.T) {
	rootCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var (
		order      []string
		errAtStop  error
		errAtFlush error
	)

	shutdown(shutdownBudget, cancel, closeFunc(func() {
		order = append(order, "intake")
		require.NoError(t, rootCtx.Err(), "trap intake closes before anything is cancelled")
	}), stopFunc(func() {
		order = append(order, "stop")
		errAtStop = rootCtx.Err()
	}), func(time.Duration) {
		order = append(order, "flush")
		errAtFlush = rootCtx.Err()
	})

	require.Equal(t, []string{"intake", "flush", "stop"}, order,
		"trap intake closes first so nothing is counted after the final export; the flush still precedes the cancel")
	require.ErrorIs(t, errAtStop, context.Canceled, "the root context must be cancelled before the server is stopped")
	require.NoError(t, errAtFlush, "the root context must still be live during the final flush")
}

// The agent gives the process one stop grace. Closing trap intake spends part
// of it, so the flush is handed what is left of the shared budget rather than
// a budget of its own that, added to the intake close, could outlast the grace.
func TestShutdownChargesTheIntakeCloseAgainstTheFlushBudget(t *testing.T) {
	const budget = 500 * time.Millisecond
	const intakeTook = 200 * time.Millisecond

	var flushGot time.Duration
	shutdown(budget, func() {}, closeFunc(func() { time.Sleep(intakeTook) }), stopFunc(func() {}), func(timeout time.Duration) {
		flushGot = timeout
	})

	assert.Greater(t, flushGot, time.Duration(0), "the flush still runs when the intake close leaves budget")
	assert.LessOrEqual(t, flushGot, budget-intakeTook, "the intake close is charged against the flush's budget")
}

// The flush runs on its own context, so a root context already cancelled when
// the shutdown sequence is entered does not cost the last export. Nothing
// speaks gRPC on the listener, so the export fails; that it dials at all is the
// signal, and it is the part a cancelled context would skip.
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

	// Cancelled directly rather than through the sequence, which now flushes
	// before it cancels: what is under test is the flush's own context.
	cancel()
	flushMetrics(logger, time.Second)

	select {
	case <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the final flush did not reach the endpoint after the root context was cancelled")
	}
}

// metricsReceiver is an OTLP metrics endpoint that keeps what it is handed, so
// a test can assert on the payload of an export rather than on the fact that
// one was attempted.
type metricsReceiver struct {
	collectormetricspb.UnimplementedMetricsServiceServer

	mu       sync.Mutex
	requests []*collectormetricspb.ExportMetricsServiceRequest
}

func (r *metricsReceiver) Export(_ context.Context,
	req *collectormetricspb.ExportMetricsServiceRequest,
) (*collectormetricspb.ExportMetricsServiceResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	return &collectormetricspb.ExportMetricsServiceResponse{}, nil
}

// gaugeValues returns every int64 gauge point exported under name.
func (r *metricsReceiver) gaugeValues(name string) []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	var values []int64
	for _, req := range r.requests {
		for _, rm := range req.GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				for _, m := range sm.GetMetrics() {
					if m.GetName() != name {
						continue
					}
					for _, pt := range m.GetGauge().GetDataPoints() {
						values = append(values, pt.GetAsInt())
					}
				}
			}
		}
	}
	return values
}

// startMetricsReceiver serves an OTLP metrics endpoint and returns it with the
// address to point the exporter at.
func startMetricsReceiver(t *testing.T) (*metricsReceiver, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	receiver := &metricsReceiver{}
	srv := grpc.NewServer()
	collectormetricspb.RegisterMetricsServiceServer(srv, receiver)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	return receiver, ln.Addr().String()
}

// Every metric this backend exports is an observable gauge reading the
// collector's observation store, so the final export carries SNMP data only
// while the callbacks are registered and the store still holds the readings.
// Stopping the server tears both down: it stops the runners, which forget
// their policies, and releases the collectors, which unregisters the
// callbacks. Flushing after that exports nothing, and with a long export
// period that is everything observed since the last periodic export.
func TestShutdownFlushesObservationsBeforeTheServerStopDropsThem(t *testing.T) {
	receiver, endpoint := startMetricsReceiver(t)

	rootCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := discardLogger()
	// An hour, so nothing exports on the periodic cadence and the only export
	// is the one the shutdown sequence asks for.
	require.NoError(t, metrics.SetupMetricsExport(rootCtx, logger, endpoint, 3600))
	t.Cleanup(metrics.ResetMeter)

	const metricName = "snmp.test.interface.status"

	var (
		storeMu sync.Mutex
		store   = map[string]int64{"device": 42}
	)
	gauge, err := metrics.GetMeter().Int64ObservableGauge(metricName)
	require.NoError(t, err)
	reg, err := metrics.GetMeter().RegisterCallback(func(_ context.Context, o metric.Observer) error {
		storeMu.Lock()
		defer storeMu.Unlock()
		for _, value := range store {
			o.ObserveInt64(gauge, value)
		}
		return nil
	}, gauge)
	require.NoError(t, err)

	// What stopping the server reaches: the callback is unregistered and the
	// observations it reads are dropped.
	stop := stopFunc(func() {
		assert.NoError(t, reg.Unregister())
		storeMu.Lock()
		store = map[string]int64{}
		storeMu.Unlock()
	})

	shutdown(shutdownBudget, cancel, closeFunc(func() {}), stop, func(timeout time.Duration) { flushMetrics(logger, timeout) })

	assert.Equal(t, []int64{42}, receiver.gaugeValues(metricName),
		"the final export must carry the observations the server stop drops")
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

// A scheduled collection can be in flight when the shutdown begins. Cancelling
// the root context makes it return a context error, and a collection that
// returns an error has its device forgotten, which deletes the observations the
// final export is there to carry. The flush has to be taken before anything is
// cancelled, or the deletion can win and the export it was moved forward for is
// empty.
func TestShutdownFlushesBeforeACancelledCollectionForgetsTheDevice(t *testing.T) {
	receiver, endpoint := startMetricsReceiver(t)

	rootCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := discardLogger()
	// An hour, so nothing exports on the periodic cadence and the only export
	// is the one the shutdown sequence asks for.
	require.NoError(t, metrics.SetupMetricsExport(rootCtx, logger, endpoint, 3600))
	t.Cleanup(metrics.ResetMeter)

	const metricName = "snmp.test.cancelled.collection"

	var (
		storeMu sync.Mutex
		store   = map[string]int64{"device": 7}
	)
	gauge, err := metrics.GetMeter().Int64ObservableGauge(metricName)
	require.NoError(t, err)
	reg, err := metrics.GetMeter().RegisterCallback(func(_ context.Context, o metric.Observer) error {
		storeMu.Lock()
		defer storeMu.Unlock()
		for _, value := range store {
			o.ObserveInt64(gauge, value)
		}
		return nil
	}, gauge)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reg.Unregister() })

	// The collection in flight. The cancellation makes it return a context
	// error, and its caller forgets the device, deleting what it had stored.
	forgotten := make(chan struct{})
	go func() {
		defer close(forgotten)
		<-rootCtx.Done()
		storeMu.Lock()
		store = map[string]int64{}
		storeMu.Unlock()
	}()

	// The deletion and the flush race in the real sequence. Waiting here for the
	// collection to unwind pins the interleaving the flush loses, so the
	// assertion below reads the ordering rather than the scheduler.
	cancelRoot := func() {
		cancel()
		<-forgotten
	}

	shutdown(shutdownBudget, cancelRoot, closeFunc(func() {}), stopFunc(func() {}), func(timeout time.Duration) { flushMetrics(logger, timeout) })

	assert.Equal(t, []int64{7}, receiver.gaugeValues(metricName),
		"the final export must carry the observations a cancelled collection forgets")
}

// closeFunc adapts a function to the closer stopAll's tally field takes.
type closeFunc func()

func (f closeFunc) Close() { f() }

// stopAll closes the tally, then the server; the trap pool closes earlier, in
// shutdown itself, ahead of the flush. shutdown's
// own flush, cancel, stop order is a separate concern, already pinned by
// TestShutdownCancelsRootBetweenTheFlushAndTheServerStop; this test is only
// about the sequence stopAll.Stop itself encodes.
func TestStopAllOrder(t *testing.T) {
	var order []string
	sa := stopAll{
		tally:  closeFunc(func() { order = append(order, "tally") }),
		server: stopFunc(func() { order = append(order, "server") }),
	}
	sa.Stop()
	assert.Equal(t, []string{"tally", "server"}, order)
}

// The adapter is what the manager is given, so it must satisfy the interface
// and must surface a bind failure as an error with a nil lease, not a typed
// nil pointer inside a non-nil interface.
func TestTrapPoolAdapter(t *testing.T) {
	var _ policy.TrapPool = trapPool{}

	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Close() })

	pool := traps.NewPool(traps.NewTally(discardLogger()), discardLogger())
	t.Cleanup(pool.Close)
	var adapted policy.TrapPool = trapPool{pool: pool}

	lease, err := adapted.Acquire(blocker.LocalAddr().String(), "core", nil, nil)
	require.Error(t, err)
	assert.True(t, lease == nil, "an error must come with an untyped nil lease")

	lease, err = adapted.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, lease)
	lease.Release()
}
