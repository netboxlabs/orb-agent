package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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

	shutdown(cancel, stopFunc(func() {
		order = append(order, "stop")
		errAtStop = rootCtx.Err()
	}), func() {
		order = append(order, "flush")
		errAtFlush = rootCtx.Err()
	})

	require.Equal(t, []string{"flush", "stop"}, order)
	require.ErrorIs(t, errAtStop, context.Canceled, "the root context must be cancelled before the server is stopped")
	require.NoError(t, errAtFlush, "the root context must still be live during the final flush")
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

	shutdown(cancel, stop, func() { flushMetrics(logger, metricsFlushTimeout) })

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

	shutdown(cancelRoot, stopFunc(func() {}), func() { flushMetrics(logger, metricsFlushTimeout) })

	assert.Equal(t, []int64{7}, receiver.gaugeValues(metricName),
		"the final export must carry the observations a cancelled collection forgets")
}

// With no --trap-listen, no socket is opened and nothing else changes.
func TestTrapListenEmptyOpensNoSocket(t *testing.T) {
	rcv, err := startTrapReceiver("", "", nil, nil, discardLogger())
	require.NoError(t, err)
	assert.Nil(t, rcv)
}

func TestTrapListenBindFailureIsAnError(t *testing.T) {
	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Close() })
	_, err = startTrapReceiver(blocker.LocalAddr().String(), "", traps.NewRegistry(), traps.NewTally(discardLogger()), discardLogger())
	require.Error(t, err, "a bind failure is reported, not logged from a goroutine")
}

// closeFunc adapts a function to the closer stopAll's tally field takes.
type closeFunc func()

func (f closeFunc) Close() { f() }

// stopAll stops the receiver, then closes the tally, then stops the server.
// shutdown's own flush, cancel, stop order is a separate concern, already
// pinned by TestShutdownCancelsRootBetweenTheFlushAndTheServerStop; this test
// is only about the sequence stopAll.Stop itself encodes.
func TestStopAllOrder(t *testing.T) {
	t.Run("with a receiver", func(t *testing.T) {
		var order []string
		sa := stopAll{
			receiver: stopFunc(func() { order = append(order, "receiver") }),
			tally:    closeFunc(func() { order = append(order, "tally") }),
			server:   stopFunc(func() { order = append(order, "server") }),
		}
		sa.Stop()
		assert.Equal(t, []string{"receiver", "tally", "server"}, order)
	})

	t.Run("without a receiver", func(t *testing.T) {
		var order []string
		sa := stopAll{
			tally:  closeFunc(func() { order = append(order, "tally") }),
			server: stopFunc(func() { order = append(order, "server") }),
		}
		assert.NotPanics(t, sa.Stop)
		assert.Equal(t, []string{"tally", "server"}, order)
	})
}

// trapSeries collects the trap counters and keys each data point by its
// metric name and attributes, so a withdrawn policy's absence is observable.
func trapSeries(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				key := m.Name
				for _, kv := range dp.Attributes.ToSlice() {
					key += "|" + string(kv.Key) + "=" + kv.Value.String()
				}
				got[key] = dp.Value
			}
		}
	}
	return got
}

// F6: a stopped policy must stop exporting its trap series, and that only
// happens if the withdrawal reaches the tally. The registry on its own
// satisfies policy.TrapRegistry, so passing it in bare compiles and runs and
// leaves every count a stopped policy ever recorded exporting for the life of
// the process, which is exactly the contract Runner.Stop documents.
func TestTrapRegistration_WithdrawReachesTheRegistryAndTheTally(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	metrics.SetMeterForTest(provider.Meter("test"))
	t.Cleanup(metrics.ResetMeter)

	registry := traps.NewRegistry()
	tally := traps.NewTally(discardLogger())
	tally.Register()
	t.Cleanup(tally.Close)

	// Through the interface the manager is given, so the test fails if the
	// adapter stops satisfying it.
	var reg policy.TrapRegistry = newTrapRegistration(registry, tally)
	reg.Register("core", []traps.Device{{Policy: "core", Addr: netip.MustParseAddr("10.0.0.5")}}, nil)
	reg.Register("edge", []traps.Device{{Policy: "edge", Addr: netip.MustParseAddr("10.0.0.6")}}, nil)
	tally.Received("10.0.0.5", "core", "linkDown", traps.V2c)
	tally.Received("10.0.0.6", "edge", "linkDown", traps.V2c)

	const coreSeries = "snmp.traps_received|device_ip=10.0.0.5|policy=core|trap_name=linkDown|version=2c"
	const edgeSeries = "snmp.traps_received|device_ip=10.0.0.6|policy=edge|trap_name=linkDown|version=2c"
	require.Equal(t, 2, registry.Size())
	require.Contains(t, trapSeries(t, reader), coreSeries)

	reg.Withdraw("core")
	assert.Equal(t, 1, registry.Size(), "the registry stops attributing the policy's addresses")
	series := trapSeries(t, reader)
	assert.NotContains(t, series, coreSeries, "the tally stops exporting the policy's counts")
	assert.Contains(t, series, edgeSeries, "another policy's series is untouched")
}
