package metrics

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// testLogger returns a no-op slog logger for use in tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setupTestMeter installs a real SDK MeterProvider backed by an in-memory
// ManualReader (no network, no goroutines) and wires the package globals so
// that every Get* helper works against it. It returns a cleanup function that
// resets the package state and restores the global OTel meter provider.
func setupTestMeter(t *testing.T) {
	t.Helper()

	ResetMeter()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(mp)
	m := otel.Meter("gnmi-discovery-test")

	cacheLock.Lock()
	meterProvider = mp
	meter = m
	logger = testLogger()
	cacheLock.Unlock()

	t.Cleanup(func() {
		_ = mp.Shutdown(context.Background())
		ResetMeter()
		otel.SetMeterProvider(nil)
	})
}

// ---------------------------------------------------------------------------
// SetupMetricsExport
// ---------------------------------------------------------------------------

// TestSetupMetricsExport_EmptyEndpoint verifies the early-return path when no
// endpoint is supplied: the function should succeed and leave the meter nil.
func TestSetupMetricsExport_EmptyEndpoint(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	err := SetupMetricsExport(context.Background(), testLogger(), "", 60)
	require.NoError(t, err)

	// meter must remain nil because no provider was installed.
	cacheLock.Lock()
	m := meter
	cacheLock.Unlock()
	assert.Nil(t, m)
}

// shutdownIgnoreConnRefused shuts down the provider created by
// SetupMetricsExport and tolerates the "connection refused" error that the
// PeriodicReader raises when it tries to flush to a non-existent collector.
// Tests that exercise SetupMetricsExport must use this helper in their cleanup
// because the package's Shutdown wraps mp.Shutdown which flushes in-flight
// data; without a live collector that returns an UNAVAILABLE error.
func shutdownIgnoreConnRefused(t *testing.T) {
	t.Helper()
	// Shutdown flushes in-flight data to the (non-existent) collector; the OTLP
	// gRPC exporter would otherwise retry/backoff for ~30s before giving up. Use
	// a short deadline so the flush aborts fast — we only need Shutdown's code
	// path covered, and the flush error is expected/ignored in a unit test.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = Shutdown(ctx)
	ResetMeter()
}

// TestSetupMetricsExport_BareHostPort verifies that a bare host:port endpoint
// (no scheme) is accepted. otlpmetricgrpc.New is lazy — it does NOT dial the
// collector at construction time — so this succeeds even with a dummy address.
func TestSetupMetricsExport_BareHostPort(t *testing.T) {
	ResetMeter()
	t.Cleanup(func() { shutdownIgnoreConnRefused(t) })

	err := SetupMetricsExport(context.Background(), testLogger(), "localhost:4317", 60)
	require.NoError(t, err)

	cacheLock.Lock()
	m := meter
	mp := meterProvider
	cacheLock.Unlock()

	assert.NotNil(t, m, "meter should be set after successful setup")
	assert.NotNil(t, mp, "meterProvider should be set after successful setup")
}

// TestSetupMetricsExport_URLEndpoint verifies the scheme-bearing URL path
// (WithEndpointURL branch).
func TestSetupMetricsExport_URLEndpoint(t *testing.T) {
	ResetMeter()
	t.Cleanup(func() { shutdownIgnoreConnRefused(t) })

	err := SetupMetricsExport(context.Background(), testLogger(), "http://localhost:4317", 60)
	require.NoError(t, err)

	cacheLock.Lock()
	mp := meterProvider
	cacheLock.Unlock()
	assert.NotNil(t, mp)
}

// TestSetupMetricsExport_TrailingSlash verifies that a bare host:port with a
// trailing slash is normalised without error (TrimRight branch).
func TestSetupMetricsExport_TrailingSlash(t *testing.T) {
	ResetMeter()
	t.Cleanup(func() { shutdownIgnoreConnRefused(t) })

	err := SetupMetricsExport(context.Background(), testLogger(), "localhost:4317/", 60)
	require.NoError(t, err)
}

// TestSetupMetricsExport_MeterUsable verifies that after a successful setup a
// meter obtained from the package can create and record a counter without panic.
func TestSetupMetricsExport_MeterUsable(t *testing.T) {
	ResetMeter()
	t.Cleanup(func() { shutdownIgnoreConnRefused(t) })

	require.NoError(t, SetupMetricsExport(context.Background(), testLogger(), "localhost:4317", 1))

	require.NotPanics(t, func() {
		c := GetCounter("test.setup.counter", "counter created after setup")
		require.NotNil(t, c)
		c.Add(context.Background(), 1)
	})
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

// TestShutdown_BeforeSetup verifies that calling Shutdown before
// SetupMetricsExport is a no-op that returns nil without consuming shutdownOnce.
func TestShutdown_BeforeSetup(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	err := Shutdown(context.Background())
	assert.NoError(t, err)
}

// TestShutdown_AfterSetup verifies that Shutdown returns nil after a real
// meter provider has been installed. The provider is backed by a ManualReader
// (no network) so the flush on shutdown always succeeds.
func TestShutdown_AfterSetup(t *testing.T) {
	setupTestMeter(t) // installs ManualReader-backed provider into package globals

	err := Shutdown(context.Background())
	assert.NoError(t, err)
}

// TestShutdown_Idempotent verifies that a second Shutdown call is a no-op.
func TestShutdown_Idempotent(t *testing.T) {
	setupTestMeter(t) // installs ManualReader-backed provider

	assert.NoError(t, Shutdown(context.Background()))
	// second call must not error (shutdownOnce guards the inner call)
	assert.NoError(t, Shutdown(context.Background()))
}

// ---------------------------------------------------------------------------
// ResetMeter
// ---------------------------------------------------------------------------

// TestResetMeter_ClearsState verifies that ResetMeter wipes meter and all
// caches, and that subsequent Get* calls return nil (no meter installed).
func TestResetMeter_ClearsState(t *testing.T) {
	setupTestMeter(t) // installs a real meter
	// populate caches
	require.NotNil(t, GetCounter("reset.c", ""))
	require.NotNil(t, GetUpDownCounter("reset.ud", ""))
	require.NotNil(t, GetHistogram("reset.h", ""))
	require.NotNil(t, GetGauge("reset.g", ""))

	ResetMeter()

	// after reset, all Get* must return nil (no meter)
	assert.Nil(t, GetCounter("reset.c", ""))
	assert.Nil(t, GetUpDownCounter("reset.ud", ""))
	assert.Nil(t, GetHistogram("reset.h", ""))
	assert.Nil(t, GetGauge("reset.g", ""))
}

// TestResetMeter_AllowsNewSetup verifies that after ResetMeter a fresh
// setup-then-shutdown cycle works correctly (shutdownOnce is also reset).
// Both cycles use ManualReader-backed providers so no network flush occurs.
func TestResetMeter_AllowsNewSetup(t *testing.T) {
	t.Cleanup(func() {
		ResetMeter()
		otel.SetMeterProvider(nil)
	})

	installManualMeter := func() {
		reader := sdkmetric.NewManualReader()
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		otel.SetMeterProvider(mp)
		cacheLock.Lock()
		meterProvider = mp
		meter = otel.Meter("gnmi-discovery-test")
		logger = testLogger()
		cacheLock.Unlock()
	}

	// First setup/shutdown cycle.
	ResetMeter()
	installManualMeter()
	assert.NoError(t, Shutdown(context.Background()))

	// ResetMeter resets shutdownOnce so the second cycle can use it.
	ResetMeter()

	// Second setup/shutdown cycle.
	installManualMeter()
	assert.NoError(t, Shutdown(context.Background()))
}

// ---------------------------------------------------------------------------
// GetCounter
// ---------------------------------------------------------------------------

// TestGetCounter_NilMeter verifies that GetCounter returns nil when no meter is
// installed (the nil-meter guard branch).
func TestGetCounter_NilMeter(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	assert.Nil(t, GetCounter("x", "desc"))
}

// TestGetCounter_Creates verifies that GetCounter returns a non-nil instrument
// when a meter is installed and records without panic.
func TestGetCounter_Creates(t *testing.T) {
	setupTestMeter(t)

	c := GetCounter("test.counter", "a test counter")
	require.NotNil(t, c)
	require.NotPanics(t, func() { c.Add(context.Background(), 5) })
}

// TestGetCounter_CacheHit verifies that a second call with the same name
// returns the identical instrument (cache branch).
func TestGetCounter_CacheHit(t *testing.T) {
	setupTestMeter(t)

	c1 := GetCounter("test.counter.cached", "desc")
	c2 := GetCounter("test.counter.cached", "desc")
	require.NotNil(t, c1)
	assert.Equal(t, c1, c2, "expected same instrument from cache")
}

// ---------------------------------------------------------------------------
// GetUpDownCounter
// ---------------------------------------------------------------------------

// TestGetUpDownCounter_NilMeter verifies nil return when no meter is installed.
func TestGetUpDownCounter_NilMeter(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	assert.Nil(t, GetUpDownCounter("x", "desc"))
}

// TestGetUpDownCounter_Creates verifies creation and usability.
func TestGetUpDownCounter_Creates(t *testing.T) {
	setupTestMeter(t)

	ud := GetUpDownCounter("test.updown", "an updown counter")
	require.NotNil(t, ud)
	require.NotPanics(t, func() { ud.Add(context.Background(), -1) })
}

// TestGetUpDownCounter_CacheHit verifies the cache branch.
func TestGetUpDownCounter_CacheHit(t *testing.T) {
	setupTestMeter(t)

	ud1 := GetUpDownCounter("test.updown.cached", "desc")
	ud2 := GetUpDownCounter("test.updown.cached", "desc")
	require.NotNil(t, ud1)
	assert.Equal(t, ud1, ud2)
}

// ---------------------------------------------------------------------------
// GetHistogram
// ---------------------------------------------------------------------------

// TestGetHistogram_NilMeter verifies nil return when no meter is installed.
func TestGetHistogram_NilMeter(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	assert.Nil(t, GetHistogram("x", "desc"))
}

// TestGetHistogram_Creates verifies creation and usability.
func TestGetHistogram_Creates(t *testing.T) {
	setupTestMeter(t)

	h := GetHistogram("test.histogram", "a test histogram")
	require.NotNil(t, h)
	require.NotPanics(t, func() { h.Record(context.Background(), 3.14) })
}

// TestGetHistogram_CacheHit verifies the cache branch.
func TestGetHistogram_CacheHit(t *testing.T) {
	setupTestMeter(t)

	h1 := GetHistogram("test.histogram.cached", "desc")
	h2 := GetHistogram("test.histogram.cached", "desc")
	require.NotNil(t, h1)
	assert.Equal(t, h1, h2)
}

// ---------------------------------------------------------------------------
// GetGauge
// ---------------------------------------------------------------------------

// TestGetGauge_NilMeter verifies nil return when no meter is installed.
func TestGetGauge_NilMeter(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	assert.Nil(t, GetGauge("x", "desc"))
}

// TestGetGauge_Creates verifies creation and usability.
func TestGetGauge_Creates(t *testing.T) {
	setupTestMeter(t)

	g := GetGauge("test.gauge", "a test gauge")
	require.NotNil(t, g)
	require.NotPanics(t, func() { g.Record(context.Background(), 42) })
}

// TestGetGauge_CacheHit verifies the cache branch.
func TestGetGauge_CacheHit(t *testing.T) {
	setupTestMeter(t)

	g1 := GetGauge("test.gauge.cached", "desc")
	g2 := GetGauge("test.gauge.cached", "desc")
	require.NotNil(t, g1)
	assert.Equal(t, g1, g2)
}

// ---------------------------------------------------------------------------
// GetAPIRequests / GetAPIResponseLatency
// ---------------------------------------------------------------------------

// TestGetAPIRequests_NilMeter verifies nil return when no meter is installed.
func TestGetAPIRequests_NilMeter(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	assert.Nil(t, GetAPIRequests())
}

// TestGetAPIRequests_WithMeter verifies creation and recording.
func TestGetAPIRequests_WithMeter(t *testing.T) {
	setupTestMeter(t)

	c := GetAPIRequests()
	require.NotNil(t, c)
	require.NotPanics(t, func() { c.Add(context.Background(), 1) })
}

// TestGetAPIRequests_CacheHit verifies that repeated calls return the same counter.
func TestGetAPIRequests_CacheHit(t *testing.T) {
	setupTestMeter(t)

	c1 := GetAPIRequests()
	c2 := GetAPIRequests()
	require.NotNil(t, c1)
	assert.Equal(t, c1, c2)
}

// TestGetAPIResponseLatency_NilMeter verifies nil return when no meter is installed.
func TestGetAPIResponseLatency_NilMeter(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	assert.Nil(t, GetAPIResponseLatency())
}

// TestGetAPIResponseLatency_WithMeter verifies creation and recording.
func TestGetAPIResponseLatency_WithMeter(t *testing.T) {
	setupTestMeter(t)

	h := GetAPIResponseLatency()
	require.NotNil(t, h)
	require.NotPanics(t, func() { h.Record(context.Background(), 0.123) })
}

// TestGetAPIResponseLatency_CacheHit verifies repeated calls return the same histogram.
func TestGetAPIResponseLatency_CacheHit(t *testing.T) {
	setupTestMeter(t)

	h1 := GetAPIResponseLatency()
	h2 := GetAPIResponseLatency()
	require.NotNil(t, h1)
	assert.Equal(t, h1, h2)
}

// ---------------------------------------------------------------------------
// gnmi_metrics.go internal helpers: counter / upDown
// ---------------------------------------------------------------------------

// TestCounter_WithMeter covers the GetCounter-returns-non-nil branch of the
// internal counter helper.
func TestCounter_WithMeter(t *testing.T) {
	setupTestMeter(t)

	require.NotPanics(t, func() {
		// counter() calls GetCounter; with meter installed it returns a real instrument.
		c := counter("gnmi.test.internal.counter", "internal test")
		require.NotNil(t, c)
		c.Add(context.Background(), 1)
	})
}

// TestUpDown_WithMeter covers the GetUpDownCounter-returns-non-nil branch of
// the internal upDown helper.
func TestUpDown_WithMeter(t *testing.T) {
	setupTestMeter(t)

	require.NotPanics(t, func() {
		ud := upDown("gnmi.test.internal.updown", "internal test")
		require.NotNil(t, ud)
		ud.Add(context.Background(), 2)
	})
}

// TestGnmiAccessors_WithMeter covers all gNMI accessor functions when a real
// meter is installed (the non-noop path through counter/upDown).
func TestGnmiAccessors_WithMeter(t *testing.T) {
	setupTestMeter(t)

	require.NotPanics(t, func() {
		GetTargetsActive().Add(context.Background(), 1)
		GetSubscriptionsActive().Add(context.Background(), -1)
		GetReconnects().Add(context.Background(), 1)
		GetNotifications().Add(context.Background(), 10)
		GetNotificationsDropped().Add(context.Background(), 2)
		GetCapabilityErrors().Add(context.Background(), 1)
		GetFlushes().Add(context.Background(), 5)
		GetIngestErrors().Add(context.Background(), 1)
		GetModeFallbacks().Add(context.Background(), 1)
		GetProfileFallbacks().Add(context.Background(), 1)
		GetRemovalsBlocked().Add(context.Background(), 3)
		GetFlushSkippedNoIdentity().Add(context.Background(), 1)
	})
}
