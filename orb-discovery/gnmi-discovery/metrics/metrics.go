package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	otlpmetric "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// defaultExportPeriodSeconds is the fallback metrics export interval used when an
// invalid (<= 0) period is supplied; mirrors the --otel-export-period flag default.
const defaultExportPeriodSeconds = 10

// Global variables for meter and cache
var (
	meterProvider      *sdkmetric.MeterProvider
	meter              metric.Meter
	cacheLock          sync.Mutex
	shutdownOnce       sync.Once
	counterCache       = map[string]metric.Int64Counter{}
	upDownCounterCache = map[string]metric.Int64UpDownCounter{}
	histogramCache     = map[string]metric.Float64Histogram{}
	gaugeCache         = map[string]metric.Int64Gauge{}
	logger             *slog.Logger
)

// SetupMetricsExport configures the OTLP metrics exporter with a periodic reader.
func SetupMetricsExport(ctx context.Context, logg *slog.Logger, endpoint string, exportPeriodSeconds int) error {
	if endpoint == "" {
		logg.Info("No metrics endpoint provided, metrics collection is disabled")
		return nil
	}

	// A zero/negative interval would make the periodic reader misbehave; clamp to
	// the default rather than failing startup over a bad flag.
	if exportPeriodSeconds <= 0 {
		logg.Warn("invalid otel export period; using default",
			"given_seconds", exportPeriodSeconds, "default_seconds", defaultExportPeriodSeconds)
		exportPeriodSeconds = defaultExportPeriodSeconds
	}

	var endpointOpt otlpmetric.Option
	if strings.Contains(endpoint, "://") {
		endpointOpt = otlpmetric.WithEndpointURL(endpoint)
	} else {
		// WithEndpoint expects a bare host:port; a trailing slash (e.g.
		// "localhost:4317/") would be passed through unnormalized, so strip it.
		endpointOpt = otlpmetric.WithEndpoint(strings.TrimRight(endpoint, "/"))
	}
	exporter, err := otlpmetric.New(ctx,
		endpointOpt,
		otlpmetric.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(time.Duration(exportPeriodSeconds)*time.Second),
	)
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(mp)
	m := otel.Meter("gnmi-discovery")

	cacheLock.Lock()
	meterProvider = mp
	meter = m
	logger = logg
	cacheLock.Unlock()
	return nil
}

// GetCounter returns a cached counter or creates a new one if not exists.
func GetCounter(name string, description string) metric.Int64Counter {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	if meter == nil {
		return nil
	}

	if c, ok := counterCache[name]; ok {
		return c
	}

	// Create the counter; on error log and return nil so callers no-op safely.
	c, err := meter.Int64Counter(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("error creating counter", "name", name, "error", err)
		return nil
	}
	counterCache[name] = c
	return c
}

// GetUpDownCounter returns a cached updown counter or creates a new one if not exists.
func GetUpDownCounter(name string, description string) metric.Int64UpDownCounter {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	if meter == nil {
		return nil
	}

	if c, ok := upDownCounterCache[name]; ok {
		return c
	}
	c, err := meter.Int64UpDownCounter(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("error creating updown counter", "name", name, "error", err)
		return nil
	}
	upDownCounterCache[name] = c
	return c
}

// GetHistogram returns a cached histogram or creates a new one if not exists.
func GetHistogram(name string, description string) metric.Float64Histogram {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	if meter == nil {
		return nil
	}

	if h, ok := histogramCache[name]; ok {
		return h
	}
	h, err := meter.Float64Histogram(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("error creating histogram", "name", name, "error", err)
		return nil
	}
	histogramCache[name] = h
	return h
}

// GetGauge returns a cached gauge or creates a new one if not exists.
func GetGauge(name string, description string) metric.Int64Gauge {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	if meter == nil {
		return nil
	}

	if g, ok := gaugeCache[name]; ok {
		return g
	}
	g, err := meter.Int64Gauge(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("error creating gauge", "name", name, "error", err)
		return nil
	}
	gaugeCache[name] = g
	return g
}

// GetAPIRequests returns the counter for API requests
func GetAPIRequests() metric.Int64Counter {
	return GetCounter("api_requests", "Number of API requests")
}

// GetAPIResponseLatency returns the histogram for API response latency
func GetAPIResponseLatency() metric.Float64Histogram {
	return GetHistogram("api_response_latency", "Time taken to respond to API requests")
}

// ResetMeter resets the meter and all cached instruments to nil for testing
// purposes. It also resets shutdownOnce so that a subsequent Setup +
// SetupMetricsExport + Shutdown cycle works correctly in test sequences that
// need to exercise multiple setup/teardown rounds.
func ResetMeter() {
	cacheLock.Lock()
	meter = nil
	meterProvider = nil
	counterCache = map[string]metric.Int64Counter{}
	upDownCounterCache = map[string]metric.Int64UpDownCounter{}
	histogramCache = map[string]metric.Float64Histogram{}
	gaugeCache = map[string]metric.Int64Gauge{}
	shutdownOnce = sync.Once{}
	cacheLock.Unlock()
}

// Shutdown gracefully shuts down the metrics exporter. It is idempotent: a
// second real shutdown attempt (e.g. from both the signal handler and the
// server-error path) is a no-op that returns nil.
//
// Calling Shutdown before SetupMetricsExport (meterProvider == nil) is a
// no-op that does NOT consume the Once, so a later SetupMetricsExport +
// Shutdown cycle still works correctly.
//
// Test sequences that need multiple setup/teardown cycles must call ResetMeter
// between cycles; ResetMeter resets both the meter and shutdownOnce under the
// cache lock, ensuring a fresh shutdown guard for the next cycle.
func Shutdown(ctx context.Context) error {
	cacheLock.Lock()
	mp := meterProvider
	cacheLock.Unlock()

	if mp == nil {
		// No real provider yet; don't burn the Once so a future real shutdown works.
		return nil
	}

	var shutdownErr error
	shutdownOnce.Do(func() {
		shutdownErr = mp.Shutdown(ctx)
	})
	return shutdownErr
}
