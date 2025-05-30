package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	otlpmetric "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Global variables for meter and cache
var (
	meterProvider      *sdkmetric.MeterProvider
	meter              metric.Meter
	cacheLock          sync.Mutex
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

	exporter, err := otlpmetric.New(ctx,
		otlpmetric.WithEndpointURL(endpoint),
		otlpmetric.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(time.Duration(exportPeriodSeconds)*time.Second),
	)
	meterProvider = sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(meterProvider)
	meter = otel.Meter("snmp-discovery")
	logger = logg
	return nil
}

// GetCounter returns a cached counter or creates a new one if not exists.
func GetCounter(name string, description string) metric.Int64Counter {
	if meter == nil {
		return nil
	}
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if c, ok := counterCache[name]; ok {
		return c
	}

	// Create the counter (error handling omitted for brevity)
	c, err := meter.Int64Counter(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("Error creating counter", "name", name, "error", err)
		return nil
	}
	counterCache[name] = c
	return c
}

// GetUpDownCounter returns a cached updown counter or creates a new one if not exists.
func GetUpDownCounter(name string, description string) metric.Int64UpDownCounter {
	if meter == nil {
		return nil
	}
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if c, ok := upDownCounterCache[name]; ok {
		return c
	}
	c, err := meter.Int64UpDownCounter(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("Error creating updown counter", "name", name, "error", err)
		return nil
	}
	upDownCounterCache[name] = c
	return c
}

// GetHistogram returns a cached histogram or creates a new one if not exists.
func GetHistogram(name string, description string) metric.Float64Histogram {
	if meter == nil {
		return nil
	}
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if h, ok := histogramCache[name]; ok {
		return h
	}
	h, err := meter.Float64Histogram(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("Error creating histogram", "name", name, "error", err)
		return nil
	}
	histogramCache[name] = h
	return h
}

// GetGauge returns a cached gauge or creates a new one if not exists.
func GetGauge(name string, description string) metric.Int64Gauge {
	if meter == nil {
		return nil
	}
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if g, ok := gaugeCache[name]; ok {
		return g
	}
	g, err := meter.Int64Gauge(name, metric.WithDescription(description))
	if err != nil {
		logger.Error("Error creating gauge", "name", name, "error", err)
		return nil
	}
	gaugeCache[name] = g
	return g
}

// GetDiscoverySuccess returns the counter for successful discoveries.
func GetDiscoverySuccess() metric.Int64Counter {
	return GetCounter("discovery_success", "Number of successful network discoveries")
}

// GetDiscoveryFailure returns the counter for failed discoveries.
func GetDiscoveryFailure() metric.Int64Counter {
	return GetCounter("discovery_failure", "Number of failed network discoveries")
}

// GetPolicyExecutions returns the counter for policy executions
func GetPolicyExecutions() metric.Int64Counter {
	return GetCounter("policy_executions", "Number of policy executions")
}

// GetAPIRequests returns the counter for API requests
func GetAPIRequests() metric.Int64Counter {
	return GetCounter("api_requests", "Number of API requests")
}

// GetDiscoveredHosts returns the gauge for number of hosts discovered
func GetDiscoveredHosts() metric.Int64Gauge {
	return GetGauge("discovered_hosts", "Number of hosts discovered in each run")
}

// GetDiscoveryLatency returns the histogram for discovery latency
func GetDiscoveryLatency() metric.Float64Histogram {
	return GetHistogram("discovery_latency", "Time taken for the network discovery process")
}

// GetAPIResponseLatency returns the histogram for API response latency
func GetAPIResponseLatency() metric.Float64Histogram {
	return GetHistogram("api_response_latency", "Time taken to respond to API requests")
}

// GetActivePolicies returns the updown counter for active policies
func GetActivePolicies() metric.Int64UpDownCounter {
	return GetUpDownCounter("active_policies", "Number of currently active policies")
}

// GetDiscoveryAttempts returns the counter for SNMP discovery attempts
func GetDiscoveryAttempts() metric.Int64Counter {
	return GetCounter("discovery_attempts", "Number of SNMP discovery attempts")
}

// ResetMeter resets the meter to nil for testing purposes.
func ResetMeter() {
	meter = nil
}

// Shutdown gracefully shuts down the metrics exporter
func Shutdown(ctx context.Context) error {
	if meterProvider != nil {
		return meterProvider.Shutdown(ctx)
	}
	return nil
}
