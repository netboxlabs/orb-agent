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
	"google.golang.org/grpc/credentials"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
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

// cardinalityLimit bounds the attribute sets one instrument may hold before
// the SDK folds new ones into a single overflow bucket. The default is 2000
// and, once reached, every later series including a genuine device's first
// trap lands in that bucket for the life of the process. Ten thousand
// accommodates a few hundred trapping devices each sending a dozen kinds,
// five times the default, and stays well below where one OTLP export payload
// becomes a problem. Trap series are bounded above by registered addresses
// times the closed trap name set times three versions; the README says that a
// policy naming a whole /16 whose every host sends every kind is past this.
const cardinalityLimit = 10000

// providerOptions is everything the meter provider is configured with beside
// its reader. It is a function rather than a literal in SetupMetricsExport so
// a test can build a provider configured exactly the way this process
// configures its own, over a manual reader, with no OTLP endpoint to export
// to: the limit only matters for what it does to an instrument, and that is
// only observable through a provider that has it.
func providerOptions() []sdkmetric.Option {
	return []sdkmetric.Option{sdkmetric.WithCardinalityLimit(cardinalityLimit)}
}

// endpointOptions returns the otlpmetricgrpc options for the configured
// endpoint: where to connect, and whether that connection is plaintext.
//
// A bare host:port is not a valid URL, so WithEndpointURL would misparse or
// silently reject it; use WithEndpoint for that case and reserve
// WithEndpointURL for values that actually carry a scheme.
//
// Transport security follows the scheme. A bare host:port carries none and
// means plaintext, matching how the agent normalizes the same value for its
// own OTLP exporters. Applying the insecure option unconditionally would
// override the scheme, send plaintext to a collector expecting TLS, and fail
// every export.
func endpointOptions(endpoint string) []otlpmetric.Option {
	scheme, _, hasScheme := strings.Cut(endpoint, "://")
	if !hasScheme {
		// WithEndpoint expects a bare host:port and passes a trailing slash
		// through unnormalized, so strip it.
		return []otlpmetric.Option{
			otlpmetric.WithEndpoint(strings.TrimRight(endpoint, "/")),
			otlpmetric.WithInsecure(),
		}
	}

	// WithEndpointURL keys TLS off https alone and leaves every other scheme
	// plaintext, which is right for http and grpc but not for grpcs. Give
	// grpcs the credentials the SDK uses by default, verified against the
	// host's root CAs.
	opts := []otlpmetric.Option{otlpmetric.WithEndpointURL(endpoint)}
	if strings.EqualFold(scheme, "grpcs") {
		opts = append(opts, otlpmetric.WithTLSCredentials(credentials.NewTLS(nil)))
	}
	return opts
}

// SetupMetricsExport configures the OTLP metrics exporter with a periodic reader.
//
// A non-positive export period is refused rather than corrected. The SDK's
// WithInterval discards such a value and leaves the reader on its own 60
// second default, so the period this flag documents never applies and the
// startup line reports a cadence nothing exports at. Refusing it reports the
// value while there is still a caller to report it to.
//
// A period past config.MaxDurationSeconds is refused for the mirror reason.
// The seconds are multiplied by time.Second below, and above the representable
// range that multiply wraps to a small value, so a huge period would pass the
// check above and then configure a near-continuous export loop under a startup
// line reporting the huge number. The bound is applied here rather than at the
// flag because this is where the multiply happens, which is the same place the
// policy fields are bounded, and it is the only caller-facing point a value
// reaching this function has to pass.
func SetupMetricsExport(ctx context.Context, logg *slog.Logger, endpoint string, exportPeriodSeconds int) error {
	if endpoint == "" {
		logg.Info("No metrics endpoint provided, metrics collection is disabled")
		return nil
	}
	if exportPeriodSeconds <= 0 {
		return fmt.Errorf("otel export period must be greater than 0 seconds, got %d", exportPeriodSeconds)
	}
	if exportPeriodSeconds > config.MaxDurationSeconds {
		return fmt.Errorf("otel export period must be at most %d seconds, got %d",
			config.MaxDurationSeconds, exportPeriodSeconds)
	}

	exporter, err := otlpmetric.New(ctx, endpointOptions(endpoint)...)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(time.Duration(exportPeriodSeconds)*time.Second),
	)
	meterProvider = sdkmetric.NewMeterProvider(append(providerOptions(), sdkmetric.WithReader(reader))...)
	otel.SetMeterProvider(meterProvider)
	meter = otel.Meter("snmp-telemetry")
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

// GetMeter returns the global meter, or nil if metrics are not configured.
func GetMeter() metric.Meter {
	return meter
}

// ResetMeter resets the meter to nil for testing purposes.
func ResetMeter() {
	meter = nil
}

// SetMeterForTest installs a meter without an exporter, for tests that read
// instruments through a manual reader. ResetMeter undoes it.
func SetMeterForTest(m metric.Meter) {
	meter = m
}

// Shutdown gracefully shuts down the metrics exporter
func Shutdown(ctx context.Context) error {
	if meterProvider != nil {
		return meterProvider.Shutdown(ctx)
	}
	return nil
}
