package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	otlpmetric "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc/credentials"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
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

// CardinalityLimit is ten thousand attribute sets per instrument. A series is
// one metric on one device with one attribute set, so a policy over a /24 with
// fifty interfaces and ten counters is a few thousand series per metric name,
// and the limit is per instrument. Past it the SDK folds new series into its
// overflow set. Exported so the collector's series budget can bound itself one
// below this and never hand the SDK a series it would fold. That budget counts
// for the whole process, because one instrument per metric name serves every
// collector.
const CardinalityLimit = 10000

// providerOptions is everything the meter provider is configured with beside
// its reader. It is a function rather than a literal in SetupMetricsExport so
// a test can build a provider configured exactly the way this process
// configures its own, over a manual reader, with no OTLP endpoint to export
// to: the limit only matters for what it does to an instrument, and that is
// only observable through a provider that has it.
func providerOptions() []sdkmetric.Option {
	return []sdkmetric.Option{sdkmetric.WithCardinalityLimit(CardinalityLimit)}
}

// dnsName is the shape of a hostname: labels of letters, digits and hyphens,
// joined by dots, none starting or ending with a hyphen.
var dnsName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$`)

// endpointURL parses a scheme-bearing endpoint and checks it: a hostname, a
// port in range when one is written, and a scheme the exporter knows. A URL
// without a port is given the OTLP gRPC default, 4317. Left to the resolver,
// a missing port became 443 whatever the scheme, so a plaintext http:// or
// grpc:// URL exported to a port nothing plaintext listens on.
func endpointURL(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("otel endpoint %q is not a valid URL: %w", endpoint, err)
	}
	scheme := u.Scheme
	// The parsed hostname, not the authority: "http://:4317" has an authority
	// and no host, and gRPC reads the empty host as localhost.
	if u.Hostname() == "" {
		return nil, fmt.Errorf("otel endpoint %q names no host", endpoint)
	}
	// The same shape the bare form is held to: a URL parses with any host
	// text, and one no resolver could look up would be retried for ever.
	if h := u.Hostname(); net.ParseIP(h) == nil && !dnsName.MatchString(h) {
		return nil, fmt.Errorf("otel endpoint %q: host %q is neither an IP address nor a DNS name", endpoint, h)
	}
	// A port written into the URL is held to the same range as the bare form's:
	// the SDK keeps an out-of-range one and every export fails on it.
	if port := u.Port(); port != "" {
		if n, perr := strconv.ParseUint(port, 10, 16); perr != nil || n == 0 {
			return nil, fmt.Errorf("otel endpoint %q: port %q must be a number between 1 and 65535", endpoint, port)
		}
	}
	// Only the documented schemes reach the exporter. The SDK reads every
	// scheme but https as plaintext, so a mistyped one such as "htps" would
	// have exported in the clear, or failed every export, under a startup line
	// reporting the URL as configured.
	switch strings.ToLower(scheme) {
	case "http", "https", "grpc", "grpcs":
	default:
		return nil, fmt.Errorf("otel endpoint %q: scheme %q is not http, https, grpc or grpcs", endpoint, scheme)
	}

	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "4317")
	}
	return u, nil
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
//
// A scheme-bearing endpoint is parsed here and refused when it does not parse
// or names no host. WithEndpointURL does not return that failure: it logs the
// parse error and keeps the SDK's default endpoint, so a mistyped URL let the
// exporter start, the startup line report the URL as configured, and every
// export go to localhost:4317.
func endpointOptions(endpoint string) ([]otlpmetric.Option, error) {
	scheme, _, hasScheme := strings.Cut(endpoint, "://")
	if !hasScheme {
		// WithEndpoint expects a bare host:port and passes a trailing slash
		// through unnormalized, so strip it. The form is checked here: the
		// gRPC connection opens lazily, so a value that is not host:port let
		// the exporter build and every export retry an address that could
		// never be dialled, under a startup line reporting it as configured.
		bare := strings.TrimRight(endpoint, "/")
		host, port, err := net.SplitHostPort(bare)
		if err != nil {
			return nil, fmt.Errorf("otel endpoint %q is neither host:port nor a URL with a scheme: %w", endpoint, err)
		}
		if host == "" {
			return nil, fmt.Errorf("otel endpoint %q names no host", endpoint)
		}
		// The split only separates the fields: "collector/path:4317" splits
		// into a host no resolver could look up, and the exporter would retry
		// it for ever. The host is an IP literal or a DNS name.
		if net.ParseIP(host) == nil && !dnsName.MatchString(host) {
			return nil, fmt.Errorf("otel endpoint %q: host %q is neither an IP address nor a DNS name", endpoint, host)
		}
		if n, perr := strconv.ParseUint(port, 10, 16); perr != nil || n == 0 {
			return nil, fmt.Errorf("otel endpoint %q: port %q must be a number between 1 and 65535", endpoint, port)
		}
		return []otlpmetric.Option{
			otlpmetric.WithEndpoint(bare),
			otlpmetric.WithInsecure(),
		}, nil
	}
	u, err := endpointURL(endpoint)
	if err != nil {
		return nil, err
	}
	endpoint = u.String()

	// WithEndpointURL keys TLS off https alone and leaves every other scheme
	// plaintext, which is right for http and grpc but not for grpcs. Give
	// grpcs the credentials the SDK uses by default, verified against the
	// host's root CAs.
	opts := []otlpmetric.Option{otlpmetric.WithEndpointURL(endpoint)}
	if strings.EqualFold(scheme, "grpcs") {
		opts = append(opts, otlpmetric.WithTLSCredentials(credentials.NewTLS(nil)))
	}
	return opts, nil
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

	opts, err := endpointOptions(endpoint)
	if err != nil {
		return err
	}
	exporter, err := otlpmetric.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(time.Duration(exportPeriodSeconds)*time.Second),
	)
	meterProvider = sdkmetric.NewMeterProvider(append(providerOptions(), sdkmetric.WithReader(reader))...)
	otel.SetMeterProvider(meterProvider)
	meter = otel.Meter("gnmi-telemetry")
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

// ResetMeter resets the meter to nil for testing purposes. The instrument
// caches are cleared with it: an instrument is bound to the meter that created
// it, so a cached one handed out after a reset would still write to the
// previous test's provider.
func ResetMeter() {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	meter = nil
	counterCache = map[string]metric.Int64Counter{}
	upDownCounterCache = map[string]metric.Int64UpDownCounter{}
	histogramCache = map[string]metric.Float64Histogram{}
	gaugeCache = map[string]metric.Int64Gauge{}
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
