package metrics

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otlpmetric "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// testLogger returns a no-op slog logger for use in tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// dialAttempt builds the exporter that SetupMetricsExport would build for the
// given endpoint, via the real endpointOption function, and attempts a single
// export against it. No collector is listening, so the export always fails,
// but the failure reveals which address the exporter actually dialed. That is
// exactly what url.Parse gets wrong for a schemeless endpoint, and swallows
// for an IP-literal one, so the dial target is the only reliable signal that
// the fix is doing its job: otlpmetric.New itself never returns an error for
// these inputs, and the exporter is always non-nil either way.
func dialAttempt(t *testing.T, endpoint string) error {
	t.Helper()

	exp, err := otlpmetric.New(context.Background(), endpointOption(endpoint), otlpmetric.WithInsecure())
	require.NoError(t, err, "exporter construction should never fail")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = exp.Shutdown(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	return exp.Export(ctx, &metricdata.ResourceMetrics{})
}

// TestEndpointOption_BareHostPort verifies that a schemeless "host:port"
// endpoint dials the given host directly instead of falling into
// WithEndpointURL's url.Parse, which treats the host as a scheme and leaves
// the resulting target empty ("dns resolver: missing address").
func TestEndpointOption_BareHostPort(t *testing.T) {
	err := dialAttempt(t, "localhost:4317")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "missing address",
		"a bare host:port must not be parsed as a URL")
	assert.Contains(t, err.Error(), "4317", "expected a dial attempt against the configured port")
}

// TestEndpointOption_IPLiteral verifies that a schemeless IP:port endpoint
// dials the configured address. Before the fix, WithEndpointURL's url.Parse
// fails outright for an IP literal (the leading digit is not a valid URL
// scheme character), the parse error is swallowed into the OTel global error
// handler, and the exporter silently falls back to the SDK default
// "localhost:4317" instead of the operator's address.
func TestEndpointOption_IPLiteral(t *testing.T) {
	err := dialAttempt(t, "127.0.0.1:4317")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "127.0.0.1:4317",
		"expected a dial attempt against the configured address, not the SDK default")
}

// TestEndpointOption_GRPCSchemeURL verifies that a scheme-bearing endpoint
// still takes the WithEndpointURL path and its host is actually used for
// resolution.
func TestEndpointOption_GRPCSchemeURL(t *testing.T) {
	err := dialAttempt(t, "grpc://collector:4317")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero addresses",
		"expected resolution to be attempted for the URL host, which does not resolve here")
}

// TestEndpointOption_HTTPSchemeURL verifies that an http:// endpoint also
// takes the WithEndpointURL path and dials the host and port from the URL.
func TestEndpointOption_HTTPSchemeURL(t *testing.T) {
	err := dialAttempt(t, "http://0.0.0.0:4319")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0.0.0.0:4319",
		"expected a dial attempt against the configured address")
}

// TestSetupMetricsExport_EmptyEndpoint verifies the early-return path when no
// endpoint is supplied: the function should succeed and leave the meter nil.
func TestSetupMetricsExport_EmptyEndpoint(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	err := SetupMetricsExport(context.Background(), testLogger(), "", 60)
	require.NoError(t, err)
	assert.Nil(t, GetMeter())
}

// shutdownIgnoreFlushError shuts down the provider created by
// SetupMetricsExport with a short deadline and discards the flush error: with
// no real collector listening, the flush is expected to fail. This test only
// needs SetupMetricsExport's code path exercised, not a successful export.
func shutdownIgnoreFlushError(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = Shutdown(ctx)
	ResetMeter()
}

// TestSetupMetricsExport_WiresMeter verifies that SetupMetricsExport installs
// a usable meter for a bare host:port endpoint.
func TestSetupMetricsExport_WiresMeter(t *testing.T) {
	ResetMeter()
	t.Cleanup(func() { shutdownIgnoreFlushError(t) })

	err := SetupMetricsExport(context.Background(), testLogger(), "localhost:4317", 60)
	require.NoError(t, err)
	assert.NotNil(t, GetMeter())
}
