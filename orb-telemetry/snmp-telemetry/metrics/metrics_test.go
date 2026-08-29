package metrics

import (
	"context"
	"io"
	"log/slog"
	"net"
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

// dialTarget starts a listener on loopback, builds the exporter that
// SetupMetricsExport would build for the endpoint that endpointFor derives
// from that listener's address, and reports whether the exporter actually
// connected to it. Nothing speaks gRPC on the listener, so the export always
// fails; the connection itself is the signal. Asserting on the export error
// text instead would depend on the resolver, which differs between a
// developer machine and CI.
func dialTarget(t *testing.T, endpointFor func(addr string) string) bool {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	connected := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
		connected <- struct{}{}
	}()

	exp, err := otlpmetric.New(context.Background(), endpointOption(endpointFor(ln.Addr().String())), otlpmetric.WithInsecure())
	require.NoError(t, err, "exporter construction should never fail")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = exp.Shutdown(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = exp.Export(ctx, &metricdata.ResourceMetrics{})

	select {
	case <-connected:
		return true
	case <-time.After(time.Second):
		return false
	}
}

// TestEndpointOption_BareHostPort verifies that a schemeless "host:port"
// endpoint dials the configured address. WithEndpointURL would treat the host
// as a URL scheme and leave the target empty, so nothing would connect.
func TestEndpointOption_BareHostPort(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string {
		_, port, _ := net.SplitHostPort(addr)
		return "localhost:" + port
	}), "a bare host:port must reach the configured address")
}

// TestEndpointOption_IPLiteral verifies that a schemeless IP:port endpoint
// dials the configured address. WithEndpointURL's url.Parse fails outright for
// an IP literal, the error is swallowed, and the exporter would silently fall
// back to the SDK default instead.
func TestEndpointOption_IPLiteral(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string { return addr }),
		"a bare IP:port must reach the configured address, not the SDK default")
}

// TestEndpointOption_GRPCSchemeURL verifies that a scheme-bearing endpoint
// still takes the WithEndpointURL path and dials the host from the URL.
func TestEndpointOption_GRPCSchemeURL(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string { return "grpc://" + addr }),
		"a grpc:// URL must reach the address it names")
}

// TestEndpointOption_HTTPSchemeURL verifies that an http:// endpoint also
// takes the WithEndpointURL path and dials the host and port from the URL.
func TestEndpointOption_HTTPSchemeURL(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string { return "http://" + addr }),
		"an http:// URL must reach the address it names")
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
