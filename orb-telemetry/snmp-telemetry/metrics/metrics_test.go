package metrics

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otlpmetric "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// http2ClientPreface opens every plaintext gRPC connection.
const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// tlsRecordHeader opens every TLS connection: a handshake record (0x16)
// carrying the legacy record version 3.1, then the ClientHello.
var tlsRecordHeader = []byte{0x16, 0x03, 0x01}

// testLogger returns a no-op slog logger for use in tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// firstBytes starts a listener on loopback, builds the exporter that
// SetupMetricsExport would build for the endpoint that endpointFor derives
// from that listener's address, and returns the first bytes the exporter puts
// on the wire. It returns nil when nothing connects.
//
// Nothing speaks gRPC on the listener, so the export always fails; what the
// exporter sends is the signal. Asserting on the export error text instead
// would depend on the resolver, which differs between a developer machine and
// CI.
//
// Those opening bytes are also what separates the two transports, since a TLS
// client and a plaintext client both open a TCP connection to a plaintext
// listener: a plaintext gRPC client writes the HTTP/2 client preface, a TLS
// client writes a handshake record.
func firstBytes(t *testing.T, endpointFor func(addr string) string) []byte {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	opened := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, len(http2ClientPreface))
		n, _ := io.ReadFull(conn, buf)
		opened <- buf[:n]
	}()

	exp, err := otlpmetric.New(context.Background(), endpointOptions(endpointFor(ln.Addr().String()))...)
	require.NoError(t, err, "exporter construction should never fail")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = exp.Shutdown(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	exported := make(chan struct{})
	go func() {
		defer close(exported)
		_ = exp.Export(ctx, &metricdata.ResourceMetrics{})
	}()
	defer func() {
		cancel()
		<-exported
	}()

	select {
	case b := <-opened:
		return b
	case <-time.After(2 * time.Second):
		return nil
	}
}

// dialTarget reports whether the exporter built for endpointFor's endpoint
// reached the loopback listener at all, without regard to what it sent.
func dialTarget(t *testing.T, endpointFor func(addr string) string) bool {
	t.Helper()
	return len(firstBytes(t, endpointFor)) > 0
}

// TestEndpointOptions_BareHostPort verifies that a schemeless "host:port"
// endpoint dials the configured address. WithEndpointURL would treat the host
// as a URL scheme and leave the target empty, so nothing would connect.
func TestEndpointOptions_BareHostPort(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string {
		_, port, _ := net.SplitHostPort(addr)
		return "localhost:" + port
	}), "a bare host:port must reach the configured address")
}

// TestEndpointOptions_IPLiteral verifies that a schemeless IP:port endpoint
// dials the configured address. WithEndpointURL's url.Parse fails outright for
// an IP literal, the error is swallowed, and the exporter would silently fall
// back to the SDK default instead.
func TestEndpointOptions_IPLiteral(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string { return addr }),
		"a bare IP:port must reach the configured address, not the SDK default")
}

// TestEndpointOptions_GRPCSchemeURL verifies that a scheme-bearing endpoint
// still takes the WithEndpointURL path and dials the host from the URL.
func TestEndpointOptions_GRPCSchemeURL(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string { return "grpc://" + addr }),
		"a grpc:// URL must reach the address it names")
}

// TestEndpointOptions_HTTPSchemeURL verifies that an http:// endpoint also
// takes the WithEndpointURL path and dials the host and port from the URL.
func TestEndpointOptions_HTTPSchemeURL(t *testing.T) {
	assert.True(t, dialTarget(t, func(addr string) string { return "http://" + addr }),
		"an http:// URL must reach the address it names")
}

// TestEndpointOptions_BareHostPortIsPlaintext pins the meaning of a schemeless
// endpoint: no scheme means plaintext, so the exporter must open with the
// HTTP/2 preface and not a TLS handshake.
func TestEndpointOptions_BareHostPortIsPlaintext(t *testing.T) {
	assert.Equal(t, []byte(http2ClientPreface), firstBytes(t, func(addr string) string { return addr }),
		"a bare host:port must connect in plaintext")
}

// TestEndpointOptions_PlaintextSchemes verifies the schemes that name no TLS
// connect in plaintext rather than inheriting the SDK's TLS default.
func TestEndpointOptions_PlaintextSchemes(t *testing.T) {
	for _, scheme := range []string{"http", "grpc"} {
		t.Run(scheme, func(t *testing.T) {
			got := firstBytes(t, func(addr string) string { return scheme + "://" + addr })
			assert.Equal(t, []byte(http2ClientPreface), got, "%s:// must connect in plaintext", scheme)
		})
	}
}

// TestEndpointOptions_TLSSchemes is the regression guard: a scheme that names
// TLS must negotiate TLS. An unconditional insecure option overrides the
// scheme, and the collector then receives plaintext and rejects every export.
// The upper-case cases matter because the scheme is compared here, not by
// url.Parse, which lower-cases it.
func TestEndpointOptions_TLSSchemes(t *testing.T) {
	for _, scheme := range []string{"https", "HTTPS", "grpcs", "GRPCS"} {
		t.Run(scheme, func(t *testing.T) {
			got := firstBytes(t, func(addr string) string { return scheme + "://" + addr })
			assert.True(t, bytes.HasPrefix(got, tlsRecordHeader),
				"%s:// must open a TLS handshake, got %q", scheme, got)
		})
	}
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

// The SDK's periodic reader starts a ticker at the interval it is handed, and
// a ticker cannot run at zero or less: it panics on a goroutine nobody
// recovers, so the process dies instead of serving. A period that cannot run
// is refused here, while there is still a caller to report it to.
func TestSetupMetricsExport_NonPositivePeriodIsRefused(t *testing.T) {
	for _, period := range []int{0, -1, -60} {
		t.Run(strconv.Itoa(period), func(t *testing.T) {
			ResetMeter()
			t.Cleanup(ResetMeter)

			err := SetupMetricsExport(context.Background(), testLogger(), "localhost:4317", period)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be greater than 0")
			assert.Contains(t, err.Error(), strconv.Itoa(period), "the error must name the value it refused")
			assert.Nil(t, GetMeter(), "a refused period installs no meter")
		})
	}
}

// One second is the shortest interval a ticker runs at, so it is accepted
// rather than rounded up to the default.
func TestSetupMetricsExport_ShortestUsablePeriodIsAccepted(t *testing.T) {
	ResetMeter()
	t.Cleanup(func() { shutdownIgnoreFlushError(t) })

	err := SetupMetricsExport(context.Background(), testLogger(), "localhost:4317", 1)
	require.NoError(t, err)
	assert.NotNil(t, GetMeter())
}

// No endpoint disables metrics collection, so there is no reader to interval
// and nothing to refuse.
func TestSetupMetricsExport_NonPositivePeriodIsInertWithNoEndpoint(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	require.NoError(t, SetupMetricsExport(context.Background(), testLogger(), "", 0))
	assert.Nil(t, GetMeter())
}

// ---------------------------------------------------------------------------
// A period that cannot be represented as a Duration
// ---------------------------------------------------------------------------

// Multiplying seconds by time.Second wraps above the representable range, and
// the wrapped value is small: 40423014371506394 seconds becomes about a
// microsecond. The non-positive check above passes on the number the operator
// typed, so without a bound the reader is handed the wrapped duration and
// exports continuously under a startup line reporting the huge period.
func TestSetupMetricsExport_PeriodPastTheBoundIsRefused(t *testing.T) {
	// A variable, not a constant: the compiler refuses the same multiply on an
	// untyped constant, which is exactly the overflow under test.
	wrapping := 40423014371506394
	require.Positive(t, time.Duration(wrapping)*time.Second,
		"the value under test must be one the old non-positive check accepts")
	require.Less(t, time.Duration(wrapping)*time.Second, time.Second,
		"the value under test must be one the multiply wraps to a tight period")

	for _, period := range []int{config.MaxDurationSeconds + 1, wrapping, math.MaxInt} {
		t.Run(strconv.Itoa(period), func(t *testing.T) {
			ResetMeter()
			t.Cleanup(ResetMeter)

			err := SetupMetricsExport(context.Background(), testLogger(), "localhost:4317", period)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "at most")
			assert.Contains(t, err.Error(), strconv.Itoa(config.MaxDurationSeconds),
				"the error must name the bound it enforced")
			assert.Contains(t, err.Error(), strconv.Itoa(period), "the error must name the value it refused")
			assert.Nil(t, GetMeter(), "a refused period installs no meter")
		})
	}
}

// The bound is on the seconds, so what survives it converts faithfully rather
// than to a wrapped remainder, and the largest accepted period still installs a
// meter.
func TestSetupMetricsExport_PeriodAtTheBoundIsAccepted(t *testing.T) {
	ResetMeter()
	t.Cleanup(func() { shutdownIgnoreFlushError(t) })

	require.Equal(t, 365*24*time.Hour, time.Duration(config.MaxDurationSeconds)*time.Second,
		"the bound must convert to the year it names")
	require.NoError(t, SetupMetricsExport(context.Background(), testLogger(), "localhost:4317", config.MaxDurationSeconds))
	assert.NotNil(t, GetMeter())
}

// No endpoint disables metrics collection, so there is no reader to interval
// and an outsized period is as inert as a non-positive one.
func TestSetupMetricsExport_PeriodPastTheBoundIsInertWithNoEndpoint(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)

	require.NoError(t, SetupMetricsExport(context.Background(), testLogger(), "", config.MaxDurationSeconds+1))
	assert.Nil(t, GetMeter())
}
