package metrics

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
)

// countingExporter counts the exports handed to it.
type countingExporter struct {
	sdkmetric.Exporter
	exports int
}

func (c *countingExporter) Export(context.Context, *metricdata.ResourceMetrics) error {
	c.exports++
	return nil
}

// clockedPollExporter is a pollExporter over a counting exporter, on a clock
// the test moves.
func clockedPollExporter() (*pollExporter, *countingExporter, *time.Time) {
	next := &countingExporter{}
	e := newPollExporter(next)
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	return e, next, &now
}

// collection is what one collection holds: one gauge datapoint per scope, a
// policy's scope for each name in policies and, when process is set, the
// process's own scope.
func collection(process bool, policies ...string) *metricdata.ResourceMetrics {
	scope := func(attrs ...attribute.KeyValue) metricdata.ScopeMetrics {
		return metricdata.ScopeMetrics{
			Scope: instrumentation.Scope{Name: scopeName, Attributes: attribute.NewSet(attrs...)},
			Metrics: []metricdata.Metrics{{
				Name: "gnmi.cpu",
				Data: metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{{Value: 1}}},
			}},
		}
	}
	rm := &metricdata.ResourceMetrics{}
	if process {
		rm.ScopeMetrics = append(rm.ScopeMetrics, scope())
	}
	for _, p := range policies {
		rm.ScopeMetrics = append(rm.ScopeMetrics, scope(attribute.String(PolicyNameAttribute, p)))
	}
	return rm
}

// Every collection that carries a policy's series holds an update, so it is
// sent, however soon after the last.
func TestPollExporter_SendsEveryExportCarryingAPolicysSeries(t *testing.T) {
	e, next, now := clockedPollExporter()
	for range 6 {
		require.NoError(t, e.Export(t.Context(), collection(true, "core")))
		*now = now.Add(time.Second)
	}
	require.NoError(t, e.Export(t.Context(), collection(false, "edge")))
	assert.Equal(t, 7, next.exports)
}

// A collection carrying only the process's own series is sent at most once
// per IdleExportInterval: the first one, then none until the interval has
// passed. At the default period that is one of every six collections, so a
// process between updates sends one small export a minute rather than six.
func TestPollExporter_SendsTheProcessSeriesAloneOncePerIdleInterval(t *testing.T) {
	e, next, now := clockedPollExporter()
	sent := 0
	for tick := range 13 {
		require.NoError(t, e.Export(t.Context(), collection(true)))
		if next.exports > sent {
			sent = next.exports
			assert.Equal(t, 0, tick%6, "sent at %ds", tick*10)
		}
		*now = now.Add(10 * time.Second)
	}
	assert.Equal(t, 3, next.exports, "at 0s, 60s and 120s")
}

// The process's series leave with every update's export, so an update
// restarts the idle interval: a device sampling every minute makes one
// export a minute.
func TestPollExporter_APollRestartsTheIdleInterval(t *testing.T) {
	e, next, now := clockedPollExporter()
	for second := 0; second < 180; second += 10 {
		policies := []string{}
		if second%60 == 30 {
			policies = append(policies, "core")
		}
		require.NoError(t, e.Export(t.Context(), collection(true, policies...)))
		*now = now.Add(10 * time.Second)
	}
	assert.Equal(t, 4, next.exports, "the first collection, then the updates at 30s, 90s and 150s")
}

// Once sendAll has been called, a collection with none of a policy's series
// is sent however soon after the last: that is the final collection of a
// shutdown, which would otherwise wait for an idle interval that never comes.
func TestPollExporter_SendsAnExportWithNoPolicysSeriesOnceSendAllIsCalled(t *testing.T) {
	e, next, now := clockedPollExporter()
	require.NoError(t, e.Export(t.Context(), collection(true)))
	*now = now.Add(time.Second)
	require.NoError(t, e.Export(t.Context(), collection(true)))
	assert.Equal(t, 1, next.exports, "the second is within the idle interval")

	e.sendAll()
	require.NoError(t, e.Export(t.Context(), collection(true)))
	assert.Equal(t, 2, next.exports, "and is sent once the bound is lifted")
	require.NoError(t, e.Export(t.Context(), &metricdata.ResourceMetrics{}))
	assert.Equal(t, 2, next.exports, "an empty collection still is not")
}

// A collection that holds nothing at all is never sent.
func TestPollExporter_SendsNothingForAnEmptyCollection(t *testing.T) {
	e, next, now := clockedPollExporter()
	require.NoError(t, e.Export(t.Context(), &metricdata.ResourceMetrics{}))
	*now = now.Add(time.Hour)
	require.NoError(t, e.Export(t.Context(), &metricdata.ResourceMetrics{}))
	require.NoError(t, e.Export(t.Context(), nil))
	assert.Zero(t, next.exports)
}

// otlpServer is an OTLP metrics collector on loopback that keeps every
// request it receives.
type otlpServer struct {
	collectormetricspb.UnimplementedMetricsServiceServer
	requests chan *collectormetricspb.ExportMetricsServiceRequest
}

func (s *otlpServer) Export(_ context.Context, req *collectormetricspb.ExportMetricsServiceRequest) (*collectormetricspb.ExportMetricsServiceResponse, error) {
	s.requests <- req
	return &collectormetricspb.ExportMetricsServiceResponse{}, nil
}

func startOTLPServer(t *testing.T) (string, *otlpServer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &otlpServer{requests: make(chan *collectormetricspb.ExportMetricsServiceRequest, 16)}
	gs := grpc.NewServer()
	collectormetricspb.RegisterMetricsServiceServer(gs, srv)
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return ln.Addr().String(), srv
}

// Through the exporter SetupMetricsExport builds, a collection with none of a
// policy's series is held back once the process has sent one, and the next
// that carries a policy's is sent, the process's series with it.
func TestSetupMetricsExport_HoldsBackAnExportWithNoPolicysSeries(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)
	addr, srv := startOTLPServer(t)
	require.NoError(t, SetupMetricsExport(context.Background(), testLogger(), addr, 3600))
	t.Cleanup(func() { _ = Shutdown(context.Background()) })
	ctx := context.Background()

	processCounter := GetCounter("gnmi.test.process", "a series of the process's own")
	require.NotNil(t, processCounter)
	processCounter.Add(ctx, 1)
	require.NoError(t, meterProvider.ForceFlush(ctx))
	first := receive(t, srv)
	assert.Len(t, first.GetResourceMetrics()[0].GetScopeMetrics(), 1, "the first is sent")

	processCounter.Add(ctx, 1)
	require.NoError(t, meterProvider.ForceFlush(ctx))
	select {
	case req := <-srv.requests:
		t.Fatalf("an export with no policy's series was sent within the idle interval: %v", req)
	case <-time.After(200 * time.Millisecond):
	}

	g, err := PolicyMeter("core").Float64Gauge("gnmi.cpu")
	require.NoError(t, err)
	g.Record(ctx, 7)
	require.NoError(t, meterProvider.ForceFlush(ctx))
	scopes := map[string]bool{}
	for _, sm := range receive(t, srv).GetResourceMetrics()[0].GetScopeMetrics() {
		policy := ""
		for _, kv := range sm.GetScope().GetAttributes() {
			if kv.GetKey() == PolicyNameAttribute {
				policy = kv.GetValue().GetStringValue()
			}
		}
		scopes[policy] = true
	}
	assert.Equal(t, map[string]bool{"": true, "core": true}, scopes, "the update's export carries the process's series too")
}

// Shutdown's final collection is sent whatever it carries, so the process's
// counters leave with their final totals: here a count raised after the last
// export, within the idle interval of it.
func TestShutdown_SendsTheFinalCollection(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)
	addr, srv := startOTLPServer(t)
	require.NoError(t, SetupMetricsExport(context.Background(), testLogger(), addr, 3600))
	ctx := context.Background()

	processCounter := GetCounter("gnmi.test.final", "a series of the process's own")
	require.NotNil(t, processCounter)
	processCounter.Add(ctx, 1)
	require.NoError(t, meterProvider.ForceFlush(ctx))
	assert.Equal(t, int64(1), sumOf(t, receive(t, srv), "gnmi.test.final"))

	processCounter.Add(ctx, 1)
	require.NoError(t, Shutdown(ctx))
	assert.Equal(t, int64(2), sumOf(t, receive(t, srv), "gnmi.test.final"), "the final total left with the shutdown")
}

// sumOf is the value of the one data point of the sum named name in req.
func sumOf(t *testing.T, req *collectormetricspb.ExportMetricsServiceRequest, name string) int64 {
	t.Helper()
	for _, rm := range req.GetResourceMetrics() {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				if m.GetName() != name {
					continue
				}
				points := m.GetSum().GetDataPoints()
				require.Len(t, points, 1, "one data point of %s", name)
				return points[0].GetAsInt()
			}
		}
	}
	t.Fatalf("the export carries no %s", name)
	return 0
}

func receive(t *testing.T, srv *otlpServer) *collectormetricspb.ExportMetricsServiceRequest {
	t.Helper()
	select {
	case req := <-srv.requests:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("no export reached the collector")
		return nil
	}
}
