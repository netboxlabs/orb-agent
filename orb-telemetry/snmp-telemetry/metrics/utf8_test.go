package metrics

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otlpmetric "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc"
)

// badMAC is an ifPhysAddress read as text: binary, and not valid UTF-8.
const badMAC = "\x00\x1b!\xbb\xe6\xf0"

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

// startOTLPServer serves the OTLP metrics service on loopback and returns its
// address with the server.
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

// twoPolicyExport is one export carrying two policies' gauges, the way one
// snmp-telemetry process exports every policy it runs. Policy core's device
// answered a binary ifPhysAddress.
func twoPolicyExport() *metricdata.ResourceMetrics {
	scope := func(policy, mac string) metricdata.ScopeMetrics {
		return metricdata.ScopeMetrics{
			Scope: instrumentation.Scope{
				Name:       scopeName,
				Attributes: attribute.NewSet(attribute.String(PolicyNameAttribute, policy)),
			},
			Metrics: []metricdata.Metrics{{
				Name: "snmp.ifouterrors",
				Data: metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{{
					Attributes: attribute.NewSet(attribute.String("if_mac", mac)),
					Time:       time.Now(),
					Value:      10,
				}}},
			}},
		}
	}
	return &metricdata.ResourceMetrics{
		Resource:     resource.NewSchemaless(attribute.String("service.name", "snmp-telemetry")),
		ScopeMetrics: []metricdata.ScopeMetrics{scope("core", badMAC), scope("edge", "00:1b:21:bb:e6:ea")},
	}
}

func newPlainExporter(t *testing.T, addr string) sdkmetric.Exporter {
	t.Helper()
	exp, err := otlpmetric.New(context.Background(),
		otlpmetric.WithEndpoint(addr), otlpmetric.WithInsecure(),
		otlpmetric.WithRetry(otlpmetric.RetryConfig{Enabled: false}))
	require.NoError(t, err)
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	return exp
}

// The failure the lab hit: one value that is not UTF-8 fails the marshalling
// of the whole request, so neither policy's telemetry is sent. This pins the
// exporter's behaviour, not ours: if it starts passing, the gRPC exporter or
// protobuf changed how they treat such strings, and the wrapper's purpose
// should be checked again.
func TestOTLPExport_InvalidUTF8FailsTheWholeRequest(t *testing.T) {
	addr, srv := startOTLPServer(t)
	exp := newPlainExporter(t, addr)

	err := exp.Export(context.Background(), twoPolicyExport())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid UTF-8")
	assert.Empty(t, srv.requests, "nothing reaches the collector")
}

// Through the exporter SetupMetricsExport builds, the same value is repaired
// and both policies reach the collector.
func TestSetupMetricsExport_InvalidUTF8DoesNotDropTheExport(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)
	addr, srv := startOTLPServer(t)
	require.NoError(t, SetupMetricsExport(context.Background(), testLogger(), addr, 3600))
	t.Cleanup(func() { _ = Shutdown(context.Background()) })

	ctx := context.Background()
	for policy, mac := range map[string]string{"core": badMAC, "edge": "00:1b:21:bb:e6:ea"} {
		g, err := PolicyMeter(policy).Int64Gauge("snmp.ifouterrors")
		require.NoError(t, err)
		g.Record(ctx, 10, otelmetric.WithAttributes(attribute.String("if_mac", mac)))
	}
	require.NoError(t, meterProvider.ForceFlush(ctx))

	var req *collectormetricspb.ExportMetricsServiceRequest
	select {
	case req = <-srv.requests:
	case <-time.After(5 * time.Second):
		t.Fatal("no export reached the collector")
	}
	got := map[string]string{}
	for _, rm := range req.GetResourceMetrics() {
		for _, sm := range rm.GetScopeMetrics() {
			policy := stringAttr(sm.GetScope().GetAttributes(), PolicyNameAttribute)
			for _, m := range sm.GetMetrics() {
				if m.GetName() != "snmp.ifouterrors" {
					continue
				}
				for _, dp := range m.GetGauge().GetDataPoints() {
					got[policy] = stringAttr(dp.GetAttributes(), "if_mac")
				}
			}
		}
	}
	assert.Equal(t, map[string]string{"core": "00:1b:21:bb:e6:f0", "edge": "00:1b:21:bb:e6:ea"}, got)
}

func stringAttr(kvs []*commonpb.KeyValue, key string) string {
	for _, kv := range kvs {
		if kv.GetKey() == key {
			return kv.GetValue().GetStringValue()
		}
	}
	return ""
}

// captureExporter keeps the last export it was handed.
type captureExporter struct {
	sdkmetric.Exporter
	got *metricdata.ResourceMetrics
}

func (c *captureExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	c.got = rm
	return nil
}

// Every string an OTLP export carries is repaired: the resource, the scope,
// the metric's own strings, and the attributes and exemplars of every kind of
// data point.
func TestValidUTF8Exporter_RepairsEveryString(t *testing.T) {
	bad := attribute.String("tag", badMAC)
	badSlice := attribute.StringSlice("tags", []string{"ok", badMAC})
	badKey := attribute.String("tag\xff", "ok")
	badList := attribute.Slice("list", attribute.StringValue("ok"), attribute.StringValue(badMAC))
	badMap := attribute.Map("map", attribute.String("k\xff", badMAC), attribute.Slice("inner", attribute.StringValue(badMAC)))
	set := attribute.NewSet(bad, badSlice, badKey, badList, badMap)
	exemplars := func() []metricdata.Exemplar[int64] {
		return []metricdata.Exemplar[int64]{{FilteredAttributes: []attribute.KeyValue{bad}}}
	}
	fexemplars := func() []metricdata.Exemplar[float64] {
		return []metricdata.Exemplar[float64]{{FilteredAttributes: []attribute.KeyValue{bad}}}
	}
	rm := &metricdata.ResourceMetrics{
		Resource: resource.NewSchemaless(bad),
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Scope: instrumentation.Scope{Name: "scope\xff", Version: "v\xff", Attributes: set},
			Metrics: []metricdata.Metrics{
				{Name: "gauge\xff", Description: "d\xff", Unit: "u\xff", Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{{Attributes: set, Exemplars: exemplars()}},
				}},
				{Name: "fgauge", Data: metricdata.Gauge[float64]{
					DataPoints: []metricdata.DataPoint[float64]{{Attributes: set, Exemplars: fexemplars()}},
				}},
				{Name: "sum", Data: metricdata.Sum[int64]{
					DataPoints: []metricdata.DataPoint[int64]{{Attributes: set, Exemplars: exemplars()}},
				}},
				{Name: "fsum", Data: metricdata.Sum[float64]{
					DataPoints: []metricdata.DataPoint[float64]{{Attributes: set}},
				}},
				{Name: "hist", Data: metricdata.Histogram[int64]{
					DataPoints: []metricdata.HistogramDataPoint[int64]{{Attributes: set, Exemplars: exemplars()}},
				}},
				{Name: "fhist", Data: metricdata.Histogram[float64]{
					DataPoints: []metricdata.HistogramDataPoint[float64]{{Attributes: set}},
				}},
				{Name: "exp", Data: metricdata.ExponentialHistogram[int64]{
					DataPoints: []metricdata.ExponentialHistogramDataPoint[int64]{{Attributes: set, Exemplars: exemplars()}},
				}},
				{Name: "fexp", Data: metricdata.ExponentialHistogram[float64]{
					DataPoints: []metricdata.ExponentialHistogramDataPoint[float64]{{Attributes: set}},
				}},
				{Name: "summary", Data: metricdata.Summary{
					DataPoints: []metricdata.SummaryDataPoint{{Attributes: set}},
				}},
			},
		}},
	}

	inner := &captureExporter{}
	require.NoError(t, newValidUTF8Exporter(inner, testLogger()).Export(context.Background(), rm))
	require.Same(t, rm, inner.got)

	var invalid []string
	check := func(where, s string) {
		if !utf8.ValidString(s) {
			invalid = append(invalid, where+": "+s)
		}
	}
	var checkKVs func(where string, kvs []attribute.KeyValue)
	var checkValue func(where string, v attribute.Value)
	checkValue = func(where string, v attribute.Value) {
		check(where, v.String())
		for _, s := range v.AsStringSlice() {
			check(where+" element", s)
		}
		for _, e := range v.AsSlice() {
			checkValue(where+" element", e)
		}
		checkKVs(where, v.AsMap())
	}
	checkKVs = func(where string, kvs []attribute.KeyValue) {
		for _, kv := range kvs {
			check(where+" key", string(kv.Key))
			checkValue(where+" "+string(kv.Key), kv.Value)
		}
	}
	checkKVs("resource", rm.Resource.Attributes())
	sm := rm.ScopeMetrics[0]
	check("scope name", sm.Scope.Name)
	check("scope version", sm.Scope.Version)
	checkKVs("scope", sm.Scope.Attributes.ToSlice())
	for _, m := range sm.Metrics {
		check("metric name", m.Name)
		check("metric description", m.Description)
		check("metric unit", m.Unit)
		switch d := m.Data.(type) {
		case metricdata.Gauge[int64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
			checkKVs(m.Name+" exemplar", d.DataPoints[0].Exemplars[0].FilteredAttributes)
		case metricdata.Gauge[float64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
			checkKVs(m.Name+" exemplar", d.DataPoints[0].Exemplars[0].FilteredAttributes)
		case metricdata.Sum[int64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
			checkKVs(m.Name+" exemplar", d.DataPoints[0].Exemplars[0].FilteredAttributes)
		case metricdata.Sum[float64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
		case metricdata.Histogram[int64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
			checkKVs(m.Name+" exemplar", d.DataPoints[0].Exemplars[0].FilteredAttributes)
		case metricdata.Histogram[float64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
		case metricdata.ExponentialHistogram[int64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
			checkKVs(m.Name+" exemplar", d.DataPoints[0].Exemplars[0].FilteredAttributes)
		case metricdata.ExponentialHistogram[float64]:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
		case metricdata.Summary:
			checkKVs(m.Name, d.DataPoints[0].Attributes.ToSlice())
		default:
			t.Fatalf("unhandled data type %T", d)
		}
	}
	assert.Empty(t, invalid)

	tag, ok := rm.ScopeMetrics[0].Scope.Attributes.Value("tag")
	require.True(t, ok)
	assert.Equal(t, "00:1b:21:bb:e6:f0", tag.AsString(), "a value is repaired as the hex of every byte")
	_, ok = rm.ScopeMetrics[0].Scope.Attributes.Value("74:61:67:ff")
	assert.True(t, ok, "a key is repaired as the hex of its bytes that are not UTF-8")
}

// Checking an export with nothing to repair allocates nothing, so the wrapper
// costs a scan, not a copy of every attribute set, on every export.
func TestValidUTF8Exporter_CleanExportAllocatesNothing(t *testing.T) {
	rm := twoPolicyExport()
	rm.ScopeMetrics = rm.ScopeMetrics[1:]
	e := newValidUTF8Exporter(&captureExporter{}, testLogger())
	ctx := context.Background()
	assert.Zero(t, testing.AllocsPerRun(20, func() { e.repairResourceMetrics(ctx, rm) }))
}

// A valid export is handed on untouched.
func TestValidUTF8Exporter_LeavesValidExportAlone(t *testing.T) {
	rm := twoPolicyExport()
	rm.ScopeMetrics = rm.ScopeMetrics[1:]
	before := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Gauge[int64]).DataPoints[0].Attributes

	inner := &captureExporter{}
	require.NoError(t, newValidUTF8Exporter(inner, testLogger()).Export(context.Background(), rm))
	after := inner.got.ScopeMetrics[0].Metrics[0].Data.(metricdata.Gauge[int64]).DataPoints[0].Attributes
	assert.True(t, before.Equals(&after))
}

// A repair is counted every time, and logged once per attribute key, so a
// device answering the same bad value every poll does not flood the log.
func TestValidUTF8Exporter_CountsEveryRepairAndWarnsOncePerKey(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	SetMeterProviderForTest(provider)

	var logs bytes.Buffer
	exp := newValidUTF8Exporter(&captureExporter{}, slog.New(slog.NewTextHandler(&logs, nil)))
	ctx := context.Background()
	require.NoError(t, exp.Export(ctx, twoPolicyExport()))
	require.NoError(t, exp.Export(ctx, twoPolicyExport()))

	assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), logs.String())
	assert.Contains(t, logs.String(), "attribute=if_mac")
	assert.Contains(t, logs.String(), "policy=core", "the warning names where to look")
	assert.Contains(t, logs.String(), "metric=snmp.ifouterrors")
	assert.Equal(t, map[string]int64{"if_mac": 2}, repairedCounts(t, reader))
}

// An attribute whose key and value are both not UTF-8 is one repair.
func TestValidUTF8Exporter_CountsAnAttributeOnce(t *testing.T) {
	ResetMeter()
	t.Cleanup(ResetMeter)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	SetMeterProviderForTest(provider)

	rm := twoPolicyExport()
	rm.ScopeMetrics = rm.ScopeMetrics[:1]
	rm.ScopeMetrics[0].Metrics[0].Data = metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{{
		Attributes: attribute.NewSet(attribute.String("if\xff", badMAC)),
	}}}
	require.NoError(t, newValidUTF8Exporter(&captureExporter{}, testLogger()).Export(context.Background(), rm))
	assert.Equal(t, map[string]int64{"69:66:ff": 1}, repairedCounts(t, reader))
}

// repairedCounts reads InvalidUTF8RepairedName by attribute key.
func repairedCounts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != InvalidUTF8RepairedName {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				key, _ := dp.Attributes.Value("attribute")
				got[key.AsString()] += dp.Value
			}
		}
	}
	return got
}
