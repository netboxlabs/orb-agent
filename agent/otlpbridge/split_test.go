package otlpbridge

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// policyScope is a backend's scope for one policy, the shape snmp-telemetry
// and gnmi-telemetry export.
func policyScope(policy string, metrics ...*metricsv1.Metric) *metricsv1.ScopeMetrics {
	return &metricsv1.ScopeMetrics{
		Scope:   &commonv1.InstrumentationScope{Name: "snmp-telemetry", Attributes: []*commonv1.KeyValue{strAttr("policy_name", policy)}},
		Metrics: metrics,
	}
}

// gaugeMetric is a gauge with n points, one per interface of device, each
// carrying the attributes a polled series carries.
func gaugeMetric(name, device string, n int) *metricsv1.Metric {
	g := &metricsv1.Gauge{}
	for i := range n {
		g.DataPoints = append(g.DataPoints, &metricsv1.NumberDataPoint{
			Attributes: []*commonv1.KeyValue{
				strAttr("device_ip", device), strAttr("if_name", fmt.Sprintf("GigabitEthernet1/0/%d", i)),
				strAttr("if_descr", strings.Repeat("x", 40)),
			},
			TimeUnixNano: 1_700_000_000_000_000_000 + uint64(i),
			Value:        &metricsv1.NumberDataPoint_AsInt{AsInt: int64(i)},
		})
	}
	return &metricsv1.Metric{Name: name, Unit: "By", Data: &metricsv1.Metric_Gauge{Gauge: g}}
}

func sumMetric(name, device string, n int) *metricsv1.Metric {
	s := &metricsv1.Sum{AggregationTemporality: metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE, IsMonotonic: true}
	for i := range n {
		s.DataPoints = append(s.DataPoints, &metricsv1.NumberDataPoint{
			Attributes:   []*commonv1.KeyValue{strAttr("device_ip", device), strAttr("if_index", fmt.Sprint(i))},
			TimeUnixNano: 1_700_000_000_000_000_000,
			Value:        &metricsv1.NumberDataPoint_AsInt{AsInt: int64(i) * 1000},
		})
	}
	return &metricsv1.Metric{Name: name, Data: &metricsv1.Metric_Sum{Sum: s}}
}

func export(rms ...*metricsv1.ResourceMetrics) *collectormetrics.ExportMetricsServiceRequest {
	return &collectormetrics.ExportMetricsServiceRequest{ResourceMetrics: rms}
}

func backendResource(service string, scopes ...*metricsv1.ScopeMetrics) *metricsv1.ResourceMetrics {
	return &metricsv1.ResourceMetrics{
		Resource:     &resourcev1.Resource{Attributes: []*commonv1.KeyValue{strAttr("service.name", service)}},
		ScopeMetrics: scopes,
	}
}

// pointKey identifies one data point by everything that attributes it: the
// resource, the scope with its policy, the metric and the point's own
// attributes and time.
type pointKey struct {
	resource, scope, policy, metric, attrs string
	ts                                     uint64
}

// pointKeys lists every point of a request, decoded from payload with enc.
func pointKeys(t *testing.T, payloads [][]byte, decode func([]byte) *collectormetrics.ExportMetricsServiceRequest) map[pointKey]int {
	t.Helper()
	keys := map[pointKey]int{}
	for _, p := range payloads {
		req := decode(p)
		for _, rm := range req.GetResourceMetrics() {
			require.NotNil(t, rm.GetResource(), "every payload carries its resource")
			for _, sm := range rm.GetScopeMetrics() {
				require.NotNil(t, sm.GetScope(), "every payload carries its scope")
				policy := ""
				for _, kv := range sm.GetScope().GetAttributes() {
					if kv.GetKey() == "policy_name" {
						policy = kv.GetValue().GetStringValue()
					}
				}
				require.NotEmpty(t, policy, "the scope keeps policy_name")
				for _, m := range sm.GetMetrics() {
					if s := m.GetSum(); s != nil {
						assert.True(t, s.GetIsMonotonic(), "the sum keeps its header")
						assert.Equal(t, metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE, s.GetAggregationTemporality())
					}
					for _, pt := range points(m) {
						np := pt.(*metricsv1.NumberDataPoint)
						var attrs []string
						for _, kv := range np.GetAttributes() {
							attrs = append(attrs, kv.GetKey()+"="+kv.GetValue().GetStringValue())
						}
						k := pointKey{
							resource: rm.GetResource().GetAttributes()[0].GetValue().GetStringValue(),
							scope:    sm.GetScope().GetName(), policy: policy, metric: m.GetName(),
							attrs: strings.Join(attrs, ","), ts: np.GetTimeUnixNano(),
						}
						keys[k]++
					}
				}
			}
		}
	}
	return keys
}

func decodeProto(b []byte) *collectormetrics.ExportMetricsServiceRequest {
	var req collectormetrics.ExportMetricsServiceRequest
	if err := proto.Unmarshal(b, &req); err != nil {
		panic(err)
	}
	return &req
}

// An export under the limit is one payload, the export as encoded.
func TestSplitMetrics_AnExportThatFitsIsOnePayload(t *testing.T) {
	req := export(backendResource("snmp-telemetry", policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 10))))
	whole, err := ProtobufEncoder{}.Marshal(req)
	require.NoError(t, err)

	payloads, dropped, err := splitMetrics(req, ProtobufEncoder{}, len(whole))
	require.NoError(t, err)
	require.Len(t, payloads, 1)
	assert.Equal(t, whole, payloads[0])
	assert.Empty(t, dropped)
}

// An export over the limit arrives as several payloads, each under it, with
// every point once, under its own resource, scope and policy, and the
// metrics' headers on every piece.
func TestSplitMetrics_AnExportOverTheLimitIsCutIntoPayloadsUnderIt(t *testing.T) {
	req := export(
		backendResource("snmp-telemetry",
			policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 300), sumMetric("snmp.ifinerrors", "10.0.0.1", 300)),
			policyScope("edge", gaugeMetric("snmp.ifinoctets", "10.0.0.2", 200)),
		),
		backendResource("gnmi-telemetry", policyScope("dc", gaugeMetric("gnmi.if_in_octets", "10.0.1.1", 150))),
	)
	whole, err := ProtobufEncoder{}.Marshal(req)
	require.NoError(t, err)
	limit := len(whole) / 5

	payloads, dropped, err := splitMetrics(req, ProtobufEncoder{}, limit)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	require.GreaterOrEqual(t, len(payloads), 5)
	for i, p := range payloads {
		assert.LessOrEqual(t, len(p), limit, "payload %d", i)
	}
	got := pointKeys(t, payloads, decodeProto)
	want := pointKeys(t, [][]byte{whole}, decodeProto)
	assert.Equal(t, want, got, "every point once, with its resource, scope, policy and metric")
	assert.Len(t, got, 950)
}

// Splitting is measured in the encoding published: a JSON export is about
// twice its protobuf size, and the limit is on the JSON.
func TestSplitMetrics_MeasuresTheEncodingPublished(t *testing.T) {
	req := export(backendResource("snmp-telemetry", policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 400))))
	enc := NewJSONEncoder()
	whole, err := enc.Marshal(req)
	require.NoError(t, err)
	limit := len(whole) / 3

	payloads, dropped, err := splitMetrics(req, enc, limit)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	require.GreaterOrEqual(t, len(payloads), 3)
	for i, p := range payloads {
		assert.LessOrEqual(t, len(p), limit, "payload %d", i)
	}
	decodeJSON := func(b []byte) *collectormetrics.ExportMetricsServiceRequest {
		var req collectormetrics.ExportMetricsServiceRequest
		require.NoError(t, protojson.Unmarshal(b, &req))
		return &req
	}
	assert.Equal(t, pointKeys(t, [][]byte{whole}, decodeJSON), pointKeys(t, payloads, decodeJSON))
}

// A point whose own payload is over the limit is left out and reported, and
// the rest of the export is published.
func TestSplitMetrics_APointThatCannotFitIsDroppedAndReported(t *testing.T) {
	huge := gaugeMetric("snmp.sysdescr", "10.0.0.9", 1)
	huge.GetGauge().DataPoints[0].Attributes = append(huge.GetGauge().DataPoints[0].Attributes, strAttr("blob", strings.Repeat("z", 5000)))
	req := export(backendResource("snmp-telemetry", policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 50), huge, gaugeMetric("snmp.ifoutoctets", "10.0.0.1", 50))))

	payloads, dropped, err := splitMetrics(req, ProtobufEncoder{}, 2000)
	require.NoError(t, err)
	require.Len(t, dropped, 1)
	assert.Equal(t, "snmp.sysdescr", dropped[0].Metric)
	assert.Greater(t, dropped[0].Bytes, 2000)
	for i, p := range payloads {
		assert.LessOrEqual(t, len(p), 2000, "payload %d", i)
	}
	got := pointKeys(t, payloads, decodeProto)
	assert.Len(t, got, 100, "every other point is published")
	for k := range got {
		assert.NotEqual(t, "snmp.sysdescr", k.metric)
	}
}

// Every kind of metric survives the cut with its header.
func TestSplitMetrics_KeepsEveryKindsHeader(t *testing.T) {
	h := &metricsv1.Metric{Name: "h", Data: &metricsv1.Metric_Histogram{Histogram: &metricsv1.Histogram{
		AggregationTemporality: metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		DataPoints:             []*metricsv1.HistogramDataPoint{{Count: 1, BucketCounts: []uint64{1}}, {Count: 2, BucketCounts: []uint64{2}}},
	}}}
	e := &metricsv1.Metric{Name: "e", Data: &metricsv1.Metric_ExponentialHistogram{ExponentialHistogram: &metricsv1.ExponentialHistogram{
		AggregationTemporality: metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
		DataPoints:             []*metricsv1.ExponentialHistogramDataPoint{{Count: 1, Scale: 2}, {Count: 2, Scale: 2}},
	}}}
	s := &metricsv1.Metric{Name: "s", Data: &metricsv1.Metric_Summary{Summary: &metricsv1.Summary{
		DataPoints: []*metricsv1.SummaryDataPoint{{Count: 1}, {Count: 2}},
	}}}
	req := export(backendResource("snmp-telemetry", policyScope("core", h, e, s, sumMetric("c", "10.0.0.1", 2))))
	whole, err := ProtobufEncoder{}.Marshal(req)
	require.NoError(t, err)

	payloads, dropped, err := splitMetrics(req, ProtobufEncoder{}, len(whole)/2)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	require.Greater(t, len(payloads), 1)
	kinds := map[string]int{}
	for _, p := range payloads {
		for _, rm := range decodeProto(p).GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				for _, m := range sm.GetMetrics() {
					switch d := m.GetData().(type) {
					case *metricsv1.Metric_Histogram:
						assert.Equal(t, metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA, d.Histogram.GetAggregationTemporality())
						kinds["h"] += len(d.Histogram.GetDataPoints())
					case *metricsv1.Metric_ExponentialHistogram:
						assert.Equal(t, metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE, d.ExponentialHistogram.GetAggregationTemporality())
						kinds["e"] += len(d.ExponentialHistogram.GetDataPoints())
					case *metricsv1.Metric_Summary:
						kinds["s"] += len(d.Summary.GetDataPoints())
					case *metricsv1.Metric_Sum:
						assert.True(t, d.Sum.GetIsMonotonic())
						kinds["c"] += len(d.Sum.GetDataPoints())
					}
				}
			}
		}
	}
	assert.Equal(t, map[string]int{"h": 2, "e": 2, "s": 2, "c": 2}, kinds)
}

// A metric with no data point is not lost in the cut: its header lands in one
// payload, as it would have in the whole export, and nothing is dropped.
func TestSplitMetrics_AMetricWithNoPointKeepsItsHeader(t *testing.T) {
	emptyGauge := &metricsv1.Metric{Name: "snmp.empty_gauge", Unit: "1", Data: &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{}}}
	emptySum := sumMetric("snmp.empty_sum", "10.0.0.1", 0)
	req := export(backendResource("snmp-telemetry",
		policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 200), emptyGauge),
		policyScope("edge", emptySum, gaugeMetric("snmp.ifoutoctets", "10.0.0.2", 200)),
	))
	whole, err := ProtobufEncoder{}.Marshal(req)
	require.NoError(t, err)
	limit := len(whole) / 4

	payloads, dropped, err := splitMetrics(req, ProtobufEncoder{}, limit)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	require.GreaterOrEqual(t, len(payloads), 4)
	headers := map[string]string{}
	for i, p := range payloads {
		assert.LessOrEqual(t, len(p), limit, "payload %d", i)
		for _, rm := range decodeProto(p).GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				for _, m := range sm.GetMetrics() {
					if len(points(m)) == 0 {
						assert.NotContains(t, headers, m.GetName(), "carried once")
						headers[m.GetName()] = sm.GetScope().GetAttributes()[0].GetValue().GetStringValue()
						if s := m.GetSum(); s != nil {
							assert.True(t, s.GetIsMonotonic(), "the sum keeps its header")
						}
					}
				}
			}
		}
	}
	assert.Equal(t, map[string]string{"snmp.empty_gauge": "core", "snmp.empty_sum": "edge"}, headers, "each under its own scope")
	assert.Equal(t, pointKeys(t, [][]byte{whole}, decodeProto), pointKeys(t, payloads, decodeProto))
}

// A metric with no data point whose header alone is over the limit is
// dropped and reported like a point that cannot fit.
func TestSplitMetrics_AMetricHeaderThatCannotFitIsDroppedAndReported(t *testing.T) {
	huge := &metricsv1.Metric{Name: "snmp.huge", Description: strings.Repeat("d", 5000), Data: &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{}}}
	req := export(backendResource("snmp-telemetry", policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 50), huge)))

	payloads, dropped, err := splitMetrics(req, ProtobufEncoder{}, 2000)
	require.NoError(t, err)
	require.Len(t, dropped, 1)
	assert.Equal(t, "snmp.huge", dropped[0].Metric)
	assert.Greater(t, dropped[0].Bytes, 2000)
	assert.Len(t, pointKeys(t, payloads, decodeProto), 50, "every point is published")
}

// The request handed in is not changed by splitting: the handler answers the
// backend from it after the split.
func TestSplitMetrics_LeavesTheRequestAsItWas(t *testing.T) {
	req := export(backendResource("snmp-telemetry", policyScope("core", gaugeMetric("snmp.ifinoctets", "10.0.0.1", 100))))
	before, err := proto.Marshal(req)
	require.NoError(t, err)
	_, _, err = splitMetrics(req, ProtobufEncoder{}, len(before)/4)
	require.NoError(t, err)
	after, err := proto.Marshal(req)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
