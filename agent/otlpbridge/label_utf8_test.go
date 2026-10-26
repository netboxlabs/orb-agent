package otlpbridge

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// qnameExport is a pktvisor-shaped interval: one plain metric and one top-N
// metric whose qname label comes from a packet.
func qnameExport(qname string) *collectormetrics.ExportMetricsServiceRequest {
	return &collectormetrics.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricsv1.ResourceMetrics{{
			ScopeMetrics: []*metricsv1.ScopeMetrics{{
				Metrics: []*metricsv1.Metric{
					{Name: "dns_wire_packets_total"},
					{Name: "dns_top_qname2", Data: &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{
						DataPoints: []*metricsv1.NumberDataPoint{{
							Attributes: []*commonv1.KeyValue{{
								Key:   "qname",
								Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: qname}},
							}},
							Value: &metricsv1.NumberDataPoint_AsInt{AsInt: 1},
						}},
					}}},
				},
			}},
		}},
	}
}

// pktvisor writes a qname byte that is not UTF-8 as a \DDD escape (RFC 4343),
// so the export decodes and reaches MQTT whole, the escape intact.
func TestHTTP_EscapedQnameLabel_PublishesWholeExport(t *testing.T) {
	_, fp, base := startHTTPBridgeConfig(t, BridgeConfig{Encoding: "json", MetricsEncoding: "protobuf"})
	const escaped = `bad\255name.example.`
	body, err := proto.Marshal(qnameExport(escaped))
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, postBody(t, base+"/v1/metrics", "application/x-protobuf", body).status)

	waitForPayload(t, fp)
	var published collectormetrics.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(fp.getPayload(), &published))
	metrics := published.ResourceMetrics[0].ScopeMetrics[0].Metrics
	require.Len(t, metrics, 2, "the other metrics of the interval must arrive too")
	assert.Equal(t, "dns_wire_packets_total", metrics[0].Name)
	points := metrics[1].GetGauge().GetDataPoints()
	require.Len(t, points, 1)
	require.Len(t, points[0].GetAttributes(), 1)
	assert.Equal(t, escaped, points[0].GetAttributes()[0].GetValue().GetStringValue())
}

// A label that is not UTF-8, as pktvisor sent before escaping them, makes the
// body undecodable for Go protobuf: the bridge refuses it with 400 and
// publishes nothing, rather than guessing which parts were valid.
func TestHTTP_QnameLabelNotUTF8_Returns400(t *testing.T) {
	_, fp, base := startHTTPBridgeConfig(t, BridgeConfig{Encoding: "json", MetricsEncoding: "protobuf"})
	body, err := proto.Marshal(qnameExport("bad.QQQQ.example."))
	require.NoError(t, err)
	require.Equal(t, 1, bytes.Count(body, []byte("QQQQ")))
	body = bytes.Replace(body, []byte("QQQQ"), []byte{0xff, 0xfe, 0xfd, 0xfc}, 1)

	resp := postBody(t, base+"/v1/metrics", "application/x-protobuf", body)

	assert.Equal(t, http.StatusBadRequest, resp.status)
	assert.Contains(t, string(resp.body), "invalid UTF-8")
	assert.Never(t, func() bool { return fp.getPayload() != nil }, 200*time.Millisecond, 10*time.Millisecond)
}
