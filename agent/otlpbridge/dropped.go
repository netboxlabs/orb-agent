package otlpbridge

import (
	"sort"
	"sync"
	"time"

	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
)

// The bridge's own series, published with the agent's metrics so a drop is
// seen where the data was expected. They ride in a resource of the agent's
// own, service.name orb-agent, in a scope that names no policy: the platform
// keeps such series as the agent's rather than attributing them to an
// organisation's policy, and the metric name's prefix is what it files them
// under.
const (
	selfServiceName   = "orb-agent"
	selfScopeName     = "orb-agent/otlpbridge"
	droppedMetricName = "orb_agent_otlp_bridge_dropped_total"

	// Signals, the signal attribute of a drop.
	signalMetrics = "metrics"
	signalLogs    = "logs"
	signalTraces  = "traces"

	// Reasons, the reason attribute of a drop.
	//
	// reasonTooLarge: the payload, or a single data point, cannot fit under
	// the message cap or the broker's maximum packet size.
	reasonTooLarge = "too_large"
	// reasonPublishFailed: the broker refused the publish for good, or the
	// retries ran out.
	reasonPublishFailed = "publish_failed"
	// reasonNoPipeline: a logs export that is not Diode data (unless
	// BridgeConfig.ForwardLogs), or any traces export, which the platform
	// keeps none of, so the bridge does not publish it.
	reasonNoPipeline = "no_pipeline"
)

// droppedCounter counts what the bridge dropped, by signal and reason, as a
// cumulative sum from the bridge's start. A dropped export is counted once
// however many points it held, a dropped data point once.
type droppedCounter struct {
	start time.Time
	now   func() time.Time

	mu     sync.Mutex
	counts map[[2]string]int64
}

func newDroppedCounter() *droppedCounter {
	now := time.Now()
	return &droppedCounter{start: now, now: time.Now, counts: map[[2]string]int64{}}
}

// add counts n drops of signal for reason.
func (d *droppedCounter) add(signal, reason string, n int64) {
	if signal == "" {
		signal = "unknown"
	}
	d.mu.Lock()
	d.counts[[2]string{signal, reason}] += n
	d.mu.Unlock()
}

// total is the count for signal and reason.
func (d *droppedCounter) total(signal, reason string) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counts[[2]string{signal, reason}]
}

// appendTo adds the counter's series to req, as one more resource, when any
// drop has been counted: an export with nothing dropped is sent as it came.
func (d *droppedCounter) appendTo(req *collectormetrics.ExportMetricsServiceRequest) {
	if rm := d.resourceMetrics(); rm != nil {
		req.ResourceMetrics = append(req.ResourceMetrics, rm)
	}
}

// resourceMetrics is the counter as OTLP: nil while nothing was dropped.
func (d *droppedCounter) resourceMetrics() *metricsv1.ResourceMetrics {
	d.mu.Lock()
	keys := make([][2]string, 0, len(d.counts))
	for k := range d.counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	now := uint64(d.now().UnixNano())
	points := make([]*metricsv1.NumberDataPoint, 0, len(keys))
	for _, k := range keys {
		points = append(points, &metricsv1.NumberDataPoint{
			Attributes: []*commonv1.KeyValue{
				{Key: "signal", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: k[0]}}},
				{Key: "reason", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: k[1]}}},
			},
			StartTimeUnixNano: uint64(d.start.UnixNano()),
			TimeUnixNano:      now,
			Value:             &metricsv1.NumberDataPoint_AsInt{AsInt: d.counts[k]},
		})
	}
	d.mu.Unlock()
	if len(points) == 0 {
		return nil
	}
	return &metricsv1.ResourceMetrics{
		Resource: &resourcev1.Resource{Attributes: []*commonv1.KeyValue{
			{Key: "service.name", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: selfServiceName}}},
		}},
		ScopeMetrics: []*metricsv1.ScopeMetrics{{
			Scope: &commonv1.InstrumentationScope{Name: selfScopeName},
			Metrics: []*metricsv1.Metric{{
				Name:        droppedMetricName,
				Description: "Exports and data points the OTLP bridge dropped, by signal and reason.",
				Unit:        "1",
				Data: &metricsv1.Metric_Sum{Sum: &metricsv1.Sum{
					AggregationTemporality: metricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
					IsMonotonic:            true,
					DataPoints:             points,
				}},
			}},
		}},
	}
}
