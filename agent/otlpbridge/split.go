package otlpbridge

import (
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// splitMetrics encodes req with enc as one or more payloads of at most limit
// bytes each. An export that fits is one payload, encoded once. One that does
// not is cut along the OTLP tree: by resource, then scope, then metric, then
// data point, so every payload keeps the resource and the scope (with its
// policy_name) of each point it carries, and the enricher attributes it as it
// would the whole. A metric with no data point is carried too, its header in
// one payload. A single data point, or a pointless metric's header, whose
// payload is still over limit on its own is left out, and reported in dropped
// with the metric it belongs to: the alternative, sending it and losing the
// connection, costs every other point too. A resource or scope with no metric
// carries nothing to publish and is not carried over.
//
// Sizes are measured in the encoding published, not in protobuf: a JSON
// payload is about twice its protobuf size, and the broker's limit is on the
// bytes it receives.
func splitMetrics(req *collectormetrics.ExportMetricsServiceRequest, enc Encoder, limit int) (payloads [][]byte, dropped []droppedPoint, err error) {
	whole, err := enc.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	if len(whole) <= limit {
		return [][]byte{whole}, nil, nil
	}
	units := flattenMetrics(req)
	if len(units) == 0 {
		// Over the limit with no metric to cut it by: the resource and scope
		// headers alone do not fit.
		return nil, []droppedPoint{{Bytes: len(whole)}}, nil
	}
	// The packing estimate is each unit's protobuf size scaled by how much
	// larger the published encoding of the whole export came out: for
	// protobuf that is one, for JSON about two. A chunk the estimate fits is
	// still measured for real before it is taken.
	ratio := float64(len(whole)) / float64(max(proto.Size(req), 1))
	s := &splitter{enc: enc, limit: limit, ratio: ratio}
	if err := s.pack(units); err != nil {
		return nil, nil, err
	}
	return s.payloads, s.dropped, nil
}

// droppedPoint names a data point that could not be published: its metric,
// and the bytes its own payload would have taken. An export over the limit
// with no metric at all is one droppedPoint naming no metric.
type droppedPoint struct {
	Metric string
	Bytes  int
}

// unit is one data point with the path that leads to it: its resource, its
// scope and its metric, so a payload rebuilt from units can carry each of
// those once however many points it has. A metric with no data point is one
// unit with no point, which carries its header.
type unit struct {
	rm *metricsv1.ResourceMetrics
	sm *metricsv1.ScopeMetrics
	m  *metricsv1.Metric
	// point is nil for the unit of a metric with no data point.
	point proto.Message
	// estimate is the unit's protobuf size, the point plus its share of the
	// headers it would introduce in a new payload.
	estimate int
}

// flattenMetrics lists every data point of req in order, with its path, and
// a unit with no point for each metric that has none.
// Headers are counted on the first unit of each resource, scope and metric,
// which overstates a payload that starts in the middle of one by at most
// those headers: the estimate errs on the small side of the cap, and a
// payload is measured for real before it is taken.
func flattenMetrics(req *collectormetrics.ExportMetricsServiceRequest) []unit {
	var units []unit
	for _, rm := range req.GetResourceMetrics() {
		if rm == nil {
			continue
		}
		rmHeader := proto.Size(&metricsv1.ResourceMetrics{Resource: rm.GetResource(), SchemaUrl: rm.GetSchemaUrl()})
		for _, sm := range rm.GetScopeMetrics() {
			if sm == nil {
				continue
			}
			smHeader := proto.Size(&metricsv1.ScopeMetrics{Scope: sm.GetScope(), SchemaUrl: sm.GetSchemaUrl()})
			for _, m := range sm.GetMetrics() {
				if m == nil {
					continue
				}
				mHeader := proto.Size(withoutPoints(m))
				pts := points(m)
				if len(pts) == 0 {
					units = append(units, unit{rm: rm, sm: sm, m: m, estimate: rmHeader + smHeader + mHeader + 12})
					continue
				}
				first := true
				for _, pt := range pts {
					u := unit{rm: rm, sm: sm, m: m, point: pt, estimate: proto.Size(pt) + 4}
					if first {
						u.estimate += rmHeader + smHeader + mHeader + 12
						first = false
					}
					units = append(units, u)
				}
			}
		}
	}
	return units
}

// splitter packs units into payloads under limit.
type splitter struct {
	enc      Encoder
	limit    int
	ratio    float64
	payloads [][]byte
	dropped  []droppedPoint
}

// pack takes units in order into payloads: a run of units whose scaled
// estimate fits is encoded and measured; one that measures over limit is
// halved and each half packed again, down to a single unit, which is dropped
// when it is over limit on its own.
func (s *splitter) pack(units []unit) error {
	for len(units) > 0 {
		n := s.fitByEstimate(units)
		payload, err := s.enc.Marshal(build(units[:n]))
		if err != nil {
			return err
		}
		switch {
		case len(payload) <= s.limit:
			s.payloads = append(s.payloads, payload)
		case n == 1:
			s.dropped = append(s.dropped, droppedPoint{Metric: units[0].m.GetName(), Bytes: len(payload)})
		default:
			// The estimate was short: measure each half rather than the run.
			if err := s.pack(units[:n/2]); err != nil {
				return err
			}
			if err := s.pack(units[n/2 : n]); err != nil {
				return err
			}
		}
		units = units[n:]
	}
	return nil
}

// fitByEstimate is how many leading units the scaled estimate fits in limit,
// at least one.
func (s *splitter) fitByEstimate(units []unit) int {
	budget := float64(s.limit) / s.ratio
	total := 0.0
	for i, u := range units {
		total += float64(u.estimate)
		if total > budget && i > 0 {
			return i
		}
	}
	return len(units)
}

// build is the export the units make: each resource once, each scope once
// under its resource, each metric once under its scope with its points. The
// headers are shared with req's messages, not copied; the point slices are
// new.
func build(units []unit) *collectormetrics.ExportMetricsServiceRequest {
	out := &collectormetrics.ExportMetricsServiceRequest{}
	var rm *metricsv1.ResourceMetrics
	var sm *metricsv1.ScopeMetrics
	var m *metricsv1.Metric
	var lastRM *metricsv1.ResourceMetrics
	var lastSM *metricsv1.ScopeMetrics
	var lastM *metricsv1.Metric
	for _, u := range units {
		if u.rm != lastRM {
			rm = &metricsv1.ResourceMetrics{Resource: u.rm.GetResource(), SchemaUrl: u.rm.GetSchemaUrl()}
			out.ResourceMetrics = append(out.ResourceMetrics, rm)
			lastRM, lastSM, lastM = u.rm, nil, nil
		}
		if u.sm != lastSM {
			sm = &metricsv1.ScopeMetrics{Scope: u.sm.GetScope(), SchemaUrl: u.sm.GetSchemaUrl()}
			rm.ScopeMetrics = append(rm.ScopeMetrics, sm)
			lastSM, lastM = u.sm, nil
		}
		if u.m != lastM {
			m = withoutPoints(u.m)
			sm.Metrics = append(sm.Metrics, m)
			lastM = u.m
		}
		if u.point != nil {
			addPoint(m, u.point)
		}
	}
	return out
}

// points lists a metric's data points, whatever its kind.
func points(m *metricsv1.Metric) []proto.Message {
	var out []proto.Message
	switch d := m.GetData().(type) {
	case *metricsv1.Metric_Gauge:
		for _, p := range d.Gauge.GetDataPoints() {
			out = append(out, p)
		}
	case *metricsv1.Metric_Sum:
		for _, p := range d.Sum.GetDataPoints() {
			out = append(out, p)
		}
	case *metricsv1.Metric_Histogram:
		for _, p := range d.Histogram.GetDataPoints() {
			out = append(out, p)
		}
	case *metricsv1.Metric_ExponentialHistogram:
		for _, p := range d.ExponentialHistogram.GetDataPoints() {
			out = append(out, p)
		}
	case *metricsv1.Metric_Summary:
		for _, p := range d.Summary.GetDataPoints() {
			out = append(out, p)
		}
	}
	return out
}

// withoutPoints is a copy of m's header: name, description, unit, metadata
// and the kind with its temporality and monotonicity, and no data points.
func withoutPoints(m *metricsv1.Metric) *metricsv1.Metric {
	out := &metricsv1.Metric{Name: m.GetName(), Description: m.GetDescription(), Unit: m.GetUnit(), Metadata: m.GetMetadata()}
	switch d := m.GetData().(type) {
	case *metricsv1.Metric_Gauge:
		out.Data = &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{}}
	case *metricsv1.Metric_Sum:
		out.Data = &metricsv1.Metric_Sum{Sum: &metricsv1.Sum{AggregationTemporality: d.Sum.GetAggregationTemporality(), IsMonotonic: d.Sum.GetIsMonotonic()}}
	case *metricsv1.Metric_Histogram:
		out.Data = &metricsv1.Metric_Histogram{Histogram: &metricsv1.Histogram{AggregationTemporality: d.Histogram.GetAggregationTemporality()}}
	case *metricsv1.Metric_ExponentialHistogram:
		out.Data = &metricsv1.Metric_ExponentialHistogram{ExponentialHistogram: &metricsv1.ExponentialHistogram{AggregationTemporality: d.ExponentialHistogram.GetAggregationTemporality()}}
	case *metricsv1.Metric_Summary:
		out.Data = &metricsv1.Metric_Summary{Summary: &metricsv1.Summary{}}
	}
	return out
}

// addPoint appends pt to m, whose kind withoutPoints set.
func addPoint(m *metricsv1.Metric, pt proto.Message) {
	switch d := m.GetData().(type) {
	case *metricsv1.Metric_Gauge:
		d.Gauge.DataPoints = append(d.Gauge.DataPoints, pt.(*metricsv1.NumberDataPoint))
	case *metricsv1.Metric_Sum:
		d.Sum.DataPoints = append(d.Sum.DataPoints, pt.(*metricsv1.NumberDataPoint))
	case *metricsv1.Metric_Histogram:
		d.Histogram.DataPoints = append(d.Histogram.DataPoints, pt.(*metricsv1.HistogramDataPoint))
	case *metricsv1.Metric_ExponentialHistogram:
		d.ExponentialHistogram.DataPoints = append(d.ExponentialHistogram.DataPoints, pt.(*metricsv1.ExponentialHistogramDataPoint))
	case *metricsv1.Metric_Summary:
		d.Summary.DataPoints = append(d.Summary.DataPoints, pt.(*metricsv1.SummaryDataPoint))
	}
}
