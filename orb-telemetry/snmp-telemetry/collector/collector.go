package collector

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

const (
	sysDescrOID    = "1.3.6.1.2.1.1.1"
	sysObjectIDOID = "1.3.6.1.2.1.1.2"
	sysNameOID     = "1.3.6.1.2.1.1.5"
)

// deviceKey identifies one polled device. A device belongs to the policy that
// named it: two policies may poll the same address with different credentials
// or intervals, so their observations and poll timestamps are kept apart. Port
// is part of the identity because one host can answer on more than one.
type deviceKey struct {
	policy string
	host   string
	port   uint16
}

// DialOptions carries the SNMP transport settings for one collection. They
// belong to the policy that named the target, not to the profile set, so the
// collector takes them per call rather than holding them.
type DialOptions struct {
	Timeout time.Duration
	Retries int
}

// observedPoint holds a single metric observation with its attribute set.
type observedPoint struct {
	value int64
	attrs []attribute.KeyValue
}

// MetricsCollector collects SNMP operational metrics from devices using ktranslate profiles
// and exports them via the configured OTLP endpoint.
type MetricsCollector struct {
	clientFactory snmp.ClientFactory
	matcher       *profiles.Matcher
	logger        *slog.Logger

	pollMu    sync.Mutex
	pollState map[deviceKey]map[string]time.Time // device -> symbolOID -> lastPoll

	// Observable gauge store: device -> metricName -> observations.
	// Updated after each CollectTarget run; read by OTLP callbacks on every export cycle.
	storeMu     sync.RWMutex
	deviceStore map[deviceKey]map[string][]observedPoint

	// Registered observable gauge instruments (one per unique metric name).
	gaugeMu       sync.Mutex
	instruments   map[string]metric.Int64ObservableGauge
	registrations []metric.Registration // kept alive to prevent GC

	// Profiles already checked for conversions the collector cannot apply.
	reviewMu         sync.Mutex
	reviewedProfiles map[string]struct{}
}

// NewMetricsCollector creates a MetricsCollector.
func NewMetricsCollector(clientFactory snmp.ClientFactory, matcher *profiles.Matcher, logger *slog.Logger) *MetricsCollector {
	return &MetricsCollector{
		clientFactory:    clientFactory,
		matcher:          matcher,
		logger:           logger,
		pollState:        make(map[deviceKey]map[string]time.Time),
		deviceStore:      make(map[deviceKey]map[string][]observedPoint),
		instruments:      make(map[string]metric.Int64ObservableGauge),
		reviewedProfiles: make(map[string]struct{}),
	}
}

// isPollReady returns true if the symbol OID is due to be polled for the given device.
// pollTimeSec == 0 means always poll. Updates the last-poll timestamp on true.
func (c *MetricsCollector) isPollReady(key deviceKey, oid string, pollTimeSec int) bool {
	if pollTimeSec <= 0 {
		return true
	}
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	if c.pollState[key] == nil {
		c.pollState[key] = make(map[string]time.Time)
	}
	now := time.Now()
	if last, ok := c.pollState[key][oid]; ok && now.Before(last.Add(time.Duration(pollTimeSec)*time.Second)) {
		return false
	}
	c.pollState[key][oid] = now
	return true
}

// ensureInstrument lazily registers an observable gauge callback for metricName.
// The callback reads from the shared deviceStore on every OTLP export cycle.
func (c *MetricsCollector) ensureInstrument(name, description string) {
	c.gaugeMu.Lock()
	defer c.gaugeMu.Unlock()
	if _, ok := c.instruments[name]; ok {
		return
	}
	m := metrics.GetMeter()
	if m == nil {
		return
	}
	g, err := m.Int64ObservableGauge(name, metric.WithDescription(description))
	if err != nil {
		c.logger.Error("Failed to create observable gauge", "name", name, "error", err)
		return
	}
	// Capture name and g by value for the closure.
	gInst := g
	metricName := name
	reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		c.storeMu.RLock()
		defer c.storeMu.RUnlock()
		for _, deviceMetrics := range c.deviceStore {
			for _, pt := range deviceMetrics[metricName] {
				o.ObserveInt64(gInst, pt.value, metric.WithAttributes(pt.attrs...))
			}
		}
		return nil
	}, gInst)
	if err != nil {
		c.logger.Error("Failed to register observable gauge callback", "name", name, "error", err)
		return
	}
	c.instruments[name] = g
	c.registrations = append(c.registrations, reg)
}

// ForgetPolicy drops every observation and poll timestamp owned by policyName,
// so a policy that has been stopped stops exporting. Devices named by other
// policies are untouched, which is what keying on the policy name buys.
func (c *MetricsCollector) ForgetPolicy(policyName string) {
	c.storeMu.Lock()
	for key := range c.deviceStore {
		if key.policy == policyName {
			delete(c.deviceStore, key)
		}
	}
	c.storeMu.Unlock()

	c.pollMu.Lock()
	for key := range c.pollState {
		if key.policy == policyName {
			delete(c.pollState, key)
		}
	}
	c.pollMu.Unlock()
}

// forgetDevice drops one device's observations and poll timestamps. A device
// that failed to collect stops exporting rather than repeating its last values,
// so staleness is visible as an absent series. Clearing the poll timestamps too
// means the next successful run repopulates every metric instead of throttling
// some of them against a window that has nothing left to carry forward.
func (c *MetricsCollector) forgetDevice(key deviceKey) {
	c.storeMu.Lock()
	delete(c.deviceStore, key)
	c.storeMu.Unlock()

	c.pollMu.Lock()
	delete(c.pollState, key)
	c.pollMu.Unlock()
}

// CollectTarget collects SNMP metrics from a single target using its matched profile.
// Returns nil if the device has no matching profile (not an error condition).
// A run that fails leaves nothing behind for the device it was polling.
func (c *MetricsCollector) CollectTarget(ctx context.Context, target config.Target, auth *config.Authentication, policyName string, dial DialOptions) error {
	key := deviceKey{policy: policyName, host: target.Host, port: target.Port}
	if err := c.collect(ctx, key, target, auth, dial); err != nil {
		c.forgetDevice(key)
		return err
	}
	return nil
}

func (c *MetricsCollector) collect(ctx context.Context, key deviceKey, target config.Target, auth *config.Authentication, dial DialOptions) error {
	walker, err := c.clientFactory(target.Host, target.Port, dial.Retries, dial.Timeout, auth, c.logger)
	if err != nil {
		return fmt.Errorf("creating SNMP client for %s: %w", target.Host, err)
	}
	defer func() {
		if err := walker.Close(); err != nil {
			c.logger.Warn("Error closing SNMP connection", "host", config.SanitizeLogValue(target.Host), "error", err)
		}
	}()

	if err := walker.Connect(); err != nil {
		return fmt.Errorf("connecting to %s: %w", target.Host, err)
	}

	// Fetch sysObjectID for profile matching.
	sysOIDValue, err := c.walkScalar(walker, sysObjectIDOID)
	if err != nil {
		return fmt.Errorf("getting sysObjectID from %s: %w", target.Host, err)
	}

	// Fetch sysDescr for matches-redirect resolution (best-effort).
	sysDescr, _ := c.walkScalar(walker, sysDescrOID)

	profile, ok := c.matcher.MatchWithDescr(sysOIDValue, sysDescr)
	if !ok {
		// The address may have been reassigned to a device no profile covers,
		// so anything collected under the old profile is dropped rather than
		// left exporting.
		c.forgetDevice(key)
		c.logger.Debug("No SNMP profile matched, skipping metrics collection", "host", config.SanitizeLogValue(target.Host), "sysObjectID", config.SanitizeLogValue(sysOIDValue))
		return nil
	}
	c.logger.Debug("Matched SNMP profile", "host", config.SanitizeLogValue(target.Host), "sysObjectID", config.SanitizeLogValue(sysOIDValue), "profile", profile.FileName)
	c.reportUnsupportedConversions(profile)

	// The attribute set carries every dimension the device key does: two
	// policies may poll one device, and one host may answer on more than one
	// port, so without them the series would be indistinguishable and the
	// observable gauge would receive duplicate points for one attribute set.
	baseAttrs := []attribute.KeyValue{
		attribute.String("device_ip", target.Host),
		attribute.Int("device_port", int(key.port)),
		attribute.String("policy", key.policy),
	}
	if target.ID != "" {
		baseAttrs = append(baseAttrs, attribute.String("netbox_id", target.ID))
	}
	baseAttrs = c.appendDeviceTags(ctx, walker, profile, baseAttrs, sysDescr, sysOIDValue)

	// localBuf accumulates fresh observations for this run.
	// throttledMetrics records metric names skipped due to poll_time_sec not elapsed.
	localBuf := make(map[string][]observedPoint)
	throttledMetrics := make(map[string]struct{})

	for _, entry := range profile.Metrics {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch {
		case entry.Symbol != nil:
			c.collectScalar(ctx, walker, entry.Symbol, baseAttrs, key, localBuf, throttledMetrics)
		case entry.Table != nil:
			c.collectTable(ctx, walker, &entry, baseAttrs, key, localBuf, throttledMetrics)
		case len(entry.Symbols) > 0:
			// Scalars grouped under `symbols:` with no `table:`. Almost all of
			// them name a `.0` instance, so they collect as scalars. One entry
			// can carry dozens, each a request of its own, so the deadline is
			// checked between them and not only between entries.
			for i := range entry.Symbols {
				if err := ctx.Err(); err != nil {
					return err
				}
				c.collectScalar(ctx, walker, &entry.Symbols[i], baseAttrs, key, localBuf, throttledMetrics)
			}
		}
	}

	// Rebuild the device store:
	// - throttled metrics: carry last-known value forward (poll not yet due)
	// - polled metrics: use fresh values from localBuf (empty = device doesn't support that OID)
	// This prevents stale rows from persisting when a table row disappears.
	c.storeMu.Lock()
	prevStore := c.deviceStore[key]
	newStore := make(map[string][]observedPoint, len(localBuf)+len(throttledMetrics))
	for metricName := range throttledMetrics {
		if pts, ok := prevStore[metricName]; ok {
			newStore[metricName] = pts
		}
	}
	for name, pts := range localBuf {
		newStore[name] = pts
	}
	c.deviceStore[key] = newStore
	c.storeMu.Unlock()

	// Ensure an observable gauge callback is registered for each metric name.
	for name := range newStore {
		c.ensureInstrument(name, name+" (SNMP profile metric)")
	}

	return nil
}

// appendDeviceTags renders the profile's top-level metric_tags and appends them
// to attrs. They describe the device rather than a row, so they belong on every
// series the profile produces. Each uncached column is a request of its own, so
// the walk stops once the deadline has expired and the caller returns on the
// same check straight after.
func (c *MetricsCollector) appendDeviceTags(ctx context.Context, walker snmp.Walker, profile *profiles.Profile, attrs []attribute.KeyValue, sysDescr, sysObjectID string) []attribute.KeyValue {
	for _, mt := range profile.MetricTags {
		if ctx.Err() != nil {
			return attrs
		}
		col := metricTagColumn(&mt)
		if col == nil || col.OID == "" {
			continue
		}
		name := mt.Tag
		if name == "" {
			// The bare `column:` form carries no tag, so the column name is the key.
			name = col.Name
		}
		if name == "" {
			continue
		}
		if value, ok := cachedSystemValue(col.OID, sysDescr, sysObjectID); ok {
			if value != "" {
				attrs = append(attrs, attribute.String(name, value))
			}
			continue
		}
		pdus, err := c.walk(walker, col.OID, 0)
		if err != nil {
			c.logger.Debug("Error walking device tag", "oid", col.OID, "tag", name, "error", err)
			continue
		}
		if value := firstTagValue(pdus, col); value != "" {
			attrs = append(attrs, attribute.String(name, value))
		}
	}
	return attrs
}

// cachedSystemValue returns the value CollectTarget already read for the two
// system OIDs it walks before profile matching, so neither is walked twice.
func cachedSystemValue(oid, sysDescr, sysObjectID string) (string, bool) {
	switch strings.TrimSuffix(oid, ".0") {
	case sysDescrOID:
		return sysDescr, true
	case sysObjectIDOID:
		return sysObjectID, true
	}
	return "", false
}

// firstTagValue renders the lowest-numbered PDU of a device tag walk. Device
// tags name a scalar instance, so one value is expected; sorting keeps the
// choice stable if a device answers with more.
func firstTagValue(pdus map[string]snmp.PDU, col *profiles.TagColumn) string {
	oids := make([]string, 0, len(pdus))
	for oid := range pdus {
		oids = append(oids, oid)
	}
	sort.Strings(oids)
	for _, oid := range oids {
		if value := pduToString(pdus[oid], col); value != "" {
			return value
		}
	}
	return ""
}

// supportedConversion reports whether pduToValue implements the conversion a
// symbol declares. An empty conversion is the plain numeric path.
//
// It mirrors the branches in pduToValue: a new conversion has to be added in
// both places, or it will be reported as unsupported while working.
func supportedConversion(conversion string) bool {
	switch conversion {
	case "", "to_one", "hextoip", "hwaddr":
		return true
	}
	return strings.HasPrefix(conversion, "hextoint:") || strings.HasPrefix(conversion, "regexp:")
}

// reportUnsupportedConversions warns about every symbol in a matched profile
// that declares a conversion pduToValue does not implement. Such a symbol never
// produces a metric, and without this nothing says why it is missing.
//
// A profile is reviewed the first time a device matches it and never again, so
// the warnings appear once for the life of the process however many devices
// carry the profile and however often they are polled.
func (c *MetricsCollector) reportUnsupportedConversions(profile *profiles.Profile) {
	name := profile.RelPath
	if name == "" {
		name = profile.FileName
	}
	c.reviewMu.Lock()
	_, reviewed := c.reviewedProfiles[name]
	if !reviewed {
		c.reviewedProfiles[name] = struct{}{}
	}
	c.reviewMu.Unlock()
	if reviewed {
		return
	}

	warn := func(sym *profiles.Symbol) {
		if supportedConversion(sym.Conversion) {
			return
		}
		c.logger.Warn("Skipping metric: SNMP profile declares a conversion this collector does not implement",
			"conversion", sym.Conversion, "symbol", sym.Name, "oid", sym.OID, "profile", name)
	}
	for _, entry := range profile.Metrics {
		if entry.Symbol != nil {
			warn(entry.Symbol)
		}
		for i := range entry.Symbols {
			warn(&entry.Symbols[i])
		}
	}
}

// collectScalar collects a single scalar OID metric into localBuf.
// Records the metric name in throttledMetrics when poll_time_sec has not elapsed.
func (c *MetricsCollector) collectScalar(_ context.Context, walker snmp.Walker, sym *profiles.Symbol, baseAttrs []attribute.KeyValue, key deviceKey, localBuf map[string][]observedPoint, throttledMetrics map[string]struct{}) {
	metricName := buildMetricName(sym.Name)
	if !c.isPollReady(key, sym.OID, sym.PollTimeSec) {
		throttledMetrics[metricName] = struct{}{}
		return
	}
	pdus, err := c.walk(walker, sym.OID, 0)
	if err != nil {
		c.logger.Debug("Error walking scalar OID", "oid", sym.OID, "name", sym.Name, "error", err)
		return
	}
	for _, pdu := range pdus {
		val, strVal, err := pduToValue(pdu, sym.Conversion)
		if err != nil {
			c.logger.Debug("Skipping non-numeric PDU", "oid", sym.OID, "name", sym.Name, "error", err)
			continue
		}

		attrs := make([]attribute.KeyValue, len(baseAttrs))
		copy(attrs, baseAttrs)
		if len(sym.Enum) > 0 {
			if name := enumName(sym.Enum, val); name != "" {
				attrs = append(attrs, attribute.String(sym.Name+"_status", name))
			}
		}
		if sym.Tag != "" {
			attrs = append(attrs, attribute.String("tag", sym.Tag))
		}
		if strVal != "" {
			attrs = append(attrs, attribute.String(sym.Name+"_value", strVal))
		}

		localBuf[metricName] = append(localBuf[metricName], observedPoint{value: val, attrs: attrs})
	}
}

// conditionCheck holds the parsed condition for a table symbol.
type conditionCheck struct {
	columnOID string
	expected  int64
}

// joinedTag is a metric_tag whose column lives in a table other than the one
// the metric rows come from. byIndex is keyed by that other table's index, and
// transform turns a metric row's composite index into that key.
type joinedTag struct {
	name      string
	transform profiles.IndexTransform
	byIndex   map[string]string
}

// collectTable collects all columns in an SNMP table, joining metric and tag columns by row index.
func (c *MetricsCollector) collectTable(ctx context.Context, walker snmp.Walker, entry *profiles.MetricEntry, baseAttrs []attribute.KeyValue, key deviceKey, localBuf map[string][]observedPoint, throttledMetrics map[string]struct{}) {
	// --- Phase 1: decide which symbols need polling this run ---
	type symState struct {
		sym       *profiles.Symbol
		throttled bool
	}
	states := make([]symState, len(entry.Symbols))
	anyActive := false
	for i := range entry.Symbols {
		sym := &entry.Symbols[i]
		if c.isPollReady(key, sym.OID, sym.PollTimeSec) {
			states[i] = symState{sym: sym, throttled: false}
			anyActive = true
		} else {
			states[i] = symState{sym: sym, throttled: true}
			throttledMetrics[buildMetricName(sym.Name)] = struct{}{}
		}
	}
	if !anyActive {
		return // all symbols throttled; skip all SNMP walks
	}

	// --- Phase 2: obtain PDUs (walk_full_table or per-column walks) ---
	// columnPDUs maps columnOID -> (fullOID -> PDU), used for both metric and condition columns.
	var columnPDUs map[string]map[string]snmp.PDU
	if entry.WalkFullTable && entry.Table != nil {
		columnPDUs = c.walkFullTable(walker, entry)
	}

	// --- Phase 3: walk tag columns ---
	// rowTags: rowIndex -> tag name -> tag value string, for columns indexed
	// the same way as the metric rows.
	// joinedTags: columns read from another table, matched to a metric row by
	// transforming that row's composite index.
	rowTags := make(map[string]map[string]string)
	var joinedTags []joinedTag
	for i := range entry.MetricTags {
		mt := &entry.MetricTags[i]
		col := metricTagColumn(mt)
		if col == nil || col.OID == "" {
			continue
		}
		var pdus map[string]snmp.PDU
		// A column carrying an index_transform belongs to another table, so a
		// full-table walk of this table cannot have picked it up.
		if columnPDUs != nil && len(mt.IndexTransform) == 0 {
			pdus = columnPDUs[col.OID]
		} else {
			var err error
			pdus, err = c.walk(walker, col.OID, 1)
			if err != nil {
				c.logger.Debug("Error walking tag column", "oid", col.OID, "tag", mt.Tag, "error", err)
				continue
			}
		}
		tagName := mt.Tag
		if tagName == "" {
			tagName = col.Name
		}
		if len(mt.IndexTransform) > 0 {
			jt := joinedTag{name: tagName, transform: mt.IndexTransform, byIndex: make(map[string]string, len(pdus))}
			for fullOID, pdu := range pdus {
				jt.byIndex[extractRowIndex(fullOID, col.OID)] = pduToString(pdu, col)
			}
			joinedTags = append(joinedTags, jt)
			continue
		}
		for fullOID, pdu := range pdus {
			rowIdx := extractRowIndex(fullOID, col.OID)
			if rowTags[rowIdx] == nil {
				rowTags[rowIdx] = make(map[string]string)
			}
			rowTags[rowIdx][tagName] = pduToString(pdu, col)
		}
	}

	// --- Phase 4: parse and walk condition columns (active symbols only) ---
	symOIDByName := make(map[string]string, len(entry.Symbols))
	for _, sym := range entry.Symbols {
		symOIDByName[sym.Name] = sym.OID
	}
	conditionRowVals := make(map[string]map[string]int64)
	conditions := make(map[string]conditionCheck)
	for _, st := range states {
		if st.throttled || st.sym.Condition == "" {
			continue
		}
		parts := strings.SplitN(st.sym.Condition, "=", 2)
		if len(parts) != 2 {
			c.logger.Warn("Ignoring malformed condition", "symbol", st.sym.Name, "condition", st.sym.Condition)
			continue
		}
		refName := strings.TrimSpace(parts[0])
		expectedStr := strings.TrimSpace(parts[1])
		expected, err := strconv.ParseInt(expectedStr, 10, 64)
		if err != nil {
			c.logger.Warn("Ignoring condition with non-integer value", "symbol", st.sym.Name, "condition", st.sym.Condition)
			continue
		}
		refOID, ok := symOIDByName[refName]
		if !ok {
			c.logger.Warn("Condition references unknown symbol", "symbol", st.sym.Name, "ref", refName)
			continue
		}
		conditions[st.sym.OID] = conditionCheck{columnOID: refOID, expected: expected}
		if _, walked := conditionRowVals[refOID]; !walked {
			var pdus map[string]snmp.PDU
			if columnPDUs != nil {
				pdus = columnPDUs[refOID]
			} else {
				pdus, err = c.walk(walker, refOID, 1)
				if err != nil {
					c.logger.Debug("Error walking condition column", "oid", refOID, "error", err)
					conditionRowVals[refOID] = nil
					continue
				}
			}
			rowVals := make(map[string]int64, len(pdus))
			for fullOID, pdu := range pdus {
				rowIdx := extractRowIndex(fullOID, refOID)
				if v, _, err := pduToValue(pdu, ""); err == nil {
					rowVals[rowIdx] = v
				}
			}
			conditionRowVals[refOID] = rowVals
		}
	}

	// --- Phase 5: collect active metric columns ---
	for _, st := range states {
		if st.throttled {
			continue
		}
		sym := st.sym
		var pdus map[string]snmp.PDU
		if columnPDUs != nil {
			pdus = columnPDUs[sym.OID]
		} else {
			var err error
			pdus, err = c.walk(walker, sym.OID, 1)
			if err != nil {
				c.logger.Debug("Error walking table column", "oid", sym.OID, "name", sym.Name, "error", err)
				continue
			}
		}

		cond, hasCondition := conditions[sym.OID]
		metricName := buildMetricName(sym.Name)

		for fullOID, pdu := range pdus {
			if err := ctx.Err(); err != nil {
				return
			}
			rowIdx := extractRowIndex(fullOID, sym.OID)

			if hasCondition {
				rowVals := conditionRowVals[cond.columnOID]
				if rowVals == nil {
					continue
				}
				if rowVals[rowIdx] != cond.expected {
					continue
				}
			}

			val, strVal, err := pduToValue(pdu, sym.Conversion)
			if err != nil {
				continue
			}

			rowAttrs := make([]attribute.KeyValue, len(baseAttrs))
			copy(rowAttrs, baseAttrs)
			rowAttrs = append(rowAttrs, attribute.String("row_index", rowIdx))
			if tags, ok := rowTags[rowIdx]; ok {
				for k, v := range tags {
					rowAttrs = append(rowAttrs, attribute.String(k, v))
				}
			}
			for _, jt := range joinedTags {
				key, ok := jt.transform.Apply(rowIdx)
				if !ok {
					continue
				}
				if v, ok := jt.byIndex[key]; ok {
					rowAttrs = append(rowAttrs, attribute.String(jt.name, v))
				}
			}
			if len(sym.Enum) > 0 {
				if name := enumName(sym.Enum, val); name != "" {
					rowAttrs = append(rowAttrs, attribute.String(sym.Name+"_status", name))
				}
			}
			if sym.Tag != "" {
				rowAttrs = append(rowAttrs, attribute.String("tag", sym.Tag))
			}
			if strVal != "" {
				rowAttrs = append(rowAttrs, attribute.String(sym.Name+"_value", strVal))
			}

			localBuf[metricName] = append(localBuf[metricName], observedPoint{value: val, attrs: rowAttrs})
		}
	}
}

// walkFullTable walks the table root OID once and distributes PDUs to per-column maps.
// The returned maps are keyed by the profile's own column OID, which is how the
// callers look them up.
func (c *MetricsCollector) walkFullTable(walker snmp.Walker, entry *profiles.MetricEntry) map[string]map[string]snmp.PDU {
	allPDUs, err := c.walk(walker, entry.Table.OID, 0)
	if err != nil {
		c.logger.Debug("Error walking full table", "oid", entry.Table.OID, "table", entry.Table.Name, "error", err)
		return nil
	}

	// Build set of interesting column OID prefixes (metric + tag + condition refs),
	// keyed by the normalized prefix and carrying the profile OID to key the result by.
	colPrefixes := make(map[string]string)
	for _, sym := range entry.Symbols {
		colPrefixes[normalizeOID(sym.OID)] = sym.OID
	}
	for _, mt := range entry.MetricTags {
		if col := metricTagColumn(&mt); col != nil && col.OID != "" {
			colPrefixes[normalizeOID(col.OID)] = col.OID
		}
	}

	result := make(map[string]map[string]snmp.PDU, len(colPrefixes))
	for fullOID, pdu := range allPDUs {
		for prefix, colOID := range colPrefixes {
			if strings.HasPrefix(fullOID, prefix+".") || fullOID == prefix {
				if result[colOID] == nil {
					result[colOID] = make(map[string]snmp.PDU)
				}
				result[colOID][fullOID] = pdu
			}
		}
	}
	return result
}

// walk walks an OID subtree and returns the PDUs keyed by normalized OID.
// gosnmp names every PDU with a leading dot, so normalizing once here spares
// every caller from carrying the difference into its own comparisons.
func (c *MetricsCollector) walk(walker snmp.Walker, oid string, identifierSize int) (map[string]snmp.PDU, error) {
	pdus, err := walker.Walk(oid, identifierSize)
	if err != nil {
		return nil, err
	}
	normalized := make(map[string]snmp.PDU, len(pdus))
	for name, pdu := range pdus {
		pdu.Name = normalizeOID(pdu.Name)
		normalized[normalizeOID(name)] = pdu
	}
	return normalized, nil
}

// walkScalar walks a scalar OID subtree and returns the first string value found.
func (c *MetricsCollector) walkScalar(walker snmp.Walker, oid string) (string, error) {
	pdus, err := c.walk(walker, oid, 0)
	if err != nil {
		return "", err
	}
	for _, pdu := range pdus {
		switch pdu.Type {
		case gosnmp.OctetString:
			if s, ok := pdu.Value.(string); ok {
				return strings.TrimSpace(s), nil
			}
			if b, ok := pdu.Value.([]byte); ok {
				return strings.TrimSpace(string(b)), nil
			}
		case gosnmp.ObjectIdentifier:
			if s, ok := pdu.Value.(string); ok {
				return s, nil
			}
		case gosnmp.IPAddress:
			if s, ok := pdu.Value.(string); ok {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("no value returned for OID %s", oid)
}

// normalizeOID strips the leading dot gosnmp puts on every PDU name. Profile
// OIDs mostly omit it and a few carry one, so both sides go through here before
// any OID is compared or used as a prefix.
func normalizeOID(oid string) string {
	return strings.TrimPrefix(oid, ".")
}

// extractRowIndex strips the column OID prefix from a full OID to get the row index suffix.
func extractRowIndex(fullOID, columnOID string) string {
	fullOID = normalizeOID(fullOID)
	prefix := normalizeOID(columnOID) + "."
	if strings.HasPrefix(fullOID, prefix) {
		return fullOID[len(prefix):]
	}
	return fullOID
}

// buildMetricName converts a profile symbol name to an OTLP metric name.
func buildMetricName(symbolName string) string {
	return "snmp." + strings.ToLower(symbolName)
}

// metricTagColumn returns the tag column from a MetricTag, handling the
// alias where some profiles use "symbol" instead of "column".
func metricTagColumn(mt *profiles.MetricTag) *profiles.TagColumn {
	if mt.Column != nil {
		return mt.Column
	}
	return mt.Symbol
}

// pduToValue converts a PDU to an int64 metric value, applying conversion rules.
// It also returns an optional non-empty string for display-only conversions (hextoip, hwaddr, regexp).
// Returns an error for PDU types that cannot produce a numeric value.
func pduToValue(pdu snmp.PDU, conversion string) (int64, string, error) {
	// conversion: to_one — always emit 1 regardless of actual PDU type.
	if conversion == "to_one" {
		return 1, "", nil
	}

	switch pdu.Type {
	case gosnmp.Integer:
		if v, ok := pdu.Value.(int); ok {
			return int64(v), "", nil
		}
	case gosnmp.Counter32, gosnmp.Gauge32:
		if v, ok := pdu.Value.(uint); ok {
			return int64(v), "", nil //nolint:gosec
		}
	case gosnmp.Counter64:
		if v, ok := pdu.Value.(uint64); ok {
			return int64(v), "", nil //nolint:gosec
		}
	case gosnmp.TimeTicks:
		if v, ok := pdu.Value.(uint32); ok {
			return int64(v), "", nil
		}
	case gosnmp.OctetString:
		raw := pduRawBytes(pdu)
		rawStr := strings.TrimSpace(string(raw))
		switch {
		case conversion == "hextoip":
			if ip := hexBytesToIP(raw); ip != "" {
				return 1, ip, nil
			}
		case conversion == "hwaddr":
			if mac := net.HardwareAddr(raw).String(); mac != "" {
				return 1, mac, nil
			}
		case strings.HasPrefix(conversion, "hextoint:"):
			if v, err := applyHexToInt(raw, conversion); err == nil {
				return v, "", nil
			}
		case strings.HasPrefix(conversion, "regexp:"):
			if v, display, err := applyRegexp(rawStr, conversion); err == nil {
				return v, display, nil
			}
		}
		return 0, "", fmt.Errorf("non-numeric OctetString PDU (conversion=%q)", conversion)
	}
	return 0, "", fmt.Errorf("non-numeric PDU type %v", pdu.Type)
}

// applyHexToInt converts an OctetString byte slice to an integer using
// the hextoint:<endianness>:<type> conversion rule.
func applyHexToInt(raw []byte, conversion string) (int64, error) {
	parts := strings.SplitN(conversion, ":", 3)
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid hextoint format: %s", conversion)
	}
	endianStr := parts[1]
	typeStr := parts[2]

	decoded := raw
	if b, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil {
		decoded = b
	}

	var order binary.ByteOrder
	switch endianStr {
	case "BigEndian":
		order = binary.BigEndian
	case "LittleEndian":
		order = binary.LittleEndian
	default:
		return 0, fmt.Errorf("unknown endianness: %s", endianStr)
	}

	switch typeStr {
	case "uint16":
		if len(decoded) < 2 {
			return 0, fmt.Errorf("too few bytes for uint16")
		}
		return int64(order.Uint16(decoded[:2])), nil
	case "uint32":
		if len(decoded) < 4 {
			return 0, fmt.Errorf("too few bytes for uint32")
		}
		return int64(order.Uint32(decoded[:4])), nil //nolint:gosec
	case "uint64":
		if len(decoded) < 8 {
			return 0, fmt.Errorf("too few bytes for uint64")
		}
		return int64(order.Uint64(decoded[:8])), nil //nolint:gosec
	}
	return 0, fmt.Errorf("unknown hextoint type: %s", typeStr)
}

// applyRegexp applies a regexp: conversion to a string value.
func applyRegexp(raw, conversion string) (int64, string, error) {
	pattern := strings.TrimPrefix(conversion, "regexp:")
	re, err := regexp.Compile(pattern)
	if err != nil {
		return 0, "", fmt.Errorf("invalid regexp %q: %w", pattern, err)
	}
	matches := re.FindStringSubmatch(raw)
	if len(matches) == 0 {
		return 0, "", fmt.Errorf("regexp %q did not match %q", pattern, raw)
	}
	extracted := matches[0]
	if len(matches) > 1 {
		extracted = matches[1]
	}
	v, err := strconv.ParseInt(strings.TrimSpace(extracted), 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("regexp extracted non-integer %q: %w", extracted, err)
	}
	return v, extracted, nil
}

// pduRawBytes returns the byte slice from an OctetString PDU.
func pduRawBytes(pdu snmp.PDU) []byte {
	if b, ok := pdu.Value.([]byte); ok {
		return b
	}
	if s, ok := pdu.Value.(string); ok {
		return []byte(s)
	}
	return nil
}

// hexBytesToIP converts a raw 4-byte or 16-byte slice to an IP string.
func hexBytesToIP(raw []byte) string {
	if len(raw) == 4 || len(raw) == 16 {
		return net.IP(raw).String()
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err == nil && (len(decoded) == 4 || len(decoded) == 16) {
		return net.IP(decoded).String()
	}
	return ""
}

// pduToString converts a PDU value to a human-readable string for tag/attribute use.
func pduToString(pdu snmp.PDU, col *profiles.TagColumn) string {
	switch pdu.Type {
	case gosnmp.OctetString:
		raw := pduRawBytes(pdu)
		if col != nil {
			switch col.Conversion {
			case "hextoip":
				if ip := hexBytesToIP(raw); ip != "" {
					return ip
				}
			case "hwaddr":
				if mac := net.HardwareAddr(raw).String(); mac != "" {
					return mac
				}
			default:
				// A hextoint tag column renders as its decoded number. Without
				// this the raw octets reach the attribute as text, which looks
				// like a value rather than a missing one.
				if strings.HasPrefix(col.Conversion, "hextoint:") {
					if v, err := applyHexToInt(raw, col.Conversion); err == nil {
						return strconv.FormatInt(v, 10)
					}
				}
			}
		}
		return strings.TrimSpace(string(raw))
	case gosnmp.Integer:
		if v, ok := pdu.Value.(int); ok {
			if col != nil {
				for name, intVal := range col.Enum {
					if intVal == v {
						return name
					}
				}
			}
			return fmt.Sprintf("%d", v)
		}
	case gosnmp.Counter32, gosnmp.Gauge32:
		if v, ok := pdu.Value.(uint); ok {
			return fmt.Sprintf("%d", v)
		}
	case gosnmp.IPAddress, gosnmp.ObjectIdentifier:
		if s, ok := pdu.Value.(string); ok {
			return s
		}
	}
	return fmt.Sprintf("%v", pdu.Value)
}

// enumName returns the enum string for val, or "" if not found.
func enumName(enum map[string]int, val int64) string {
	for name, intVal := range enum {
		if int64(intVal) == val {
			return name
		}
	}
	return ""
}
