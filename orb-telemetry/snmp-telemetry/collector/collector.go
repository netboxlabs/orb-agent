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
//
// One policy can also name the same endpoint more than once. Two such entries
// are told apart by their NetBox ID and by their SNMPv3 context name, which
// selects a different MIB view on the same agent. Credentials are not part of
// the key: they are secret, so no attribute could carry them, and a key
// dimension the exported series cannot express is one that silently merges two
// devices' points.
//
// Every field here has an exported attribute in appendIdentityAttrs. Adding one
// without the other is what made this identity wrong twice.
type deviceKey struct {
	policy  string
	host    string
	port    uint16
	id      string
	context string
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

// pollDue reports whether the symbol OID is due to be polled for the given
// device. pollTimeSec == 0 means always poll.
//
// It reads the last-poll timestamp and does not write one: markPolled does that
// once the request has come back. Recording it here instead would start the
// poll window on a request that failed, and since a failed request leaves no
// observation to carry forward, an hourly symbol would then be missing for an
// hour after one timeout.
func (c *MetricsCollector) pollDue(key deviceKey, oid string, pollTimeSec int) bool {
	if pollTimeSec <= 0 {
		return true
	}
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	last, ok := c.pollState[key][oid]
	return !ok || !time.Now().Before(last.Add(time.Duration(pollTimeSec)*time.Second))
}

// markPolled starts the poll window for the symbol OID on the given device.
//
// It is called once the walk has returned without error, whatever the device
// answered with: a device that does not implement an OID has still been asked,
// and re-asking it every cycle is what the poll window is there to prevent.
// A device forgotten after a failed run loses these timestamps with the rest of
// its state, so the two rules agree that nothing throttles what was not
// collected.
func (c *MetricsCollector) markPolled(key deviceKey, oid string, pollTimeSec int) {
	if pollTimeSec <= 0 {
		return
	}
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	if c.pollState[key] == nil {
		c.pollState[key] = make(map[string]time.Time)
	}
	c.pollState[key][oid] = time.Now()
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

// appendIdentityAttrs renders every dimension of a device key as an attribute.
// Without them the series of two devices the collector keeps apart would be
// indistinguishable, and the observable gauge would receive duplicate points
// for one attribute set. A dimension that is empty is left off rather than
// exported as blank, so the common target carries no dead attributes.
func appendIdentityAttrs(attrs []attribute.KeyValue, key deviceKey) []attribute.KeyValue {
	attrs = append(attrs, attribute.String("device_ip", key.host))
	attrs = append(attrs, attribute.Int("device_port", int(key.port)))
	attrs = append(attrs, attribute.String("policy", key.policy))
	if key.id != "" {
		attrs = append(attrs, attribute.String("netbox_id", key.id))
	}
	if key.context != "" {
		attrs = append(attrs, attribute.String("snmp_context", key.context))
	}
	return attrs
}

// CollectTarget collects SNMP metrics from a single target using its matched profile.
// Returns nil if the device has no matching profile (not an error condition).
// A run that fails leaves nothing behind for the device it was polling.
func (c *MetricsCollector) CollectTarget(ctx context.Context, target config.Target, auth *config.Authentication, policyName string, dial DialOptions) error {
	key := deviceKey{policy: policyName, host: target.Host, port: target.Port, id: target.ID}
	if auth != nil {
		key.context = auth.ContextName
	}
	if err := c.collect(ctx, key, target, auth, dial); err != nil {
		c.forgetDevice(key)
		return err
	}
	return nil
}

func (c *MetricsCollector) collect(ctx context.Context, key deviceKey, target config.Target, auth *config.Authentication, dial DialOptions) error {
	walker, err := c.clientFactory(ctx, target.Host, target.Port, dial.Retries, dial.Timeout, auth, c.logger)
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
	c.reviewProfile(profile)

	// Everything from here walks the profile's tables, which is where the round
	// trips are. The two walks above chose the profile, so this is the first
	// point at which the device's tolerance for GETBULK is known.
	walker.SetBulkWalk(!profile.NoUseBulkWalkAll)

	baseAttrs := c.appendDeviceTags(ctx, walker, profile, appendIdentityAttrs(nil, key), sysDescr, sysOIDValue)

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
		case len(entry.Symbols) > 0 && groupedSymbolsAreTableColumns(&entry):
			// Columns of a table the profile names no `table:` root for. The
			// rows still have to be joined by index, or the entry's row-scoped
			// metadata is lost and the rows carry no identity.
			c.collectTable(ctx, walker, &entry, baseAttrs, key, localBuf, throttledMetrics)
		case len(entry.Symbols) > 0:
			// Scalars grouped under `symbols:` with no `table:`. One entry can
			// carry dozens, each a request of its own, so the deadline is
			// checked between them and not only between entries.
			for i := range entry.Symbols {
				if err := ctx.Err(); err != nil {
					return err
				}
				c.collectScalar(ctx, walker, &entry.Symbols[i], baseAttrs, key, localBuf, throttledMetrics)
			}
		}
	}

	// A deadline that expires inside the last entry truncates the run as much
	// as one that expires between entries, and the table path returns without
	// an error of its own. Checking once more here fails the run either way
	// rather than persisting half a profile as if it were complete.
	if err := ctx.Err(); err != nil {
		return err
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

// groupedSymbolsAreTableColumns reports whether an entry that lists `symbols:`
// with no `table:` root is describing table columns rather than grouped scalars.
//
// The OID shape does not decide it. Of the 60 such entries in the bundled set,
// 44 name a `.0` instance throughout and 16 do not, but those 16 include
// genuine scalars, and a table column can equally be written as a fully
// qualified instance. What does decide it is row-scoped metadata: an entry
// `metric_tags:` block names a per-row dimension and a symbol `condition:`
// selects rows, and neither has any meaning for a scalar. Both are also exactly
// what the scalar path has nowhere to put.
//
// Entries that are table columns yet declare neither cannot be told apart from
// grouped scalars without the MIB, so they stay on the scalar path. They are
// not lost there: collectScalar gives a walk that answers with several rows a
// row identity, which is the part of the table treatment such an entry needs.
// What only this function can decide is the row-scoped metadata, which is why
// it tests for that and not for the shape of the OIDs.
func groupedSymbolsAreTableColumns(entry *profiles.MetricEntry) bool {
	if len(entry.MetricTags) > 0 {
		return true
	}
	for i := range entry.Symbols {
		if entry.Symbols[i].Condition != "" {
			return true
		}
	}
	return false
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
		// The bare `column:` form carries no tag, so the column name is the key.
		name := metricTagName(&mt, col)
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

// unusableSymbolReason says why a symbol can produce no metric at all, or ""
// when it can. The collection path skips exactly these symbols and the
// once-per-profile review names exactly these, so the two cannot disagree.
func unusableSymbolReason(sym *profiles.Symbol) string {
	if strings.TrimSpace(sym.OID) == "" {
		// gosnmp reads an empty root as the whole .1.3.6.1 subtree, so the walk
		// can consume the collection deadline on its own.
		return "declares no OID"
	}
	if sym.Script != "" {
		// The script rescales the polled value, and its dialect is ktranslate's
		// rather than anything this collector can read. The untransformed number
		// carries the name and tag of the transformed one, so exporting it would
		// be wrong rather than merely coarse.
		return "declares a script this collector does not run"
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

// reviewProfile warns about every declaration in a matched profile that the
// collector cannot act on: a symbol it skips outright, a conversion pduToValue
// does not implement, and a condition it cannot resolve. Each of those leaves a
// metric missing or unfiltered, and without this nothing says why.
//
// A profile is reviewed the first time a device matches it and never again, so
// the warnings appear once for the life of the process however many devices
// carry the profile and however often they are polled.
func (c *MetricsCollector) reviewProfile(profile *profiles.Profile) {
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
		if reason := unusableSymbolReason(sym); reason != "" {
			c.logger.Warn("Skipping metric: SNMP profile declares a symbol this collector cannot collect",
				"reason", reason, "symbol", sym.Name, "oid", sym.OID, "profile", name)
			return
		}
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
		c.reportUnusableConditions(entry, name)
		c.reportUnusableFilters(entry.MetricTags, name, "")
		c.reportUnusableTags(entry.MetricTags, name)
	}
	c.reportUnusableFilters(profile.MetricTags, name, "column tags the device rather than a row")
	c.reportUnusableTags(profile.MetricTags, name)
}

// reportUnusableConditions reports a condition the collector cannot apply.
// Whether a condition parses and resolves the column it names is a property of
// the profile, not of the device, so it is reported here once rather than on
// every collection. The collection path logs the same cases at debug level.
func (c *MetricsCollector) reportUnusableConditions(entry profiles.MetricEntry, profileName string) {
	for i := range entry.Symbols {
		sym := &entry.Symbols[i]
		if sym.Condition == "" {
			continue
		}
		if _, reason := resolveCondition(&entry, sym.Condition); reason != "" {
			c.logger.Warn("Ignoring condition this collector cannot apply",
				"condition", sym.Condition, "reason", reason,
				"symbol", sym.Name, "profile", profileName)
		}
	}
}

// collectScalar collects a single scalar OID metric into localBuf.
// Records the metric name in throttledMetrics when poll_time_sec has not elapsed.
//
// A walk that answers with more than one instance is walking a table column,
// whatever the profile calls it, so its points are given a row identity. The
// profile cannot always say which entries are columns; the device can, and it
// answers before any point is written. Without the identity every row carries
// the same attribute set and the export keeps one arbitrary value.
func (c *MetricsCollector) collectScalar(_ context.Context, walker snmp.Walker, sym *profiles.Symbol, baseAttrs []attribute.KeyValue, key deviceKey, localBuf map[string][]observedPoint, throttledMetrics map[string]struct{}) {
	if unusableSymbolReason(sym) != "" {
		// Reported once per profile by reviewProfile. Skipping before the walk
		// is what keeps an empty OID from being issued as a whole-tree walk.
		return
	}
	metricName := buildMetricName(sym.Name)
	if !c.pollDue(key, sym.OID, sym.PollTimeSec) {
		throttledMetrics[metricName] = struct{}{}
		return
	}
	pdus, err := c.walk(walker, sym.OID, 0)
	if err != nil {
		c.logger.Debug("Error walking scalar OID", "oid", sym.OID, "name", sym.Name, "error", err)
		return
	}
	c.markPolled(key, sym.OID, sym.PollTimeSec)
	// One instance is the scalar case, and it keeps the attribute set it has.
	severalRows := len(pdus) > 1
	for fullOID, pdu := range pdus {
		val, strVal, err := pduToValue(pdu, sym.Conversion)
		if err != nil {
			c.logger.Debug("Skipping non-numeric PDU", "oid", sym.OID, "name", sym.Name, "error", err)
			continue
		}

		attrs := make([]attribute.KeyValue, len(baseAttrs))
		copy(attrs, baseAttrs)
		if severalRows {
			if rowIdx, indexed := rowIndex(fullOID, sym.OID); indexed {
				attrs = append(attrs, attribute.String("row_index", rowIdx))
			}
		}
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

// conditionCheck holds the resolved condition for a table symbol: the column
// whose rows it tests and the value a row has to carry to be emitted.
type conditionCheck struct {
	columnOID string
	// column is set when the reference is a metric_tags column rather than a
	// sibling symbol, so the row renders through the same conversion and enum
	// the tag itself would use.
	column *profiles.TagColumn
	// numeric selects which of expectInt and expected is compared.
	numeric   bool
	expectInt int64
	expected  string
}

// conditionRow carries both renderings of one row of a condition column, so a
// single walk serves an integer comparison and a textual one alike.
type conditionRow struct {
	num    int64
	hasNum bool
	str    string
}

// matches reports whether one row of the condition column satisfies the
// condition.
//
// A textual value is compared exactly and case-sensitively. Both sides are
// already free of surrounding whitespace: pduToString trims what the device
// returns, and the profile's quotes delimit exactly the text it means. Case is
// kept significant because a MIB display string is, and folding it would let a
// condition select a row the profile did not name.
func (cc conditionCheck) matches(row conditionRow) bool {
	if cc.numeric {
		return row.hasNum && row.num == cc.expectInt
	}
	return row.str == cc.expected
}

// resolveCondition parses a symbol `condition:` and resolves the column it
// names. A condition reads `name=value`. The name is either a sibling symbol or
// a column the entry declares under metric_tags, named by its tag or by the
// column name. The value is either a bare integer or a quoted string.
//
// The returned reason is empty when the condition can be applied and otherwise
// says why it cannot. The collection path and the once-per-profile report both
// go through here, so they cannot disagree about which conditions are usable.
func resolveCondition(entry *profiles.MetricEntry, condition string) (conditionCheck, string) {
	parts := strings.SplitN(condition, "=", 2)
	if len(parts) != 2 {
		return conditionCheck{}, "not a name=value pair"
	}
	refName := strings.TrimSpace(parts[0])
	if refName == "" {
		return conditionCheck{}, "not a name=value pair"
	}

	var check conditionCheck
	raw := strings.TrimSpace(parts[1])
	if unquoted, quoted := trimQuotes(raw); quoted {
		check.expected = unquoted
	} else if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
		check.numeric, check.expectInt = true, v
	} else {
		check.expected = raw
	}

	for i := range entry.Symbols {
		if entry.Symbols[i].Name == refName {
			check.columnOID = entry.Symbols[i].OID
			return check, ""
		}
	}
	for i := range entry.MetricTags {
		mt := &entry.MetricTags[i]
		col := metricTagColumn(mt)
		if col == nil || col.OID == "" {
			continue
		}
		if col.Name != refName && mt.Tag != refName {
			continue
		}
		if len(mt.IndexTransform) > 0 {
			// The column is read from another table and keyed by that table's
			// index, so its rows do not line up with the metric rows.
			return conditionCheck{}, "column is joined from another table"
		}
		check.columnOID, check.column = col.OID, col
		return check, ""
	}
	return conditionCheck{}, "names no symbol or tag column in this entry"
}

// trimQuotes strips a matching pair of quotes and reports whether there was
// one. A profile writes a textual condition value quoted, and the quotes are
// stored with it because the surrounding YAML scalar is plain.
func trimQuotes(s string) (string, bool) {
	if len(s) < 2 {
		return s, false
	}
	if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1], true
	}
	return s, false
}

// rowFilter is one tag column's match_attributes: the tag the column renders
// under, and the patterns a row's value has to match for the row to be emitted.
type rowFilter struct {
	tagName  string
	patterns []*regexp.Regexp
}

// compileRowFilter compiles a tag column's match_attributes and reports whether
// anything is left to filter on. ktranslate compiles each entry as a regular
// expression and matches it unanchored, so a plain string selects every row
// whose value contains it.
//
// A pattern that does not compile is left out, and a column left with none
// filters nothing, so a profile typo cannot silence an entry outright. Both
// cases are named once per profile by reviewProfile.
func (c *MetricsCollector) compileRowFilter(tagName string, col *profiles.TagColumn) (rowFilter, bool) {
	f := rowFilter{tagName: tagName, patterns: make([]*regexp.Regexp, 0, len(col.MatchAttributes))}
	for _, pattern := range col.MatchAttributes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			c.logger.Debug("Ignoring row filter this collector cannot apply",
				"pattern", pattern, "column", col.Name, "error", err)
			continue
		}
		f.patterns = append(f.patterns, re)
	}
	return f, len(f.patterns) > 0
}

// rowPassesFilters reports whether one row satisfies every filter the entry's
// tag columns declare.
//
// A row the filter column returned no value for is left alone: the profile
// names the values to keep rather than saying a row without one is unwanted,
// and ktranslate likewise only tests the rows that carry the attribute. It also
// means a filter column the device does not implement leaves the entry
// collecting as it did before the filter was declared.
func rowPassesFilters(filters []rowFilter, tags map[string]string) bool {
	for _, f := range filters {
		value, ok := tags[f.tagName]
		if !ok {
			continue
		}
		matched := false
		for _, re := range f.patterns {
			if re.MatchString(value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// reportUnusableFilters reports a match_attributes declaration the collector
// cannot apply. Whether a pattern compiles, and whether the column carrying it
// selects rows at all, are properties of the profile rather than of the device,
// so they are reported here once rather than on every collection. The
// collection path logs the same cases at debug level.
//
// unusable, when set, is the reason every filter in tags is ignored: the
// top-level metric_tags describe the device, so a filter there has no rows.
func (c *MetricsCollector) reportUnusableFilters(tags []profiles.MetricTag, profileName, unusable string) {
	for i := range tags {
		mt := &tags[i]
		col := metricTagColumn(mt)
		if col == nil || len(col.MatchAttributes) == 0 {
			continue
		}
		reason := unusable
		if reason == "" && len(mt.IndexTransform) > 0 {
			// The column is read from another table and keyed by that table's
			// index, so its rows do not line up with the metric rows.
			reason = "column is joined from another table"
		}
		if reason != "" {
			c.logger.Warn("Ignoring row filter this collector cannot apply",
				"reason", reason, "column", col.Name, "profile", profileName)
			continue
		}
		for _, pattern := range col.MatchAttributes {
			if _, err := regexp.Compile(pattern); err != nil {
				c.logger.Warn("Ignoring row filter this collector cannot apply",
					"reason", "pattern is not a valid regular expression",
					"pattern", pattern, "column", col.Name, "profile", profileName)
			}
		}
	}
}

// reportUnusableTags reports a metric tag that names no OID in either the
// nested `column:` form or the direct one. It tags nothing, so it leaves an
// attribute missing from every row of the entry, and like the other
// declarations this collector cannot act on it is a property of the profile
// rather than of the device.
func (c *MetricsCollector) reportUnusableTags(tags []profiles.MetricTag, profileName string) {
	for i := range tags {
		mt := &tags[i]
		col := metricTagColumn(mt)
		if col != nil && col.OID != "" {
			continue
		}
		name := metricTagName(mt, col)
		if name == "" {
			name = mt.Name
		}
		c.logger.Warn("Ignoring metric tag this collector cannot apply",
			"reason", "names no OID", "tag", name, "profile", profileName)
	}
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
	states := make([]symState, 0, len(entry.Symbols))
	anyActive := false
	for i := range entry.Symbols {
		sym := &entry.Symbols[i]
		if unusableSymbolReason(sym) != "" {
			// Reported once per profile by reviewProfile. Left out of states, so
			// it neither drives a walk nor carries a previous value forward.
			continue
		}
		if c.pollDue(key, sym.OID, sym.PollTimeSec) {
			states = append(states, symState{sym: sym, throttled: false})
			anyActive = true
		} else {
			states = append(states, symState{sym: sym, throttled: true})
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
	// tagColumnPDUs keeps what each tag column walk returned, keyed by column
	// OID, so a condition naming one of those columns reuses the walk instead
	// of asking the device for the same column twice.
	tagColumnPDUs := make(map[string]map[string]snmp.PDU)
	// rowFilters are the match_attributes of the tag columns that declare them.
	// A row has to satisfy every one of them to be emitted.
	var rowFilters []rowFilter
	var joinedTags []joinedTag
	for i := range entry.MetricTags {
		// Each uncached column is a request of its own and one entry can
		// declare a couple of dozen. Returning here leaves the entry's rows
		// uncollected rather than emitting them with their tags half applied.
		if ctx.Err() != nil {
			return
		}
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
		tagName := metricTagName(mt, col)
		if len(mt.IndexTransform) > 0 {
			jt := joinedTag{name: tagName, transform: mt.IndexTransform, byIndex: make(map[string]string, len(pdus))}
			for fullOID, pdu := range pdus {
				jt.byIndex[extractRowIndex(fullOID, col.OID)] = pduToString(pdu, col)
			}
			joinedTags = append(joinedTags, jt)
			continue
		}
		tagColumnPDUs[col.OID] = pdus
		if len(col.MatchAttributes) > 0 {
			if f, ok := c.compileRowFilter(tagName, col); ok {
				rowFilters = append(rowFilters, f)
			}
		}
		for fullOID, pdu := range pdus {
			rowIdx := extractRowIndex(fullOID, col.OID)
			if rowTags[rowIdx] == nil {
				rowTags[rowIdx] = make(map[string]string)
			}
			rowTags[rowIdx][tagName] = pduToString(pdu, col)
		}
	}

	// --- Phase 4: resolve and walk condition columns (active symbols only) ---
	conditionRows := make(map[string]map[string]conditionRow)
	conditions := make(map[string]conditionCheck)
	for _, st := range states {
		// A condition names a column of its own to walk. Returning here leaves
		// the rows uncollected rather than emitting them unfiltered.
		if ctx.Err() != nil {
			return
		}
		if st.throttled || st.sym.Condition == "" {
			continue
		}
		check, reason := resolveCondition(entry, st.sym.Condition)
		if reason != "" {
			c.logger.Debug("Ignoring condition this collector cannot apply",
				"symbol", st.sym.Name, "condition", st.sym.Condition, "reason", reason)
			continue
		}
		conditions[st.sym.OID] = check
		if _, walked := conditionRows[check.columnOID]; walked {
			continue
		}
		var pdus map[string]snmp.PDU
		switch {
		case columnPDUs != nil:
			pdus = columnPDUs[check.columnOID]
		case tagColumnPDUs[check.columnOID] != nil:
			pdus = tagColumnPDUs[check.columnOID]
		default:
			var err error
			pdus, err = c.walk(walker, check.columnOID, 1)
			if err != nil {
				c.logger.Debug("Error walking condition column", "oid", check.columnOID, "error", err)
				conditionRows[check.columnOID] = nil
				continue
			}
		}
		rows := make(map[string]conditionRow, len(pdus))
		for fullOID, pdu := range pdus {
			row := conditionRow{str: pduToString(pdu, check.column)}
			if v, _, err := pduToValue(pdu, ""); err == nil {
				row.num, row.hasNum = v, true
			}
			rows[extractRowIndex(fullOID, check.columnOID)] = row
		}
		conditionRows[check.columnOID] = rows
	}

	// --- Phase 5: collect active metric columns ---
	for _, st := range states {
		// The check inside the row loop below does not cover a column the
		// device answers with nothing, so the deadline is checked per column.
		if ctx.Err() != nil {
			return
		}
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
		c.markPolled(key, sym.OID, sym.PollTimeSec)

		cond, hasCondition := conditions[sym.OID]
		metricName := buildMetricName(sym.Name)

		for fullOID, pdu := range pdus {
			if err := ctx.Err(); err != nil {
				return
			}
			rowIdx, indexed := rowIndex(fullOID, sym.OID)

			if !rowPassesFilters(rowFilters, rowTags[rowIdx]) {
				continue
			}

			if hasCondition {
				rows := conditionRows[cond.columnOID]
				if rows == nil {
					continue
				}
				row, present := rows[rowIdx]
				if !present || !cond.matches(row) {
					continue
				}
			}

			val, strVal, err := pduToValue(pdu, sym.Conversion)
			if err != nil {
				continue
			}

			rowAttrs := make([]attribute.KeyValue, len(baseAttrs))
			copy(rowAttrs, baseAttrs)
			if indexed {
				rowAttrs = append(rowAttrs, attribute.String("row_index", rowIdx))
			}
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
	idx, _ := rowIndex(fullOID, columnOID)
	return idx
}

// rowIndex strips the column OID prefix from a full OID and reports whether
// there was one to strip. A symbol may name a fully qualified instance rather
// than a column, and its single PDU then identifies no row.
func rowIndex(fullOID, columnOID string) (string, bool) {
	fullOID = normalizeOID(fullOID)
	prefix := normalizeOID(columnOID) + "."
	if strings.HasPrefix(fullOID, prefix) {
		return fullOID[len(prefix):], true
	}
	return fullOID, false
}

// buildMetricName converts a profile symbol name to an OTLP metric name.
func buildMetricName(symbolName string) string {
	return "snmp." + strings.ToLower(symbolName)
}

// metricTagColumn returns the tag column from a MetricTag, handling the
// alias where some profiles use "symbol" instead of "column", and the direct
// form where the OID and name sit on the tag beside an empty `column:`.
//
// Every reader of a tag column comes through here, so a shape supported here
// reaches the row tags, the device tags, the full-table walk, the row filters
// and the conditions at once.
//
// A profile may declare `conversion:` beside the tag rather than inside the
// column. It renders the same column, so it is folded in here and reaches
// every caller. The column's own conversion is the more specific of the two,
// so it wins when both are present. The copy keeps the profile itself
// untouched, since one is shared by every device that matches it.
func metricTagColumn(mt *profiles.MetricTag) *profiles.TagColumn {
	col := mt.Column
	if col == nil {
		col = mt.Symbol
	}
	if col == nil || col.OID == "" {
		// The nested column is the more specific declaration and wins whenever
		// it names an OID. One that names none walks nothing, so the direct
		// declaration beside it stands in whole.
		if direct := directTagColumn(mt); direct != nil {
			col = direct
		}
	}
	if col == nil || mt.Conversion == "" || col.Conversion != "" {
		return col
	}
	converted := *col
	converted.Conversion = mt.Conversion
	return &converted
}

// directTagColumn builds the column a tag describes when it writes the OID and
// name on itself rather than inside `column:`, and returns nil when it does
// not. An OID of nothing but spaces is no OID: gosnmp reads an empty root as
// the whole .1.3.6.1 subtree.
func directTagColumn(mt *profiles.MetricTag) *profiles.TagColumn {
	if strings.TrimSpace(mt.OID) == "" {
		return nil
	}
	return &profiles.TagColumn{OID: mt.OID, Name: mt.Name}
}

// metricTagName is the attribute key a tag renders under: its own `tag:` when
// it has one, and otherwise the name of the column it resolved to.
func metricTagName(mt *profiles.MetricTag, col *profiles.TagColumn) string {
	if mt.Tag != "" {
		return mt.Tag
	}
	if col == nil {
		return ""
	}
	return col.Name
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
