package collector

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
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

// rowIndexAttr carries the table index a point was read at. It is the device
// identity's row-level counterpart: without it every row of a table shares one
// attribute set.
const rowIndexAttr = "row_index"

// enumStatusSuffix and displayValueSuffix name the two attributes a point
// derives from its own reading, under the export name of the symbol that
// produced it: the enum label for the value, and the text a conversion rendered
// it as.
const (
	enumStatusSuffix   = "_status"
	displayValueSuffix = "_value"
)

// appendDerivedAttr appends an attribute a point derives from its own reading,
// unless the point already carries that name.
//
// A duplicate key resolves last-value-wins, so appending over an attribute
// already there would erase it. The one already there is what survives, for two
// reasons that point the same way. It is either a profile tag, which is a
// declaration carrying a reading of another column that appears nowhere else on
// the point, or an identity attribute; the derived attribute is generated, and
// renders a value the point already exports under its metric. And the
// attributes already present are the ones the row key was taken from, while the
// derived pair is deliberately outside it, so dropping a tag here would move
// series identity and dropping the derived attribute moves nothing.
//
// reviewProfile names the collision once per profile, so the loss is reported
// rather than silent.
func appendDerivedAttr(attrs []attribute.KeyValue, name, value string) []attribute.KeyValue {
	for i := range attrs {
		if string(attrs[i].Key) == name {
			return attrs
		}
	}
	return append(attrs, attribute.String(name, value))
}

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
	// decl names the declaration that produced the point. One metric name can
	// be declared twice on different periods or columns, and the declarations
	// are throttled independently, so retention has to carry one forward
	// without disturbing the other.
	decl string
	// rowKey identifies the row the point describes: its attribute set without
	// the status and display value the reading itself produced. It is what
	// decides that two declarations of one metric name are talking about the
	// same thing, and it is carried on the point because those two attributes
	// cannot be told from the rest once they have been appended.
	rowKey string
	// prec is the standing of the declaration that produced the point. Two
	// declarations answering for one row are settled with it.
	prec profiles.Precedence
}

// pointSink accumulates one run's fresh points, at most one per metric name and
// row.
//
// A profile can declare one metric name more than once. Upstream calls those
// declarations duplicates and drops all but one, unless a declaration marks
// itself `allow_duplicate: true`, which is how a profile offers alternative
// OIDs for one reading so a device answering either of them reports it. Which
// of them a device answers is a property of the device, and a device answering
// two is answering the same question twice: appending both points would give a
// single exported series two values in one collection cycle.
//
// So a row keeps one observation. The declaration Precedence ranks first keeps
// it, and where precedence does not separate two declarations the first
// collected keeps it, which is declaration order. A device answering both
// therefore exports the same source's reading on every poll and across
// restarts. Upstream resolves the same collision by writing each reading into a
// map keyed on the metric name within a row, so it also ships one value, but
// which one follows the map order it walked its OIDs in.
type pointSink struct {
	logger *slog.Logger
	// points holds the run's observations by metric name, in collection order.
	points map[string][]observedPoint
	// held locates the point a metric name currently holds for a row, as
	// metric name to row key to position in points[name].
	held map[string]map[string]int
}

func newPointSink(logger *slog.Logger) *pointSink {
	return &pointSink{
		logger: logger,
		points: make(map[string][]observedPoint),
		held:   make(map[string]map[string]int),
	}
}

// add records one observation, unless another declaration of the same metric
// name already holds the row with a better claim to it.
func (s *pointSink) add(metricName string, pt observedPoint) {
	rows := s.held[metricName]
	if rows == nil {
		rows = make(map[string]int)
		s.held[metricName] = rows
	}
	at, taken := rows[pt.rowKey]
	if !taken {
		rows[pt.rowKey] = len(s.points[metricName])
		s.points[metricName] = append(s.points[metricName], pt)
		return
	}
	// The row is taken. Whichever of the two declarations ranks first holds it,
	// and the pair is swapped so the log below names them by what happened to
	// them rather than by which arrived first.
	held := s.points[metricName][at]
	if pt.prec.Beats(held.prec) {
		s.points[metricName][at] = pt
		held, pt = pt, held
	}
	s.logger.Debug("More than one answer for one row of an SNMP metric, keeping one point",
		"metric_name", config.SanitizeLogValue(metricName),
		"kept_declaration", config.SanitizeLogValue(held.decl),
		"kept_value", held.value,
		"dropped_declaration", config.SanitizeLogValue(pt.decl),
		"dropped_value", pt.value)
}

// symbolDeclKey identifies the declaration a point came from, and the poll
// window that declaration consults. Retention reads it to carry a throttled
// declaration's points forward and pollState keys its timestamps on it, so the
// declaration that was recorded as throttled is the one whose points are kept.
//
// A declaration is its exported metric name, its OID and its poll period. Two
// declarations agreeing on all three are one series polled on one window, so
// one key serves them. Two differing in any of them are polled apart and need
// keys of their own: the metric name is part of it because a `tag:` renames the
// metric, so one OID can be declared twice and export under two names, and a
// window keyed on the OID alone would let the first declaration to walk it
// throttle the second before that second name had produced a point.
//
// A `condition:` is not part of it. It selects rows out of a walk that serves
// every declaration of the column, so two symbols differing only in one are
// still one window, and each keeps its own predicate on the symbol it was
// declared on rather than on this key.
func symbolDeclKey(sym *profiles.Symbol) string {
	return sym.MetricName() + "|" + sym.OID + "@" + strconv.Itoa(sym.PollTimeSec)
}

// throttledDecls collects the declarations that were not due this run, as
// metric name to declaration key. The metric name alone would not do: one name
// can be declared twice, and retaining every point under it would carry a due
// declaration's rows forward as well.
type throttledDecls map[string]map[string]struct{}

func (t throttledDecls) add(metricName, decl string) {
	if t[metricName] == nil {
		t[metricName] = make(map[string]struct{}, 1)
	}
	t[metricName][decl] = struct{}{}
}

// attrSetKey renders an attribute set the way the SDK identifies a series:
// sorted by key, duplicate keys resolved last-value-wins, separators escaped.
// Two points that encode alike are one exported series whichever declaration
// produced them.
//
// The collection paths call it on a point's row attributes to fill
// observedPoint.rowKey, before the status and display value of the reading are
// appended. Two readings of one row differ in those two attributes and in
// nothing else, so a key taken after them would call them two series.
//
// The attributes are copied because building the set sorts what it is given,
// and a point keeps the attribute order it was collected in.
func attrSetKey(attrs []attribute.KeyValue) string {
	sorted := make([]attribute.KeyValue, len(attrs))
	copy(sorted, attrs)
	set := attribute.NewSet(sorted...)
	return set.Encoded(attribute.DefaultEncoder())
}

// retainThrottled appends the points a throttled declaration left last run to
// the points this run polled, and returns the metric's new slice.
//
// Only the declarations named in throttled are carried. A declaration that was
// due is represented by its fresh points alone, so a row it has stopped
// answering for does not live on under a sibling's retention. Declarations are
// told apart by symbolDeclKey, which is the same key their poll windows are
// held under, so what was recorded as throttled is what is carried.
//
// A retained point whose row a point already in the slice describes is dropped
// as well, whether that point is a fresh one or another retained one. A row
// carries one observation of a metric, so keeping both would observe the metric
// twice for one row in a single collection cycle, and would do it with the
// stale half of the pair. A declaration that has been overtaken this way takes
// the row back on the run that polls it again.
func retainThrottled(fresh, prev []observedPoint, throttled map[string]struct{}) []observedPoint {
	if len(prev) == 0 {
		return fresh
	}
	taken := make(map[string]struct{}, len(fresh)+len(prev))
	for i := range fresh {
		taken[fresh[i].rowKey] = struct{}{}
	}
	for _, pt := range prev {
		if _, ok := throttled[pt.decl]; !ok {
			continue
		}
		if _, held := taken[pt.rowKey]; held {
			continue
		}
		taken[pt.rowKey] = struct{}{}
		fresh = append(fresh, pt)
	}
	return fresh
}

// MetricsCollector collects SNMP operational metrics from devices using ktranslate profiles
// and exports them via the configured OTLP endpoint.
type MetricsCollector struct {
	clientFactory snmp.ClientFactory
	matcher       *profiles.Matcher
	logger        *slog.Logger

	pollMu    sync.Mutex
	pollState map[deviceKey]map[string]time.Time // device -> symbolDeclKey -> lastPoll

	// Profile each device last matched, so a device replaced at an address
	// does not inherit the previous one's poll windows and retained points.
	profileMu     sync.Mutex
	deviceProfile map[deviceKey]string // device -> profileID

	// Observable gauge store: device -> metricName -> observations.
	// Updated after each CollectTarget run; read by OTLP callbacks on every export cycle.
	storeMu     sync.RWMutex
	deviceStore map[deviceKey]map[string][]observedPoint

	// Registered observable gauge instruments (one per unique metric name).
	// closed is set by Close and is final: a collector no policy is using must
	// not install a callback that nothing is left to unregister.
	gaugeMu       sync.Mutex
	closed        bool
	instruments   map[string]metric.Int64ObservableGauge
	registrations []metric.Registration // held so Close can give them back

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
		deviceProfile:    make(map[deviceKey]string),
		deviceStore:      make(map[deviceKey]map[string][]observedPoint),
		instruments:      make(map[string]metric.Int64ObservableGauge),
		reviewedProfiles: make(map[string]struct{}),
	}
}

// pollDue reports whether the symbol's declaration is due to be polled for the
// given device. poll_time_sec == 0 means always poll.
//
// The window is per declaration rather than per OID, so a second declaration of
// one OID exporting under a second name is not throttled by the first. Two
// declarations that differ only in poll period are separate windows too: each
// waits out the period it asks for, and a walk taken for the due one does not
// satisfy the other.
//
// It reads the last-poll timestamp and does not write one: markPolled does that
// once the request has come back. Recording it here instead would start the
// poll window on a request that failed, and since a failed request leaves no
// observation to carry forward, an hourly symbol would then be missing for an
// hour after one timeout.
func (c *MetricsCollector) pollDue(key deviceKey, sym *profiles.Symbol) bool {
	if sym.PollTimeSec <= 0 {
		return true
	}
	if pollPeriodPastBound(sym) {
		// unusableSymbolReason refuses the symbol before the collection path
		// reaches here, and this answers not due rather than due so the two
		// cannot disagree about a period the collector will not honour. Reading
		// it as due is what the multiply below would produce on its own, since
		// an outsized period wraps to a tight duration every check accepts.
		return false
	}
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	last, ok := c.pollState[key][symbolDeclKey(sym)]
	return !ok || !time.Now().Before(last.Add(time.Duration(sym.PollTimeSec)*time.Second))
}

// markPolled starts the poll window for the symbol's declaration on the given
// device. It starts no other declaration's window, including another one of the
// same OID.
//
// It is called once the walk has returned without error, whatever the device
// answered with: a device that does not implement an OID has still been asked,
// and re-asking it every cycle is what the poll window is there to prevent.
// A device forgotten after a failed run loses these timestamps with the rest of
// its state, so the two rules agree that nothing throttles what was not
// collected.
func (c *MetricsCollector) markPolled(key deviceKey, sym *profiles.Symbol) {
	if sym.PollTimeSec <= 0 || pollPeriodPastBound(sym) {
		// A refused period leaves no window to start, so writing a timestamp
		// here would throttle a declaration pollDue never reports due anyway.
		return
	}
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	if c.pollState[key] == nil {
		c.pollState[key] = make(map[string]time.Time)
	}
	c.pollState[key][symbolDeclKey(sym)] = time.Now()
}

// ensureInstrument lazily registers an observable gauge callback for metricName.
// The callback reads from the shared deviceStore on every OTLP export cycle.
func (c *MetricsCollector) ensureInstrument(name, description string) {
	c.gaugeMu.Lock()
	defer c.gaugeMu.Unlock()
	if c.closed {
		return
	}
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

// Close releases everything the collector holds, once no policy is using it.
// Dropping the last reference to a collector does not free it on its own:
// every callback ensureInstrument registered closes over the collector, so
// while the meter still holds the registration it keeps the collector, its
// matcher and its whole resolved profile set live, and runs the callback on
// every export cycle. Routine policy replacement would grow both.
//
// Unregister is idempotent and concurrent safe, and the SDK takes the same
// pipeline lock a collection cycle holds while it runs callbacks, so a
// callback already running finishes and none starts afterwards. That makes
// Unregister as slow as a collection, and the callback it is waiting for takes
// storeMu, so it is called with none of the collector's locks held: unregister
// under storeMu and the two wait on each other.
func (c *MetricsCollector) Close() {
	c.gaugeMu.Lock()
	regs := c.registrations
	c.registrations = nil
	c.instruments = make(map[string]metric.Int64ObservableGauge)
	c.closed = true
	c.gaugeMu.Unlock()

	for _, reg := range regs {
		if err := reg.Unregister(); err != nil {
			c.logger.Error("Failed to unregister observable gauge callback", "error", err)
		}
	}

	c.storeMu.Lock()
	c.deviceStore = make(map[deviceKey]map[string][]observedPoint)
	c.storeMu.Unlock()

	c.pollMu.Lock()
	c.pollState = make(map[deviceKey]map[string]time.Time)
	c.pollMu.Unlock()

	c.profileMu.Lock()
	c.deviceProfile = make(map[deviceKey]string)
	c.profileMu.Unlock()

	c.reviewMu.Lock()
	c.reviewedProfiles = make(map[string]struct{})
	c.reviewMu.Unlock()
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

	c.profileMu.Lock()
	for key := range c.deviceProfile {
		if key.policy == policyName {
			delete(c.deviceProfile, key)
		}
	}
	c.profileMu.Unlock()
}

// profileID names a matched profile. The relative path tells apart two profiles
// that share a base name in different directories; a profile loaded without one
// falls back to that base name.
func profileID(profile *profiles.Profile) string {
	if profile.RelPath != "" {
		return profile.RelPath
	}
	return profile.FileName
}

// noteProfile records the profile a device matched and drops the device's
// cached state when the match has changed. A device replaced at an address can
// match a different profile, and every declaration the two profiles share has
// one symbolDeclKey, so the new profile would be throttled against the old
// device's poll window and would export the old device's retained point until
// that window expired. Inherited IF-MIB metrics are the common case, and a long
// poll_time_sec is the long one.
//
// The state of the profile no longer matched is dropped rather than kept beside
// the new one. Keeping it would spare a device flapping between two profiles a
// re-poll, at the price of state with no reader and no bound; dropping it costs
// one collection cycle and cannot leak.
func (c *MetricsCollector) noteProfile(key deviceKey, id string) {
	c.profileMu.Lock()
	defer c.profileMu.Unlock()
	if prev, known := c.deviceProfile[key]; known && prev != id {
		c.forgetDevice(key)
	}
	c.deviceProfile[key] = id
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

// reservedAttrNames are the attribute keys the collector's own identity owns.
// A profile tag carrying one of them would replace the value rather than sit
// beside it, since a duplicate key resolves last-value-wins, and two policies
// polling one endpoint would then export series nothing tells apart.
//
// The device dimensions are read back from appendIdentityAttrs rather than
// restated, so a dimension added to the identity reserves its name by the same
// edit. The row index is added here because it is appended per point rather
// than per device.
//
// The suffixes a reading derives are deliberately absent: no identity name ends
// in _status or _value, so neither can shadow one, and which of them exist
// depends on the symbols of the entry rather than on the collector. The mirror
// case, a derived attribute landing on a tag's name, is handled where the
// derived attribute is appended rather than by reserving names here.
var reservedAttrNames = reservedAttrNameSet()

func reservedAttrNameSet() map[string]struct{} {
	// Every dimension is filled: appendIdentityAttrs leaves an empty one off,
	// and a set built from a partly filled key would miss exactly the names a
	// profile could then overwrite. A dimension added to deviceKey without a
	// value here fails TestReservedAttrNames_AreTheExportedIdentity.
	probe := deviceKey{policy: "p", host: "h", port: 1, id: "i", context: "c"}
	names := map[string]struct{}{rowIndexAttr: {}}
	for _, attr := range appendIdentityAttrs(nil, probe) {
		names[string(attr.Key)] = struct{}{}
	}
	return names
}

// reservedTagName reports whether a profile tag of this name would overwrite an
// identity attribute. The collection path drops exactly these tags and the
// once-per-profile review names exactly these, so the two cannot disagree.
func reservedTagName(name string) bool {
	_, reserved := reservedAttrNames[name]
	return reserved
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
	// Before anything reads a poll window: a device that now matches a
	// different profile starts from nothing.
	c.noteProfile(key, profileID(profile))
	c.reviewProfile(profile)

	// Everything from here walks the profile's tables, which is where the round
	// trips are. The two walks above chose the profile, so this is the first
	// point at which the device's tolerance for GETBULK is known.
	walker.SetBulkWalk(!profile.NoUseBulkWalkAll)

	// One walk per OID for the whole run, so declarations sharing a poll
	// window share the walk that starts it. It is created before the device
	// tags because they are read first and name OIDs the profile also declares
	// as metrics, so the two have to be served by one response.
	walks := make(walkCache)

	baseAttrs := c.appendDeviceTags(ctx, walker, walks, profile, appendIdentityAttrs(nil, key), sysDescr, sysOIDValue)

	// fresh accumulates this run's observations, one per metric name and row.
	// throttled records the declarations skipped because poll_time_sec has not
	// elapsed, per metric name.
	fresh := newPointSink(c.logger)
	throttled := make(throttledDecls)

	for _, entry := range profile.Metrics {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch {
		case entry.Symbol != nil:
			c.collectScalar(ctx, walker, walks, entry.Symbol, profiles.SymbolPrecedence(&entry, entry.Symbol), baseAttrs, key, fresh, throttled)
		case entry.Table != nil:
			c.collectTable(ctx, walker, walks, &entry, baseAttrs, key, fresh, throttled)
		case len(entry.Symbols) > 0 && groupedSymbolsAreTableColumns(&entry):
			// Columns of a table the profile names no `table:` root for. The
			// rows still have to be joined by index, or the entry's row-scoped
			// metadata is lost and the rows carry no identity.
			c.collectTable(ctx, walker, walks, &entry, baseAttrs, key, fresh, throttled)
		case len(entry.Symbols) > 0:
			// Scalars grouped under `symbols:` with no `table:`. One entry can
			// carry dozens, each a request of its own, so the deadline is
			// checked between them and not only between entries.
			for i := range entry.Symbols {
				if err := ctx.Err(); err != nil {
					return err
				}
				sym := &entry.Symbols[i]
				c.collectScalar(ctx, walker, walks, sym, profiles.SymbolPrecedence(&entry, sym), baseAttrs, key, fresh, throttled)
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
	// - a declaration that polled is represented by this run's points alone, so
	//   a table row that has gone stops being exported, and a device that no
	//   longer answers an OID at all leaves the metric empty
	// - a declaration that was not due keeps the points it left last run
	// The two are decided per declaration rather than per metric name, since a
	// resolved profile can declare one name twice with different poll periods
	// and replacing the name would drop the series the other one owns.
	c.storeMu.Lock()
	prevStore := c.deviceStore[key]
	newStore := make(map[string][]observedPoint, len(fresh.points)+len(throttled))
	for name, pts := range fresh.points {
		newStore[name] = pts
	}
	for name, decls := range throttled {
		if retained := retainThrottled(newStore[name], prevStore[name], decls); len(retained) > 0 {
			newStore[name] = retained
		}
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
// not lost there: collectScalar reads the row identity off the OID the device
// answered at, which is the part of the table treatment such an entry needs.
// What only this function can decide is the row-scoped metadata, which is why
// it tests for that and not for the shape of the OIDs the profile declares.
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
// series the profile produces. Each column not already read is a request of its
// own, so the walk stops once the deadline has expired and the caller returns
// on the same check straight after.
func (c *MetricsCollector) appendDeviceTags(ctx context.Context, walker snmp.Walker, walks walkCache, profile *profiles.Profile, attrs []attribute.KeyValue, sysDescr, sysObjectID string) []attribute.KeyValue {
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
		if reservedTagName(name) {
			// Reported once per profile by reviewProfile. Appending it would
			// replace the identity attribute of that name on every series the
			// profile produces, and the walk it would take is skipped with it.
			continue
		}
		if value, ok := cachedSystemValue(col.OID, sysDescr, sysObjectID); ok {
			if value != "" {
				attrs = append(attrs, attribute.String(name, value))
			}
			continue
		}
		pdus, err := c.cachedWalk(walks, walker, col.OID)
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
	if conversionError(sym.Conversion) != nil {
		return unusableConversionReason
	}
	if pollPeriodPastBound(sym) {
		return fmt.Sprintf("declares a poll_time_sec of %d seconds, past the bound of %d",
			sym.PollTimeSec, config.MaxDurationSeconds)
	}
	return ""
}

// pollPeriodPastBound reports whether a symbol states a poll period this
// backend cannot turn into a duration. The bound is config.MaxDurationSeconds,
// which every value stated in seconds shares, rather than a ceiling of the
// collector's own.
//
// Past it the multiply by time.Second wraps: the reporter's 40423014371506394
// seconds becomes roughly a microsecond, so the declaration is polled on every
// cycle instead of the long interval it asked for, which is the inverse of the
// request and sustained traffic at the device. The symbol is refused rather
// than clamped, since a clamp would invent an interval the profile never
// stated.
func pollPeriodPastBound(sym *profiles.Symbol) bool {
	return sym.PollTimeSec > config.MaxDurationSeconds
}

// unusableConversionReason is why a symbol declaring a conversion pduToValue
// cannot apply is unusable. It is named so the review can recognise it and
// report the conversion and the reason rather than this text.
const unusableConversionReason = "declares a conversion this collector cannot apply"

// conversionError says why pduToValue cannot apply the conversion a symbol
// declares, or nil when it can. An empty conversion is the plain numeric path.
//
// It mirrors the branches in pduToValue: a new conversion has to be added in
// both places, or it will be reported as unusable while working.
//
// The set is the union across PDU types, which is what a symbol can be judged
// on before the walk that reveals the type. Per type: to_one is implemented for
// every PDU, since it reads the value's presence rather than the value; an
// empty conversion is the plain numeric path; hextoip, hwaddr, hextoint and
// regexp decode an OctetString. An enum is not a conversion and is applied to
// the value afterwards, so it does not appear here.
//
// The two prefixed forms carry an argument, and it is parsed here through the
// same calls that apply them rather than checked against a second description
// of the syntax. A pattern that does not compile, or an endianness or width
// nothing recognises, can be applied to no PDU at all, so a prefix on its own
// is not enough to call the conversion supported.
func conversionError(conversion string) error {
	switch conversion {
	case "", "to_one", "hextoip", "hwaddr":
		return nil
	}
	if strings.HasPrefix(conversion, "hextoint:") {
		_, _, err := parseHexToInt(conversion)
		return err
	}
	if strings.HasPrefix(conversion, "regexp:") {
		_, err := parseRegexpConversion(conversion)
		return err
	}
	return fmt.Errorf("conversion %q is not implemented", conversion)
}

// reviewProfile warns about every declaration in a matched profile that the
// collector cannot act on: a symbol it skips outright, a conversion pduToValue
// does not implement, a condition it cannot resolve, a tag whose name the
// identity attributes own, and a tag whose name one of the profile's own
// symbols derives. Each of those leaves a metric missing, unfiltered or short
// of an attribute, and without this nothing says why.
//
// A profile is reviewed the first time a device matches it and never again, so
// the warnings appear once for the life of the process however many devices
// carry the profile and however often they are polled.
func (c *MetricsCollector) reviewProfile(profile *profiles.Profile) {
	name := profileID(profile)
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
		c.reportUnsetEnumMembers(sym.Enum, "symbol", sym.Name, name)
		switch reason := unusableSymbolReason(sym); reason {
		case "":
		case unusableConversionReason:
			c.logger.Warn("Skipping metric: SNMP profile declares a conversion this collector cannot apply",
				"conversion", sym.Conversion, "reason", conversionError(sym.Conversion),
				"symbol", sym.Name, "oid", sym.OID, "profile", name)
		default:
			c.logger.Warn("Skipping metric: SNMP profile declares a symbol this collector cannot collect",
				"reason", reason, "symbol", sym.Name, "oid", sym.OID, "profile", name)
		}
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
		c.reportReservedTags(entry.MetricTags, name)
		c.reportUnhandledTagIndex(entry.MetricTags, name)
		c.reportUnsetTagEnums(entry.MetricTags, name)
	}
	c.reportUnusableFilters(profile.MetricTags, name, "column tags the device rather than a row")
	c.reportUnusableTags(profile.MetricTags, name)
	c.reportReservedTags(profile.MetricTags, name)
	c.reportUnhandledTagIndex(profile.MetricTags, name)
	c.reportUnsetTagEnums(profile.MetricTags, name)
	c.reportShadowedTags(profile, name)
}

// entryAppliesRowTags reports whether an entry's own metric_tags reach the
// points it exports. Only collectTable applies them, and an entry that declares
// tags routes itself there: groupedSymbolsAreTableColumns answers yes to any
// entry with tags, so a `symbols:` group carrying them is collected as a table
// whether or not it names a `table:` root. A `symbol:` scalar entry has no row
// to hang them on, and collectScalar never reads them.
func entryAppliesRowTags(entry *profiles.MetricEntry) bool {
	return entry.Symbol == nil && len(entry.MetricTags) > 0
}

// tagNameSet is the set of attribute names a group of metric_tags declares.
// A tag under a reserved name is left out: the collection path drops it before
// anything can shadow it, so it is not a declaration a derived attribute takes
// away.
func tagNameSet(tags []profiles.MetricTag) map[string]struct{} {
	names := make(map[string]struct{}, len(tags))
	for i := range tags {
		mt := &tags[i]
		if name := metricTagName(mt, metricTagColumn(mt)); name != "" && !reservedTagName(name) {
			names[name] = struct{}{}
		}
	}
	return names
}

// reportShadowedTags reports a metric tag whose name a symbol of the same
// profile derives for itself. A symbol exported as `CPU` with an enum derives
// `CPU_status`, and one whose conversion renders text derives `CPU_value`, so a
// profile declaring a tag under either name has two attributes claiming one
// key on every point that symbol produces.
//
// The derived attribute is dropped and the tag kept, so this names what the
// export no longer carries. It is reported here rather than per reading because
// the names are a property of the profile even though filling them is not:
// reviewing the entry gives the pair each of its symbols can derive, which a
// static reserved list could not, since the pair depends on the symbol.
//
// Device tags reach every entry, so they are checked against every symbol.
// Row tags reach only the entry that declares them.
func (c *MetricsCollector) reportShadowedTags(profile *profiles.Profile, profileName string) {
	deviceTags := tagNameSet(profile.MetricTags)
	for i := range profile.Metrics {
		entry := &profile.Metrics[i]
		var rowTags map[string]struct{}
		if entryAppliesRowTags(entry) {
			rowTags = tagNameSet(entry.MetricTags)
		}
		if len(deviceTags) == 0 && len(rowTags) == 0 {
			continue
		}
		report := func(sym *profiles.Symbol) {
			for _, derived := range derivedAttrNames(sym) {
				scope := ""
				switch {
				case setHas(rowTags, derived):
					scope = "row"
				case setHas(deviceTags, derived):
					scope = "device"
				default:
					continue
				}
				c.logger.Warn("Ignoring derived attribute that would overwrite a metric tag",
					"reason", "the profile declares a tag under the name this symbol derives",
					"attribute", derived, "symbol", sym.ExportName(),
					"tag_scope", scope, "profile", profileName)
			}
		}
		if entry.Symbol != nil {
			report(entry.Symbol)
		}
		for j := range entry.Symbols {
			report(&entry.Symbols[j])
		}
	}
}

// setHas reports membership in a name set, including a nil one.
func setHas(set map[string]struct{}, name string) bool {
	_, ok := set[name]
	return ok
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

// collectScalar collects a single scalar OID metric into the run's points.
// Records the metric name in throttledMetrics when poll_time_sec has not elapsed.
//
// A returned instance that is not the symbol's scalar instance is a table row,
// whatever the profile calls it, so its point is given a row identity. The
// profile cannot always say which entries are columns; the OID the device
// answers at can. Without the identity every row carries the same attribute
// set and the export keeps one arbitrary value.
func (c *MetricsCollector) collectScalar(ctx context.Context, walker snmp.Walker, walks walkCache, sym *profiles.Symbol, prec profiles.Precedence, baseAttrs []attribute.KeyValue, key deviceKey, fresh *pointSink, throttled throttledDecls) {
	if unusableSymbolReason(sym) != "" {
		// Reported once per profile by reviewProfile. Skipping before the walk
		// is what keeps an empty OID from being issued as a whole-tree walk, and
		// what keeps a conversion the collector cannot apply from exporting the
		// undecoded value the numeric branches would otherwise return.
		return
	}
	name := sym.ExportName()
	metricName := sym.MetricName()
	decl := symbolDeclKey(sym)
	if !c.pollDue(key, sym) {
		throttled.add(metricName, decl)
		return
	}
	pdus, err := c.cachedWalk(walks, walker, sym.OID)
	if err != nil {
		c.logger.Debug("Error walking scalar OID", "oid", sym.OID, "name", sym.Name, "error", err)
		return
	}
	c.markPolled(key, sym)
	for fullOID, pdu := range pdus {
		// A scalar walk answers with as many rows as a table does, and the
		// caller discards the run once the deadline has expired, so converting
		// the rest of the response only delays the runner's shutdown.
		if err := ctx.Err(); err != nil {
			return
		}
		val, strVal, err := pduToValue(pdu, sym.Conversion)
		if err != nil {
			c.logger.Debug("Skipping PDU this collector cannot turn into a value",
				"oid", fullOID, "name", sym.Name, "error", err)
			continue
		}

		attrs := make([]attribute.KeyValue, len(baseAttrs))
		copy(attrs, baseAttrs)
		if rowIdx, indexed := scalarRowIndex(fullOID, sym.OID); indexed {
			attrs = append(attrs, attribute.String(rowIndexAttr, rowIdx))
		}
		rowKey := attrSetKey(attrs)
		if status := enumStatusName(sym, val); status != "" {
			attrs = appendDerivedAttr(attrs, name+enumStatusSuffix, status)
		}
		if strVal != "" {
			attrs = appendDerivedAttr(attrs, name+displayValueSuffix, strVal)
		}

		fresh.add(metricName, observedPoint{value: val, attrs: attrs, decl: decl, rowKey: rowKey, prec: prec})
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

// matches reports whether one row of the condition column satisfies the
// condition.
//
// The row is rendered here rather than when the column was walked. Two
// conditions can name one column through different renderings, a sibling
// symbol's raw reading and a tag column's enum being the shape, and they share
// the walk: rendering once for the column would have the second compare
// against the first one's rendering and never match.
//
// A textual value is compared exactly and case-sensitively. Both sides are
// already free of surrounding whitespace: pduToString trims what the device
// returns, and the profile's quotes delimit exactly the text it means. Case is
// kept significant because a MIB display string is, and folding it would let a
// condition select a row the profile did not name.
func (cc conditionCheck) matches(pdu snmp.PDU) bool {
	if cc.numeric {
		v, _, err := pduToValue(pdu, "")
		return err == nil && v == cc.expectInt
	}
	return pduToString(pdu, cc.column) == cc.expected
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
		if col.Name != refName && metricTagName(mt, col) != refName {
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

// reportReservedTags reports a metric tag named after one of the collector's
// identity attributes. The tag is dropped rather than the profile refused: a
// bundled profile is vendored and cannot be edited, so refusing to load one
// would take away every metric it carries over one attribute name. The operator
// is told instead, and an override can be renamed.
func (c *MetricsCollector) reportReservedTags(tags []profiles.MetricTag, profileName string) {
	for i := range tags {
		mt := &tags[i]
		name := metricTagName(mt, metricTagColumn(mt))
		if !reservedTagName(name) {
			continue
		}
		c.logger.Warn("Ignoring metric tag that would overwrite an identity attribute",
			"reason", "the name is reserved for the identity of the device or the row",
			"tag", name, "profile", profileName)
	}
}

// reportUnsetTagEnums reports the enum members a tag column named without a
// value.
func (c *MetricsCollector) reportUnsetTagEnums(tags []profiles.MetricTag, profileName string) {
	for i := range tags {
		col := metricTagColumn(&tags[i])
		if col == nil {
			continue
		}
		c.reportUnsetEnumMembers(col.Enum, "column", col.Name, profileName)
	}
}

// reportUnhandledTagIndex reports a metric tag carrying a bare `index`. The
// selector has no join behind it: upstream parses the field and acts on it
// nowhere, and the bundled use puts it on a column whose table shares the
// metric table's composite index, so every reading of it as a component
// selector keys the join by fewer components than that column's rows carry and
// loses the tag. The tag is collected as if the selector were absent, which is
// what makes it worth naming.
func (c *MetricsCollector) reportUnhandledTagIndex(tags []profiles.MetricTag, profileName string) {
	for i := range tags {
		mt := &tags[i]
		if mt.Index == 0 {
			continue
		}
		c.logger.Warn("Ignoring metric tag index this collector does not implement",
			"index", mt.Index, "tag", metricTagName(mt, metricTagColumn(mt)), "profile", profileName)
	}
}

// reportUnsetEnumMembers reports the enum members a profile named without a
// value. Such a member maps nothing, so the label it names is never emitted,
// and where the profile gives a real member the value 0 it is the label the
// device reporting 0 would otherwise have collided with. Like the other
// declarations this collector cannot act on it is a property of the profile,
// so it is named once rather than on every collection.
func (c *MetricsCollector) reportUnsetEnumMembers(enum profiles.Enum, ownerKey, ownerName, profileName string) {
	for _, member := range enum.Unset {
		c.logger.Warn("Ignoring enum member this collector cannot apply",
			"reason", "declares no value", "member", member,
			ownerKey, ownerName, "profile", profileName)
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
func (c *MetricsCollector) collectTable(ctx context.Context, walker snmp.Walker, walks walkCache, entry *profiles.MetricEntry, baseAttrs []attribute.KeyValue, key deviceKey, fresh *pointSink, throttled throttledDecls) {
	// --- Phase 1: decide which symbols need polling this run ---
	type symState struct {
		sym       *profiles.Symbol
		throttled bool
		// cond is the symbol's own resolved condition, set in phase 4 and read
		// back in phase 5. hasCond tells a resolved predicate from a symbol
		// that declares none or declares one this collector cannot apply.
		cond    conditionCheck
		hasCond bool
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
		if c.pollDue(key, sym) {
			states = append(states, symState{sym: sym, throttled: false})
			anyActive = true
		} else {
			states = append(states, symState{sym: sym, throttled: true})
			throttled.add(sym.MetricName(), symbolDeclKey(sym))
		}
	}
	if !anyActive {
		return // all symbols throttled; skip all SNMP walks
	}

	// --- Phase 2: obtain PDUs (walk_full_table or per-column walks) ---
	// columnPDUs maps columnOID -> (fullOID -> PDU), used for both metric and condition columns.
	var columnPDUs map[string]map[string]snmp.PDU
	if entry.WalkFullTable && entry.Table != nil {
		columnPDUs = c.walkFullTable(walker, walks, entry)
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
			pdus, err = c.cachedWalk(walks, walker, col.OID)
			if err != nil {
				c.logger.Debug("Error walking tag column", "oid", col.OID, "tag", mt.Tag, "error", err)
				continue
			}
		}
		tagName := metricTagName(mt, col)
		if len(mt.IndexTransform) > 0 {
			if reservedTagName(tagName) {
				// Reported once per profile by reviewProfile. A joined tag
				// carries nothing but the attribute, so the join goes with it.
				continue
			}
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
	// conditionPDUs keeps what each condition column walk returned, keyed by
	// column OID and then by row index. What is cached is the PDU, not its
	// rendering: two conditions can name one column and render it differently,
	// so each renders the row it reads. A key present with a nil map is a
	// column whose walk failed.
	conditionPDUs := make(map[string]map[string]snmp.PDU)
	// A predicate is kept on the state of the symbol that declared it, and
	// phase 5 reads it back off that same state, so it filters that
	// declaration's rows and no others. Held in a map instead, whatever the key,
	// it reached every declaration the key merged: on the OID, a `tag:` renames
	// the metric, so one column declared twice under two names had one
	// declaration's predicate filtering the other's rows; on the declaration,
	// two symbols agreeing on name, OID and period and differing only in their
	// `condition:` left the predicate resolved last deciding both. The PDUs are
	// still collected per condition column, so two declarations naming one
	// column walk it once.
	for i := range states {
		st := &states[i]
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
		st.cond, st.hasCond = check, true
		if _, walked := conditionPDUs[check.columnOID]; walked {
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
			pdus, err = c.cachedWalk(walks, walker, check.columnOID)
			if err != nil {
				c.logger.Debug("Error walking condition column", "oid", check.columnOID, "error", err)
				conditionPDUs[check.columnOID] = nil
				continue
			}
		}
		rows := make(map[string]snmp.PDU, len(pdus))
		for fullOID, pdu := range pdus {
			rows[extractRowIndex(fullOID, check.columnOID)] = pdu
		}
		conditionPDUs[check.columnOID] = rows
	}

	// --- Phase 5: collect active metric columns ---
	for i := range states {
		st := &states[i]
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
			pdus, err = c.cachedWalk(walks, walker, sym.OID)
			if err != nil {
				c.logger.Debug("Error walking table column", "oid", sym.OID, "name", sym.Name, "error", err)
				continue
			}
		}
		c.markPolled(key, sym)

		decl := symbolDeclKey(sym)
		cond, hasCondition := st.cond, st.hasCond
		name := sym.ExportName()
		metricName := sym.MetricName()
		prec := profiles.SymbolPrecedence(entry, sym)

		for fullOID, pdu := range pdus {
			if err := ctx.Err(); err != nil {
				return
			}
			rowIdx, indexed := rowIndex(fullOID, sym.OID)

			if !rowPassesFilters(rowFilters, rowTags[rowIdx]) {
				continue
			}

			if hasCondition {
				rows := conditionPDUs[cond.columnOID]
				if rows == nil {
					continue
				}
				condPDU, present := rows[rowIdx]
				if !present || !cond.matches(condPDU) {
					continue
				}
			}

			val, strVal, err := pduToValue(pdu, sym.Conversion)
			if err != nil {
				c.logger.Debug("Skipping PDU this collector cannot turn into a value",
					"oid", fullOID, "name", sym.Name, "error", err)
				continue
			}

			rowAttrs := make([]attribute.KeyValue, len(baseAttrs))
			copy(rowAttrs, baseAttrs)
			if indexed {
				rowAttrs = append(rowAttrs, attribute.String(rowIndexAttr, rowIdx))
			}
			if tags, ok := rowTags[rowIdx]; ok {
				for k, v := range tags {
					if reservedTagName(k) {
						// Reported once per profile by reviewProfile. Dropped
						// here rather than at the walk, since a match_attributes
						// filter on the same column still decides which rows
						// are emitted.
						continue
					}
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
			rowKey := attrSetKey(rowAttrs)
			if status := enumStatusName(sym, val); status != "" {
				rowAttrs = appendDerivedAttr(rowAttrs, name+enumStatusSuffix, status)
			}
			if strVal != "" {
				rowAttrs = appendDerivedAttr(rowAttrs, name+displayValueSuffix, strVal)
			}

			fresh.add(metricName, observedPoint{value: val, attrs: rowAttrs, decl: decl, rowKey: rowKey, prec: prec})
		}
	}
}

// walkFullTable walks the table root OID once and distributes PDUs to per-column maps.
// The returned maps are keyed by the profile's own column OID, which is how the
// callers look them up.
func (c *MetricsCollector) walkFullTable(walker snmp.Walker, walks walkCache, entry *profiles.MetricEntry) map[string]map[string]snmp.PDU {
	allPDUs, err := c.cachedWalk(walks, walker, entry.Table.OID)
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

// walkResult is what a walk returned, kept whether it answered or failed.
type walkResult struct {
	pdus map[string]snmp.PDU
	err  error
}

// walkCache holds the walks of one collection run, so an OID is asked for once
// however many declarations name it.
//
// Declarations agreeing on metric name, OID and poll period share one poll
// window. Given a walk each they could disagree about it: the first to answer
// starts the window for both, and a second that fails leaves its rows absent
// for the whole poll_time_sec, because the next cycle finds the shared window
// still open. One walk cannot disagree with itself.
//
// The error is cached with the PDUs for that reason, and it costs the run
// nothing: gosnmp has already spent this policy's retries on the request, and
// no window is started either way, so the retry belongs to the next cycle
// rather than to this one.
//
// Top-level metric_tags read through it too, and there the second reading is
// wrong rather than merely wasteful: a tag can name an OID the profile also
// declares as a metric, and the tag is read first, so an attribute from the
// first response would travel on a point whose value came from the second.
//
// The OID is the whole key. A walk asks the device for one subtree and the
// scalar, column and full-table paths all want the same answer for it, so
// anything else in the key would split one request into two entries and hand
// the two callers readings taken at different moments.
//
// The maps handed back are the cache's own. Every caller reads them and builds
// its own row maps from what it reads.
type walkCache map[string]walkResult

// cachedWalk walks an OID once per run and hands every later caller what the
// first one got.
func (c *MetricsCollector) cachedWalk(cache walkCache, walker snmp.Walker, oid string) (map[string]snmp.PDU, error) {
	if res, ok := cache[oid]; ok {
		return res.pdus, res.err
	}
	pdus, err := c.walk(walker, oid)
	cache[oid] = walkResult{pdus: pdus, err: err}
	return pdus, err
}

// walk walks an OID subtree and returns the PDUs keyed by normalized OID.
// gosnmp names every PDU with a leading dot, so normalizing once here spares
// every caller from carrying the difference into its own comparisons.
func (c *MetricsCollector) walk(walker snmp.Walker, oid string) (map[string]snmp.PDU, error) {
	pdus, err := walker.Walk(oid)
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
	pdus, err := c.walk(walker, oid)
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

// scalarRowIndex reports the row a PDU from a scalar-path walk belongs to, and
// whether it belongs to one at all.
//
// SNMP names the single instance of a scalar object by appending .0 to it, so
// a PDU answering there, or at the symbol's OID itself when the profile
// already named the instance, is that scalar. Any other suffix is a table
// index, and the symbol is a column whatever the profile calls it.
//
// The OID decides it rather than the size of the walk, because the size is a
// property of one poll: a column that answers with one row today and two
// tomorrow would otherwise write today's point into a series that tomorrow's
// point cannot continue.
func scalarRowIndex(fullOID, symbolOID string) (string, bool) {
	idx, indexed := rowIndex(fullOID, symbolOID)
	if !indexed || idx == "0" {
		return "", false
	}
	return idx, true
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

// metricTagName is the attribute key a tag renders under: the `tag:` inside the
// column it resolved to, then its own, and otherwise the column's name.
//
// The two declarations name the same key, and the column's is the more
// specific of them, so it wins the way the column's conversion does.
func metricTagName(mt *profiles.MetricTag, col *profiles.TagColumn) string {
	if col != nil && col.Tag != "" {
		return col.Tag
	}
	if mt.Tag != "" {
		return mt.Tag
	}
	if col == nil {
		return ""
	}
	return col.Name
}

// pduToValue converts a PDU to an int64 metric value, applying conversion rules.
// It also returns an optional non-empty string for display-only conversions (to_one, hextoip, hwaddr, regexp).
// Returns an error for PDU types that cannot produce a numeric value.
func pduToValue(pdu snmp.PDU, conversion string) (int64, string, error) {
	// conversion: to_one emits 1 whatever the PDU holds, because the metric
	// counts the presence of a state and the state itself belongs in an
	// attribute. The text is what tells two states apart, so it is returned
	// as the display value rather than dropped. A PDU carrying no value has
	// no text to return.
	if conversion == "to_one" {
		if pdu.Value == nil {
			return 1, "", nil
		}
		return 1, pduToString(pdu, nil), nil
	}

	// The numeric branches below read the value and not the conversion, so
	// which conversions may reach them is decided here rather than left to fall
	// out of the control flow. The cases are the numeric cases of the switch
	// that follows.
	switch pdu.Type {
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Counter64, gosnmp.TimeTicks, gosnmp.Uinteger32:
		if !numericPDUAcceptsConversion(conversion) {
			return 0, "", fmt.Errorf("conversion %q is not meaningful for numeric PDU type %v", conversion, pdu.Type)
		}
	}

	switch pdu.Type {
	case gosnmp.Integer:
		if v, ok := pdu.Value.(int); ok {
			return int64(v), "", nil
		}
	case gosnmp.Counter32, gosnmp.Gauge32:
		if v, ok := pdu.Value.(uint); ok {
			val, err := signedValue(uint64(v))
			return val, "", err
		}
	case gosnmp.Counter64:
		if v, ok := pdu.Value.(uint64); ok {
			val, err := signedValue(v)
			return val, "", err
		}
	case gosnmp.Uinteger32:
		// gosnmp decodes this one as uint32, unlike the uint it uses for
		// Counter32 and Gauge32, and a uint32 always fits an int64.
		if v, ok := pdu.Value.(uint32); ok {
			return int64(v), "", nil
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

// numericPDUAcceptsConversion reports whether a conversion may be carried
// through a PDU the device answered numerically.
//
// hextoint and regexp are representation decoders: they recover a number that a
// device chose to encode as text, so a device that answered with a number has
// already supplied their output and passing it through is an equivalence rather
// than a relaxation. Skipping it would drop correct telemetry for the sake of
// representation.
//
// hextoip and hwaddr are not in that family. Their output is an address, and a
// number is not one, so they fail closed rather than shipping an undecoded
// value under a metric named for a decoded one.
//
// The conversion is read through conversionError, the parse profile review
// uses, so a malformed one is refused here as well rather than accepted on its
// prefix. to_one is answered before this is reached, since it counts the
// value's presence whatever the type.
func numericPDUAcceptsConversion(conversion string) bool {
	if conversionError(conversion) != nil {
		return false
	}
	return conversion == "" ||
		strings.HasPrefix(conversion, "hextoint:") ||
		strings.HasPrefix(conversion, "regexp:")
}

// signedValue converts an unsigned SNMP value to the int64 an observation
// carries, and fails when it does not fit.
//
// SNMP counters are unsigned. A 64-bit counter passes math.MaxInt64 halfway
// round, and an unchecked cast reports it as a negative gauge. Clamping to
// math.MaxInt64 would be no better: it is a plausible-looking number the
// device never reported, and a rate read off it is a fabricated one. The
// caller skips the point instead, which is what this collector does with every
// other value it cannot render.
func signedValue(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("unsigned value %d does not fit a signed 64-bit metric", v)
	}
	return int64(v), nil
}

// parseHexToInt reads the byte order and width out of a
// hextoint:<endianness>:<type> conversion. It is the syntax half of
// applyHexToInt, split out so profile review judges the conversion through the
// same parse that applies it.
func parseHexToInt(conversion string) (binary.ByteOrder, int, error) {
	parts := strings.SplitN(conversion, ":", 3)
	if len(parts) != 3 {
		return nil, 0, fmt.Errorf("invalid hextoint format: %s", conversion)
	}
	var order binary.ByteOrder
	switch parts[1] {
	case "BigEndian":
		order = binary.BigEndian
	case "LittleEndian":
		order = binary.LittleEndian
	default:
		return nil, 0, fmt.Errorf("unknown endianness: %s", parts[1])
	}
	switch parts[2] {
	case "uint16":
		return order, 2, nil
	case "uint32":
		return order, 4, nil
	case "uint64":
		return order, 8, nil
	}
	return nil, 0, fmt.Errorf("unknown hextoint type: %s", parts[2])
}

// applyHexToInt converts an OctetString byte slice to an integer using
// the hextoint:<endianness>:<type> conversion rule.
func applyHexToInt(raw []byte, conversion string) (int64, error) {
	order, width, err := parseHexToInt(conversion)
	if err != nil {
		return 0, err
	}

	decoded := raw
	if b, err := hex.DecodeString(strings.TrimSpace(string(raw))); err == nil {
		decoded = b
	}
	if len(decoded) < width {
		return 0, fmt.Errorf("too few bytes for %s", conversion)
	}

	switch width {
	case 2:
		return int64(order.Uint16(decoded[:2])), nil
	case 4:
		return int64(order.Uint32(decoded[:4])), nil
	default:
		return signedValue(order.Uint64(decoded[:8]))
	}
}

// parseRegexpConversion compiles the pattern a regexp: conversion carries. It
// is the syntax half of applyRegexp, split out so profile review judges the
// conversion through the same compile that applies it.
func parseRegexpConversion(conversion string) (*regexp.Regexp, error) {
	pattern := strings.TrimPrefix(conversion, "regexp:")
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp %q: %w", pattern, err)
	}
	return re, nil
}

// applyRegexp applies a regexp: conversion to a string value.
func applyRegexp(raw, conversion string) (int64, string, error) {
	re, err := parseRegexpConversion(conversion)
	if err != nil {
		return 0, "", err
	}
	matches := re.FindStringSubmatch(raw)
	if len(matches) == 0 {
		return 0, "", fmt.Errorf("regexp %q did not match %q", re, raw)
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
				if name := col.Enum.Name(int64(v)); name != "" {
					return name
				}
			}
			return fmt.Sprintf("%d", v)
		}
	case gosnmp.Counter32, gosnmp.Gauge32:
		if v, ok := pdu.Value.(uint); ok {
			return fmt.Sprintf("%d", v)
		}
	case gosnmp.Uinteger32:
		if v, ok := pdu.Value.(uint32); ok {
			return fmt.Sprintf("%d", v)
		}
	case gosnmp.IPAddress, gosnmp.ObjectIdentifier:
		if s, ok := pdu.Value.(string); ok {
			return s
		}
	}
	return fmt.Sprintf("%v", pdu.Value)
}

// enumStatusName names the enum member a symbol's value falls on, or "" when
// the symbol declares no enum or the number the enum reads was never the
// device's. to_one reports 1 whatever the device sent, so reading an enum off
// it would put the name of member 1 on every state the device can be in.
func enumStatusName(sym *profiles.Symbol, val int64) string {
	if !symbolLabelsEnum(sym) {
		return ""
	}
	return sym.Enum.Name(val)
}

// symbolLabelsEnum reports whether a reading of this symbol can carry an enum
// label at all. to_one exports the presence of a state and puts the state's own
// text in the display value, so its enum never becomes a label.
//
// The collection path and the profile review both read it, so they cannot
// disagree about which symbols derive a _status attribute.
func symbolLabelsEnum(sym *profiles.Symbol) bool {
	return sym.Enum.Len() > 0 && sym.Conversion != "to_one"
}

// conversionRendersText reports whether pduToValue has a branch that returns a
// display value for this conversion. to_one returns the PDU's own text whatever
// the type, and hextoip, hwaddr and regexp decode an OctetString into text.
// Every other branch returns none, so those symbols never derive a _value
// attribute.
//
// It mirrors pduToValue's branches the way numericPDUAcceptsConversion does: a
// conversion that starts rendering text has to be added here too, or the review
// will stop naming a collision the collection still makes.
func conversionRendersText(conversion string) bool {
	return conversion == "to_one" ||
		conversion == "hextoip" ||
		conversion == "hwaddr" ||
		strings.HasPrefix(conversion, "regexp:")
}

// derivedAttrNames returns the attribute names a symbol derives from its own
// reading: the enum label for its value and the text a conversion rendered it
// as. Both are built from the same export name and suffixes the collection path
// appends, so the two cannot name them differently.
//
// Which of the pair a given reading fills is not knowable here, since it takes
// a device answer to say whether the value matches an enum member or renders as
// text. Whether the symbol can ever fill either is knowable from the profile,
// and that is what makes a collision with a declared tag reportable once per
// profile. The set is one pair per symbol of an entry, so it is derived from
// the entry under review rather than reserved as a static list.
func derivedAttrNames(sym *profiles.Symbol) []string {
	if unusableSymbolReason(sym) != "" {
		// Never read, so it derives nothing and shadows nothing.
		return nil
	}
	var names []string
	if symbolLabelsEnum(sym) {
		names = append(names, sym.ExportName()+enumStatusSuffix)
	}
	if conversionRendersText(sym.Conversion) {
		names = append(names, sym.ExportName()+displayValueSuffix)
	}
	return names
}
