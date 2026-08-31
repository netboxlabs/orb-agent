package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

// ---------------------------------------------------------------------------
// Mock Walker
// ---------------------------------------------------------------------------

// recordingWalker is a configurable mock Walker that records calls and returns preset data.
type recordingWalker struct {
	// responses maps OID -> PDUs returned by Walk.  Nil slice means empty result.
	responses map[string]map[string]snmp.PDU
	// walkCalls records each (oid, depth) call.
	walkCalls []string
	// onWalk, when set, runs before each Walk returns. A test uses it to expire
	// the collection deadline partway through a profile.
	onWalk func(oid string)
	// walkErrs maps OID -> error returned instead of PDUs, so a test can fail
	// one request of a run that otherwise succeeds.
	walkErrs map[string]error
	// bulkWalk is the walk mode currently selected, and bulkByOID records the
	// mode each walk was issued under. A double that answered the same however
	// it was asked would hide a regression from GETBULK back to GETNEXT.
	bulkWalk  bool
	bulkByOID map[string]bool
}

func (r *recordingWalker) Connect() error { return nil }
func (r *recordingWalker) Close() error   { return nil }
func (r *recordingWalker) SetBulkWalk(enabled bool) {
	r.bulkWalk = enabled
}

func (r *recordingWalker) Walk(oid string, _ int) (map[string]snmp.PDU, error) {
	r.walkCalls = append(r.walkCalls, oid)
	if r.bulkByOID == nil {
		r.bulkByOID = make(map[string]bool)
	}
	r.bulkByOID[oid] = r.bulkWalk
	if r.onWalk != nil {
		r.onWalk(oid)
	}
	if err := r.walkErrs[oid]; err != nil {
		return nil, err
	}
	pdus, ok := r.responses[oid]
	if !ok {
		return map[string]snmp.PDU{}, nil
	}
	// gosnmp names every PDU with a leading dot. Fixtures are written without
	// one, the way profile OIDs are, so it is added here instead.
	out := make(map[string]snmp.PDU, len(pdus))
	for name, pdu := range pdus {
		pdu.Name = "." + strings.TrimPrefix(name, ".")
		out[pdu.Name] = pdu
	}
	return out, nil
}

// walkerFactory returns a ClientFactory that always returns the same walker.
func walkerFactory(w snmp.Walker) snmp.ClientFactory {
	return func(_ context.Context, _ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return w, nil
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

var discardLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func oIDPDU(oid string) snmp.PDU {
	return snmp.PDU{Name: oid, Type: gosnmp.ObjectIdentifier, Value: oid}
}

func intPDU(oid string, v int) snmp.PDU {
	return snmp.PDU{Name: oid, Type: gosnmp.Integer, Value: v}
}

func counter32PDU(oid string, v uint) snmp.PDU {
	return snmp.PDU{Name: oid, Type: gosnmp.Counter32, Value: v}
}

func counter64PDU(oid string, v uint64) snmp.PDU {
	return snmp.PDU{Name: oid, Type: gosnmp.Counter64, Value: v}
}

func stringPDU(oid string, v string) snmp.PDU {
	return snmp.PDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(v)}
}

// profileWithOID creates a minimal Profile that matches the given exact sysObjectID.
func profileWithOID(oid, filename string, metrics []profiles.MetricEntry) *profiles.Profile {
	p := &profiles.Profile{
		SysObjectID: profiles.StringOrSlice{oid},
		FileName:    filename,
		Metrics:     metrics,
	}
	return p
}

// newCollector builds a MetricsCollector with the given factory + profile, no OTLP meter.
func newCollector(factory snmp.ClientFactory, p *profiles.Profile) *MetricsCollector {
	var ps []*profiles.Profile
	if p != nil {
		ps = []*profiles.Profile{p}
	}
	matcher := profiles.NewMatcher(ps, discardLogger)
	return NewMetricsCollector(factory, matcher, discardLogger)
}

// testDeviceStore is a test-only accessor to read the collector's internal
// store for a device polled on the default port.
func (c *MetricsCollector) testDeviceStore(policy, host string) map[string][]observedPoint {
	return c.testDeviceStoreKeyed(deviceKey{policy: policy, host: host, port: 161})
}

// testDeviceStoreKeyed is a test-only accessor for a device whose identity
// carries more than policy, host and port.
func (c *MetricsCollector) testDeviceStoreKeyed(key deviceKey) map[string][]observedPoint {
	c.storeMu.RLock()
	defer c.storeMu.RUnlock()
	return c.deviceStore[key]
}

func mustTarget(host string) config.Target {
	return config.Target{Host: host, Port: 161}
}

func mustAuth() *config.Authentication {
	return &config.Authentication{ProtocolVersion: "SNMPv2c", Community: "public"}
}

// ---------------------------------------------------------------------------
// Unit tests: pduToValue
// ---------------------------------------------------------------------------

func TestPduToValue_Numeric(t *testing.T) {
	tests := []struct {
		name       string
		pdu        snmp.PDU
		conversion string
		wantVal    int64
	}{
		{"Integer", intPDU("x", 42), "", 42},
		{"Counter32", counter32PDU("x", 99), "", 99},
		{"Counter64", counter64PDU("x", 1<<40), "", 1 << 40},
		{"TimeTicks", snmp.PDU{Name: "x", Type: gosnmp.TimeTicks, Value: uint32(12345)}, "", 12345},
		{"Gauge32", snmp.PDU{Name: "x", Type: gosnmp.Gauge32, Value: uint(7)}, "", 7},
		{"Uinteger32", snmp.PDU{Name: "x", Type: gosnmp.Uinteger32, Value: uint32(4294967295)}, "", 4294967295},
		{"to_one ignores type", snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: []byte("hello")}, "to_one", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := pduToValue(tt.pdu, tt.conversion)
			require.NoError(t, err)
			assert.Equal(t, tt.wantVal, got)
		})
	}
}

func TestPduToValue_HexToIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.10").To4()
	pdu := snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: []byte(ip)}
	_, display, err := pduToValue(pdu, "hextoip")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.10", display)
}

func TestPduToValue_HwAddr(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	pdu := snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: []byte(mac)}
	_, display, err := pduToValue(pdu, "hwaddr")
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", display)
}

func TestPduToValue_HexToInt(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 305419896)
	pdu := snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: buf}
	got, _, err := pduToValue(pdu, "hextoint:BigEndian:uint32")
	require.NoError(t, err)
	assert.Equal(t, int64(305419896), got)
}

func TestPduToValue_Regexp(t *testing.T) {
	pdu := stringPDU("x", "load average: 42")
	got, _, err := pduToValue(pdu, "regexp:(\\d+)")
	require.NoError(t, err)
	assert.Equal(t, int64(42), got)
}

func TestPduToValue_OctetString_NonNumeric(t *testing.T) {
	pdu := stringPDU("x", "hello")
	_, _, err := pduToValue(pdu, "")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Unit tests: extractRowIndex
// ---------------------------------------------------------------------------

func TestExtractRowIndex(t *testing.T) {
	assert.Equal(t, "3", extractRowIndex("1.3.6.1.2.1.2.2.1.2.3", "1.3.6.1.2.1.2.2.1.2"))
	assert.Equal(t, "10.2", extractRowIndex("1.3.6.1.2.1.2.2.1.2.10.2", "1.3.6.1.2.1.2.2.1.2"))
	// A leading dot on either side is not part of the OID.
	assert.Equal(t, "3", extractRowIndex(".1.3.6.1.2.1.2.2.1.2.3", "1.3.6.1.2.1.2.2.1.2"))
	assert.Equal(t, "3", extractRowIndex("1.3.6.1.2.1.2.2.1.2.3", ".1.3.6.1.2.1.2.2.1.2"))
	assert.Equal(t, "3", extractRowIndex(".1.3.6.1.2.1.2.2.1.2.3", ".1.3.6.1.2.1.2.2.1.2"))
	// No prefix match — returns full OID unchanged.
	assert.Equal(t, "1.2.3.4", extractRowIndex("1.2.3.4", "9.9.9.9"))

	// A fully qualified instance OID has no column prefix to strip.
	idx, indexed := rowIndex("1.3.6.1.2.1.2.2.1.2.3", "1.3.6.1.2.1.2.2.1.2")
	assert.Equal(t, "3", idx)
	assert.True(t, indexed)
	idx, indexed = rowIndex("1.2.3.4", "1.2.3.4")
	assert.Equal(t, "1.2.3.4", idx)
	assert.False(t, indexed)
}

// ---------------------------------------------------------------------------
// Unit tests: pollDue and markPolled
// ---------------------------------------------------------------------------

func testKey(policy, host string) deviceKey {
	return deviceKey{policy: policy, host: host, port: 161}
}

// sym builds a symbol declaration for the poll window tests.
func sym(name, oid string, pollTimeSec int) *profiles.Symbol {
	return &profiles.Symbol{Name: name, OID: oid, PollTimeSec: pollTimeSec}
}

func TestPollDue_ZeroAlwaysDue(t *testing.T) {
	c := newCollector(nil, nil)
	k := testKey("p", "host1")
	assert.True(t, c.pollDue(k, sym("load", "1.2.3", 0)))
	c.markPolled(k, sym("load", "1.2.3", 0))
	assert.True(t, c.pollDue(k, sym("load", "1.2.3", 0)))

	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	assert.Empty(t, c.pollState[k], "an always-polled symbol needs no timestamp")
}

func TestPollDue_ThrottleAndExpiry(t *testing.T) {
	c := newCollector(nil, nil)
	k := testKey("p", "host1")
	s := sym("load", "1.2.3", 60)
	// Asking does not start the window.
	assert.True(t, c.pollDue(k, s))
	assert.True(t, c.pollDue(k, s))
	// Collecting does.
	c.markPolled(k, s)
	assert.False(t, c.pollDue(k, s))
	// Simulate time elapsed by backdating the last-poll entry.
	c.pollMu.Lock()
	c.pollState[k][symbolDeclKey(s)] = time.Now().Add(-61 * time.Second)
	c.pollMu.Unlock()
	assert.True(t, c.pollDue(k, s))
}

func TestPollDue_IndependentPerDevice(t *testing.T) {
	c := newCollector(nil, nil)
	s := sym("load", "1.2.3", 60)
	c.markPolled(testKey("p", "host1"), s)
	assert.True(t, c.pollDue(testKey("p", "host2"), s)) // different host, same declaration
	assert.True(t, c.pollDue(testKey("q", "host1"), s)) // different policy, same host
	assert.True(t, c.pollDue(deviceKey{policy: "p", host: "host1", port: 1161}, s))
	assert.False(t, c.pollDue(testKey("p", "host1"), s))
}

// A declaration is its exported metric name, its OID and its poll period. Two
// declarations of one OID exporting under two names are throttled apart, so the
// first to walk the column does not silence the second.
func TestPollDue_IndependentPerDeclaration(t *testing.T) {
	c := newCollector(nil, nil)
	k := testKey("p", "host1")
	const oid = "1.3.6.1.2.1.2.2.1.7"
	inherited := &profiles.Symbol{Name: "ifAdminStatus", OID: oid, Tag: "if_AdminStatus", PollTimeSec: 60}
	own := sym("ifAdminStatus", oid, 60)

	c.markPolled(k, inherited)
	assert.False(t, c.pollDue(k, inherited))
	assert.True(t, c.pollDue(k, own), "a second metric name on one column keeps its own window")

	// Same name and column, a different period: separate windows, since the
	// period each waits out is a different length.
	c.markPolled(k, own)
	assert.True(t, c.pollDue(k, sym("ifAdminStatus", oid, 3600)))

	// Same name, column and period is one declaration however many symbols
	// write it, and one window serves them.
	assert.False(t, c.pollDue(k, sym("ifAdminStatus", oid, 60)))
	assert.False(t, c.pollDue(k, sym("IFADMINSTATUS", oid, 60)),
		"the name is the exported one, so two spellings of it are one declaration")

	// A different column under the same name is a walk of its own.
	assert.True(t, c.pollDue(k, sym("ifAdminStatus", "1.3.6.1.2.1.2.2.1.8", 60)))
}

// Poll state and retention read one declaration key, so the declaration
// recorded as throttled is the declaration whose points are carried forward.
// Keys that disagreed would leave a metric exporting a value nothing refreshes,
// or exporting nothing at all.
func TestMarkPolled_KeysThePollWindowOnTheRetentionKey(t *testing.T) {
	c := newCollector(nil, nil)
	k := testKey("p", "host1")
	s := &profiles.Symbol{Name: "hrProcessorLoad", OID: "1.3.6.1.2.1.25.3.3.1.2", Tag: "CPU", PollTimeSec: 60}
	c.markPolled(k, s)

	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	require.Len(t, c.pollState[k], 1)
	assert.Contains(t, c.pollState[k], symbolDeclKey(s),
		"the poll window is keyed on the declaration retention carries points for")
}

// ---------------------------------------------------------------------------
// CollectTarget: no profile match
// ---------------------------------------------------------------------------

func TestCollectTarget_NoProfileMatch(t *testing.T) {
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjectIDOID + ".0")},
	}}
	c := newCollector(walkerFactory(w), nil) // matcher has no profiles
	err := c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "policy1", DialOptions{})
	assert.NoError(t, err)
	assert.Nil(t, c.testDeviceStore("policy1", "10.0.0.1"))
}

// ---------------------------------------------------------------------------
// CollectTarget: scalar metric collection
// ---------------------------------------------------------------------------

func TestCollectTarget_ScalarMetric(t *testing.T) {
	const (
		host        = "10.0.0.1"
		cpuOID      = "1.3.6.1.4.1.9999.1.1"
		sysObjValue = "1.3.6.1.4.1.9999"
	)
	p := profileWithOID(sysObjValue, "test.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		sysNameOID:     {sysNameOID: stringPDU(sysNameOID, "router1")},
		cpuOID:         {cpuOID: intPDU(cpuOID, 75)},
	}}
	c := newCollector(walkerFactory(w), p)
	err := c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "policy1", DialOptions{})
	require.NoError(t, err)

	store := c.testDeviceStore("policy1", host)
	require.NotNil(t, store)
	pts := store["snmp.cpuutil"]
	require.Len(t, pts, 1)
	assert.Equal(t, int64(75), pts[0].value)
}

// ---------------------------------------------------------------------------
// CollectTarget: table metric with tag columns
// ---------------------------------------------------------------------------

func TestCollectTarget_TableWithTags(t *testing.T) {
	const (
		host        = "10.0.0.2"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20" // ifOutErrors
		descrColOID = "1.3.6.1.2.1.2.2.1.2"  // ifDescr
		sysObjValue = "1.3.6.1.4.1.9999.2"
	)
	p := profileWithOID(sysObjValue, "test2.yml", []profiles.MetricEntry{
		{
			Table: &profiles.Table{Name: "ifTable", OID: tableOID},
			Symbols: []profiles.Symbol{
				{Name: "ifOutErrors", OID: errColOID},
			},
			MetricTags: []profiles.MetricTag{
				{Tag: "if_desc", Column: &profiles.TagColumn{OID: descrColOID, Name: "ifDescr"}},
			},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		sysNameOID:     {},
		// Two table rows
		errColOID: {
			errColOID + ".1": counter32PDU(errColOID+".1", 10),
			errColOID + ".2": counter32PDU(errColOID+".2", 20),
		},
		descrColOID: {
			descrColOID + ".1": stringPDU(descrColOID+".1", "eth0"),
			descrColOID + ".2": stringPDU(descrColOID+".2", "eth1"),
		},
	}}
	c := newCollector(walkerFactory(w), p)
	err := c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "policy1", DialOptions{})
	require.NoError(t, err)

	store := c.testDeviceStore("policy1", host)
	pts := store["snmp.ifouterrors"]
	require.Len(t, pts, 2)

	// Extract values and tag map.
	got := map[string]int64{}
	for _, pt := range pts {
		var desc, rowIdx string
		for _, kv := range pt.attrs {
			switch string(kv.Key) {
			case "if_desc":
				desc = kv.Value.AsString()
			case "row_index":
				rowIdx = kv.Value.AsString()
			}
		}
		_ = rowIdx
		got[desc] = pt.value
	}
	assert.Equal(t, map[string]int64{"eth0": 10, "eth1": 20}, got)
}

// ---------------------------------------------------------------------------
// Staleness fix: throttled metrics carry forward; polled-but-empty are cleared
// ---------------------------------------------------------------------------

func TestCollectTarget_ThrottledMetricCarriesForward(t *testing.T) {
	const (
		host        = "10.0.0.3"
		fastOID     = "1.3.6.1.4.1.9999.3.1"
		slowOID     = "1.3.6.1.4.1.9999.3.2"
		sysObjValue = "1.3.6.1.4.1.9999.3"
	)
	p := profileWithOID(sysObjValue, "test3.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "fastMetric", OID: fastOID}},                   // no poll_time_sec, always polled
		{Symbol: &profiles.Symbol{Name: "slowMetric", OID: slowOID, PollTimeSec: 300}}, // 5 min throttle
	})

	makeWalker := func(fastVal, slowVal int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			sysNameOID:     {},
			fastOID:        {fastOID: intPDU(fastOID, fastVal)},
			slowOID:        {slowOID: intPDU(slowOID, slowVal)},
		}}
	}

	c := newCollector(nil, p) // factory overridden per-run
	ctx := context.Background()

	// First run: both polled.
	c.clientFactory = walkerFactory(makeWalker(1, 100))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Equal(t, int64(1), store["snmp.fastmetric"][0].value)
	assert.Equal(t, int64(100), store["snmp.slowmetric"][0].value)

	// Second run: slowMetric is throttled (poll_time_sec=300, only seconds have passed).
	// The walker returns different slow values but they should NOT be used.
	c.clientFactory = walkerFactory(makeWalker(2, 999))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))

	store = c.testDeviceStore("p", host)
	assert.Equal(t, int64(2), store["snmp.fastmetric"][0].value, "fast metric should be updated")
	assert.Equal(t, int64(100), store["snmp.slowmetric"][0].value, "slow metric should retain last-known value")
}

func TestCollectTarget_PolledButEmptyIsCleared(t *testing.T) {
	const (
		host        = "10.0.0.4"
		metricOID   = "1.3.6.1.4.1.9999.4.1"
		sysObjValue = "1.3.6.1.4.1.9999.4"
	)
	p := profileWithOID(sysObjValue, "test4.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "someMetric", OID: metricOID}},
	})

	makeWalker := func(includeMetric bool) *recordingWalker {
		resp := map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			sysNameOID:     {},
		}
		if includeMetric {
			resp[metricOID] = map[string]snmp.PDU{metricOID: intPDU(metricOID, 42)}
		}
		return &recordingWalker{responses: resp}
	}

	c := newCollector(nil, p)
	ctx := context.Background()

	// First run: metric present.
	c.clientFactory = walkerFactory(makeWalker(true))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	assert.Len(t, c.testDeviceStore("p", host)["snmp.somemetric"], 1)

	// Second run: metric OID returns empty (OID vanished from device).
	c.clientFactory = walkerFactory(makeWalker(false))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	assert.Empty(t, c.testDeviceStore("p", host)["snmp.somemetric"], "polled-but-empty metric should be cleared")
}

// attrSetKey is asked for a key, not for a sorted point. Building an attribute
// set sorts the slice it is given, so a point handed to it straight would come
// back with its attributes rearranged.
func TestAttrSetKey_LeavesTheCallersAttributesAlone(t *testing.T) {
	attrs := []attribute.KeyValue{
		attribute.String("row_index", "2"),
		attribute.String("device_ip", "10.0.0.1"),
		attribute.String("sensor_name", "Board 0"),
	}
	before := append([]attribute.KeyValue(nil), attrs...)

	key := attrSetKey(attrs)

	assert.Equal(t, before, attrs, "the point keeps the attribute order it was collected in")
	assert.Equal(t, "device_ip=10.0.0.1,row_index=2,sensor_name=Board 0", key)
	assert.Equal(t, key, attrSetKey([]attribute.KeyValue{
		attribute.String("sensor_name", "Board 0"),
		attribute.String("device_ip", "10.0.0.1"),
		attribute.String("row_index", "2"),
	}), "the same attributes are the same series in any order")
	assert.NotEqual(t, key, attrSetKey(attrs[:2]), "a missing attribute is a different series")
}

// ---------------------------------------------------------------------------
// Retention when one metric name is declared twice
// ---------------------------------------------------------------------------

// The bundled Dell OS10 profile inherits an unthrottled hrProcessorLoad tagged
// by processor description and adds a 60 second declaration of the same column
// carrying `tag: CPU`. The tag names the metric, so the throttled declaration
// exports as snmp.cpu and the inherited one keeps snmp.hrprocessorload.
//
// Retention is decided per declaration, not per metric name: on a
// metrics_interval under 60 seconds the throttled declaration keeps the points
// it left while the unthrottled one refreshes.
func TestCollectTarget_BundledDellTagNamesTheThrottledCPUMetric(t *testing.T) {
	const (
		host     = "10.0.0.75"
		loadCol  = "1.3.6.1.2.1.25.3.3.1.2"
		descrCol = "1.3.6.1.2.1.25.3.2.1.3"
	)
	makeWalker := func(first, second int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.674.11000.5000.100.2.1.1")},
			loadCol: {
				loadCol + ".1": intPDU(loadCol+".1", first),
				loadCol + ".2": intPDU(loadCol+".2", second),
			},
			descrCol: {
				descrCol + ".1": stringPDU(descrCol+".1", "core 1"),
				descrCol + ".2": stringPDU(descrCol+".2", "core 2"),
			},
		}}
	}
	byIndex := func(pts []observedPoint) map[string]int64 {
		out := make(map[string]int64)
		for _, pt := range pts {
			out[attrValue(pt, "row_index")] = pt.value
		}
		return out
	}

	c := newCollector(nil, bundledProfile(t, "dell/dell-os10.yml"))
	ctx := context.Background()

	c.clientFactory = walkerFactory(makeWalker(11, 22))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	store := c.testDeviceStore("p", host)
	require.Equal(t, map[string]int64{"1": 11, "2": 22}, byIndex(store["snmp.cpu"]),
		"the tagged declaration exports under the name its tag gives it")
	require.Equal(t, map[string]int64{"1": 11, "2": 22}, byIndex(store["snmp.hrprocessorload"]),
		"the inherited declaration keeps the name it declares")
	for _, pt := range store["snmp.cpu"] {
		assert.Empty(t, attrValue(pt, "tag"), "a symbol tag names the metric and adds no attribute")
	}

	// Seconds later: the inherited declaration is due, the 60 second one is not.
	c.clientFactory = walkerFactory(makeWalker(33, 44))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))

	store = c.testDeviceStore("p", host)
	assert.Equal(t, map[string]int64{"1": 11, "2": 22}, byIndex(store["snmp.cpu"]),
		"the throttled declaration keeps the points it left")
	assert.Equal(t, map[string]int64{"1": 33, "2": 44}, byIndex(store["snmp.hrprocessorload"]),
		"the due declaration is refreshed")
	for _, pt := range store["snmp.hrprocessorload"] {
		assert.NotEmpty(t, attrValue(pt, "processor_description"), "the inherited series keeps its tag column")
	}
}

// A `tag:` renames the metric, so one OID can be declared twice and export
// under two names. The poll window has to be one per declaration: keyed on the
// OID alone, the first declaration to walk it throttles the second, and that
// second metric never exports at all.
//
// The bundled Mikrotik switch profile is the case. It inherits ifAdminStatus
// and ifOperStatus tagged if_AdminStatus and if_OperStatus from the interface
// MIB and declares its own untagged pair on the same two columns. Inherited
// entries are prepended, so the tagged pair runs first.
func TestCollectTarget_BundledMikrotikExportsBothNamesOfOneColumn(t *testing.T) {
	const (
		host     = "10.0.0.78"
		adminCol = "1.3.6.1.2.1.2.2.1.7"
		operCol  = "1.3.6.1.2.1.2.2.1.8"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.14988.2.1.1")},
		adminCol:       {adminCol + ".1": intPDU(adminCol+".1", 1)},
		operCol:        {operCol + ".1": intPDU(operCol+".1", 2)},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "mikrotik/mikrotik-switch.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	for name, want := range map[string]int64{
		"snmp.if_adminstatus": 1,
		"snmp.ifadminstatus":  1,
		"snmp.if_operstatus":  2,
		"snmp.ifoperstatus":   2,
	} {
		pts := store[name]
		require.Len(t, pts, 1, "%s exported nothing", name)
		assert.Equal(t, want, pts[0].value, "%s carries the value the column answered", name)
		assert.Equal(t, "1", attrValue(pts[0], "row_index"), "%s keeps its row identity", name)
	}
	assert.Equal(t, "up", attrValue(store["snmp.if_adminstatus"][0], "if_AdminStatus_status"),
		"each declaration names its status attribute after the name it exports under")
	assert.Equal(t, "up", attrValue(store["snmp.ifadminstatus"][0], "ifAdminStatus_status"))
}

// Retention that merged on the attribute set alone would carry a row the due
// declaration no longer answers for, which is what rebuilding the store from
// the fresh points was there to prevent. A point is retained only when its own
// declaration was throttled.
func TestCollectTarget_AThrottledSiblingDoesNotRestoreAVanishedRow(t *testing.T) {
	const (
		host        = "10.0.0.76"
		tableOID    = "1.3.6.1.4.1.99.10.1"
		loadCol     = "1.3.6.1.4.1.99.10.1.1.2"
		descrCol    = "1.3.6.1.4.1.99.10.1.1.3"
		sysObjValue = "1.3.6.1.4.1.99.10"
	)
	p := profileWithOID(sysObjValue, "two-declarations.yml", []profiles.MetricEntry{
		{
			Table:   &profiles.Table{Name: "loadTable", OID: tableOID},
			Symbols: []profiles.Symbol{{Name: "cpuLoad", OID: loadCol}},
			MetricTags: []profiles.MetricTag{
				{Tag: "core_name", Column: &profiles.TagColumn{OID: descrCol, Name: "coreDescr"}},
			},
		},
		{
			Table:   &profiles.Table{Name: "loadTable", OID: tableOID},
			Symbols: []profiles.Symbol{{Name: "cpuLoad", OID: loadCol, PollTimeSec: 300, AllowDup: true}},
		},
	})
	makeWalker := func(rows map[string]int) *recordingWalker {
		load := make(map[string]snmp.PDU, len(rows))
		descr := make(map[string]snmp.PDU, len(rows))
		for idx, v := range rows {
			load[loadCol+"."+idx] = intPDU(loadCol+"."+idx, v)
			descr[descrCol+"."+idx] = stringPDU(descrCol+"."+idx, "core "+idx)
		}
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
			loadCol:        load,
			descrCol:       descr,
		}}
	}

	c := newCollector(nil, p)
	ctx := context.Background()

	c.clientFactory = walkerFactory(makeWalker(map[string]int{"1": 11, "2": 22}))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.Len(t, c.testDeviceStore("p", host)["snmp.cpuload"], 4)

	// The second row is gone from the device, and the tagged declaration is
	// still throttled.
	c.clientFactory = walkerFactory(makeWalker(map[string]int{"1": 33}))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))

	// Only the first declaration reads the row name column, so a point
	// carrying core_name came from it and the rest were retained.
	var due, retained []string
	for _, pt := range c.testDeviceStore("p", host)["snmp.cpuload"] {
		if attrValue(pt, "core_name") == "" {
			retained = append(retained, attrValue(pt, "row_index"))
			continue
		}
		due = append(due, attrValue(pt, "row_index"))
	}
	sort.Strings(due)
	sort.Strings(retained)
	assert.Equal(t, []string{"1"}, due, "a row the due declaration no longer answers for must not survive")
	assert.Equal(t, []string{"1", "2"}, retained, "the throttled declaration keeps every row it left")
}

// Two declarations of one metric name may render the same attribute set, which
// is one exported series however many declarations produced it. Retention must
// not add a second point to a series the fresh points already carry: this PR
// has twice had to take such a duplicate back out.
func TestCollectTarget_RetentionAddsNoSecondPointForOneAttributeSet(t *testing.T) {
	const (
		host        = "10.0.0.77"
		loadOID     = "1.3.6.1.4.1.99.11.1.0"
		sysObjValue = "1.3.6.1.4.1.99.11"
	)
	p := profileWithOID(sysObjValue, "same-attributes.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuLoad", OID: loadOID}},
		{Symbol: &profiles.Symbol{Name: "cpuLoad", OID: loadOID, PollTimeSec: 300}},
	})
	makeWalker := func(v int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
			loadOID:        {loadOID: intPDU(loadOID, v)},
		}}
	}

	c := newCollector(nil, p)
	ctx := context.Background()

	c.clientFactory = walkerFactory(makeWalker(11))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))

	c.clientFactory = walkerFactory(makeWalker(33))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.cpuload"]
	require.Len(t, pts, 1, "one attribute set carries one point")
	assert.Equal(t, int64(33), pts[0].value, "the due declaration wins the series it shares")
}

// ---------------------------------------------------------------------------
// Medium fix: tag columns are NOT walked when all table symbols are throttled
// ---------------------------------------------------------------------------

func TestCollectTarget_TagNotWalkedWhenAllThrottled(t *testing.T) {
	const (
		host        = "10.0.0.5"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20"
		descrColOID = "1.3.6.1.2.1.2.2.1.2"
		sysObjValue = "1.3.6.1.4.1.9999.5"
	)
	p := profileWithOID(sysObjValue, "test5.yml", []profiles.MetricEntry{
		{
			Table: &profiles.Table{Name: "ifTable", OID: tableOID},
			Symbols: []profiles.Symbol{
				{Name: "ifOutErrors", OID: errColOID, PollTimeSec: 300},
			},
			MetricTags: []profiles.MetricTag{
				{Tag: "if_desc", Column: &profiles.TagColumn{OID: descrColOID, Name: "ifDescr"}},
			},
		},
	})

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		sysNameOID:     {},
		errColOID:      {errColOID + ".1": counter32PDU(errColOID+".1", 5)},
		descrColOID:    {descrColOID + ".1": stringPDU(descrColOID+".1", "eth0")},
	}}

	c := newCollector(walkerFactory(w), p)
	ctx := context.Background()

	// First run: symbol is polled, tag column MUST be walked.
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	firstRunCalls := make([]string, len(w.walkCalls))
	copy(firstRunCalls, w.walkCalls)
	assert.Contains(t, firstRunCalls, descrColOID, "tag column should be walked on first run")

	// Second run: poll_time_sec=300 not elapsed, symbol is throttled.
	w.walkCalls = nil
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	assert.NotContains(t, w.walkCalls, descrColOID, "tag column must NOT be walked when all symbols are throttled")
	assert.NotContains(t, w.walkCalls, errColOID, "metric column must NOT be walked when throttled")
}

// ---------------------------------------------------------------------------
// walk_full_table: single table walk distributes PDUs to columns
// ---------------------------------------------------------------------------

func TestCollectTarget_WalkFullTable(t *testing.T) {
	const (
		host        = "10.0.0.6"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20"
		descrColOID = "1.3.6.1.2.1.2.2.1.2"
		sysObjValue = "1.3.6.1.4.1.9999.6"
	)
	p := profileWithOID(sysObjValue, "test6.yml", []profiles.MetricEntry{
		{
			Table:         &profiles.Table{Name: "ifTable", OID: tableOID},
			WalkFullTable: true,
			Symbols: []profiles.Symbol{
				{Name: "ifOutErrors", OID: errColOID},
			},
			MetricTags: []profiles.MetricTag{
				{Tag: "if_desc", Column: &profiles.TagColumn{OID: descrColOID, Name: "ifDescr"}},
			},
		},
	})

	// The table root walk returns ALL column PDUs in one call.
	tableWalkPDUs := map[string]snmp.PDU{
		errColOID + ".1":   counter32PDU(errColOID+".1", 11),
		errColOID + ".2":   counter32PDU(errColOID+".2", 22),
		descrColOID + ".1": stringPDU(descrColOID+".1", "eth0"),
		descrColOID + ".2": stringPDU(descrColOID+".2", "eth1"),
	}
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		sysNameOID:     {},
		tableOID:       tableWalkPDUs,
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	// Only the table root OID (plus sysObjectID/sysDescr/sysName) should appear — not individual column OIDs.
	for _, call := range w.walkCalls {
		assert.NotEqual(t, errColOID, call, "individual error column should not be walked separately")
		assert.NotEqual(t, descrColOID, call, "individual descr column should not be walked separately")
	}
	assert.Contains(t, w.walkCalls, tableOID)

	store := c.testDeviceStore("p", host)
	pts := store["snmp.ifouterrors"]
	require.Len(t, pts, 2)
}

// ---------------------------------------------------------------------------
// Grouped scalars: `symbols:` with no `table:`
// ---------------------------------------------------------------------------

// newBundledCollector builds a MetricsCollector over the profiles bundled into
// the binary, so a test can drive a real profile rather than a hand-built one.
func newBundledCollector(t *testing.T, factory snmp.ClientFactory) *MetricsCollector {
	t.Helper()
	loader, err := profiles.LoadProfiles("", discardLogger)
	require.NoError(t, err)
	all, err := loader.AllResolved()
	require.NoError(t, err)
	return NewMetricsCollector(factory, profiles.NewMatcher(all, discardLogger), discardLogger)
}

// A profile may group scalars under `symbols:` with no `table:`. Those entries
// are neither a scalar `symbol:` nor a table, and 86 bundled profiles use the
// shape, five of them exclusively.
func TestCollectTarget_GroupedScalarSymbols(t *testing.T) {
	const (
		host        = "10.0.0.7"
		sysObjValue = "1.3.6.1.4.1.20916"
		tempFOID    = "1.3.6.1.4.1.20916.1.11.1.1.1.1.0"
		humidityOID = "1.3.6.1.4.1.20916.1.11.1.1.2.1.0"
		powerOID    = "1.3.6.1.4.1.20916.1.11.1.1.3.1.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		tempFOID:       {tempFOID: intPDU(tempFOID, 72)},
		humidityOID:    {humidityOID: intPDU(humidityOID, 41)},
		powerOID:       {powerOID: intPDU(powerOID, 1)},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Contains(t, w.walkCalls, tempFOID, "grouped scalar OID must be walked")

	store := c.testDeviceStore("p", host)
	require.Len(t, store["snmp.internal-tempf"], 1)
	assert.Equal(t, int64(72), store["snmp.internal-tempf"][0].value)
	require.Len(t, store["snmp.internal-humidity"], 1)
	assert.Equal(t, int64(41), store["snmp.internal-humidity"][0].value)
}

// A grouped symbol keeps the per-symbol decorations a scalar `symbol:` gets.
func TestCollectTarget_GroupedScalarSymbolsCarryEnum(t *testing.T) {
	const (
		host        = "10.0.0.8"
		sysObjValue = "1.3.6.1.4.1.20916"
		powerOID    = "1.3.6.1.4.1.20916.1.11.1.1.3.1.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		powerOID:       {powerOID: intPDU(powerOID, 1)},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.internal-power"]
	require.Len(t, pts, 1)
	assert.Equal(t, "ac", attrValue(pts[0], "internal-power_status"))
}

// attrValue returns the string value of one attribute on an observation, or "".
func attrValue(pt observedPoint, key string) string {
	for _, kv := range pt.attrs {
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Profile-level metric_tags become device-wide attributes
// ---------------------------------------------------------------------------

// A profile carries a top-level `metric_tags:` block describing device-wide
// dimensions. 181 of the bundled profiles declare one, almost all of them
// through the inherited system MIB block, and every series has to carry them.
func TestCollectTarget_ProfileMetricTagsBecomeDeviceAttributes(t *testing.T) {
	const (
		host        = "10.0.0.9"
		sysObjValue = "1.3.6.1.4.1.20916"
		descr       = "environment monitor"
		contactOID  = "1.3.6.1.2.1.1.4.0"
		nameOID     = "1.3.6.1.2.1.1.5.0"
		locationOID = "1.3.6.1.2.1.1.6.0"
		tempFOID    = "1.3.6.1.4.1.20916.1.11.1.1.1.1.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {sysDescrOID: stringPDU(sysDescrOID, descr)},
		contactOID:     {contactOID: stringPDU(contactOID, "noc@example.com")},
		nameOID:        {nameOID: stringPDU(nameOID, "sensor-1")},
		locationOID:    {locationOID: stringPDU(locationOID, "rack 4")},
		tempFOID:       {tempFOID: intPDU(tempFOID, 72)},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.internal-tempf"]
	require.Len(t, pts, 1)
	assert.Equal(t, "sensor-1", attrValue(pts[0], "SysName"))
	assert.Equal(t, "rack 4", attrValue(pts[0], "SysLocation"))
	assert.Equal(t, "noc@example.com", attrValue(pts[0], "SysContact"))
	assert.Equal(t, descr, attrValue(pts[0], "SysDescr"))
	assert.Equal(t, sysObjValue, attrValue(pts[0], "SysObjectID"))
	assert.Equal(t, host, attrValue(pts[0], "device_ip"))
}

// sysDescr and sysObjectID are already read before profile matching, so the
// tags naming them must not cost a second walk.
func TestCollectTarget_ProfileMetricTagsReuseSystemWalks(t *testing.T) {
	const (
		host        = "10.0.0.10"
		sysObjValue = "1.3.6.1.4.1.20916"
		nameOID     = "1.3.6.1.2.1.1.5.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {sysDescrOID: stringPDU(sysDescrOID, "environment monitor")},
		nameOID:        {nameOID: stringPDU(nameOID, "sensor-1")},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.NotContains(t, w.walkCalls, sysDescrOID+".0", "sysDescr must not be walked twice")
	assert.NotContains(t, w.walkCalls, sysObjectIDOID+".0", "sysObjectID must not be walked twice")
	assert.Contains(t, w.walkCalls, nameOID, "a device tag with no cached value must be walked")
}

// Table rows carry the device-wide tags alongside their own row tags.
func TestCollectTarget_ProfileMetricTagsReachTableRows(t *testing.T) {
	const (
		host        = "10.0.0.11"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20"
		descrColOID = "1.3.6.1.2.1.2.2.1.2"
		nameOID     = "1.3.6.1.2.1.1.5.0"
		sysObjValue = "1.3.6.1.4.1.9999.11"
	)
	p := profileWithOID(sysObjValue, "test11.yml", []profiles.MetricEntry{
		{
			Table:      &profiles.Table{Name: "ifTable", OID: tableOID},
			Symbols:    []profiles.Symbol{{Name: "ifOutErrors", OID: errColOID}},
			MetricTags: []profiles.MetricTag{{Tag: "if_desc", Column: &profiles.TagColumn{OID: descrColOID, Name: "ifDescr"}}},
		},
	})
	p.MetricTags = []profiles.MetricTag{{Column: &profiles.TagColumn{OID: nameOID, Name: "SysName"}}}

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		nameOID:        {nameOID: stringPDU(nameOID, "sensor-1")},
		errColOID:      {errColOID + ".1": counter32PDU(errColOID+".1", 10)},
		descrColOID:    {descrColOID + ".1": stringPDU(descrColOID+".1", "eth0")},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.ifouterrors"]
	require.Len(t, pts, 1)
	assert.Equal(t, "sensor-1", attrValue(pts[0], "SysName"))
	assert.Equal(t, "eth0", attrValue(pts[0], "if_desc"))
}

// ---------------------------------------------------------------------------
// Leading-dot PDU names
// ---------------------------------------------------------------------------

// gosnmp names every PDU with a leading dot and profile OIDs carry none, so
// every prefix comparison in the table path has to tolerate the difference.
// Without it row_index degrades to the whole OID and no tag ever joins.
func TestCollectTarget_TableRowIndexIgnoresLeadingDot(t *testing.T) {
	const (
		host        = "10.0.0.12"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20"
		descrColOID = "1.3.6.1.2.1.2.2.1.2"
		sysObjValue = "1.3.6.1.4.1.9999.12"
	)
	p := profileWithOID(sysObjValue, "test12.yml", []profiles.MetricEntry{
		{
			Table:      &profiles.Table{Name: "ifTable", OID: tableOID},
			Symbols:    []profiles.Symbol{{Name: "ifOutErrors", OID: errColOID}},
			MetricTags: []profiles.MetricTag{{Tag: "if_desc", Column: &profiles.TagColumn{OID: descrColOID, Name: "ifDescr"}}},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		errColOID: {
			errColOID + ".1":  counter32PDU(errColOID+".1", 10),
			errColOID + ".42": counter32PDU(errColOID+".42", 20),
		},
		descrColOID: {
			descrColOID + ".1":  stringPDU(descrColOID+".1", "eth0"),
			descrColOID + ".42": stringPDU(descrColOID+".42", "eth1"),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.ifouterrors"]
	require.Len(t, pts, 2)

	byRow := map[string]string{}
	for _, pt := range pts {
		byRow[attrValue(pt, "row_index")] = attrValue(pt, "if_desc")
	}
	assert.Equal(t, map[string]string{"1": "eth0", "42": "eth1"}, byRow)
}

// walk_full_table takes one walk of the table root and splits the answer by
// column prefix, which is the same comparison and fails the same way. A handful
// of profiles write their own OIDs with a leading dot, so the tag column here
// carries one the device's answer does not.
func TestCollectTarget_WalkFullTableIgnoresLeadingDot(t *testing.T) {
	const (
		host        = "10.0.0.13"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20"
		descrColOID = "1.3.6.1.2.1.2.2.1.2"
		sysObjValue = "1.3.6.1.4.1.9999.13"
	)
	p := profileWithOID(sysObjValue, "test13.yml", []profiles.MetricEntry{
		{
			Table:         &profiles.Table{Name: "ifTable", OID: tableOID},
			WalkFullTable: true,
			Symbols:       []profiles.Symbol{{Name: "ifOutErrors", OID: errColOID}},
			MetricTags:    []profiles.MetricTag{{Tag: "if_desc", Column: &profiles.TagColumn{OID: "." + descrColOID, Name: "ifDescr"}}},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		tableOID: {
			errColOID + ".7":   counter32PDU(errColOID+".7", 33),
			descrColOID + ".7": stringPDU(descrColOID+".7", "eth0"),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.ifouterrors"]
	require.Len(t, pts, 1)
	assert.Equal(t, "7", attrValue(pts[0], "row_index"))
	assert.Equal(t, "eth0", attrValue(pts[0], "if_desc"))
}

// A condition filters rows by another column's value, joined by row index.
func TestCollectTarget_ConditionJoinIgnoresLeadingDot(t *testing.T) {
	const (
		host        = "10.0.0.14"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20"
		operColOID  = "1.3.6.1.2.1.2.2.1.8"
		sysObjValue = "1.3.6.1.4.1.9999.14"
	)
	p := profileWithOID(sysObjValue, "test14.yml", []profiles.MetricEntry{
		{
			Table: &profiles.Table{Name: "ifTable", OID: tableOID},
			Symbols: []profiles.Symbol{
				{Name: "ifOperStatus", OID: operColOID},
				{Name: "ifOutErrors", OID: errColOID, Condition: "ifOperStatus=1"},
			},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		operColOID: {
			operColOID + ".1": intPDU(operColOID+".1", 1),
			operColOID + ".2": intPDU(operColOID+".2", 2),
		},
		errColOID: {
			errColOID + ".1": counter32PDU(errColOID+".1", 10),
			errColOID + ".2": counter32PDU(errColOID+".2", 20),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.ifouterrors"]
	require.Len(t, pts, 1, "only the row whose condition column equals 1 is emitted")
	assert.Equal(t, int64(10), pts[0].value)
	assert.Equal(t, "1", attrValue(pts[0], "row_index"))
}

// ---------------------------------------------------------------------------
// Per-policy device identity
// ---------------------------------------------------------------------------

func TestCollectTarget_PoliciesDoNotOverwriteEachOther(t *testing.T) {
	const (
		host        = "10.0.0.20"
		cpuOID      = "1.3.6.1.4.1.9999.20.1"
		sysObjValue = "1.3.6.1.4.1.9999.20"
	)
	p := profileWithOID(sysObjValue, "shared.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	makeWalker := func(v int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			cpuOID:         {cpuOID: intPDU(cpuOID, v)},
		}}
	}

	c := newCollector(nil, p)
	ctx := context.Background()

	c.clientFactory = walkerFactory(makeWalker(11))
	targetA := config.Target{Host: host, Port: 161, ID: "id-a"}
	require.NoError(t, c.CollectTarget(ctx, targetA, mustAuth(), "policy-a", DialOptions{}))

	c.clientFactory = walkerFactory(makeWalker(22))
	targetB := config.Target{Host: host, Port: 161, ID: "id-b"}
	require.NoError(t, c.CollectTarget(ctx, targetB, mustAuth(), "policy-b", DialOptions{}))

	storeA := c.testDeviceStoreKeyed(deviceKey{policy: "policy-a", host: host, port: 161, id: "id-a"})
	storeB := c.testDeviceStoreKeyed(deviceKey{policy: "policy-b", host: host, port: 161, id: "id-b"})
	require.Len(t, storeA["snmp.cpuutil"], 1)
	require.Len(t, storeB["snmp.cpuutil"], 1)
	assert.Equal(t, int64(11), storeA["snmp.cpuutil"][0].value)
	assert.Equal(t, int64(22), storeB["snmp.cpuutil"][0].value)
	assert.Equal(t, "id-a", attrValue(storeA["snmp.cpuutil"][0], "netbox_id"))
	assert.Equal(t, "id-b", attrValue(storeB["snmp.cpuutil"][0], "netbox_id"))

	// The two series would otherwise be indistinguishable at the OTLP endpoint.
	assert.Equal(t, "policy-a", attrValue(storeA["snmp.cpuutil"][0], "policy"))
	assert.Equal(t, "policy-b", attrValue(storeB["snmp.cpuutil"][0], "policy"))
}

func TestCollectTarget_SameHostDifferentPortStaysSeparate(t *testing.T) {
	const (
		host        = "10.0.0.21"
		cpuOID      = "1.3.6.1.4.1.9999.21.1"
		sysObjValue = "1.3.6.1.4.1.9999.21"
	)
	p := profileWithOID(sysObjValue, "ports.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	makeWalker := func(v int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			cpuOID:         {cpuOID: intPDU(cpuOID, v)},
		}}
	}

	c := newCollector(nil, p)
	ctx := context.Background()

	c.clientFactory = walkerFactory(makeWalker(5))
	require.NoError(t, c.CollectTarget(ctx, config.Target{Host: host, Port: 161}, mustAuth(), "p", DialOptions{}))
	c.clientFactory = walkerFactory(makeWalker(6))
	require.NoError(t, c.CollectTarget(ctx, config.Target{Host: host, Port: 1161}, mustAuth(), "p", DialOptions{}))

	c.storeMu.RLock()
	defer c.storeMu.RUnlock()
	assert.Equal(t, int64(5), c.deviceStore[deviceKey{policy: "p", host: host, port: 161}]["snmp.cpuutil"][0].value)
	assert.Equal(t, int64(6), c.deviceStore[deviceKey{policy: "p", host: host, port: 1161}]["snmp.cpuutil"][0].value)
}

func TestCollectTarget_PollStateIsPerPolicy(t *testing.T) {
	const (
		host        = "10.0.0.22"
		slowOID     = "1.3.6.1.4.1.9999.22.1"
		sysObjValue = "1.3.6.1.4.1.9999.22"
	)
	p := profileWithOID(sysObjValue, "throttled.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "slowMetric", OID: slowOID, PollTimeSec: 300}},
	})
	makeWalker := func(v int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			slowOID:        {slowOID: intPDU(slowOID, v)},
		}}
	}

	c := newCollector(nil, p)
	ctx := context.Background()

	c.clientFactory = walkerFactory(makeWalker(100))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "policy-a", DialOptions{}))

	// Policy B has never polled this OID, so the throttle must not apply and
	// policy A's value must not be carried into policy B's store.
	c.clientFactory = walkerFactory(makeWalker(999))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "policy-b", DialOptions{}))

	require.Len(t, c.testDeviceStore("policy-b", host)["snmp.slowmetric"], 1)
	assert.Equal(t, int64(999), c.testDeviceStore("policy-b", host)["snmp.slowmetric"][0].value)
}

// ---------------------------------------------------------------------------
// Forgetting: policy teardown and devices that stop responding
// ---------------------------------------------------------------------------

func TestForgetPolicy_DropsOnlyThatPolicy(t *testing.T) {
	const (
		hostA       = "10.0.0.30"
		hostB       = "10.0.0.31"
		cpuOID      = "1.3.6.1.4.1.9999.30.1"
		sysObjValue = "1.3.6.1.4.1.9999.30"
	)
	p := profileWithOID(sysObjValue, "forget.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID, PollTimeSec: 300}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 7)},
	}}
	c := newCollector(walkerFactory(w), p)
	ctx := context.Background()

	require.NoError(t, c.CollectTarget(ctx, mustTarget(hostA), mustAuth(), "doomed", DialOptions{}))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(hostB), mustAuth(), "keeper", DialOptions{}))
	require.NotEmpty(t, c.testDeviceStore("doomed", hostA))
	require.NotEmpty(t, c.testDeviceStore("keeper", hostB))

	c.ForgetPolicy("doomed")

	assert.Nil(t, c.testDeviceStore("doomed", hostA), "the stopped policy must stop exporting")
	assert.NotEmpty(t, c.testDeviceStore("keeper", hostB), "another policy's devices must survive")

	// The poll timestamps go too, so a policy restarted under the same name
	// polls a throttled OID immediately instead of waiting out the old window.
	c.pollMu.Lock()
	_, doomedPolls := c.pollState[testKey("doomed", hostA)]
	_, keeperPolls := c.pollState[testKey("keeper", hostB)]
	c.pollMu.Unlock()
	assert.False(t, doomedPolls)
	assert.True(t, keeperPolls)
}

func TestCollectTarget_FailedDeviceStopsExporting(t *testing.T) {
	const (
		host        = "10.0.0.32"
		cpuOID      = "1.3.6.1.4.1.9999.32.1"
		sysObjValue = "1.3.6.1.4.1.9999.32"
	)
	p := profileWithOID(sysObjValue, "dead.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 42)},
	}}
	c := newCollector(walkerFactory(w), p)
	ctx := context.Background()

	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.Len(t, c.testDeviceStore("p", host)["snmp.cpuutil"], 1)

	// The device stops answering: the dial itself now fails.
	c.clientFactory = func(_ context.Context, _ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return nil, assert.AnError
	}
	require.Error(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	assert.Nil(t, c.testDeviceStore("p", host), "a device that fails to collect must not keep exporting its last values")
}

func TestCollectTarget_ProfileStopsMatchingClearsStore(t *testing.T) {
	const (
		host        = "10.0.0.33"
		cpuOID      = "1.3.6.1.4.1.9999.33.1"
		sysObjValue = "1.3.6.1.4.1.9999.33"
	)
	p := profileWithOID(sysObjValue, "match.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	makeWalker := func(sysObj string) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObj)},
			sysDescrOID:    {},
			cpuOID:         {cpuOID: intPDU(cpuOID, 42)},
		}}
	}
	c := newCollector(walkerFactory(makeWalker(sysObjValue)), p)
	ctx := context.Background()

	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.Len(t, c.testDeviceStore("p", host)["snmp.cpuutil"], 1)

	// The address is reassigned to a device no profile covers.
	c.clientFactory = walkerFactory(makeWalker("1.3.6.1.4.1.1234"))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}))
	assert.Nil(t, c.testDeviceStore("p", host))
}

// ---------------------------------------------------------------------------
// Per-dial settings
// ---------------------------------------------------------------------------

func TestCollectTarget_UsesCallerDialOptions(t *testing.T) {
	const (
		host        = "10.0.0.40"
		sysObjValue = "1.3.6.1.4.1.9999.40"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
	}}
	var gotTimeout time.Duration
	var gotRetries int
	c := newCollector(func(_ context.Context, _ string, _ uint16, retries int, timeout time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		gotTimeout, gotRetries = timeout, retries
		return w, nil
	}, nil)

	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(),
		"p", DialOptions{Timeout: 9 * time.Second, Retries: 3}))
	assert.Equal(t, 9*time.Second, gotTimeout)
	assert.Equal(t, 3, gotRetries)
}

// ---------------------------------------------------------------------------
// Deadline handling
// ---------------------------------------------------------------------------

// A grouped `symbols:` entry can carry dozens of symbols, so a run whose
// deadline expires partway through one must not keep polling the rest: the
// bundled environment-monitor entry alone would cost 80-odd further per-request
// timeouts against an unresponsive device, and policy shutdown waits on them.
func TestCollectTarget_GroupedScalarsStopAtTheDeadline(t *testing.T) {
	const (
		host        = "10.0.0.50"
		sysObjValue = "1.3.6.1.4.1.9999.50"
		colOID      = "1.3.6.1.4.1.9999.50.1."
	)
	syms := make([]profiles.Symbol, 5)
	responses := map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
	}
	for i := range syms {
		oid := fmt.Sprintf("%s%d.0", colOID, i)
		syms[i] = profiles.Symbol{Name: fmt.Sprintf("sensor%d", i), OID: oid}
		responses[oid] = map[string]snmp.PDU{oid: intPDU(oid, i)}
	}
	p := profileWithOID(sysObjValue, "grouped.yml", []profiles.MetricEntry{{Symbols: syms}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &recordingWalker{responses: responses}
	w.onWalk = func(oid string) {
		if oid == syms[0].OID {
			cancel()
		}
	}

	c := newCollector(walkerFactory(w), p)
	err := c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{})
	require.ErrorIs(t, err, context.Canceled)

	assert.Contains(t, w.walkCalls, syms[0].OID)
	for _, sym := range syms[1:] {
		assert.NotContains(t, w.walkCalls, sym.OID, "a symbol polled after the deadline expired")
	}
}

// The profile-level metric_tags are walked one column at a time before any
// metric is collected, and a profile declares up to a dozen of them.
func TestCollectTarget_DeviceTagsStopAtTheDeadline(t *testing.T) {
	const (
		host        = "10.0.0.51"
		sysObjValue = "1.3.6.1.4.1.9999.51"
		contactOID  = "1.3.6.1.2.1.1.4.0"
		nameOID     = "1.3.6.1.2.1.1.5.0"
		locationOID = "1.3.6.1.2.1.1.6.0"
		cpuOID      = "1.3.6.1.4.1.9999.51.1"
	)
	p := profileWithOID(sysObjValue, "tags.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	p.MetricTags = []profiles.MetricTag{
		{Column: &profiles.TagColumn{OID: contactOID, Name: "SysContact"}},
		{Column: &profiles.TagColumn{OID: nameOID, Name: "SysName"}},
		{Column: &profiles.TagColumn{OID: locationOID, Name: "SysLocation"}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		contactOID:     {contactOID: stringPDU(contactOID, "noc@example.com")},
		nameOID:        {nameOID: stringPDU(nameOID, "sensor-1")},
		locationOID:    {locationOID: stringPDU(locationOID, "rack 4")},
		cpuOID:         {cpuOID: intPDU(cpuOID, 42)},
	}}
	w.onWalk = func(oid string) {
		if oid == contactOID {
			cancel()
		}
	}

	c := newCollector(walkerFactory(w), p)
	err := c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{})
	require.ErrorIs(t, err, context.Canceled)

	assert.NotContains(t, w.walkCalls, nameOID, "a device tag walked after the deadline expired")
	assert.NotContains(t, w.walkCalls, locationOID, "a device tag walked after the deadline expired")
	assert.NotContains(t, w.walkCalls, cpuOID)
}

// ---------------------------------------------------------------------------
// Exported identity
// ---------------------------------------------------------------------------

// The exported attribute set has to carry every dimension the internal device
// key does. Two agents on one host differ only by port, so without it they key
// apart internally and export the same attribute set: the observable gauge then
// receives two points for one series and one endpoint's value is lost.
func TestCollectTarget_ExportedAttrsCarryEveryKeyDimension(t *testing.T) {
	const (
		host        = "10.0.0.52"
		cpuOID      = "1.3.6.1.4.1.9999.52.1"
		sysObjValue = "1.3.6.1.4.1.9999.52"
	)
	p := profileWithOID(sysObjValue, "identity.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	makeWalker := func(v int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			cpuOID:         {cpuOID: intPDU(cpuOID, v)},
		}}
	}

	c := newCollector(nil, p)
	ctx := context.Background()

	c.clientFactory = walkerFactory(makeWalker(5))
	require.NoError(t, c.CollectTarget(ctx, config.Target{Host: host, Port: 161}, mustAuth(), "p", DialOptions{}))
	c.clientFactory = walkerFactory(makeWalker(6))
	require.NoError(t, c.CollectTarget(ctx, config.Target{Host: host, Port: 1161}, mustAuth(), "p", DialOptions{}))

	c.storeMu.RLock()
	defer c.storeMu.RUnlock()
	for _, key := range []deviceKey{
		{policy: "p", host: host, port: 161},
		{policy: "p", host: host, port: 1161},
	} {
		pts := c.deviceStore[key]["snmp.cpuutil"]
		require.Len(t, pts, 1)
		assert.Equal(t, key.host, attrValue(pts[0], "device_ip"))
		assert.Equal(t, key.policy, attrValue(pts[0], "policy"))
		assert.Equal(t, int64(key.port), attrInt(pts[0], "device_port"),
			"the exported identity must carry the port the internal key does")
	}
}

// keyDimensionAttrs names the exported attribute that carries each field of
// deviceKey. A dimension added to the internal key without an attribute here
// fails TestDeviceKey_EveryDimensionIsExported, which is what keeps the key and
// the exported series in step.
var keyDimensionAttrs = map[string]string{
	"policy":  "policy",
	"host":    "device_ip",
	"port":    "device_port",
	"id":      "netbox_id",
	"context": "snmp_context",
}

// TestDeviceKey_EveryDimensionIsExported fails when deviceKey gains a field the
// exported attribute set does not name. Two devices the collector keeps apart
// internally have to be distinguishable in the series it exports, or one
// device's points land on the other's attribute set.
func TestDeviceKey_EveryDimensionIsExported(t *testing.T) {
	typ := reflect.TypeOf(deviceKey{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		assert.Contains(t, keyDimensionAttrs, name,
			"deviceKey.%s distinguishes two devices but no exported attribute carries it", name)
	}
	assert.Len(t, keyDimensionAttrs, typ.NumField(),
		"keyDimensionAttrs names an attribute for a field deviceKey no longer has")
}

// TestCollectTarget_SameEndpointTwiceInOnePolicy covers a policy that targets
// one host and port more than once. The entries differ only by NetBox ID and by
// SNMPv3 context name, and each has to keep its own observations and its own
// exported attribute set.
func TestCollectTarget_SameEndpointTwiceInOnePolicy(t *testing.T) {
	const (
		host        = "10.0.0.70"
		cpuOID      = "1.3.6.1.4.1.9999.70.1"
		sysObjValue = "1.3.6.1.4.1.9999.70"
	)
	p := profileWithOID(sysObjValue, "sameendpoint.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	makeWalker := func(v int) *recordingWalker {
		return &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			cpuOID:         {cpuOID: intPDU(cpuOID, v)},
		}}
	}
	v3 := func(ctxName string) *config.Authentication {
		return &config.Authentication{ProtocolVersion: "SNMPv3", Username: "poller", ContextName: ctxName}
	}

	runs := []struct {
		target  config.Target
		auth    *config.Authentication
		value   int
		wantKey deviceKey
	}{
		{
			target: config.Target{Host: host, Port: 161, ID: "11"}, auth: v3("vlan-100"), value: 1,
			wantKey: deviceKey{policy: "p", host: host, port: 161, id: "11", context: "vlan-100"},
		},
		{
			target: config.Target{Host: host, Port: 161, ID: "22"}, auth: v3("vlan-100"), value: 2,
			wantKey: deviceKey{policy: "p", host: host, port: 161, id: "22", context: "vlan-100"},
		},
		{
			target: config.Target{Host: host, Port: 161, ID: "11"}, auth: v3("vlan-200"), value: 3,
			wantKey: deviceKey{policy: "p", host: host, port: 161, id: "11", context: "vlan-200"},
		},
	}

	c := newCollector(nil, p)
	for _, run := range runs {
		c.clientFactory = walkerFactory(makeWalker(run.value))
		require.NoError(t, c.CollectTarget(context.Background(), run.target, run.auth, "p", DialOptions{}))
	}

	c.storeMu.RLock()
	defer c.storeMu.RUnlock()
	require.Len(t, c.deviceStore, len(runs), "each entry keeps its own observations")
	for _, run := range runs {
		pts := c.deviceStore[run.wantKey]["snmp.cpuutil"]
		require.Len(t, pts, 1, "%+v", run.wantKey)
		assert.Equal(t, int64(run.value), pts[0].value, "a later run must not replace an earlier one")
		assert.Equal(t, run.target.ID, attrValue(pts[0], "netbox_id"))
		assert.Equal(t, run.auth.ContextName, attrValue(pts[0], "snmp_context"))
	}
}

// TestCollectTarget_AbsentDimensionsAreNotExported keeps the attribute set free
// of empty dimensions: a target with no NetBox ID and no context name exports
// neither attribute.
func TestCollectTarget_AbsentDimensionsAreNotExported(t *testing.T) {
	const (
		host        = "10.0.0.71"
		cpuOID      = "1.3.6.1.4.1.9999.71.1"
		sysObjValue = "1.3.6.1.4.1.9999.71"
	)
	p := profileWithOID(sysObjValue, "absentdims.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 7)},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.cpuutil"]
	require.Len(t, pts, 1)
	for _, kv := range pts[0].attrs {
		assert.NotEqual(t, "netbox_id", string(kv.Key))
		assert.NotEqual(t, "snmp_context", string(kv.Key))
	}
}

// attrInt returns the int value of one attribute on an observation, or -1.
func attrInt(pt observedPoint, key string) int64 {
	for _, kv := range pt.attrs {
		if string(kv.Key) == key {
			return kv.Value.AsInt64()
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// Table joins driven by index_transform, against the bundled Juniper profiles
// ---------------------------------------------------------------------------

// bundledProfile resolves one profile out of the set embedded in the binary.
func bundledProfile(t *testing.T, relPath string) *profiles.Profile {
	t.Helper()
	loader, err := profiles.LoadProfiles("", discardLogger)
	require.NoError(t, err)
	p, err := loader.Resolve(relPath)
	require.NoError(t, err)
	return p
}

// TestCollectTarget_IndexTransformJoinsAcrossTables exercises the DCU table in
// the bundled SRX profile. Its rows are indexed by ifIndex, address family and
// class name, while the ifName column it tags them from is indexed by ifIndex
// alone, so the join only lands if the index_transform is applied first.
func TestCollectTarget_IndexTransformJoinsAcrossTables(t *testing.T) {
	const (
		dcuPackets = "1.3.6.1.4.1.2636.3.6.2.1.4"
		ifName     = "1.3.6.1.2.1.31.1.1.1.1"
		// ifIndex 547, address family 1, class name "gold".
		rowGold = "547.1.4.103.111.108.100"
		// ifIndex 548, address family 2, class name "silver".
		rowSilver = "548.2.6.115.105.108.118.101.114"
	)

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {
			sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.2636.1.1.1.2.135"),
		},
		dcuPackets: {
			dcuPackets + "." + rowGold:   counter64PDU(dcuPackets+"."+rowGold, 111),
			dcuPackets + "." + rowSilver: counter64PDU(dcuPackets+"."+rowSilver, 222),
		},
		ifName: {
			ifName + ".547": stringPDU(ifName+".547", "ge-0/0/0"),
			ifName + ".548": stringPDU(ifName+".548", "ge-0/0/1"),
		},
	}}

	c := newCollector(walkerFactory(w), bundledProfile(t, "juniper/juniper-srx-firewalls.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p1", DialOptions{}))

	points := c.testDeviceStore("p1", "10.0.0.1")["snmp.jnxdcustatspackets"]
	require.Len(t, points, 2)

	got := make(map[string]string, len(points))
	for _, pt := range points {
		var rowIdx, name string
		for _, a := range pt.attrs {
			switch a.Key {
			case "row_index":
				rowIdx = a.Value.AsString()
			case "if_interface_name":
				name = a.Value.AsString()
			}
		}
		got[rowIdx] = name
	}
	assert.Equal(t, map[string]string{rowGold: "ge-0/0/0", rowSilver: "ge-0/0/1"}, got)
}

// TestCollectTarget_IndexTransformSkipsRowWithNoMatch checks that a metric row
// whose transformed index names no row in the other table keeps its metric and
// simply carries no joined attribute.
func TestCollectTarget_IndexTransformSkipsRowWithNoMatch(t *testing.T) {
	const (
		dcuPackets = "1.3.6.1.4.1.2636.3.6.2.1.4"
		ifName     = "1.3.6.1.2.1.31.1.1.1.1"
		row        = "999.1.4.103.111.108.100"
	)

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {
			sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.2636.1.1.1.2.135"),
		},
		dcuPackets: {
			dcuPackets + "." + row: counter64PDU(dcuPackets+"."+row, 7),
		},
		ifName: {
			ifName + ".547": stringPDU(ifName+".547", "ge-0/0/0"),
		},
	}}

	c := newCollector(walkerFactory(w), bundledProfile(t, "juniper/juniper-srx-firewalls.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p1", DialOptions{}))

	points := c.testDeviceStore("p1", "10.0.0.1")["snmp.jnxdcustatspackets"]
	require.Len(t, points, 1)
	for _, a := range points[0].attrs {
		assert.NotEqual(t, "if_interface_name", string(a.Key))
	}
}

// ---------------------------------------------------------------------------
// Conversions the collector does not implement
// ---------------------------------------------------------------------------

// TestCollectTarget_UnsupportedConversionIsReportedOnce uses the bundled APC UPS
// profile, whose upsBasicStateOutputState symbol declares powerset_status. The
// collector has no branch for it, so the metric is skipped; the operator has to
// be told which conversion, symbol and profile caused that, and told only once.
func TestCollectTarget_UnsupportedConversionIsReportedOnce(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.318.1.3.2.11")},
	}}
	p := bundledProfile(t, "apc/apc_ups.yml")
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)

	// Three runs across two devices: the report is bounded by the profile, not
	// by the device or the collection cycle.
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p1", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p1", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.2"), mustAuth(), "p1", DialOptions{}))

	var matched []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, "powerset_status") {
			matched = append(matched, line)
		}
	}
	require.Len(t, matched, 1, "logs: %s", logs.String())
	assert.Contains(t, matched[0], "conversion=powerset_status")
	assert.Contains(t, matched[0], "symbol=upsBasicStateOutputState")
	assert.Contains(t, matched[0], "profile=apc/apc_ups.yml")
	assert.Contains(t, matched[0], "oid=1.3.6.1.4.1.318.1.1.1.11.1.1.0")
}

// TestCollectTarget_SupportedConversionsAreNotReported keeps the report honest:
// every conversion pduToValue implements must stay silent.
func TestCollectTarget_SupportedConversionsAreNotReported(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	symbols := []profiles.Symbol{
		{Name: "plain", OID: "1.3.6.1.4.1.99.1.1.0"},
		{Name: "toOne", OID: "1.3.6.1.4.1.99.1.2.0", Conversion: "to_one"},
		{Name: "hexToIP", OID: "1.3.6.1.4.1.99.1.3.0", Conversion: "hextoip"},
		{Name: "hwAddr", OID: "1.3.6.1.4.1.99.1.4.0", Conversion: "hwaddr"},
		{Name: "hexToInt", OID: "1.3.6.1.4.1.99.1.5.0", Conversion: "hextoint:BigEndian:uint16"},
		{Name: "regexp", OID: "1.3.6.1.4.1.99.1.6.0", Conversion: "regexp:(\\d+)"},
		{Name: "unknown", OID: "1.3.6.1.4.1.99.1.7.0", Conversion: "some_future_conversion"},
	}
	p := profileWithOID("1.3.6.1.4.1.99", "future.yml", []profiles.MetricEntry{{MIB: "TEST-MIB", Symbols: symbols}})

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.99")},
	}}
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p1", DialOptions{}))

	// A conversion the collector has never heard of surfaces on its own, with
	// no branch added for it.
	assert.Contains(t, logs.String(), "conversion=some_future_conversion")
	for _, sym := range symbols {
		if sym.Name == "unknown" {
			continue
		}
		assert.NotContains(t, logs.String(), "symbol="+sym.Name, "supported conversion %q was reported", sym.Conversion)
	}
}

// The once-per-profile review reports a symbol whose conversion pduToValue does
// not implement as a skipped metric. The numeric branches of pduToValue never
// read the conversion, so an Integer, Counter, Gauge or TimeTicks PDU was
// exported raw under a metric the operator had just been told was absent: a
// value scaled by nothing beside a report claiming nothing shipped.
func TestCollectTarget_UnsupportedConversionOnAScalarExportsNothing(t *testing.T) {
	const (
		host         = "10.0.0.71"
		plainOID     = "1.3.6.1.4.1.99.7.1.0"
		convertedOID = "1.3.6.1.4.1.99.7.2.0"
		sysObjValue  = "1.3.6.1.4.1.99.7"
	)
	p := profileWithOID(sysObjValue, "unsupported-scalar.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "plainLoad", OID: plainOID}},
		{Symbol: &profiles.Symbol{Name: "scaledLoad", OID: convertedOID, Conversion: "powerset_status"}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
		plainOID:       {plainOID: intPDU(plainOID, 7)},
		convertedOID:   {convertedOID: intPDU(convertedOID, 42)},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Empty(t, store["snmp.scaledload"], "a conversion the collector cannot apply must export nothing")
	assert.NotContains(t, w.walkCalls, convertedOID, "the symbol is skipped before it is walked")

	require.Len(t, store["snmp.plainload"], 1, "a symbol declaring no conversion is untouched")
	assert.Equal(t, int64(7), store["snmp.plainload"][0].value)
	assert.Contains(t, w.walkCalls, plainOID)
}

// The table path gates the same symbols as the scalar one, so a column
// declaring a conversion the collector cannot apply emits no rows.
func TestCollectTarget_UnsupportedConversionOnATableColumnExportsNothing(t *testing.T) {
	const (
		host        = "10.0.0.72"
		tableOID    = "1.3.6.1.4.1.99.8.1"
		plainCol    = "1.3.6.1.4.1.99.8.1.1.2"
		scaledCol   = "1.3.6.1.4.1.99.8.1.1.3"
		descrCol    = "1.3.6.1.4.1.99.8.1.1.4"
		sysObjValue = "1.3.6.1.4.1.99.8"
	)
	p := profileWithOID(sysObjValue, "unsupported-table.yml", []profiles.MetricEntry{
		{
			Table: &profiles.Table{Name: "sensorTable", OID: tableOID},
			Symbols: []profiles.Symbol{
				{Name: "sensorReading", OID: plainCol},
				{Name: "sensorScaled", OID: scaledCol, Conversion: "powerset_status"},
			},
			MetricTags: []profiles.MetricTag{
				{Tag: "sensor_name", Column: &profiles.TagColumn{OID: descrCol, Name: "sensorDescr"}},
			},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
		plainCol:       {plainCol + ".1": intPDU(plainCol+".1", 7)},
		scaledCol:      {scaledCol + ".1": counter32PDU(scaledCol+".1", 42)},
		descrCol:       {descrCol + ".1": stringPDU(descrCol+".1", "inlet")},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Empty(t, store["snmp.sensorscaled"], "a conversion the collector cannot apply must export no rows")
	assert.NotContains(t, w.walkCalls, scaledCol, "the column is skipped before it is walked")

	require.Len(t, store["snmp.sensorreading"], 1, "the sibling column is untouched")
	assert.Equal(t, int64(7), store["snmp.sensorreading"][0].value)
	assert.Equal(t, "inlet", attrValue(store["snmp.sensorreading"][0], "sensor_name"))
}

// TestCollectTarget_BundledUnsupportedConversionIsNotCollected pins the one
// bundled declaration the review names: the APC UPS output state, whose
// powerset_status conversion enumerates a bit field this collector cannot read.
func TestCollectTarget_BundledUnsupportedConversionIsNotCollected(t *testing.T) {
	const stateOID = "1.3.6.1.4.1.318.1.1.1.11.1.1.0"

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.318.1.3.2.11")},
		stateOID:       {stateOID: intPDU(stateOID, 3)},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "apc/apc_ups.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.73"), mustAuth(), "p", DialOptions{}))

	assert.Empty(t, c.testDeviceStore("p", "10.0.0.73")["snmp.upsbasicstateoutputstate"])
	assert.NotContains(t, w.walkCalls, stateOID)
}

// A numeric conversion the collector does implement stays on the numeric path,
// so the gate cannot be the OctetString branch's list of conversions.
func TestCollectTarget_ToOneOnANumericPDUIsStillCollected(t *testing.T) {
	const (
		host        = "10.0.0.74"
		stateOID    = "1.3.6.1.4.1.99.9.1.0"
		sysObjValue = "1.3.6.1.4.1.99.9"
	)
	p := profileWithOID(sysObjValue, "to-one-numeric.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "linkState", OID: stateOID, Conversion: "to_one"}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
		stateOID:       {stateOID: intPDU(stateOID, 2)},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.linkstate"]
	require.Len(t, pts, 1, "to_one is implemented for every PDU type")
	assert.Equal(t, int64(1), pts[0].value)
	assert.Equal(t, "2", attrValue(pts[0], "linkState_value"))
}

// ---------------------------------------------------------------------------
// Symbols the collector cannot collect at all
// ---------------------------------------------------------------------------

// TestCollectTarget_SymbolWithNoOIDIsNotWalked uses the bundled Call Manager
// profile, whose SIP trunk entry ends in a symbol with an empty OID. gosnmp
// reads an empty root as the whole .1.3.6.1 subtree, so issuing that walk one
// PDU at a time can burn the entire collection deadline, and the run that
// misses the deadline leaves nothing behind for the device.
func TestCollectTarget_SymbolWithNoOIDIsNotWalked(t *testing.T) {
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.9.1.1348")},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "cisco/cisco-call-manager.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p1", DialOptions{}))

	for _, oid := range w.walkCalls {
		require.NotEqual(t, "", oid, "an empty OID was walked, which gosnmp reads as the whole tree")
	}
}

// TestCollectTarget_SymbolWithNoOIDIsReportedOnce checks the operator is told
// which profile carries the malformed symbol, and told once for the life of the
// process rather than on every collection cycle.
func TestCollectTarget_SymbolWithNoOIDIsReportedOnce(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.9.1.1348")},
	}}
	p := bundledProfile(t, "cisco/cisco-call-manager.yml")
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)

	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p1", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.2"), mustAuth(), "p1", DialOptions{}))

	var matched []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, "declares no OID") {
			matched = append(matched, line)
		}
	}
	require.Len(t, matched, 1, "logs: %s", logs.String())
	assert.Contains(t, matched[0], "profile=cisco/cisco-call-manager.yml")
}

// TestCollectTarget_SymbolWithNoOIDIsNotCollected pins the scalar path too: a
// symbol with no OID produces no request and no metric.
func TestCollectTarget_SymbolWithNoOIDIsNotCollected(t *testing.T) {
	const (
		host        = "10.0.0.70"
		goodOID     = "1.3.6.1.4.1.9999.70.1.0"
		sysObjValue = "1.3.6.1.4.1.9999.70"
	)
	p := profileWithOID(sysObjValue, "empty-oid.yml", []profiles.MetricEntry{
		{MIB: "TEST-MIB", Symbol: &profiles.Symbol{Name: "goodMetric", OID: goodOID}},
		{MIB: "TEST-MIB", Symbol: &profiles.Symbol{Name: "brokenMetric"}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		goodOID:        {goodOID: intPDU(goodOID, 4)},
	}}
	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	require.Len(t, store["snmp.goodmetric"], 1)
	assert.Empty(t, store["snmp.brokenmetric"])
	assert.NotContains(t, w.walkCalls, "")
}

// A scalar symbol's tag is the name of its metric, and of the attributes
// derived from that name. Nothing carries an attribute called `tag`: upstream
// produces no such dimension, and the name is where the tag goes.
func TestCollectTarget_ScalarSymbolTagNamesTheMetricAndItsAttributes(t *testing.T) {
	const (
		host        = "10.0.0.91"
		sysObjValue = "1.3.6.1.4.1.9999.91"
		stateOID    = "1.3.6.1.4.1.9999.91.1.0"
		detailOID   = "1.3.6.1.4.1.9999.91.2.0"
	)
	p := profileWithOID(sysObjValue, "tagged-scalar.yml", []profiles.MetricEntry{
		{MIB: "TEST-MIB", Symbol: &profiles.Symbol{
			Name: "vendorOutputState",
			OID:  stateOID,
			Tag:  "failover_status",
			Enum: profiles.Enum{Values: map[string]int{"onLine": 2, "onBattery": 3}},
		}},
		{MIB: "TEST-MIB", Symbol: &profiles.Symbol{
			Name:       "vendorStateDetail",
			OID:        detailOID,
			Tag:        "temp_state",
			Conversion: "to_one",
		}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		stateOID:       {stateOID: intPDU(stateOID, 3)},
		detailOID:      {detailOID: stringPDU(detailOID, "over threshold")},
	}}
	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Empty(t, store["snmp.vendoroutputstate"], "the declared name names no metric once a tag is declared")
	assert.Empty(t, store["snmp.vendorstatedetail"])

	state := store["snmp.failover_status"]
	require.Len(t, state, 1)
	assert.Equal(t, int64(3), state[0].value)
	assert.Equal(t, "onBattery", attrValue(state[0], "failover_status_status"),
		"the enum label follows the metric name")
	assert.Empty(t, attrValue(state[0], "vendorOutputState_status"))
	assert.Empty(t, attrValue(state[0], "tag"))

	detail := store["snmp.temp_state"]
	require.Len(t, detail, 1)
	assert.Equal(t, int64(1), detail[0].value)
	assert.Equal(t, "over threshold", attrValue(detail[0], "temp_state_value"),
		"the converted text follows the metric name")
	assert.Empty(t, attrValue(detail[0], "vendorStateDetail_value"))
	assert.Empty(t, attrValue(detail[0], "tag"))
}

// The bundled IF-MIB profile tags ifOperStatus `if_OperStatus`, and 146
// resolved profiles inherit it. The tag names the metric and the enum label
// alike, on the table path as on the scalar one.
func TestCollectTarget_BundledIfOperStatusTagNamesTheMetricAndItsEnumLabel(t *testing.T) {
	const (
		host       = "10.0.0.92"
		operColOID = "1.3.6.1.2.1.2.2.1.8"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.43.1.8.20")},
		operColOID: {
			operColOID + ".1": intPDU(operColOID+".1", 1),
			operColOID + ".2": intPDU(operColOID+".2", 2),
		},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "3com/3com.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Empty(t, store["snmp.ifoperstatus"], "the declared name names no metric once a tag is declared")

	byIndex := map[string]string{}
	for _, pt := range store["snmp.if_operstatus"] {
		byIndex[attrValue(pt, "row_index")] = attrValue(pt, "if_OperStatus_status")
		assert.Empty(t, attrValue(pt, "ifOperStatus_status"))
		assert.Empty(t, attrValue(pt, "tag"))
	}
	assert.Equal(t, map[string]string{"1": "up", "2": "down"}, byIndex)
}

// TestCollectTarget_ScriptedSymbolIsSkipped uses the bundled UniFi profile,
// whose loadValue symbol carries a script dividing the reading by 100 and a
// `CPU` tag. The collector runs no scripts, so exporting the raw reading under
// that tag would ship a per-mille number labelled as a percentage. The metric
// is left out instead.
func TestCollectTarget_ScriptedSymbolIsSkipped(t *testing.T) {
	const (
		host     = "10.0.0.90"
		loadOID  = "1.3.6.1.4.1.10002.1.1.1.4.2.1.3.1"
		memTotal = "1.3.6.1.4.1.10002.1.1.1.1.1.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.41112")},
		loadOID:        {loadOID: intPDU(loadOID, 4200)},
		memTotal:       {memTotal: intPDU(memTotal, 512)},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "ubiquiti/unifi-access-point.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Empty(t, store["snmp.cpu"], "a scripted symbol must not export its untransformed value")
	assert.NotContains(t, w.walkCalls, loadOID, "a symbol that cannot be exported must not be walked")
	require.Len(t, store["snmp.memorytotal"], 1, "the rest of the profile must still be collected")
}

// TestCollectTarget_ScriptedSymbolIsReportedOnce names the profile and symbol
// that stop being exported, once for the life of the process.
func TestCollectTarget_ScriptedSymbolIsReportedOnce(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.41112")},
	}}
	p := bundledProfile(t, "ubiquiti/unifi-access-point.yml")
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)

	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "p", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.2"), mustAuth(), "p", DialOptions{}))

	var matched []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, "declares a script") {
			matched = append(matched, line)
		}
	}
	require.Len(t, matched, 1, "logs: %s", logs.String())
	assert.Contains(t, matched[0], "symbol=loadValue")
	assert.Contains(t, matched[0], "profile=ubiquiti/unifi-access-point.yml")
}

// ---------------------------------------------------------------------------
// Row filters declared by match_attributes on a tag column
// ---------------------------------------------------------------------------

// filterProfile builds a one-table profile whose rows are tagged from nameOID
// and filtered by patterns.
func filterProfile(sysObjValue, metricOID, nameOID string, patterns []string) *profiles.Profile {
	return profileWithOID(sysObjValue, "filter.yml", []profiles.MetricEntry{{
		MIB:     "TEST-MIB",
		Table:   &profiles.Table{Name: "testTable", OID: sysObjValue},
		Symbols: []profiles.Symbol{{Name: "rowValue", OID: metricOID}},
		MetricTags: []profiles.MetricTag{{
			Tag:    "row_name",
			Column: &profiles.TagColumn{OID: nameOID, Name: "rowName", MatchAttributes: patterns},
		}},
	}})
}

// filteredValues reads the rowValue points a filterProfile collection produced,
// keyed by the row name each carries.
func filteredValues(t *testing.T, c *MetricsCollector, host string) map[string]int64 {
	t.Helper()
	got := make(map[string]int64)
	for _, pt := range c.testDeviceStore("p", host)["snmp.rowvalue"] {
		name := ""
		for _, a := range pt.attrs {
			if a.Key == "row_name" {
				name = a.Value.AsString()
			}
		}
		got[name] = pt.value
	}
	return got
}

// TestCollectTarget_MatchAttributesFiltersRows uses the bundled H3C switch
// profile. Its CPU and memory entry declares match_attributes ["Board"] on the
// entPhysicalName column, and the profile's own comment on the next entry calls
// that "the Board filter". Without it every entity row reports as the switch's
// CPU and memory.
func TestCollectTarget_MatchAttributesFiltersRows(t *testing.T) {
	const (
		host        = "10.0.0.100"
		sysObjValue = "1.3.6.1.4.1.25506.11.1.123"
		cpuCol      = "1.3.6.1.4.1.25506.2.6.1.1.1.1.6"
		tempCol     = "1.3.6.1.4.1.25506.2.6.1.1.1.1.12"
		nameCol     = "1.3.6.1.2.1.47.1.1.1.1.7"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
		cpuCol:         {cpuCol + ".1": intPDU(cpuCol+".1", 30), cpuCol + ".2": intPDU(cpuCol+".2", 70)},
		tempCol:        {tempCol + ".1": intPDU(tempCol+".1", 40), tempCol + ".2": intPDU(tempCol+".2", 41)},
		nameCol: {
			nameCol + ".1": stringPDU(nameCol+".1", "Board 0"),
			nameCol + ".2": stringPDU(nameCol+".2", "GigabitEthernet1/0/1"),
		},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "hp/hp-h3c-switch.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	cpu := store["snmp.cpu"]
	require.Len(t, cpu, 1, "only the board row carries the switch CPU")
	assert.Equal(t, int64(30), cpu[0].value)

	// The sibling entry reads the same table without the filter, so its rows
	// must all survive. This is what keeps the filter from becoming global.
	assert.Len(t, store["snmp.temperature"], 2, "the unfiltered entry must keep every row")
}

// TestCollectTarget_MatchAttributesIsAnOrOverPatterns pins that a row is kept
// when it matches any one of the listed patterns.
func TestCollectTarget_MatchAttributesIsAnOrOverPatterns(t *testing.T) {
	const (
		host        = "10.0.0.101"
		sysObjValue = "1.3.6.1.4.1.9999.101"
		metricOID   = sysObjValue + ".1.1"
		nameOID     = sysObjValue + ".1.2"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		metricOID: {
			metricOID + ".1": intPDU(metricOID+".1", 1),
			metricOID + ".2": intPDU(metricOID+".2", 2),
			metricOID + ".3": intPDU(metricOID+".3", 3),
		},
		nameOID: {
			nameOID + ".1": stringPDU(nameOID+".1", "alpha-1"),
			nameOID + ".2": stringPDU(nameOID+".2", "beta-2"),
			nameOID + ".3": stringPDU(nameOID+".3", "gamma-3"),
		},
	}}
	c := newCollector(walkerFactory(w), filterProfile(sysObjValue, metricOID, nameOID, []string{"alpha", "beta"}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, map[string]int64{"alpha-1": 1, "beta-2": 2}, filteredValues(t, c, host))
}

// TestCollectTarget_MatchAttributesMatchesAnywhereInTheValue pins the rule the
// bundled uses need: ktranslate compiles each entry as a regular expression and
// matches it unanchored, so "Board" selects a row named "Board 0". Anchored
// equality would drop every bundled row the filter is there to keep.
func TestCollectTarget_MatchAttributesMatchesAnywhereInTheValue(t *testing.T) {
	const (
		host        = "10.0.0.102"
		sysObjValue = "1.3.6.1.4.1.9999.102"
		metricOID   = sysObjValue + ".1.1"
		nameOID     = sysObjValue + ".1.2"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		metricOID: {
			metricOID + ".1": intPDU(metricOID+".1", 1),
			metricOID + ".2": intPDU(metricOID+".2", 2),
		},
		nameOID: {
			nameOID + ".1": stringPDU(nameOID+".1", "Board 0"),
			nameOID + ".2": stringPDU(nameOID+".2", "Fan 1"),
		},
	}}
	c := newCollector(walkerFactory(w), filterProfile(sysObjValue, metricOID, nameOID, []string{"Board"}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, map[string]int64{"Board 0": 1}, filteredValues(t, c, host))
}

// TestCollectTarget_MatchAttributesLeavesAnUnansweredRowAlone pins what happens
// to a row the filter column returned no value for. The filter says which
// values to keep, not that a row without one is unwanted, so the row is emitted
// and simply carries no such tag. It also means a filter column the device does
// not implement leaves the entry collecting as it did before.
func TestCollectTarget_MatchAttributesLeavesAnUnansweredRowAlone(t *testing.T) {
	const (
		host        = "10.0.0.103"
		sysObjValue = "1.3.6.1.4.1.9999.103"
		metricOID   = sysObjValue + ".1.1"
		nameOID     = sysObjValue + ".1.2"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		metricOID: {
			metricOID + ".1": intPDU(metricOID+".1", 1),
			metricOID + ".2": intPDU(metricOID+".2", 2),
		},
		nameOID: {nameOID + ".1": stringPDU(nameOID+".1", "Fan 1")},
	}}
	c := newCollector(walkerFactory(w), filterProfile(sysObjValue, metricOID, nameOID, []string{"Board"}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, map[string]int64{"": 2}, filteredValues(t, c, host))
}

// TestCollectTarget_InvalidMatchAttributeIsReportedAndIgnored keeps a profile
// typo from silencing an entry: a pattern that does not compile is dropped, and
// a column whose patterns all fail to compile filters nothing.
func TestCollectTarget_InvalidMatchAttributeIsReportedAndIgnored(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		host        = "10.0.0.104"
		sysObjValue = "1.3.6.1.4.1.9999.104"
		metricOID   = sysObjValue + ".1.1"
		nameOID     = sysObjValue + ".1.2"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		metricOID: {
			metricOID + ".1": intPDU(metricOID+".1", 1),
			metricOID + ".2": intPDU(metricOID+".2", 2),
		},
		nameOID: {
			nameOID + ".1": stringPDU(nameOID+".1", "Board 0"),
			nameOID + ".2": stringPDU(nameOID+".2", "Fan 1"),
		},
	}}
	p := filterProfile(sysObjValue, metricOID, nameOID, []string{"["})
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, map[string]int64{"Board 0": 1, "Fan 1": 2}, filteredValues(t, c, host))
	assert.Equal(t, 1, strings.Count(logs.String(), "not a valid regular expression"), "logs: %s", logs.String())
	assert.Contains(t, logs.String(), "profile=filter.yml")
}

// TestCollectTarget_MatchAttributesOnAJoinedColumnIsReported covers the one
// shape the collector cannot apply: a filter column read from another table is
// keyed by that table's index, so its rows do not line up with the metric rows.
// No bundled profile writes that, and the rows are emitted unfiltered rather
// than filtered against the wrong row.
func TestCollectTarget_MatchAttributesOnAJoinedColumnIsReported(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		host        = "10.0.0.105"
		sysObjValue = "1.3.6.1.4.1.9999.105"
		metricOID   = sysObjValue + ".1.1"
		nameOID     = sysObjValue + ".2.1"
	)
	p := profileWithOID(sysObjValue, "joined.yml", []profiles.MetricEntry{{
		MIB:     "TEST-MIB",
		Table:   &profiles.Table{Name: "testTable", OID: sysObjValue},
		Symbols: []profiles.Symbol{{Name: "rowValue", OID: metricOID}},
		MetricTags: []profiles.MetricTag{{
			Tag:            "row_name",
			Column:         &profiles.TagColumn{OID: nameOID, Name: "rowName", MatchAttributes: []string{"Board"}},
			IndexTransform: profiles.IndexTransform{{Start: 0, End: 0}},
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		metricOID: {
			metricOID + ".1.9": intPDU(metricOID+".1.9", 1),
			metricOID + ".2.9": intPDU(metricOID+".2.9", 2),
		},
		nameOID: {
			nameOID + ".1": stringPDU(nameOID+".1", "Board 0"),
			nameOID + ".2": stringPDU(nameOID+".2", "Fan 1"),
		},
	}}
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, map[string]int64{"Board 0": 1, "Fan 1": 2}, filteredValues(t, c, host))
	assert.Equal(t, 1, strings.Count(logs.String(), "column is joined from another table"), "logs: %s", logs.String())
}

// TestCollectTarget_MatchAttributesOnADeviceTagIsReported covers the other
// place the field can appear. The top-level metric_tags describe the device, so
// a filter there has no rows to select and is reported rather than dropped in
// silence. No bundled profile writes one.
func TestCollectTarget_MatchAttributesOnADeviceTagIsReported(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		host        = "10.0.0.106"
		sysObjValue = "1.3.6.1.4.1.9999.106"
		nameOID     = sysObjValue + ".1.0"
	)
	p := profileWithOID(sysObjValue, "device-tag.yml", nil)
	p.MetricTags = []profiles.MetricTag{{
		Tag:    "chassis",
		Column: &profiles.TagColumn{OID: nameOID, Name: "chassisName", MatchAttributes: []string{"Board"}},
	}}
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		nameOID:        {nameOID: stringPDU(nameOID, "Fan 1")},
	}}
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, 1, strings.Count(logs.String(), "column tags the device rather than a row"), "logs: %s", logs.String())
	assert.Contains(t, logs.String(), "profile=device-tag.yml")
}

// ---------------------------------------------------------------------------
// Throttling and requests that fail
// ---------------------------------------------------------------------------

// TestCollectTarget_FailedScalarWalkDoesNotThrottle covers a symbol whose walk
// fails inside a run that otherwise succeeds. The run keeps the device, so the
// blanket forget-on-failure rule never fires, and a poll timestamp recorded
// before the walk returned would hold the symbol off for its whole poll window
// with no previous value to carry forward. Bundled LLDP metrics poll hourly.
func TestCollectTarget_FailedScalarWalkDoesNotThrottle(t *testing.T) {
	const (
		host        = "10.0.0.110"
		slowOID     = "1.3.6.1.4.1.9999.110.1.0"
		sysObjValue = "1.3.6.1.4.1.9999.110"
	)
	p := profileWithOID(sysObjValue, "throttle.yml", []profiles.MetricEntry{
		{MIB: "TEST-MIB", Symbol: &profiles.Symbol{Name: "slowMetric", OID: slowOID, PollTimeSec: 3600}},
	})
	makeWalker := func(fail bool) *recordingWalker {
		w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			slowOID:        {slowOID: intPDU(slowOID, 42)},
		}}
		if fail {
			w.walkErrs = map[string]error{slowOID: errors.New("request timeout")}
		}
		return w
	}

	c := newCollector(walkerFactory(makeWalker(true)), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.Empty(t, c.testDeviceStore("p", host)["snmp.slowmetric"])

	c.clientFactory = walkerFactory(makeWalker(false))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	points := c.testDeviceStore("p", host)["snmp.slowmetric"]
	require.Len(t, points, 1, "the symbol was never collected, so nothing may throttle it")
	assert.Equal(t, int64(42), points[0].value)
}

// TestCollectTarget_FailedTableColumnWalkDoesNotThrottle is the same rule for a
// table column, whose walk fails on its own without failing the entry.
func TestCollectTarget_FailedTableColumnWalkDoesNotThrottle(t *testing.T) {
	const (
		host        = "10.0.0.111"
		sysObjValue = "1.3.6.1.4.1.9999.111"
		tableOID    = sysObjValue + ".1"
		slowCol     = tableOID + ".1.1"
		fastCol     = tableOID + ".1.2"
	)
	p := profileWithOID(sysObjValue, "throttle-table.yml", []profiles.MetricEntry{{
		MIB:   "TEST-MIB",
		Table: &profiles.Table{Name: "testTable", OID: tableOID},
		Symbols: []profiles.Symbol{
			{Name: "slowColumn", OID: slowCol, PollTimeSec: 3600},
			{Name: "fastColumn", OID: fastCol},
		},
	}})
	makeWalker := func(fail bool) *recordingWalker {
		w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			slowCol:        {slowCol + ".1": intPDU(slowCol+".1", 7)},
			fastCol:        {fastCol + ".1": intPDU(fastCol+".1", 8)},
		}}
		if fail {
			w.walkErrs = map[string]error{slowCol: errors.New("request timeout")}
		}
		return w
	}

	c := newCollector(walkerFactory(makeWalker(true)), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.Empty(t, c.testDeviceStore("p", host)["snmp.slowcolumn"])

	c.clientFactory = walkerFactory(makeWalker(false))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	points := c.testDeviceStore("p", host)["snmp.slowcolumn"]
	require.Len(t, points, 1, "the column was never collected, so nothing may throttle it")
	assert.Equal(t, int64(7), points[0].value)
}

// TestCollectTarget_WalkThatAnswersWithNothingStillThrottles keeps the fix from
// turning every unsupported OID into a request on every cycle. A walk that
// returns without error collected the symbol, whatever the device chose to
// answer, so the poll window starts.
func TestCollectTarget_WalkThatAnswersWithNothingStillThrottles(t *testing.T) {
	const (
		host        = "10.0.0.112"
		slowOID     = "1.3.6.1.4.1.9999.112.1.0"
		sysObjValue = "1.3.6.1.4.1.9999.112"
	)
	p := profileWithOID(sysObjValue, "unsupported.yml", []profiles.MetricEntry{
		{MIB: "TEST-MIB", Symbol: &profiles.Symbol{Name: "slowMetric", OID: slowOID, PollTimeSec: 3600}},
	})
	empty := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		slowOID:        {},
	}}
	answering := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		slowOID:        {slowOID: intPDU(slowOID, 42)},
	}}

	c := newCollector(walkerFactory(empty), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	c.clientFactory = walkerFactory(answering)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.NotContains(t, answering.walkCalls, slowOID, "an answered walk must start the poll window")
}

// TestPduToString_HexToIntTagColumn covers a tag column declaring a hextoint
// conversion, as brocade-fc-switch.yml does for portIndex. Without the
// conversion the raw octets render as text, which looks like a value.
func TestPduToString_HexToIntTagColumn(t *testing.T) {
	col := &profiles.TagColumn{
		OID:        "1.3.6.1.2.1.75.1.2.1.1.1",
		Name:       "portIndex",
		Conversion: "hextoint:BigEndian:uint16",
	}
	pdu := snmp.PDU{Type: gosnmp.OctetString, Value: []byte{0x00, 0x2a}}
	require.Equal(t, "42", pduToString(pdu, col))
}

// TestPduToString_UnknownConversionFallsBackToRaw pins that an unrecognised
// conversion still renders the trimmed octet string rather than panicking.
func TestPduToString_UnknownConversionFallsBackToRaw(t *testing.T) {
	col := &profiles.TagColumn{Name: "x", Conversion: "some_future_conversion"}
	pdu := snmp.PDU{Type: gosnmp.OctetString, Value: []byte("  raw  ")}
	require.Equal(t, "raw", pduToString(pdu, col))
}

// ---------------------------------------------------------------------------
// Grouped symbols that are table columns
// ---------------------------------------------------------------------------

// A grouped `symbols:` entry that also declares `metric_tags:` is describing
// table columns, not scalars: the tag names a per-row dimension. One bundled
// radio profile has that shape, and its per-interface rows are
// indistinguishable without the interface name.
func TestCollectTarget_GroupedSymbolsWithMetricTagsCollectAsTableRows(t *testing.T) {
	const (
		host        = "10.0.0.60"
		sysObjValue = "1.3.6.1.4.1.17713.60.1"
		mcsOID      = "1.3.6.1.4.1.17713.60.1.1.1.5"
		ifNameOID   = "1.3.6.1.4.1.17713.60.1.1.1.2"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		mcsOID: {
			mcsOID + ".1": intPDU(mcsOID+".1", 9),
			mcsOID + ".2": intPDU(mcsOID+".2", 11),
		},
		ifNameOID: {
			ifNameOID + ".1": stringPDU(ifNameOID+".1", "radio-1"),
			ifNameOID + ".2": stringPDU(ifNameOID+".2", "radio-2"),
		},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.mcs"]
	require.Len(t, pts, 2)
	byName := map[string]int64{}
	for _, pt := range pts {
		byName[attrValue(pt, "ifName")] = pt.value
	}
	assert.Equal(t, map[string]int64{"radio-1": 9, "radio-2": 11}, byName)
}

// A grouped `symbols:` entry whose symbol carries a `condition:` is also
// describing table columns: a condition filters rows of the same table. The
// scalar path has nowhere to apply it, so every row is emitted.
func TestCollectTarget_GroupedSymbolsWithConditionFilterRows(t *testing.T) {
	const (
		host        = "10.0.0.61"
		sysObjValue = "1.3.6.1.4.1.9999.61"
		usedOID     = "1.3.6.1.4.1.9999.61.1.7"
		typeOID     = "1.3.6.1.4.1.9999.61.1.3"
	)
	p := profileWithOID(sysObjValue, "pools.yml", []profiles.MetricEntry{{
		Symbols: []profiles.Symbol{
			{Name: "poolUsed", OID: usedOID, Condition: "poolType=10"},
			{Name: "poolType", OID: typeOID},
		},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		usedOID: {
			usedOID + ".1": intPDU(usedOID+".1", 100),
			usedOID + ".2": intPDU(usedOID+".2", 200),
		},
		typeOID: {
			typeOID + ".1": intPDU(typeOID+".1", 10),
			typeOID + ".2": intPDU(typeOID+".2", 3),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.poolused"]
	require.Len(t, pts, 1, "only the row the condition selects may be emitted")
	assert.Equal(t, int64(100), pts[0].value)
	assert.Equal(t, "1", attrValue(pts[0], "row_index"))
}

// The entries the grouped-symbols arm was added for carry no row-scoped
// metadata, so they stay on the scalar path and keep their attribute set. A
// row_index on these would split each series in two across the change.
func TestCollectTarget_GroupedScalarsKeepTheScalarPath(t *testing.T) {
	const (
		host        = "10.0.0.62"
		sysObjValue = "1.3.6.1.4.1.38218"
		vrmsOID     = "1.3.6.1.4.1.38218.1.6.1"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		vrmsOID:        {vrmsOID: intPDU(vrmsOID, 231)},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.pdu-meter1-vrms"]
	require.Len(t, pts, 1)
	assert.Equal(t, int64(231), pts[0].value)
	assert.Empty(t, attrValue(pts[0], "row_index"), "a grouped scalar must not gain a row identity")
}

// A symbol may name a fully qualified instance rather than a column, in which
// case its single PDU strips to no row index. Labelling it with the whole OID
// would put a meaningless dimension on the series.
func TestCollectTarget_TableSymbolNamingOneInstanceHasNoRowIndex(t *testing.T) {
	const (
		host        = "10.0.0.63"
		sysObjValue = "1.3.6.1.4.1.9999.63"
		instOID     = "1.3.6.1.4.1.9999.63.1.7.1.1"
		nameColOID  = "1.3.6.1.4.1.9999.63.1.3"
	)
	p := profileWithOID(sysObjValue, "instance.yml", []profiles.MetricEntry{{
		Symbols:    []profiles.Symbol{{Name: "poolUsed", OID: instOID}},
		MetricTags: []profiles.MetricTag{{Column: &profiles.TagColumn{OID: nameColOID, Name: "poolName"}}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		instOID:        {instOID: intPDU(instOID, 555)},
		nameColOID:     {nameColOID + ".1.1": stringPDU(nameColOID+".1.1", "pool-a")},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.poolused"]
	require.Len(t, pts, 1)
	assert.Equal(t, int64(555), pts[0].value)
	assert.Empty(t, attrValue(pts[0], "row_index"))
}

// ---------------------------------------------------------------------------
// Table collection stops at the deadline
// ---------------------------------------------------------------------------

// A table entry's tag columns are walked one at a time and one bundled
// wireless-controller entry declares 23 of them. A run whose deadline has
// expired must not keep issuing them, or an unavailable device holds the
// runner for a further per-request timeout each.
func TestCollectTarget_TableTagWalksStopAtTheDeadline(t *testing.T) {
	const (
		host        = "10.0.0.64"
		sysObjValue = "1.3.6.1.4.1.9999.64"
		tableOID    = "1.3.6.1.4.1.9999.64.1"
		errColOID   = "1.3.6.1.4.1.9999.64.1.1.4"
	)
	tagOIDs := []string{
		"1.3.6.1.4.1.9999.64.1.1.1",
		"1.3.6.1.4.1.9999.64.1.1.2",
		"1.3.6.1.4.1.9999.64.1.1.3",
	}
	tags := make([]profiles.MetricTag, len(tagOIDs))
	responses := map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		errColOID:      {errColOID + ".1": counter32PDU(errColOID+".1", 7)},
	}
	for i, oid := range tagOIDs {
		tags[i] = profiles.MetricTag{Tag: fmt.Sprintf("t%d", i), Column: &profiles.TagColumn{OID: oid}}
		responses[oid] = map[string]snmp.PDU{oid + ".1": stringPDU(oid+".1", "v")}
	}
	p := profileWithOID(sysObjValue, "wide.yml", []profiles.MetricEntry{{
		Table:      &profiles.Table{Name: "wide", OID: tableOID},
		Symbols:    []profiles.Symbol{{Name: "ifOutErrors", OID: errColOID}},
		MetricTags: tags,
	}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &recordingWalker{responses: responses}
	w.onWalk = func(oid string) {
		if oid == tagOIDs[0] {
			cancel()
		}
	}

	c := newCollector(walkerFactory(w), p)
	require.ErrorIs(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}), context.Canceled)

	assert.Contains(t, w.walkCalls, tagOIDs[0])
	for _, oid := range tagOIDs[1:] {
		assert.NotContains(t, w.walkCalls, oid, "a tag column walked after the deadline expired")
	}
	assert.NotContains(t, w.walkCalls, errColOID, "rows must not be collected once their tags are incomplete")
}

// A condition names a second column to walk, and one entry can carry several.
func TestCollectTarget_TableConditionWalksStopAtTheDeadline(t *testing.T) {
	const (
		host        = "10.0.0.65"
		sysObjValue = "1.3.6.1.4.1.9999.65"
		tableOID    = "1.3.6.1.4.1.9999.65.1"
		usedOID     = "1.3.6.1.4.1.9999.65.1.1.1"
		sizeOID     = "1.3.6.1.4.1.9999.65.1.1.2"
		typeOID     = "1.3.6.1.4.1.9999.65.1.1.3"
		stateOID    = "1.3.6.1.4.1.9999.65.1.1.4"
	)
	p := profileWithOID(sysObjValue, "cond.yml", []profiles.MetricEntry{{
		Table: &profiles.Table{Name: "pools", OID: tableOID},
		Symbols: []profiles.Symbol{
			{Name: "poolUsed", OID: usedOID, Condition: "poolType=10"},
			{Name: "poolSize", OID: sizeOID, Condition: "poolState=1"},
			{Name: "poolType", OID: typeOID},
			{Name: "poolState", OID: stateOID},
		},
	}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		typeOID:        {typeOID + ".1": intPDU(typeOID+".1", 10)},
		stateOID:       {stateOID + ".1": intPDU(stateOID+".1", 1)},
		usedOID:        {usedOID + ".1": intPDU(usedOID+".1", 100)},
		sizeOID:        {sizeOID + ".1": intPDU(sizeOID+".1", 200)},
	}}
	w.onWalk = func(oid string) {
		if oid == typeOID {
			cancel()
		}
	}

	c := newCollector(walkerFactory(w), p)
	require.ErrorIs(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}), context.Canceled)

	assert.Contains(t, w.walkCalls, typeOID)
	assert.NotContains(t, w.walkCalls, stateOID, "a condition column walked after the deadline expired")
	assert.NotContains(t, w.walkCalls, usedOID, "rows must not be collected once their filter is incomplete")
}

// The metric columns are walked one at a time too. A column the device does
// not answer yields no PDUs, so a deadline check inside the row loop alone
// never runs and the next column is walked regardless.
func TestCollectTarget_TableMetricWalksStopAtTheDeadline(t *testing.T) {
	const (
		host        = "10.0.0.66"
		sysObjValue = "1.3.6.1.4.1.9999.66"
		tableOID    = "1.3.6.1.4.1.9999.66.1"
		firstOID    = "1.3.6.1.4.1.9999.66.1.1.1"
		secondOID   = "1.3.6.1.4.1.9999.66.1.1.2"
	)
	p := profileWithOID(sysObjValue, "cols.yml", []profiles.MetricEntry{{
		Table: &profiles.Table{Name: "cols", OID: tableOID},
		Symbols: []profiles.Symbol{
			{Name: "ifInErrors", OID: firstOID},
			{Name: "ifOutErrors", OID: secondOID},
		},
	}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// firstOID has no entry, so the walk returns no PDUs at all.
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		secondOID:      {secondOID + ".1": counter32PDU(secondOID+".1", 3)},
	}}
	w.onWalk = func(oid string) {
		if oid == firstOID {
			cancel()
		}
	}

	c := newCollector(walkerFactory(w), p)
	require.ErrorIs(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p", DialOptions{}), context.Canceled)

	assert.Contains(t, w.walkCalls, firstOID)
	assert.NotContains(t, w.walkCalls, secondOID, "a metric column walked after the deadline expired")
}

// TestReportUnusableConditions_OncePerProfile pins that a condition the
// collector cannot apply is reported once for the profile rather than on every
// collection. This entry's condition names a column the entry declares nowhere,
// so no walk could resolve it.
func TestReportUnusableConditions_OncePerProfile(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	entry := profiles.MetricEntry{
		Symbols: []profiles.Symbol{
			{Name: "used", OID: "1.3.6.1.4.1.9.9.221.1.1.1.1.18", Condition: `absentColumn="DP System memory"`},
			{Name: "free", OID: "1.3.6.1.4.1.9.9.221.1.1.1.1.20"},
		},
	}
	c := &MetricsCollector{logger: logger, reviewedProfiles: map[string]struct{}{}}

	for range 3 {
		c.reportUnusableConditions(entry, "vendor/example.yml")
	}
	require.Equal(t, 3, strings.Count(buf.String(), "cannot apply"),
		"the helper itself reports every call; the once-per-profile guard lives in reviewProfile")

	buf.Reset()
	p := &profiles.Profile{RelPath: "vendor/example.yml", Metrics: []profiles.MetricEntry{entry}}
	c2 := &MetricsCollector{logger: logger, reviewedProfiles: map[string]struct{}{}}
	for range 3 {
		c2.reviewProfile(p)
	}
	require.Equal(t, 1, strings.Count(buf.String(), "cannot apply"),
		"three collections of one profile must report the condition once")
	require.Contains(t, buf.String(), "names no symbol or tag column in this entry")
}

// ---------------------------------------------------------------------------
// Conditions comparing a textual column
// ---------------------------------------------------------------------------

// TestResolveCondition covers every shape a profile `condition:` takes: the
// bundled integer form against a sibling symbol, the quoted form against a
// column the entry declares in metric_tags, and the forms that cannot be
// applied at all.
func TestResolveCondition(t *testing.T) {
	entry := &profiles.MetricEntry{
		Symbols: []profiles.Symbol{
			{Name: "poolType", OID: "1.3.6.1.4.1.9.9.221.1.1.1.1.2"},
			{Name: "poolUsed", OID: "1.3.6.1.4.1.9.9.221.1.1.1.1.7"},
		},
		MetricTags: []profiles.MetricTag{
			{Column: &profiles.TagColumn{Name: "poolName", OID: "1.3.6.1.4.1.9.9.221.1.1.1.1.3"}},
			{Tag: "renamed", Column: &profiles.TagColumn{Name: "poolLabel", OID: "1.3.6.1.4.1.9.9.221.1.1.1.1.4"}},
			{
				Tag:            "joined",
				Column:         &profiles.TagColumn{Name: "elsewhere", OID: "1.3.6.1.2.1.31.1.1.1.1"},
				IndexTransform: profiles.IndexTransform{{Start: 0, End: 0}},
			},
		},
	}

	tests := []struct {
		name      string
		condition string
		wantOID   string
		wantInt   int64
		wantNum   bool
		wantStr   string
		wantWhy   string
	}{
		{
			name: "integer against sibling symbol", condition: "poolType=10",
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.2", wantInt: 10, wantNum: true,
		},
		{
			name: "spaces around both sides", condition: " poolType = 10 ",
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.2", wantInt: 10, wantNum: true,
		},
		{
			name: "quoted string against tag column", condition: `poolName="DP System memory"`,
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.3", wantStr: "DP System memory",
		},
		{
			name: "tag column reached by its tag name", condition: `renamed="label"`,
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.4", wantStr: "label",
		},
		{
			name: "tag column reached by its column name", condition: `poolLabel="label"`,
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.4", wantStr: "label",
		},
		{
			name: "single quotes", condition: "poolName='DP System memory'",
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.3", wantStr: "DP System memory",
		},
		{
			name: "unquoted non-integer is a string", condition: "poolName=active",
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.3", wantStr: "active",
		},
		{
			name: "quoted digits stay a string", condition: `poolName="10"`,
			wantOID: "1.3.6.1.4.1.9.9.221.1.1.1.1.3", wantStr: "10",
		},
		{name: "no equals sign", condition: "poolType", wantWhy: "not a name=value pair"},
		{name: "empty name", condition: "=10", wantWhy: "not a name=value pair"},
		{name: "unknown name", condition: "nothingHere=1", wantWhy: "names no symbol or tag column in this entry"},
		{
			name: "column joined from another table", condition: `joined="ge-0/0/0"`,
			wantWhy: "column is joined from another table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check, why := resolveCondition(entry, tt.condition)
			if tt.wantWhy != "" {
				assert.Equal(t, tt.wantWhy, why)
				return
			}
			require.Empty(t, why)
			assert.Equal(t, tt.wantOID, check.columnOID)
			assert.Equal(t, tt.wantNum, check.numeric)
			assert.Equal(t, tt.wantInt, check.expectInt)
			assert.Equal(t, tt.wantStr, check.expected)
		})
	}
}

// TestResolveCondition_BundledIntegerCasesUnchanged pins the five bundled
// conditions that name a sibling symbol and compare an integer. All five must
// keep resolving to that symbol's OID and to a numeric comparison.
func TestResolveCondition_BundledIntegerCasesUnchanged(t *testing.T) {
	cases := []struct {
		relPath string
		symbol  string
		wantOID string
		wantVal int64
	}{
		{"cisco/cisco-asa.yml", "cempMemPoolUsed", "1.3.6.1.4.1.9.9.221.1.1.1.1.2", 10},
		{"cisco/cisco-asa.yml", "cempMemPoolFree", "1.3.6.1.4.1.9.9.221.1.1.1.1.2", 10},
		{"huawei/huawei-all-devices.yml", "hwEntityCpuUsage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.3", 4},
		{"huawei/huawei-all-devices.yml", "hwEntityMemUsage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.3", 4},
		{"_template.yml", "entSensorThresholdValue", "1.3.6.1.4.1.9.9.91.1.2.1.1.2", 30},
	}

	found := 0
	for _, tc := range cases {
		p := bundledProfile(t, tc.relPath)
		for i := range p.Metrics {
			entry := &p.Metrics[i]
			for j := range entry.Symbols {
				sym := &entry.Symbols[j]
				if sym.Name != tc.symbol || sym.Condition == "" {
					continue
				}
				found++
				check, why := resolveCondition(entry, sym.Condition)
				require.Empty(t, why, "%s %s", tc.relPath, tc.symbol)
				assert.True(t, check.numeric, "%s %s stays an integer comparison", tc.relPath, tc.symbol)
				assert.Equal(t, tc.wantVal, check.expectInt)
				assert.Equal(t, tc.wantOID, check.columnOID)
				assert.Nil(t, check.column, "a sibling symbol reference carries no tag column")
			}
		}
	}
	assert.Equal(t, 5, found, "the bundled set declares five integer conditions")
}

// TestCollectTarget_StringConditionSelectsRows checks that a condition naming a
// metric_tags column and comparing text emits only the rows that match.
func TestCollectTarget_StringConditionSelectsRows(t *testing.T) {
	const (
		host        = "10.0.0.60"
		nameColOID  = "1.3.6.1.4.1.9999.60.1.3"
		usedColOID  = "1.3.6.1.4.1.9999.60.1.18"
		sysObjValue = "1.3.6.1.4.1.9999.60"
	)
	p := profileWithOID(sysObjValue, "strcond.yml", []profiles.MetricEntry{
		{
			Symbols: []profiles.Symbol{
				{Name: "poolHCUsed", OID: usedColOID, Condition: `poolName="DP System memory"`},
			},
			MetricTags: []profiles.MetricTag{
				{Column: &profiles.TagColumn{Name: "poolName", OID: nameColOID}},
			},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		nameColOID: {
			nameColOID + ".1": stringPDU(nameColOID+".1", "DP System memory"),
			nameColOID + ".2": stringPDU(nameColOID+".2", "System memory"),
			// Agents commonly pad a display string; pduToString trims it.
			nameColOID + ".3": stringPDU(nameColOID+".3", "  DP System memory  "),
			// Case is significant, so this pool is a different one.
			nameColOID + ".4": stringPDU(nameColOID+".4", "dp system memory"),
		},
		usedColOID: {
			usedColOID + ".1": counter64PDU(usedColOID+".1", 11),
			usedColOID + ".2": counter64PDU(usedColOID+".2", 22),
			usedColOID + ".3": counter64PDU(usedColOID+".3", 33),
			usedColOID + ".4": counter64PDU(usedColOID+".4", 44),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.poolhcused"]
	got := make([]int64, 0, len(pts))
	for _, pt := range pts {
		got = append(got, pt.value)
	}
	assert.ElementsMatch(t, []int64{11, 33}, got,
		"only the rows whose name column equals the condition value are emitted")

	// The condition column is also a metric_tag, so it is walked once, not twice.
	nameWalks := 0
	for _, oid := range w.walkCalls {
		if oid == nameColOID {
			nameWalks++
		}
	}
	assert.Equal(t, 1, nameWalks)
}

// TestCollectTarget_BundledFirepowerFiltersHighCapacityPools drives the bundled
// Firepower profile, whose two high-capacity memory symbols are declared for one
// named pool only. Without the filter the collector emits a row per pool, which
// is output the profile never asked for.
func TestCollectTarget_BundledFirepowerFiltersHighCapacityPools(t *testing.T) {
	const (
		host       = "10.0.0.61"
		nameColOID = "1.3.6.1.4.1.9.9.221.1.1.1.1.3"
		hcUsedOID  = "1.3.6.1.4.1.9.9.221.1.1.1.1.18"
		hcFreeOID  = "1.3.6.1.4.1.9.9.221.1.1.1.1.20"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.9.1.2285")},
		nameColOID: {
			nameColOID + ".1.1": stringPDU(nameColOID+".1.1", "System memory"),
			nameColOID + ".1.2": stringPDU(nameColOID+".1.2", "DP System memory"),
		},
		hcUsedOID: {
			hcUsedOID + ".1.1": counter64PDU(hcUsedOID+".1.1", 100),
			hcUsedOID + ".1.2": counter64PDU(hcUsedOID+".1.2", 200),
		},
		hcFreeOID: {
			hcFreeOID + ".1.1": counter64PDU(hcFreeOID+".1.1", 300),
			hcFreeOID + ".1.2": counter64PDU(hcFreeOID+".1.2", 400),
		},
	}}

	c := newCollector(walkerFactory(w), bundledProfile(t, "cisco/cisco-firepower.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	// Four symbols carry `tag: MemoryUsed` or `tag: MemoryFree` with
	// `allow_duplicate: true`, so they share a metric name and all keep
	// exporting. Only the high capacity pair answers here.
	used := store["snmp.memoryused"]
	require.Len(t, used, 1, "only the named pool is emitted")
	assert.Equal(t, int64(200), used[0].value)
	assert.Equal(t, "DP System memory", attrValue(used[0], "cempMemPoolName"))

	free := store["snmp.memoryfree"]
	require.Len(t, free, 1, "only the named pool is emitted")
	assert.Equal(t, int64(400), free[0].value)
}

// TestCollectTarget_ApplicableConditionIsNotReported checks that the
// once-per-profile report stops naming a condition the collector now applies.
func TestCollectTarget_ApplicableConditionIsNotReported(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.9.1.2285")},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "cisco/cisco-firepower.yml"))
	c.logger = logger
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.62"), mustAuth(), "p", DialOptions{}))

	assert.NotContains(t, logs.String(), "cempMemPoolName",
		"a condition the collector applies must not be reported as unusable")
}

// TestCollectTarget_UnusableConditionIsStillReported keeps the report honest:
// a condition naming nothing in its entry is still called out.
func TestCollectTarget_UnusableConditionIsStillReported(t *testing.T) {
	const (
		host        = "10.0.0.63"
		colOID      = "1.3.6.1.4.1.9999.63.1.1"
		sysObjValue = "1.3.6.1.4.1.9999.63"
	)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	p := profileWithOID(sysObjValue, "badcond.yml", []profiles.MetricEntry{
		{
			Table:   &profiles.Table{Name: "t", OID: "1.3.6.1.4.1.9999.63.1"},
			Symbols: []profiles.Symbol{{Name: "col", OID: colOID, Condition: "absentColumn=1"}},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
	}}
	c := newCollector(walkerFactory(w), p)
	c.logger = logger
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Contains(t, logs.String(), "names no symbol or tag column in this entry")
}

// TestCollectTarget_PassesCollectionContextToFactory pins that the run's
// context reaches the SNMP client. Without it the client cannot stop when the
// collection is cancelled, and its retry sequence outlives the run.
func TestCollectTarget_PassesCollectionContextToFactory(t *testing.T) {
	var got context.Context
	c := newCollector(func(ctx context.Context, _ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		got = ctx
		return &recordingWalker{}, nil
	}, nil)

	ctx := context.WithValue(context.Background(), testCtxKey{}, "run-1")
	// The walker answers nothing, so the run fails at sysObjectID. The client
	// was still built, which is the whole of what this pins.
	_ = c.CollectTarget(ctx, mustTarget("10.0.0.72"), mustAuth(), "p", DialOptions{})
	require.NotNil(t, got)
	assert.Equal(t, "run-1", got.Value(testCtxKey{}))
}

// testCtxKey marks the context a test hands to CollectTarget.
type testCtxKey struct{}

// ---------------------------------------------------------------------------
// Scalar walks that answer with more than one row
// ---------------------------------------------------------------------------

// A grouped `symbols:` entry may name table columns and declare nothing that
// says so. The device says so instead: a walk beneath the symbol that answers
// with more than one instance is walking a column. Without a row identity
// every row carries the same attribute set and the export keeps one arbitrary
// value. The bundled Mikrotik router profile has that shape for the two
// HOST-RESOURCES storage columns.
func TestCollectTarget_ScalarWalkWithSeveralRowsGainsRowIndex(t *testing.T) {
	const (
		host        = "10.0.0.80"
		sysObjValue = "1.3.6.1.4.1.14988.1.1"
		totalOID    = "1.3.6.1.2.1.25.2.3.1.5"
		usedOID     = "1.3.6.1.2.1.25.2.3.1.6"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		totalOID: {
			totalOID + ".65": intPDU(totalOID+".65", 262144),
			totalOID + ".66": intPDU(totalOID+".66", 16384),
		},
		usedOID: {
			usedOID + ".65": intPDU(usedOID+".65", 131072),
			usedOID + ".66": intPDU(usedOID+".66", 4096),
		},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	byIndex := func(metric string) map[string]int64 {
		out := map[string]int64{}
		for _, pt := range store[metric] {
			out[attrValue(pt, "row_index")] = pt.value
		}
		return out
	}
	require.Len(t, store["snmp.memorytotal"], 2)
	assert.Equal(t, map[string]int64{"65": 262144, "66": 16384}, byIndex("snmp.memorytotal"))
	require.Len(t, store["snmp.memoryused"], 2)
	assert.Equal(t, map[string]int64{"65": 131072, "66": 4096}, byIndex("snmp.memoryused"))
}

// Two rows of the same column can hold the same value. They are still two
// rows, so both have to survive with an identity of their own.
func TestCollectTarget_ScalarWalkRowsWithEqualValuesStayApart(t *testing.T) {
	const (
		host        = "10.0.0.81"
		sysObjValue = "1.3.6.1.4.1.9999.81"
		colOID      = "1.3.6.1.4.1.9999.81.1.4"
	)
	p := profileWithOID(sysObjValue, "columns.yml", []profiles.MetricEntry{{
		Symbols: []profiles.Symbol{{Name: "fanSpeed", OID: colOID}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		colOID: {
			colOID + ".1": intPDU(colOID+".1", 3000),
			colOID + ".2": intPDU(colOID+".2", 3000),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.fanspeed"]
	require.Len(t, pts, 2)
	indexes := []string{attrValue(pts[0], "row_index"), attrValue(pts[1], "row_index")}
	sort.Strings(indexes)
	assert.Equal(t, []string{"1", "2"}, indexes)
}

// An agent may answer the walk with the symbol OID itself as well as with
// instances beneath it. The bare OID identifies no row, so labelling it with
// the whole OID would put a meaningless dimension on that one series. This is
// the scalar-path counterpart of the same rule on the table path.
func TestCollectTarget_ScalarWalkLeavesTheUnindexedInstanceUnlabelled(t *testing.T) {
	const (
		host        = "10.0.0.92"
		sysObjValue = "1.3.6.1.4.1.9999.92"
		colOID      = "1.3.6.1.4.1.9999.92.1.4"
	)
	p := profileWithOID(sysObjValue, "mixed.yml", []profiles.MetricEntry{{
		Symbols: []profiles.Symbol{{Name: "fanSpeed", OID: colOID}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		colOID: {
			colOID:        intPDU(colOID, 1000),
			colOID + ".1": intPDU(colOID+".1", 2000),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.fanspeed"]
	require.Len(t, pts, 2)
	byValue := map[int64]string{}
	for _, pt := range pts {
		byValue[pt.value] = attrValue(pt, "row_index")
	}
	assert.Equal(t, map[int64]string{1000: "", 2000: "1"}, byValue)
}

// A scalar `symbol:` entry gets the same treatment: the routing between the
// two paths is not what decides it, the device's answer is.
func TestCollectTarget_SingleScalarSymbolWalkWithSeveralRowsGainsRowIndex(t *testing.T) {
	const (
		host        = "10.0.0.82"
		sysObjValue = "1.3.6.1.4.1.9999.82"
		colOID      = "1.3.6.1.4.1.9999.82.1.9"
	)
	p := profileWithOID(sysObjValue, "single.yml", []profiles.MetricEntry{{
		Symbol: &profiles.Symbol{Name: "diskUsed", OID: colOID},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		colOID: {
			colOID + ".1": intPDU(colOID+".1", 10),
			colOID + ".2": intPDU(colOID+".2", 20),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.diskused"]
	require.Len(t, pts, 2)
	byIndex := map[string]int64{}
	for _, pt := range pts {
		byIndex[attrValue(pt, "row_index")] = pt.value
	}
	assert.Equal(t, map[string]int64{"1": 10, "2": 20}, byIndex)
}

// The five bundled profiles that collect only through grouped `symbols:` are
// answered at the instance each symbol names, or at the .0 the device supplies
// for the symbols that name none, so none of them gains a row identity and
// their series keep the shape they have. The instance OIDs are written out
// here rather than derived from the profile.
func TestCollectTarget_GroupedScalarProfilesKeepOneUnindexedSeries(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		sysObjValue string
		symbolOID   string
		instanceOID string
		metric      string
	}{
		{
			"roomalert-32s", "10.0.0.83", "1.3.6.1.4.1.20916",
			"1.3.6.1.4.1.20916.1.11.1.1.1.1.0", "1.3.6.1.4.1.20916.1.11.1.1.1.1.0", "snmp.internal-tempf",
		},
		{
			"roomalert-3e", "10.0.0.84", "1.3.6.1.4.1.20916.1.9.1",
			"1.3.6.1.4.1.20916.1.9.1.1.1.1.0", "1.3.6.1.4.1.20916.1.9.1.1.1.1.0", "snmp.digital-sen1-1",
		},
		{
			"roomalert-3s", "10.0.0.85", "1.3.6.1.4.1.20916.1.13.1",
			"1.3.6.1.4.1.20916.1.13.1.1.1.1.0", "1.3.6.1.4.1.20916.1.13.1.1.1.1.0", "snmp.internal-tempf",
		},
		{
			"infrasensing-gateway", "10.0.0.86", "1.3.6.1.4.1.17095.1",
			"1.3.6.1.4.1.17095.1000.1.4.0", "1.3.6.1.4.1.17095.1000.1.4.0", "snmp.sensor1_value_integer",
		},
		// The iPower symbols name no instance, so the device supplies the
		// scalar `.0` the profile leaves off.
		{
			"ipower-pdu", "10.0.0.87", "1.3.6.1.4.1.38218",
			"1.3.6.1.4.1.38218.1.6.1", "1.3.6.1.4.1.38218.1.6.1.0", "snmp.pdu-meter1-vrms",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
				sysObjectIDOID: {sysObjectIDOID: oIDPDU(tt.sysObjValue)},
				sysDescrOID:    {},
				tt.symbolOID:   {tt.instanceOID: intPDU(tt.instanceOID, 42)},
			}}
			c := newBundledCollector(t, walkerFactory(w))
			require.NoError(t, c.CollectTarget(context.Background(), mustTarget(tt.host), mustAuth(), "p", DialOptions{}))

			pts := c.testDeviceStore("p", tt.host)[tt.metric]
			require.Len(t, pts, 1)
			assert.Equal(t, int64(42), pts[0].value)
			assert.Empty(t, attrValue(pts[0], "row_index"), "a single-row scalar walk must not gain a row identity")
		})
	}
}

// ---------------------------------------------------------------------------
// A conversion declared on the metric tag rather than inside its column
// ---------------------------------------------------------------------------

// A tag-level `conversion:` renders the same column its own would, so the row
// attribute is the converted value and not the raw octets.
func TestCollectTable_ConversionOnTheTagIsApplied(t *testing.T) {
	const (
		host        = "10.0.0.88"
		sysObjValue = "1.3.6.1.4.1.9999.88"
		tableOID    = "1.3.6.1.4.1.9999.88.1"
		rttOID      = "1.3.6.1.4.1.9999.88.1.1"
		srcOID      = "1.3.6.1.4.1.9999.88.1.2"
	)
	p := profileWithOID(sysObjValue, "rtt.yml", []profiles.MetricEntry{{
		Table:   &profiles.Table{Name: "rttTable", OID: tableOID},
		Symbols: []profiles.Symbol{{Name: "rttLatency", OID: rttOID}},
		MetricTags: []profiles.MetricTag{{
			Tag:        "rtt_echo_source_address",
			Column:     &profiles.TagColumn{OID: srcOID, Name: "rttMonEchoAdminSourceAddress"},
			Conversion: "hextoip",
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		rttOID:         {rttOID + ".1": intPDU(rttOID+".1", 12)},
		srcOID: {srcOID + ".1": {
			Name: srcOID + ".1", Type: gosnmp.OctetString, Value: []byte{10, 0, 0, 1},
		}},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.rttlatency"]
	require.Len(t, pts, 1)
	assert.Equal(t, "10.0.0.1", attrValue(pts[0], "rtt_echo_source_address"))
}

// The column is the more specific of the two declarations, so it wins when
// both name a conversion.
func TestCollectTable_ColumnConversionBeatsTheTagConversion(t *testing.T) {
	const (
		host        = "10.0.0.89"
		sysObjValue = "1.3.6.1.4.1.9999.89"
		tableOID    = "1.3.6.1.4.1.9999.89.1"
		rttOID      = "1.3.6.1.4.1.9999.89.1.1"
		addrOID     = "1.3.6.1.4.1.9999.89.1.2"
	)
	p := profileWithOID(sysObjValue, "rtt.yml", []profiles.MetricEntry{{
		Table:   &profiles.Table{Name: "rttTable", OID: tableOID},
		Symbols: []profiles.Symbol{{Name: "rttLatency", OID: rttOID}},
		MetricTags: []profiles.MetricTag{{
			Tag:        "peer",
			Column:     &profiles.TagColumn{OID: addrOID, Name: "peerAddress", Conversion: "hwaddr"},
			Conversion: "hextoip",
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		rttOID:         {rttOID + ".1": intPDU(rttOID+".1", 12)},
		addrOID: {addrOID + ".1": {
			Name: addrOID + ".1", Type: gosnmp.OctetString, Value: []byte{10, 0, 0, 1},
		}},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.rttlatency"]
	require.Len(t, pts, 1)
	assert.Equal(t, "0a:00:00:01", attrValue(pts[0], "peer"))
}

// A device-wide `metric_tags:` entry carries the tag-level conversion the same
// way. The two paths render through one helper, and this pins that they do.
func TestCollectTarget_DeviceTagConversionOnTheTagIsApplied(t *testing.T) {
	const (
		host        = "10.0.0.90"
		sysObjValue = "1.3.6.1.4.1.9999.90"
		addrOID     = "1.3.6.1.4.1.9999.90.1.1.0"
		metricOID   = "1.3.6.1.4.1.9999.90.2.0"
	)
	p := profileWithOID(sysObjValue, "device.yml", []profiles.MetricEntry{{
		Symbol: &profiles.Symbol{Name: "uptime", OID: metricOID},
	}})
	p.MetricTags = []profiles.MetricTag{{
		Tag:        "management_ip",
		Column:     &profiles.TagColumn{OID: addrOID, Name: "mgmtAddress"},
		Conversion: "hextoip",
	}}
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		metricOID:      {metricOID: intPDU(metricOID, 5)},
		addrOID: {addrOID: {
			Name: addrOID, Type: gosnmp.OctetString, Value: []byte{192, 168, 1, 20},
		}},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.uptime"]
	require.Len(t, pts, 1)
	assert.Equal(t, "192.168.1.20", attrValue(pts[0], "management_ip"))
}

// The bundled Cisco CSR profile is the one that declares a conversion on the
// tag, so it is driven end to end through the real matcher.
func TestCollectTarget_BundledCSRSourceAddressRendersAsAnIP(t *testing.T) {
	const (
		host        = "10.0.0.91"
		sysObjValue = "1.3.6.1.4.1.9.1.1537"
		latencyOID  = "1.3.6.1.4.1.9.9.42.1.2.10.1.1"
		srcOID      = "1.3.6.1.4.1.9.9.42.1.2.2.1.6"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		latencyOID:     {latencyOID + ".7": intPDU(latencyOID+".7", 4)},
		srcOID: {srcOID + ".7": {
			Name: srcOID + ".7", Type: gosnmp.OctetString, Value: []byte{172, 16, 5, 9},
		}},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.rttmonlatestrttopercompletiontime"]
	require.Len(t, pts, 1)
	assert.Equal(t, "172.16.5.9", attrValue(pts[0], "rtt_echo_source_address"))
}

// ---------------------------------------------------------------------------
// GETBULK
// ---------------------------------------------------------------------------

// bulkWalkFixture is a device with one table column and enough of a profile to
// match it.
func bulkWalkFixture(sysObjValue, colOID string) (*profiles.Profile, *recordingWalker) {
	p := profileWithOID(sysObjValue, "bulk.yml", []profiles.MetricEntry{
		{Symbols: []profiles.Symbol{{Name: "ifInOctets", OID: colOID}}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		colOID:         {colOID + ".1": counter32PDU(colOID+".1", 4096)},
	}}
	return p, w
}

// A profile that says nothing about bulk walking gets GETBULK for its tables.
// The two walks that choose the profile come first and cannot: nothing yet
// says the device tolerates a GETBULK.
func TestCollectTarget_BulkWalksTheProfileTables(t *testing.T) {
	const (
		host        = "10.0.0.90"
		sysObjValue = "1.3.6.1.4.1.9999.90"
		colOID      = "1.3.6.1.2.1.2.2.1.10"
	)
	p, w := bulkWalkFixture(sysObjValue, colOID)
	c := newCollector(walkerFactory(w), p)

	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, map[string]bool{
		sysObjectIDOID: false,
		sysDescrOID:    false,
		colOID:         true,
	}, w.bulkByOID)
}

// A profile carrying `no_use_bulkwalkall` describes an agent that answers
// GETBULK badly, so every walk of the run stays on GETNEXT.
func TestCollectTarget_ProfileDisablingBulkWalkKeepsGetNext(t *testing.T) {
	const (
		host        = "10.0.0.91"
		sysObjValue = "1.3.6.1.4.1.8072.3.2.10"
		colOID      = "1.3.6.1.2.1.2.2.1.10"
	)
	p, w := bulkWalkFixture(sysObjValue, colOID)
	p.NoUseBulkWalkAll = true
	c := newCollector(walkerFactory(w), p)

	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, map[string]bool{
		sysObjectIDOID: false,
		sysDescrOID:    false,
		colOID:         false,
	}, w.bulkByOID)
}

// A device no profile matches is never bulk walked: the run ends at the two
// walks that failed to identify it.
func TestCollectTarget_UnmatchedDeviceIsNeverBulkWalked(t *testing.T) {
	const host = "10.0.0.92"
	_, w := bulkWalkFixture("1.3.6.1.4.1.9999.92", "1.3.6.1.2.1.2.2.1.10")
	c := newCollector(walkerFactory(w), nil)

	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.False(t, w.bulkWalk)
	assert.Equal(t, map[string]bool{sysObjectIDOID: false, sysDescrOID: false}, w.bulkByOID)
}

// ---------------------------------------------------------------------------
// A metric tag that carries its OID directly
// ---------------------------------------------------------------------------

// The direct form resolves to the column it describes, so every caller of the
// shared helper reads it the way it reads a nested `column:`.
func TestMetricTagColumn_DirectOIDBecomesAColumn(t *testing.T) {
	col := metricTagColumn(&profiles.MetricTag{OID: "1.3.6.1.4.1.9999.1.1", Name: "portDataName"})
	require.NotNil(t, col)
	assert.Equal(t, "1.3.6.1.4.1.9999.1.1", col.OID)
	assert.Equal(t, "portDataName", col.Name)
}

// The nested column is the more specific of the two declarations, so it wins
// when a tag writes both. No bundled profile does; an override file could.
func TestMetricTagColumn_NestedColumnBeatsADirectOID(t *testing.T) {
	col := metricTagColumn(&profiles.MetricTag{
		OID:    "1.3.6.1.4.1.9999.1.1",
		Name:   "directName",
		Column: &profiles.TagColumn{OID: "1.3.6.1.4.1.9999.1.2", Name: "nestedName"},
	})
	require.NotNil(t, col)
	assert.Equal(t, "1.3.6.1.4.1.9999.1.2", col.OID)
	assert.Equal(t, "nestedName", col.Name)
}

// A nested column naming no OID walks nothing, so it does not stand in the way
// of a direct declaration beside it.
func TestMetricTagColumn_ColumnWithNoOIDYieldsToADirectOID(t *testing.T) {
	col := metricTagColumn(&profiles.MetricTag{
		OID:    "1.3.6.1.4.1.9999.1.1",
		Name:   "directName",
		Column: &profiles.TagColumn{Name: "nestedName"},
	})
	require.NotNil(t, col)
	assert.Equal(t, "1.3.6.1.4.1.9999.1.1", col.OID)
	assert.Equal(t, "directName", col.Name)
}

// The tag-level conversion renders the column whichever form declared it. It is
// folded in one place, so the direct form reaches it without a path of its own.
func TestMetricTagColumn_DirectOIDCarriesTheTagConversion(t *testing.T) {
	col := metricTagColumn(&profiles.MetricTag{
		OID: "1.3.6.1.4.1.9999.1.1", Name: "mgmtAddress", Conversion: "hextoip",
	})
	require.NotNil(t, col)
	assert.Equal(t, "hextoip", col.Conversion)
}

// A tag declaring no OID in either form resolves to nothing, and the callers
// that skip a column without an OID skip it the same way.
func TestMetricTagColumn_NeitherFormResolvesToNothing(t *testing.T) {
	assert.Nil(t, metricTagColumn(&profiles.MetricTag{Tag: "row_name"}))
	assert.Nil(t, metricTagColumn(&profiles.MetricTag{Tag: "row_name", Name: "rowName"}))
	assert.Nil(t, metricTagColumn(&profiles.MetricTag{Tag: "row_name", OID: "  "}))
}

// ---------------------------------------------------------------------------
// A metric tag named inside its column
// ---------------------------------------------------------------------------

// A profile may write `tag:` inside `column:` rather than beside it. It names
// the attribute key either way, so the nested one names it too. Without that
// the tag falls back to the column's MIB name.
func TestMetricTagName_TagInsideTheColumnNamesTheAttribute(t *testing.T) {
	mt := &profiles.MetricTag{Column: &profiles.TagColumn{
		OID: "1.3.6.1.4.1.9999.1.1", Name: "systemSerialNumber", Tag: "serial_number",
	}}
	assert.Equal(t, "serial_number", metricTagName(mt, metricTagColumn(mt)))
}

// The column's tag is the more specific of the two declarations, so it wins
// when a tag writes both, the way the column's conversion and a nested column
// win over what sits beside them. No bundled profile writes both; an override
// file could.
func TestMetricTagName_TagInsideTheColumnBeatsTheOuterTag(t *testing.T) {
	mt := &profiles.MetricTag{
		Tag: "outer_key",
		Column: &profiles.TagColumn{
			OID: "1.3.6.1.4.1.9999.1.1", Name: "systemSerialNumber", Tag: "serial_number",
		},
	}
	assert.Equal(t, "serial_number", metricTagName(mt, metricTagColumn(mt)))
}

// The nested tag reaches every caller through the one helper that builds the
// effective column, so the `symbol:` alias and the tag-level conversion copy
// carry it as well.
func TestMetricTagName_NestedTagSurvivesTheAliasAndTheConversionCopy(t *testing.T) {
	alias := &profiles.MetricTag{Symbol: &profiles.TagColumn{
		OID: "1.3.6.1.4.1.9999.1.1", Name: "colName", Tag: "nested_key",
	}}
	assert.Equal(t, "nested_key", metricTagName(alias, metricTagColumn(alias)))

	converted := &profiles.MetricTag{
		Conversion: "hextoip",
		Column: &profiles.TagColumn{
			OID: "1.3.6.1.4.1.9999.1.2", Name: "colName", Tag: "nested_key",
		},
	}
	col := metricTagColumn(converted)
	require.NotNil(t, col)
	assert.Equal(t, "hextoip", col.Conversion)
	assert.Equal(t, "nested_key", metricTagName(converted, col))
}

// A nested column naming no OID walks nothing, so the direct declaration
// beside it stands in whole and the nested tag goes with the column it sat in.
func TestMetricTagName_NestedTagGoesWithAColumnThatNamesNoOID(t *testing.T) {
	mt := &profiles.MetricTag{
		Tag:    "outer_key",
		OID:    "1.3.6.1.4.1.9999.1.1",
		Name:   "directName",
		Column: &profiles.TagColumn{Name: "colName", Tag: "nested_key"},
	}
	assert.Equal(t, "outer_key", metricTagName(mt, metricTagColumn(mt)))
}

// A tag with neither a column nor a tag of its own still names nothing, so the
// callers that skip an unnamed tag keep skipping it.
func TestMetricTagName_NoDeclarationNamesNothing(t *testing.T) {
	mt := &profiles.MetricTag{}
	assert.Empty(t, metricTagName(mt, metricTagColumn(mt)))
}

// The bundled FortiSwitch profile declares its serial-number tag inside the
// column. The exported attribute is the declared key, not the MIB column name.
func TestCollectTarget_NestedTagNamesTheBundledSerialAttribute(t *testing.T) {
	const (
		host        = "10.0.0.121"
		sysObjValue = "1.3.6.1.4.1.12356.106.1.1086"
		serialOID   = "1.3.6.1.4.1.12356.106.1.1.1.0"
		diskOID     = "1.3.6.1.4.1.12356.106.4.1.6.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		serialOID:      {serialOID: stringPDU(serialOID, "S1234567890")},
		diskOID:        {diskOID: intPDU(diskOID, 4096)},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.fssysdiskcapacity"]
	require.Len(t, pts, 1)
	assert.Equal(t, "S1234567890", attrValue(pts[0], "entity_serial"))
	assert.Empty(t, attrValue(pts[0], "fsSysSerial"), "the MIB column name must not be exported as well")
}

// A row condition names a tag column by the key it renders under, so it
// resolves against the nested tag the same way it resolves against the outer
// one. Both go through the one helper that names a tag.
func TestCollectTable_ConditionResolvesANestedTagName(t *testing.T) {
	const (
		host        = "10.0.0.122"
		sysObjValue = "1.3.6.1.4.1.9999.122"
		tableOID    = "1.3.6.1.4.1.9999.122.1"
		valueOID    = "1.3.6.1.4.1.9999.122.1.1"
		stateOID    = "1.3.6.1.4.1.9999.122.1.2"
	)
	p := profileWithOID(sysObjValue, "cond.yml", []profiles.MetricEntry{{
		Table:   &profiles.Table{Name: "sensorTable", OID: tableOID},
		Symbols: []profiles.Symbol{{Name: "sensorValue", OID: valueOID, Condition: "sensor_state=1"}},
		MetricTags: []profiles.MetricTag{{
			Column: &profiles.TagColumn{OID: stateOID, Name: "sensorState", Tag: "sensor_state"},
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		valueOID: {
			valueOID + ".1": intPDU(valueOID+".1", 11),
			valueOID + ".2": intPDU(valueOID+".2", 22),
		},
		stateOID: {
			stateOID + ".1": intPDU(stateOID+".1", 1),
			stateOID + ".2": intPDU(stateOID+".2", 2),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.sensorvalue"]
	require.Len(t, pts, 1)
	assert.Equal(t, int64(11), pts[0].value)
}

// A table entry whose tag carries its own OID tags its rows with it.
func TestCollectTable_DirectOIDTagReachesRows(t *testing.T) {
	const (
		host        = "10.0.0.110"
		sysObjValue = "1.3.6.1.4.1.9999.110"
		tableOID    = sysObjValue + ".1"
		statusOID   = tableOID + ".1.5"
		nameOID     = tableOID + ".1.3"
	)
	p := profileWithOID(sysObjValue, "direct.yml", []profiles.MetricEntry{{
		Table:      &profiles.Table{Name: "portDataTable", OID: tableOID},
		Symbols:    []profiles.Symbol{{Name: "portDataStatus", OID: statusOID}},
		MetricTags: []profiles.MetricTag{{OID: nameOID, Name: "portDataName"}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID:      {statusOID + ".1": intPDU(statusOID+".1", 2)},
		nameOID:        {nameOID + ".1": stringPDU(nameOID+".1", "Console A")},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.portdatastatus"]
	require.Len(t, pts, 1)
	assert.Equal(t, int64(2), pts[0].value)
	assert.Equal(t, "Console A", attrValue(pts[0], "portDataName"))
}

// A `tag:` beside the direct form names the attribute, the way it does beside a
// nested column.
func TestCollectTable_DirectOIDTagUsesTheTagName(t *testing.T) {
	const (
		host        = "10.0.0.111"
		sysObjValue = "1.3.6.1.4.1.9999.111"
		tableOID    = sysObjValue + ".1"
		statusOID   = tableOID + ".1.5"
		nameOID     = tableOID + ".1.3"
	)
	p := profileWithOID(sysObjValue, "direct.yml", []profiles.MetricEntry{{
		Table:      &profiles.Table{Name: "portDataTable", OID: tableOID},
		Symbols:    []profiles.Symbol{{Name: "portDataStatus", OID: statusOID}},
		MetricTags: []profiles.MetricTag{{Tag: "port_name", OID: nameOID, Name: "portDataName"}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID:      {statusOID + ".1": intPDU(statusOID+".1", 2)},
		nameOID:        {nameOID + ".1": stringPDU(nameOID+".1", "Console A")},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.portdatastatus"]
	require.Len(t, pts, 1)
	assert.Equal(t, "Console A", attrValue(pts[0], "port_name"))
	assert.Empty(t, attrValue(pts[0], "portDataName"))
}

// An `index_transform:` beside the direct form joins it from another table, the
// way it does beside a nested column.
func TestCollectTable_DirectOIDTagJoinsAcrossTables(t *testing.T) {
	const (
		host        = "10.0.0.112"
		sysObjValue = "1.3.6.1.4.1.9999.112"
		tableOID    = sysObjValue + ".1"
		statusOID   = tableOID + ".1.5"
		nameOID     = sysObjValue + ".2.1.1"
	)
	p := profileWithOID(sysObjValue, "direct.yml", []profiles.MetricEntry{{
		Table:   &profiles.Table{Name: "portDataTable", OID: tableOID},
		Symbols: []profiles.Symbol{{Name: "portDataStatus", OID: statusOID}},
		MetricTags: []profiles.MetricTag{{
			Table: "ifXTable", OID: nameOID, Name: "ifName",
			IndexTransform: profiles.IndexTransform{{Start: 0, End: 0}},
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID:      {statusOID + ".7.1": intPDU(statusOID+".7.1", 2)},
		nameOID:        {nameOID + ".7": stringPDU(nameOID+".7", "ge-0/0/7")},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.portdatastatus"]
	require.Len(t, pts, 1)
	assert.Equal(t, "ge-0/0/7", attrValue(pts[0], "ifName"))
}

// A `condition:` naming the direct form's column filters on it, the way it does
// on a nested column.
func TestCollectTable_ConditionNamesADirectOIDTag(t *testing.T) {
	const (
		host        = "10.0.0.113"
		sysObjValue = "1.3.6.1.4.1.9999.113"
		tableOID    = sysObjValue + ".1"
		statusOID   = tableOID + ".1.5"
		typeOID     = tableOID + ".1.4"
	)
	p := profileWithOID(sysObjValue, "direct.yml", []profiles.MetricEntry{{
		Table: &profiles.Table{Name: "portDataTable", OID: tableOID},
		Symbols: []profiles.Symbol{
			{Name: "portDataStatus", OID: statusOID, Condition: `portDataType="serial"`},
		},
		MetricTags: []profiles.MetricTag{{OID: typeOID, Name: "portDataType"}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID: {
			statusOID + ".1": intPDU(statusOID+".1", 2),
			statusOID + ".2": intPDU(statusOID+".2", 3),
		},
		typeOID: {
			typeOID + ".1": stringPDU(typeOID+".1", "serial"),
			typeOID + ".2": stringPDU(typeOID+".2", "modem"),
		},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.portdatastatus"]
	require.Len(t, pts, 1)
	assert.Equal(t, int64(2), pts[0].value)
	assert.Equal(t, "serial", attrValue(pts[0], "portDataType"))
}

// The bundled Raritan Dominion profile is the one that writes the direct form,
// so it is driven end to end through the real matcher. Its portDataStatus rows
// were exported with neither port tag before the shape was read.
func TestCollectTarget_BundledDominionPortTagsReachRows(t *testing.T) {
	const (
		host        = "10.0.0.114"
		sysObjValue = "1.3.6.1.4.1.13742.3.2.10"
		statusOID   = "1.3.6.1.4.1.13742.3.1.4.1.5"
		nameOID     = "1.3.6.1.4.1.13742.3.1.4.1.3"
		typeOID     = "1.3.6.1.4.1.13742.3.1.4.1.4"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID:      {statusOID + ".3": intPDU(statusOID+".3", 2)},
		nameOID:        {nameOID + ".3": stringPDU(nameOID+".3", "Console A")},
		typeOID:        {typeOID + ".3": stringPDU(typeOID+".3", "serial")},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.portdatastatus"]
	require.Len(t, pts, 1)
	assert.Equal(t, "Console A", attrValue(pts[0], "portDataName"))
	assert.Equal(t, "serial", attrValue(pts[0], "portDataType"))
}

// A tag that names no OID in either form tags nothing. It is reported once for
// the profile, the way the other declarations this collector cannot act on are.
func TestCollectTarget_TagWithNoOIDIsReportedOnce(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		host        = "10.0.0.115"
		sysObjValue = "1.3.6.1.4.1.9999.115"
		tableOID    = sysObjValue + ".1"
		statusOID   = tableOID + ".1.5"
	)
	p := profileWithOID(sysObjValue, "no-oid.yml", []profiles.MetricEntry{{
		Table:      &profiles.Table{Name: "portDataTable", OID: tableOID},
		Symbols:    []profiles.Symbol{{Name: "portDataStatus", OID: statusOID}},
		MetricTags: []profiles.MetricTag{{Tag: "port_name"}},
	}})
	p.MetricTags = []profiles.MetricTag{{Name: "chassisName"}}
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID:      {statusOID + ".1": intPDU(statusOID+".1", 2)},
	}}

	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, 2, strings.Count(logs.String(), "names no OID"), "logs: %s", logs.String())
	assert.Contains(t, logs.String(), "tag=port_name")
	assert.Contains(t, logs.String(), "tag=chassisName")
	assert.Contains(t, logs.String(), "profile=no-oid.yml")
}

// ---------------------------------------------------------------------------
// A bare tag-level `index`
// ---------------------------------------------------------------------------

// A tag-level `index` is a selector this collector does not implement, so it is
// named once per profile instead of being dropped without a word.
func TestCollectTarget_TagIndexIsReportedOnce(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		host        = "10.0.0.116"
		sysObjValue = "1.3.6.1.4.1.9999.116"
		statusOID   = sysObjValue + ".1.1.1"
		nameOID     = sysObjValue + ".2.1.1"
	)
	p := profileWithOID(sysObjValue, "tag-index.yml", []profiles.MetricEntry{{
		Table:   &profiles.Table{Name: "portPhysTable", OID: sysObjValue + ".1"},
		Symbols: []profiles.Symbol{{Name: "portPhysStatus", OID: statusOID}},
		MetricTags: []profiles.MetricTag{{
			Index:  1,
			Tag:    "port_index",
			Column: &profiles.TagColumn{Name: "portName", OID: nameOID},
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID:      {statusOID + ".1.5": intPDU(statusOID+".1.5", 2)},
		nameOID:        {nameOID + ".1.5": stringPDU(nameOID+".1.5", "port5")},
	}}

	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, 1, strings.Count(logs.String(), "Ignoring metric tag index"), "logs: %s", logs.String())
	assert.Contains(t, logs.String(), "index=1")
	assert.Contains(t, logs.String(), "tag=port_index")
	assert.Contains(t, logs.String(), "profile=tag-index.yml")

	// The selector is reported, not acted on: the tag still lands on the row.
	points := c.testDeviceStore("p", host)["snmp.portphysstatus"]
	require.Len(t, points, 1)
	assert.Contains(t, attrs(points[0]), "port_index")
}

// The one bundled tag carrying an `index` reads a column from a sibling table
// that shares the metric table's composite index, so the rows already line up
// suffix for suffix. Any reading of `index` as a component selector would key
// the join by one component and match nothing, so this pins the join that lands.
func TestCollectTarget_BundledBrocadePortIndexReachesPhysRows(t *testing.T) {
	const (
		physAdmin = "1.3.6.1.2.1.75.1.2.2.1.1"
		portID    = "1.3.6.1.2.1.75.1.2.1.1.1"
	)

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.1588.2.1.1.32")},
		physAdmin: {
			physAdmin + ".1.5": intPDU(physAdmin+".1.5", 1),
			physAdmin + ".1.6": intPDU(physAdmin+".1.6", 2),
		},
		portID: {
			portID + ".1.5": stringPDU(portID+".1.5", "0005"),
			portID + ".1.6": stringPDU(portID+".1.6", "0006"),
		},
	}}

	c := newCollector(walkerFactory(w), bundledProfile(t, "brocade/brocade-fc-switch.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.117"), mustAuth(), "p", DialOptions{}))

	points := c.testDeviceStore("p", "10.0.0.117")["snmp.fcfxportphysadminstatus"]
	require.Len(t, points, 2)
	got := make(map[string]string, len(points))
	for _, pt := range points {
		a := attrs(pt)
		got[a["row_index"]] = a["port_index"]
	}
	assert.Equal(t, map[string]string{"1.5": "5", "1.6": "6"}, got)
}

// Every bundled profile resolves a column for every tag it declares, so the
// report is silent across the whole bundled set.
func TestReviewProfile_BundledProfilesDeclareNoTagWithoutAnOID(t *testing.T) {
	loader, err := profiles.LoadProfiles("", discardLogger)
	require.NoError(t, err)
	all, err := loader.AllResolved()
	require.NoError(t, err)

	var without []string
	check := func(relPath string, tags []profiles.MetricTag) {
		for i := range tags {
			if col := metricTagColumn(&tags[i]); col == nil || col.OID == "" {
				without = append(without, relPath+" "+tags[i].Tag)
			}
		}
	}
	for _, p := range all {
		check(p.RelPath, p.MetricTags)
		for _, entry := range p.Metrics {
			check(p.RelPath, entry.MetricTags)
		}
	}
	assert.Empty(t, without)
}

// ---------------------------------------------------------------------------
// to_one keeps the text it converted
// ---------------------------------------------------------------------------

// to_one exists because the value belongs in an attribute and the metric is a
// presence count. Dropping the text leaves nothing to tell one state from
// another, so it rides the display path hextoip and regexp already use.
func TestPduToValue_ToOneKeepsTheSourceText(t *testing.T) {
	tests := []struct {
		name string
		pdu  snmp.PDU
		want string
	}{
		{"OctetString", stringPDU("x", "passive"), "passive"},
		{"padded OctetString", stringPDU("x", "  active  "), "active"},
		{"Integer", intPDU("x", 3), "3"},
		{"empty OctetString", stringPDU("x", ""), ""},
		{"no value", snmp.PDU{Name: "x", Type: gosnmp.Null}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, display, err := pduToValue(tt.pdu, "to_one")
			require.NoError(t, err)
			assert.Equal(t, int64(1), val)
			assert.Equal(t, tt.want, display)
		})
	}
}

// The bundled Palo Alto profile converts its three HA state symbols with
// to_one. Two devices in different states have to produce different series,
// which they only do if the state reaches an attribute.
func TestCollectTarget_ToOneStatesAreDistinguishable(t *testing.T) {
	const (
		sysObjValue = "1.3.6.1.4.1.25461.2.3.1"
		haStateOID  = "1.3.6.1.4.1.25461.2.1.2.1.11.0"
		haModeOID   = "1.3.6.1.4.1.25461.2.1.2.1.13.0"
	)
	collectState := func(host, state, mode string) []observedPoint {
		w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
			sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
			sysDescrOID:    {},
			haStateOID:     {haStateOID: stringPDU(haStateOID, state)},
			haModeOID:      {haModeOID: stringPDU(haModeOID, mode)},
		}}
		c := newBundledCollector(t, walkerFactory(w))
		require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
		return c.testDeviceStore("p", host)["snmp.pansyshastate"]
	}

	active := collectState("10.0.0.71", "active", "active-passive")
	passive := collectState("10.0.0.72", "passive", "active-passive")
	require.Len(t, active, 1)
	require.Len(t, passive, 1)
	assert.Equal(t, int64(1), active[0].value)
	assert.Equal(t, int64(1), passive[0].value)
	assert.Equal(t, "active", attrValue(active[0], "panSysHAState_value"))
	assert.Equal(t, "passive", attrValue(passive[0], "panSysHAState_value"))
}

// The F5 pool member status detail is a table column converted with to_one, so
// the text has to survive the table path too, per row.
func TestCollectTarget_ToOneKeepsTheTextOnTableRows(t *testing.T) {
	const (
		host        = "10.0.0.73"
		sysObjValue = "1.3.6.1.4.1.3375.2.1.3.4.10"
		reasonOID   = "1.3.6.1.4.1.3375.2.2.5.6.2.1.8"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		reasonOID: {
			reasonOID + ".1": stringPDU(reasonOID+".1", "Pool member is available"),
			reasonOID + ".2": stringPDU(reasonOID+".2", "Pool member has been marked down"),
		},
	}}
	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.pool_mbr_status_detail"]
	require.Len(t, pts, 2)
	byIndex := map[string]string{}
	for _, pt := range pts {
		require.Equal(t, int64(1), pt.value)
		byIndex[attrValue(pt, "row_index")] = attrValue(pt, "pool_mbr_status_detail_value")
	}
	assert.Equal(t, map[string]string{
		"1": "Pool member is available",
		"2": "Pool member has been marked down",
	}, byIndex)
}

// A symbol may declare an enum beside to_one. The converted value is 1
// whatever the device reported, so naming the enum member numbered 1 would
// label every state with the same name, and label it wrongly. Four bundled
// symbols have that shape.
func TestCollectTarget_ToOneDoesNotNameAnEnumMember(t *testing.T) {
	const (
		host        = "10.0.0.74"
		sysObjValue = "1.3.6.1.4.1.9999.74"
		stateOID    = "1.3.6.1.4.1.9999.74.1.3.0"
	)
	p := profileWithOID(sysObjValue, "enum.yml", []profiles.MetricEntry{{
		Symbols: []profiles.Symbol{{
			Name:       "contactState",
			OID:        stateOID,
			Conversion: "to_one",
			Enum:       profiles.Enum{Values: map[string]int{"open": 1, "closed": 2}},
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		stateOID:       {stateOID: intPDU(stateOID, 2)},
	}}
	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.contactstate"]
	require.Len(t, pts, 1)
	assert.Empty(t, attrValue(pts[0], "contactState_status"), "to_one discards the number the enum names")
	assert.Equal(t, "2", attrValue(pts[0], "contactState_value"))
}

// ---------------------------------------------------------------------------
// Row identity on the scalar path is decided by the OID, not by the poll
// ---------------------------------------------------------------------------

// snmpAgent answers a walk the way a device does through gosnmp: a walk rooted
// at a column returns every instance beneath it, and a walk rooted at a fully
// qualified instance falls back to a GET and returns that instance itself.
// Profiles are driven through it so the OIDs under test are the ones a real
// agent would return rather than ones a fixture chose.
type snmpAgent struct {
	vars map[string]snmp.PDU
}

func (a *snmpAgent) Connect() error     { return nil }
func (a *snmpAgent) Close() error       { return nil }
func (a *snmpAgent) SetBulkWalk(_ bool) {}

func (a *snmpAgent) Walk(root string, _ int) (map[string]snmp.PDU, error) {
	out := make(map[string]snmp.PDU)
	prefix := root + "."
	for oid, pdu := range a.vars {
		if oid != root && !strings.HasPrefix(oid, prefix) {
			continue
		}
		pdu.Name = "." + oid
		out[pdu.Name] = pdu
	}
	return out, nil
}

// The bundled Mikrotik profile collects the two HOST-RESOURCES storage columns
// through the scalar path. How many rows a walk happened to return is a
// property of that poll, so it cannot be what decides whether a point carries
// a row identity: a device with one storage row would leave the point
// unlabelled where a device with two labels it.
func TestCollectTarget_ScalarColumnWithOneRowStillCarriesIt(t *testing.T) {
	const (
		host        = "10.0.0.88"
		sysObjValue = "1.3.6.1.4.1.14988.1.1"
		totalOID    = "1.3.6.1.2.1.25.2.3.1.5"
	)
	agent := &snmpAgent{vars: map[string]snmp.PDU{
		sysObjectIDOID + ".0": oIDPDU(sysObjValue),
		totalOID + ".65":      intPDU(totalOID+".65", 262144),
	}}
	c := newBundledCollector(t, walkerFactory(agent))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.memorytotal"]
	require.Len(t, pts, 1)
	assert.Equal(t, "65", attrValue(pts[0], "row_index"),
		"a table column keeps its row identity however many rows the walk returned")
}

// Storage rows come and go, so the same column answers with one row on one
// poll and two on the next. The row present in both has to write the same
// series both times, or the point the first poll exported is orphaned.
func TestCollectTarget_ScalarRowKeepsItsSeriesWhenAnotherRowAppears(t *testing.T) {
	const (
		host        = "10.0.0.89"
		sysObjValue = "1.3.6.1.4.1.9999.89"
		colOID      = "1.3.6.1.4.1.9999.89.2.3.1.5"
	)
	p := profileWithOID(sysObjValue, "storage.yml", []profiles.MetricEntry{{
		Symbols: []profiles.Symbol{{Name: "storageUsed", OID: colOID}},
	}})
	agent := &snmpAgent{vars: map[string]snmp.PDU{
		sysObjectIDOID + ".0": oIDPDU(sysObjValue),
		colOID + ".65":        intPDU(colOID+".65", 262144),
	}}
	c := newCollector(walkerFactory(agent), p)

	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	first := c.testDeviceStore("p", host)["snmp.storageused"]
	require.Len(t, first, 1)

	agent.vars[colOID+".66"] = intPDU(colOID+".66", 16384)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	second := c.testDeviceStore("p", host)["snmp.storageused"]
	require.Len(t, second, 2)

	var rowSixtyFive observedPoint
	for _, pt := range second {
		if pt.value == 262144 {
			rowSixtyFive = pt
		}
	}
	assert.Equal(t, attrs(first[0]), attrs(rowSixtyFive),
		"the row wrote a different series once a second row appeared")
}

// attrs renders a point's attribute set as a comparable map.
func attrs(pt observedPoint) map[string]string {
	out := make(map[string]string, len(pt.attrs))
	for _, kv := range pt.attrs {
		out[string(kv.Key)] = kv.Value.AsString()
	}
	return out
}

// A scalar instance is the object's OID plus the single component 0, so a walk
// answering there identifies no row whatever else the walk returned. A device
// answering both is unusual, and the point is that neither answer changes how
// the other is read.
func TestCollectTarget_ScalarInstanceIsNotARow(t *testing.T) {
	const (
		host        = "10.0.0.90"
		sysObjValue = "1.3.6.1.4.1.9999.90"
		symOID      = "1.3.6.1.4.1.9999.90.1.2"
	)
	p := profileWithOID(sysObjValue, "scalar.yml", []profiles.MetricEntry{{
		Symbols: []profiles.Symbol{{Name: "loadAverage", OID: symOID}},
	}})
	agent := &snmpAgent{vars: map[string]snmp.PDU{
		sysObjectIDOID + ".0": oIDPDU(sysObjValue),
		symOID + ".0":         intPDU(symOID+".0", 7),
		symOID + ".3":         intPDU(symOID+".3", 9),
	}}
	c := newCollector(walkerFactory(agent), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.loadaverage"]
	require.Len(t, pts, 2)
	byValue := map[int64]string{}
	for _, pt := range pts {
		byValue[pt.value] = attrValue(pt, "row_index")
	}
	assert.Equal(t, map[int64]string{7: "", 9: "3"}, byValue)
}

// The five bundled profiles that collect only through the scalar path are
// driven end to end, every symbol of them, against an agent that answers the
// way a device does: at the instance the profile names when it names one, and
// at the .0 the profile leaves off when it does not. None of their symbols may
// gain a row identity.
func TestCollectTarget_ScalarOnlyProfilesGainNoRowIdentity(t *testing.T) {
	tests := []struct {
		relPath     string
		sysObjValue string
		host        string
	}{
		{"avtech/roomalert-32s.yml", "1.3.6.1.4.1.20916", "10.0.0.93"},
		{"avtech/roomalert-3e.yml", "1.3.6.1.4.1.20916.1.9.1", "10.0.0.94"},
		{"avtech/roomalert-3s.yml", "1.3.6.1.4.1.20916.1.13.1", "10.0.0.95"},
		{"infrasensing/sensor-gateway-base-unit.yml", "1.3.6.1.4.1.17095.1", "10.0.0.96"},
		// iPower names no instance, so the device supplies the .0.
		{"ipower/ipower-mib.yaml", "1.3.6.1.4.1.38218", "10.0.0.97"},
	}
	for _, tt := range tests {
		t.Run(tt.relPath, func(t *testing.T) {
			p := bundledProfile(t, tt.relPath)
			agent := &snmpAgent{vars: map[string]snmp.PDU{sysObjectIDOID + ".0": oIDPDU(tt.sysObjValue)}}
			want := map[string]struct{}{}
			for _, entry := range p.Metrics {
				require.Nil(t, entry.Table, "%s no longer collects only through the scalar path", tt.relPath)
				require.False(t, groupedSymbolsAreTableColumns(&entry),
					"%s no longer collects only through the scalar path", tt.relPath)
				syms := make([]*profiles.Symbol, 0, len(entry.Symbols)+1)
				if entry.Symbol != nil {
					syms = append(syms, entry.Symbol)
				}
				for i := range entry.Symbols {
					syms = append(syms, &entry.Symbols[i])
				}
				for _, sym := range syms {
					if unusableSymbolReason(sym) != "" {
						continue
					}
					oid := sym.OID
					if !strings.HasSuffix(oid, ".0") {
						oid += ".0"
					}
					agent.vars[oid] = intPDU(oid, 42)
					want[sym.MetricName()] = struct{}{}
				}
			}
			require.NotEmpty(t, want)

			c := newBundledCollector(t, walkerFactory(agent))
			require.NoError(t, c.CollectTarget(context.Background(), mustTarget(tt.host), mustAuth(), "p", DialOptions{}))

			store := c.testDeviceStore("p", tt.host)
			for name := range want {
				require.Contains(t, store, name, "%s collected nothing for %s", tt.relPath, name)
			}
			for name, pts := range store {
				for _, pt := range pts {
					assert.Empty(t, attrValue(pt, "row_index"), "%s gained a row identity on %s", tt.relPath, name)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unsigned values that do not fit the signed range
// ---------------------------------------------------------------------------

// SNMP counters are unsigned and an observation is int64. A 64-bit counter
// passes math.MaxInt64 halfway round, and the cast turned it into a negative
// gauge. The same applies to a hextoint:...:uint64 conversion, and to the
// Counter32 and Gauge32 path, which gosnmp decodes into a uint wide enough to
// hold what a non-conforming agent encodes in eight octets.
func TestPduToValue_UnsignedValuePastTheSignedRange(t *testing.T) {
	hexBytes := func(v uint64) []byte {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, v)
		return buf
	}
	tests := []struct {
		name       string
		pdu        snmp.PDU
		conversion string
		want       int64
		wantErr    bool
	}{
		{"Counter64 at the limit", counter64PDU("x", math.MaxInt64), "", math.MaxInt64, false},
		{"Counter64 past the limit", counter64PDU("x", math.MaxInt64+1), "", 0, true},
		{"Counter64 at the top", counter64PDU("x", math.MaxUint64), "", 0, true},
		{"Counter32 past the limit", snmp.PDU{Name: "x", Type: gosnmp.Counter32, Value: uint(math.MaxInt64 + 1)}, "", 0, true},
		{"Gauge32 past the limit", snmp.PDU{Name: "x", Type: gosnmp.Gauge32, Value: uint(math.MaxInt64 + 1)}, "", 0, true},
		{"Gauge32 at its own limit", snmp.PDU{Name: "x", Type: gosnmp.Gauge32, Value: uint(math.MaxUint32)}, "", math.MaxUint32, false},
		{
			"hextoint uint64 at the limit",
			snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: hexBytes(math.MaxInt64)},
			"hextoint:BigEndian:uint64", math.MaxInt64, false,
		},
		{
			"hextoint uint64 past the limit",
			snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: hexBytes(math.MaxInt64 + 1)},
			"hextoint:BigEndian:uint64", 0, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := pduToValue(tt.pdu, tt.conversion)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// The bundled IF-MIB block the Arista profile extends carries the 64-bit octet
// counters. A row whose counter passed the signed range exports nothing: a
// negative gauge, and a MaxInt64 clamp equally, is a number the device never
// reported, and the rows that did fit are unaffected.
func TestCollectTarget_CounterPastTheSignedRangeExportsNothing(t *testing.T) {
	const (
		host        = "10.0.0.98"
		sysObjValue = "1.3.6.1.4.1.30065.1.3011.7010.427.48"
		hcInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	)
	agent := &snmpAgent{vars: map[string]snmp.PDU{
		sysObjectIDOID + ".0": oIDPDU(sysObjValue),
		hcInOctets + ".1":     counter64PDU(hcInOctets+".1", 1<<40),
		hcInOctets + ".2":     counter64PDU(hcInOctets+".2", math.MaxInt64+1),
	}}
	c := newBundledCollector(t, walkerFactory(agent))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.ifhcinoctets"]
	require.Len(t, pts, 1, "the row past the signed range was exported")
	assert.Equal(t, int64(1<<40), pts[0].value)
	assert.Equal(t, "1", attrValue(pts[0], "row_index"))
}

// A skipped point is reported rather than dropped in silence, on both the
// paths that convert one.
func TestCollectTarget_CounterPastTheSignedRangeIsReported(t *testing.T) {
	const (
		sysObjValue = "1.3.6.1.4.1.9999.99"
		tableOID    = "1.3.6.1.4.1.9999.99.2"
		columnOID   = "1.3.6.1.4.1.9999.99.2.1.4"
		scalarOID   = "1.3.6.1.4.1.9999.99.3.1"
	)
	p := profileWithOID(sysObjValue, "counters.yml", []profiles.MetricEntry{
		{
			Table:   &profiles.Table{OID: tableOID, Name: "counterTable"},
			Symbols: []profiles.Symbol{{Name: "portOctets", OID: columnOID}},
		},
		{Symbol: &profiles.Symbol{Name: "totalOctets", OID: scalarOID}},
	})
	agent := &snmpAgent{vars: map[string]snmp.PDU{
		sysObjectIDOID + ".0": oIDPDU(sysObjValue),
		columnOID + ".1":      counter64PDU(columnOID+".1", math.MaxUint64),
		scalarOID + ".0":      counter64PDU(scalarOID+".0", math.MaxUint64),
	}}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := NewMetricsCollector(walkerFactory(agent), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.99"), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", "10.0.0.99")
	assert.NotContains(t, store, "snmp.portoctets")
	assert.NotContains(t, store, "snmp.totaloctets")
	assert.Contains(t, logs.String(), "name=portOctets")
	assert.Contains(t, logs.String(), "name=totalOctets")
	assert.Contains(t, logs.String(), "18446744073709551615")
	// The instance answered, not the column the profile named, so the report
	// says which row went missing.
	assert.Contains(t, logs.String(), "oid="+columnOID+".1")
	assert.Contains(t, logs.String(), "oid="+scalarOID+".0")
}

// ---------------------------------------------------------------------------
// An enum member declared with no value
// ---------------------------------------------------------------------------

// The bundled ESX profile writes `battery:` with nothing after it. Read as a
// mapping it takes 0, and vmwSubsystemType 0 is then labelled battery on every
// row. The member maps nothing instead, so the tag carries the number.
func TestCollectTarget_BundledEsxUnsetEnumMemberDoesNotLabelZero(t *testing.T) {
	const (
		hardwareStatus = "1.3.6.1.4.1.6876.4.20.3.1.3"
		subsystemType  = "1.3.6.1.4.1.6876.4.20.3.1.2"
	)

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.6876.4.1")},
		hardwareStatus: {
			hardwareStatus + ".1": intPDU(hardwareStatus+".1", 2),
			hardwareStatus + ".2": intPDU(hardwareStatus+".2", 2),
		},
		subsystemType: {
			// A component the device reports as 0, and one it reports as the
			// value the surrounding sequence leaves for battery.
			subsystemType + ".1": intPDU(subsystemType+".1", 0),
			subsystemType + ".2": intPDU(subsystemType+".2", 7),
		},
	}}

	c := newCollector(walkerFactory(w), bundledProfile(t, "vmware/esx.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.118"), mustAuth(), "p", DialOptions{}))

	points := c.testDeviceStore("p", "10.0.0.118")["snmp.vmwhardwarestatus"]
	require.Len(t, points, 2)
	got := make(map[string]string, len(points))
	for _, pt := range points {
		a := attrs(pt)
		got[a["row_index"]] = a["vmwSubsystemType"]
	}
	assert.Equal(t, map[string]string{"1": "0", "2": "7"}, got)
}

// The bundled FortiManager profile gives `none` the value 0 and leaves
// `canceled` without one. Read as a mapping both hold 0, and which name a
// device reporting 0 gets depends on map order.
func TestCollectTarget_BundledFortinetUnsetEnumMemberDoesNotCollideWithZero(t *testing.T) {
	const deviceState = "1.3.6.1.4.1.12356.103.6.2.1.15"

	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.12356.103.1.64")},
		deviceState: {
			deviceState + ".1": intPDU(deviceState+".1", 0),
			deviceState + ".2": intPDU(deviceState+".2", 8),
		},
	}}

	c := newCollector(walkerFactory(w), bundledProfile(t, "fortinet/fortinet-appliance.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.119"), mustAuth(), "p", DialOptions{}))

	points := c.testDeviceStore("p", "10.0.0.119")["snmp.fmdeviceentstate"]
	require.Len(t, points, 2)
	got := make(map[string]string, len(points))
	for _, pt := range points {
		a := attrs(pt)
		got[a["row_index"]] = a["fmDeviceEntState_status"]
	}
	assert.Equal(t, map[string]string{"1": "none", "2": ""}, got)
}

// An unset member leaves a label off every row of the table, so it is named
// once per profile the way the other declarations this collector cannot act on
// are named.
func TestCollectTarget_UnsetEnumMemberIsReportedOnce(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		host        = "10.0.0.120"
		sysObjValue = "1.3.6.1.4.1.9999.120"
		statusOID   = sysObjValue + ".1.1.1"
		typeOID     = sysObjValue + ".1.1.2"
	)
	p := profileWithOID(sysObjValue, "unset-enum.yml", []profiles.MetricEntry{{
		Table: &profiles.Table{Name: "envTable", OID: sysObjValue + ".1"},
		Symbols: []profiles.Symbol{{
			Name: "envState", OID: statusOID,
			Enum: profiles.Enum{Values: map[string]int{"normal": 2}, Unset: []string{"failed"}},
		}},
		MetricTags: []profiles.MetricTag{{
			Tag: "env_type",
			Column: &profiles.TagColumn{
				Name: "envType", OID: typeOID,
				Enum: profiles.Enum{Values: map[string]int{"fan": 4}, Unset: []string{"battery"}},
			},
		}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		statusOID:      {statusOID + ".1": intPDU(statusOID+".1", 2)},
		typeOID:        {typeOID + ".1": intPDU(typeOID+".1", 4)},
	}}

	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Equal(t, 2, strings.Count(logs.String(), "Ignoring enum member this collector cannot apply"),
		"logs: %s", logs.String())
	assert.Contains(t, logs.String(), "member=failed")
	assert.Contains(t, logs.String(), "member=battery")
	assert.Contains(t, logs.String(), "profile=unset-enum.yml")
}

// ---------------------------------------------------------------------------
// Close: what a discarded collector has to give back
// ---------------------------------------------------------------------------

// fakeRegistration stands in for the meter's record of a callback, so a test
// can see whether the collector handed it back.
type fakeRegistration struct {
	embedded.Registration
	unregistered atomic.Int32
	err          error
}

func (f *fakeRegistration) Unregister() error {
	f.unregistered.Add(1)
	return f.err
}

// The manager deleting its cache entry does not free a collector: every
// observable gauge callback closes over it, so the meter keeps the collector,
// its matcher and its whole profile set live and calls the callback on every
// export cycle. Asserting the collector's own slice is empty would pass
// against that, so the assertion is that each registration was given back.
func TestClose_GivesEveryCallbackBackToTheMeter(t *testing.T) {
	c := newCollector(nil, nil)
	first, second := &fakeRegistration{}, &fakeRegistration{}
	c.registrations = []metric.Registration{first, second}

	c.Close()

	assert.Equal(t, int32(1), first.unregistered.Load(), "the meter still calls a callback that was not unregistered")
	assert.Equal(t, int32(1), second.unregistered.Load(), "every registration goes back, not just the first")
}

// A registration that refuses to unregister must not stop the rest going back,
// and must not be retried by a second Close: the collector is discarded either
// way.
func TestClose_ReportsAFailedUnregisterAndCarriesOn(t *testing.T) {
	var logs bytes.Buffer
	c := NewMetricsCollector(nil, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	failing := &fakeRegistration{err: errors.New("pipeline closed")}
	healthy := &fakeRegistration{}
	c.registrations = []metric.Registration{failing, healthy}

	c.Close()
	c.Close()

	assert.Equal(t, int32(1), healthy.unregistered.Load(), "a failure ahead of it must not strand a later registration")
	assert.Equal(t, int32(1), failing.unregistered.Load(), "a discarded collector must not be unregistered twice")
	assert.Contains(t, logs.String(), "pipeline closed")
}

// withMeter installs a real meter for the length of the test, so
// ensureInstrument takes the path that registers a callback. Nothing listens
// on the endpoint: the registration is what is under test, not an export.
func withMeter(t *testing.T) {
	t.Helper()
	require.NoError(t, metrics.SetupMetricsExport(context.Background(), discardLogger, "localhost:4317", 3600))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = metrics.Shutdown(ctx)
		metrics.ResetMeter()
	})
}

// The registrations Close gives back are the ones ensureInstrument installed,
// and a collector that has been discarded installs no more: a callback added
// after the release would have nothing left to unregister it.
func TestClose_EndsTheCollectorsRegistrations(t *testing.T) {
	withMeter(t)
	c := newCollector(nil, nil)

	c.ensureInstrument("snmp.close.first", "first")
	c.ensureInstrument("snmp.close.second", "second")
	require.Len(t, c.registrations, 2, "ensureInstrument must keep what Close has to give back")

	c.Close()
	c.ensureInstrument("snmp.close.third", "third")

	assert.Empty(t, c.registrations, "a discarded collector must not install a callback nothing will unregister")
	assert.Empty(t, c.instruments)
}

// The store, the poll windows and the profile review set go with the
// callbacks: nothing reads them once the last policy has released the
// collector, and they are the bulk of what it holds.
func TestClose_DropsTheStateTheCallbacksRead(t *testing.T) {
	const (
		host        = "10.0.0.90"
		cpuOID      = "1.3.6.1.4.1.9999.90.1"
		sysObjValue = "1.3.6.1.4.1.9999.90"
	)
	p := profileWithOID(sysObjValue, "close.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID, PollTimeSec: 300}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 7)},
	}}
	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))
	require.NotEmpty(t, c.testDeviceStore("p", host))

	c.Close()

	assert.Empty(t, c.deviceStore, "the observations a callback would have read go with it")
	assert.Empty(t, c.pollState, "the poll windows go with the device they throttled")
	assert.Empty(t, c.reviewedProfiles, "the profile review set goes with the profile set")
}

// ---------------------------------------------------------------------------
// A prefixed conversion has to parse before it counts as supported
// ---------------------------------------------------------------------------

// The gate classified anything carrying a known prefix as supported without
// reading the rest of it, so a pattern that does not compile, or an endianness
// or width nothing recognises, passed review. A numeric PDU then took the
// numeric branch and shipped its value raw under a metric named for a
// transformed one.
func TestConversionError_MalformedPrefixedFormsAreRefused(t *testing.T) {
	for _, tt := range []struct {
		conversion string
		wantErr    bool
	}{
		{conversion: ""},
		{conversion: "to_one"},
		{conversion: "hextoip"},
		{conversion: "hwaddr"},
		{conversion: "hextoint:BigEndian:uint16"},
		{conversion: "hextoint:LittleEndian:uint32"},
		{conversion: "hextoint:BigEndian:uint64"},
		{conversion: `regexp:(\d+)`},
		{conversion: "regexp:60 Secs.*?(\\d+)"},
		// An empty pattern compiles and matches everything, so it is a
		// question of what the device answers rather than of syntax.
		{conversion: "regexp:"},
		{conversion: "hextoint:MiddleEndian:uint16", wantErr: true},
		{conversion: "hextoint:BigEndian:uint7", wantErr: true},
		{conversion: "hextoint:BigEndian", wantErr: true},
		{conversion: "hextoint:", wantErr: true},
		{conversion: "regexp:[", wantErr: true},
		{conversion: "regexp:(", wantErr: true},
		{conversion: "regexp:a{2,1}", wantErr: true},
		{conversion: "powerset_status", wantErr: true},
	} {
		t.Run(tt.conversion, func(t *testing.T) {
			err := conversionError(tt.conversion)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// The gate and the collection path have to agree, so a malformed conversion
// makes the symbol unusable and it is skipped before it is walked, exactly like
// one the collector never implemented.
func TestCollectTarget_MalformedConversionExportsNothing(t *testing.T) {
	const (
		host        = "10.0.0.75"
		plainOID    = "1.3.6.1.4.1.99.10.1.0"
		patternOID  = "1.3.6.1.4.1.99.10.2.0"
		widthOID    = "1.3.6.1.4.1.99.10.3.0"
		sysObjValue = "1.3.6.1.4.1.99.10"
	)
	p := profileWithOID(sysObjValue, "malformed-conversion.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "plainLoad", OID: plainOID}},
		{Symbol: &profiles.Symbol{Name: "patternLoad", OID: patternOID, Conversion: "regexp:["}},
		{Symbol: &profiles.Symbol{Name: "widthLoad", OID: widthOID, Conversion: "hextoint:MiddleEndian:uint7"}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
		plainOID:       {plainOID: intPDU(plainOID, 7)},
		patternOID:     {patternOID: intPDU(patternOID, 42)},
		widthOID:       {widthOID: counter32PDU(widthOID, 42)},
	}}

	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Empty(t, store["snmp.patternload"], "a pattern that does not compile must export nothing")
	assert.Empty(t, store["snmp.widthload"], "an unrecognised endianness and width must export nothing")
	assert.NotContains(t, w.walkCalls, patternOID, "the symbol is skipped before it is walked")
	assert.NotContains(t, w.walkCalls, widthOID, "the symbol is skipped before it is walked")

	require.Len(t, store["snmp.plainload"], 1, "a symbol declaring no conversion is untouched")
	assert.Equal(t, int64(7), store["snmp.plainload"][0].value)
}

// The review has to say which conversion it refused and why, since the profile
// names a value the export will not carry.
func TestReviewProfile_MalformedConversionIsReported(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		patternOID  = "1.3.6.1.4.1.99.11.1.0"
		sysObjValue = "1.3.6.1.4.1.99.11"
	)
	p := profileWithOID(sysObjValue, "malformed-report.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "patternLoad", OID: patternOID, Conversion: "regexp:["}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(sysObjValue)},
	}}
	c := NewMetricsCollector(walkerFactory(w), profiles.NewMatcher([]*profiles.Profile{p}, logger), logger)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("10.0.0.76"), mustAuth(), "p", DialOptions{}))

	assert.Contains(t, logs.String(), "conversion=regexp:[")
	assert.Contains(t, logs.String(), "symbol=patternLoad")
	assert.Contains(t, logs.String(), "invalid regexp")
}

// Nothing bundled declares a prefixed conversion that does not parse, so the
// gate takes no bundled metric away. The counts are asserted so a profile added
// with one of these forms is not silently left unexercised.
func TestConversionError_BundledPrefixedConversionsAllParse(t *testing.T) {
	loader, err := profiles.LoadProfiles("", discardLogger)
	require.NoError(t, err)
	all, err := loader.AllResolved()
	require.NoError(t, err)

	counts := map[string]int{}
	var malformed []string
	check := func(relPath, what, conversion string) {
		switch {
		case strings.HasPrefix(conversion, "hextoint:"):
			counts["hextoint:"]++
		case strings.HasPrefix(conversion, "regexp:"):
			counts["regexp:"]++
		default:
			return
		}
		if err := conversionError(conversion); err != nil {
			malformed = append(malformed, relPath+" "+what+" "+conversion+": "+err.Error())
		}
	}
	checkTags := func(relPath string, tags []profiles.MetricTag) {
		for i := range tags {
			if col := metricTagColumn(&tags[i]); col != nil {
				check(relPath, col.Name, col.Conversion)
			}
		}
	}
	for _, p := range all {
		checkTags(p.RelPath, p.MetricTags)
		for _, entry := range p.Metrics {
			if entry.Symbol != nil {
				check(p.RelPath, entry.Symbol.Name, entry.Symbol.Conversion)
			}
			for i := range entry.Symbols {
				check(p.RelPath, entry.Symbols[i].Name, entry.Symbols[i].Conversion)
			}
			checkTags(p.RelPath, entry.MetricTags)
		}
	}
	assert.Empty(t, malformed)
	// Three regexp: symbols and two hextoint: tag columns, which is every
	// prefixed declaration the bundled set carries.
	assert.Equal(t, map[string]int{"hextoint:": 2, "regexp:": 3}, counts)
}

// ---------------------------------------------------------------------------
// A conversion has to mean something for the PDU type the device answered with
// ---------------------------------------------------------------------------

// hextoint and regexp decode a number out of an OctetString, so a device that
// answered with a number has already supplied what they exist to recover and
// the value passes through. hextoip and hwaddr decode an address, which a bare
// number is not, so passing one through would put an undecoded value under a
// metric named for a decoded one.
func TestPduToValue_NumericPDUAcceptsOnlyTheNumericConversions(t *testing.T) {
	for _, tt := range []struct {
		conversion string
		wantErr    bool
	}{
		{conversion: ""},
		{conversion: "hextoint:BigEndian:uint16"},
		{conversion: `regexp:(\d+)`},
		{conversion: "hextoip", wantErr: true},
		{conversion: "hwaddr", wantErr: true},
	} {
		t.Run(tt.conversion, func(t *testing.T) {
			val, _, err := pduToValue(intPDU("x", 42), tt.conversion)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not meaningful")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, int64(42), val)
		})
	}
}

// The pass-through covers every PDU type the collector reads a number from, not
// only Integer, and to_one keeps its own answer whatever the type.
func TestPduToValue_EveryNumericTypeTakesTheSameDecision(t *testing.T) {
	for _, tt := range []struct {
		name string
		pdu  snmp.PDU
	}{
		{"Integer", intPDU("x", 42)},
		{"Counter32", counter32PDU("x", 42)},
		{"Gauge32", snmp.PDU{Name: "x", Type: gosnmp.Gauge32, Value: uint(42)}},
		{"Counter64", snmp.PDU{Name: "x", Type: gosnmp.Counter64, Value: uint64(42)}},
		{"TimeTicks", snmp.PDU{Name: "x", Type: gosnmp.TimeTicks, Value: uint32(42)}},
		{"Uinteger32", snmp.PDU{Name: "x", Type: gosnmp.Uinteger32, Value: uint32(42)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			val, _, err := pduToValue(tt.pdu, "hextoint:BigEndian:uint16")
			require.NoError(t, err)
			assert.Equal(t, int64(42), val)

			_, _, err = pduToValue(tt.pdu, "hwaddr")
			require.Error(t, err, "an address conversion has nothing to decode here")

			val, _, err = pduToValue(tt.pdu, "to_one")
			require.NoError(t, err)
			assert.Equal(t, int64(1), val, "to_one answers before the type is read")
		})
	}
}

// The pass-through reads the conversion through the same parse the review does,
// so a malformed one is not waved through on its prefix alone.
func TestPduToValue_MalformedNumericConversionIsNotWavedThrough(t *testing.T) {
	_, _, err := pduToValue(intPDU("x", 42), "regexp:[")
	require.Error(t, err)

	_, _, err = pduToValue(intPDU("x", 42), "hextoint:MiddleEndian:uint16")
	require.Error(t, err)
}

// An OctetString still decodes, so the decision is about the PDU type rather
// than about the conversion.
func TestPduToValue_OctetStringStillDecodesTheAddressConversions(t *testing.T) {
	val, display, err := pduToValue(snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: []byte{0xc0, 0x00, 0x02, 0x01}}, "hextoip")
	require.NoError(t, err)
	assert.Equal(t, int64(1), val)
	assert.Equal(t, "192.0.2.1", display)

	val, display, err = pduToValue(snmp.PDU{Name: "x", Type: gosnmp.OctetString, Value: []byte{0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e}}, "hwaddr")
	require.NoError(t, err)
	assert.Equal(t, int64(1), val)
	assert.Equal(t, "00:1b:21:3c:4d:5e", display)
}

// A bundled symbol declaring hwaddr against a device that answers with a number
// exports nothing rather than the number. The profile names the MAC of the
// stack master, and an integer is not one.
func TestCollectTarget_BundledAddressConversionOnANumericPDUExportsNothing(t *testing.T) {
	const (
		host   = "10.0.0.77"
		macOID = "1.3.6.1.4.1.2011.5.25.183.1.4.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU("1.3.6.1.4.1.2011.2.23.343")},
		macOID:         {macOID: intPDU(macOID, 42)},
	}}
	c := newCollector(walkerFactory(w), bundledProfile(t, "huawei/huawei-switches.yml"))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	assert.Empty(t, c.testDeviceStore("p", host)["snmp.hwstacksystemmac"])
	assert.Contains(t, w.walkCalls, macOID, "the symbol is collectable, so it is still walked")
}

// ---------------------------------------------------------------------------
// A condition belongs to its declaration, not to its OID
// ---------------------------------------------------------------------------

// twoNameConditionProfile builds an entry declaring one table column twice
// under two names, each symbol carrying the condition the test wants, plus the
// column the condition tests. This is what an override profile does when it
// re-exports a bundled column under a name of its own.
func twoNameConditionProfile(first, second profiles.Symbol) *profiles.Profile {
	return profileWithOID(twoNameSysObj, "one-column-two-names.yml", []profiles.MetricEntry{
		{
			Table:   &profiles.Table{Name: "linkTable", OID: twoNameTable},
			Symbols: []profiles.Symbol{first, second},
			MetricTags: []profiles.MetricTag{
				{Tag: "link_state", Column: &profiles.TagColumn{OID: twoNameStateCol, Name: "linkState"}},
			},
		},
	})
}

const (
	twoNameSysObj   = "1.3.6.1.4.1.99.20"
	twoNameTable    = "1.3.6.1.4.1.99.20.1"
	twoNameOctetCol = "1.3.6.1.4.1.99.20.1.1.2"
	twoNameStateCol = "1.3.6.1.4.1.99.20.1.1.3"
)

// twoNameWalker answers the octet column with two rows and the state column
// with 1 for the first and 2 for the second.
func twoNameWalker() *recordingWalker {
	return &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID + ".0": oIDPDU(twoNameSysObj)},
		twoNameOctetCol: {
			twoNameOctetCol + ".1": intPDU(twoNameOctetCol+".1", 10),
			twoNameOctetCol + ".2": intPDU(twoNameOctetCol+".2", 20),
		},
		twoNameStateCol: {
			twoNameStateCol + ".1": intPDU(twoNameStateCol+".1", 1),
			twoNameStateCol + ".2": intPDU(twoNameStateCol+".2", 2),
		},
	}}
}

// rowsOf renders a metric's points as row index to value.
func rowsOf(pts []observedPoint) map[string]int64 {
	out := map[string]int64{}
	for _, pt := range pts {
		out[attrValue(pt, "row_index")] = pt.value
	}
	return out
}

// A `tag:` renames the metric, so one column can be declared twice and export
// under two names. Only one of the two declarations carries a `condition:`
// here. Keyed on the OID, the condition reached the other declaration as well
// and filtered the rows it never asked to filter.
func TestCollectTarget_AConditionDoesNotReachTheOtherNameOfOneColumn(t *testing.T) {
	const host = "10.0.0.80"
	p := twoNameConditionProfile(
		profiles.Symbol{Name: "linkOctets", Tag: "OctetsUp", OID: twoNameOctetCol, Condition: "linkState=1"},
		profiles.Symbol{Name: "linkOctets", OID: twoNameOctetCol},
	)
	c := newCollector(walkerFactory(twoNameWalker()), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Equal(t, map[string]int64{"1": 10}, rowsOf(store["snmp.octetsup"]),
		"the conditional declaration keeps only the row its condition passes")
	assert.Equal(t, map[string]int64{"1": 10, "2": 20}, rowsOf(store["snmp.linkoctets"]),
		"the unconditional declaration exports every row")
}

// Both declarations carry a condition, and the conditions differ. Keyed on the
// OID, one entry held both and the declaration resolved last decided the rows
// of the other one too.
func TestCollectTarget_TwoNamesOfOneColumnKeepDifferentConditions(t *testing.T) {
	const host = "10.0.0.81"
	p := twoNameConditionProfile(
		profiles.Symbol{Name: "linkOctets", Tag: "OctetsUp", OID: twoNameOctetCol, Condition: "linkState=1"},
		profiles.Symbol{Name: "linkOctets", Tag: "OctetsDown", OID: twoNameOctetCol, Condition: "linkState=2"},
	)
	c := newCollector(walkerFactory(twoNameWalker()), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Equal(t, map[string]int64{"1": 10}, rowsOf(store["snmp.octetsup"]),
		"the first declaration keeps its own condition")
	assert.Equal(t, map[string]int64{"2": 20}, rowsOf(store["snmp.octetsdown"]),
		"the second declaration keeps its own condition")
}

// The condition a declaration cannot resolve is dropped for that declaration
// alone. Keyed on the OID, the resolvable sibling's check was the one left in
// the map and the unresolvable declaration was filtered by it.
func TestCollectTarget_AnUnresolvableConditionDoesNotBorrowASibling(t *testing.T) {
	const host = "10.0.0.82"
	p := twoNameConditionProfile(
		profiles.Symbol{Name: "linkOctets", Tag: "OctetsUp", OID: twoNameOctetCol, Condition: "linkState=1"},
		profiles.Symbol{Name: "linkOctets", OID: twoNameOctetCol, Condition: "nothingHere=1"},
	)
	c := newCollector(walkerFactory(twoNameWalker()), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	store := c.testDeviceStore("p", host)
	assert.Equal(t, map[string]int64{"1": 10}, rowsOf(store["snmp.octetsup"]))
	assert.Equal(t, map[string]int64{"1": 10, "2": 20}, rowsOf(store["snmp.linkoctets"]),
		"a condition this collector cannot apply filters nothing")
}

// TestConditionsKeyMatchesThePollWindow pins the two to one key. Poll state
// decides which declarations run and the condition map decides what their rows
// have to satisfy, so a declaration polled on its own window and filtered on a
// key that merged it with another would disagree with itself.
func TestConditionsKeyMatchesThePollWindow(t *testing.T) {
	same := []profiles.Symbol{
		{Name: "linkOctets", OID: twoNameOctetCol},
		{Name: "linkOctets", OID: twoNameOctetCol},
	}
	assert.Equal(t, symbolDeclKey(&same[0]), symbolDeclKey(&same[1]),
		"declarations one poll window serves must share one condition")

	for name, pair := range map[string][2]profiles.Symbol{
		"exported name": {
			{Name: "linkOctets", Tag: "OctetsUp", OID: twoNameOctetCol},
			{Name: "linkOctets", OID: twoNameOctetCol},
		},
		"oid": {
			{Name: "linkOctets", OID: twoNameOctetCol},
			{Name: "linkOctets", OID: twoNameStateCol},
		},
		"poll period": {
			{Name: "linkOctets", OID: twoNameOctetCol},
			{Name: "linkOctets", OID: twoNameOctetCol, PollTimeSec: 300},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.NotEqual(t, symbolDeclKey(&pair[0]), symbolDeclKey(&pair[1]),
				"declarations polled on separate windows must be filtered separately")
		})
	}
}

// TestPduToValue_Uinteger32RefusesAnAddressConversion keeps the sixth numeric
// type inside the conversion gate rather than only the value switch: the two
// list their types separately, so a type added to one and not the other would
// pass a conversion the value it produces cannot carry.
func TestPduToValue_Uinteger32RefusesAnAddressConversion(t *testing.T) {
	pdu := snmp.PDU{Name: "x", Type: gosnmp.Uinteger32, Value: uint32(42)}
	for _, conv := range []string{"hextoip", "hwaddr"} {
		t.Run(conv, func(t *testing.T) {
			_, _, err := pduToValue(pdu, conv)
			require.Error(t, err)
			require.Contains(t, err.Error(), "not meaningful for numeric PDU type")
		})
	}
}

// TestPduToString_Uinteger32 covers a tag column whose device answers with the
// standard unsigned application type.
func TestPduToString_Uinteger32(t *testing.T) {
	pdu := snmp.PDU{Name: "x", Type: gosnmp.Uinteger32, Value: uint32(4294967295)}
	require.Equal(t, "4294967295", pduToString(pdu, nil))
}
