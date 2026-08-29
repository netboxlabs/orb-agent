package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
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
}

func (r *recordingWalker) Connect() error { return nil }
func (r *recordingWalker) Close() error   { return nil }
func (r *recordingWalker) Walk(oid string, _ int) (map[string]snmp.PDU, error) {
	r.walkCalls = append(r.walkCalls, oid)
	if r.onWalk != nil {
		r.onWalk(oid)
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
// Unit tests: extractRowIndex / buildMetricName
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

func TestBuildMetricName(t *testing.T) {
	assert.Equal(t, "snmp.ifouterrors", buildMetricName("ifOutErrors"))
	assert.Equal(t, "snmp.syscpuutil", buildMetricName("sysCPUUtil"))
}

// ---------------------------------------------------------------------------
// Unit tests: isPollReady
// ---------------------------------------------------------------------------

func testKey(policy, host string) deviceKey {
	return deviceKey{policy: policy, host: host, port: 161}
}

func TestIsPollReady_ZeroAlwaysReady(t *testing.T) {
	c := newCollector(nil, nil)
	k := testKey("p", "host1")
	assert.True(t, c.isPollReady(k, "1.2.3", 0))
	assert.True(t, c.isPollReady(k, "1.2.3", 0))
}

func TestIsPollReady_ThrottleAndExpiry(t *testing.T) {
	c := newCollector(nil, nil)
	k := testKey("p", "host1")
	// First call: ready.
	assert.True(t, c.isPollReady(k, "1.2.3", 60))
	// Immediately after: not ready.
	assert.False(t, c.isPollReady(k, "1.2.3", 60))
	// Simulate time elapsed by backdating the last-poll entry.
	c.pollMu.Lock()
	c.pollState[k]["1.2.3"] = time.Now().Add(-61 * time.Second)
	c.pollMu.Unlock()
	// Now it should be ready again.
	assert.True(t, c.isPollReady(k, "1.2.3", 60))
}

func TestIsPollReady_IndependentPerDevice(t *testing.T) {
	c := newCollector(nil, nil)
	assert.True(t, c.isPollReady(testKey("p", "host1"), "1.2.3", 60))
	assert.True(t, c.isPollReady(testKey("p", "host2"), "1.2.3", 60)) // different host, same OID
	assert.True(t, c.isPollReady(testKey("q", "host1"), "1.2.3", 60)) // different policy, same host
	assert.True(t, c.isPollReady(deviceKey{policy: "p", host: "host1", port: 1161}, "1.2.3", 60))
	assert.False(t, c.isPollReady(testKey("p", "host1"), "1.2.3", 60))
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
		"the helper itself reports every call; the once-per-profile guard lives in reportUnsupportedConversions")

	buf.Reset()
	p := &profiles.Profile{RelPath: "vendor/example.yml", Metrics: []profiles.MetricEntry{entry}}
	c2 := &MetricsCollector{logger: logger, reviewedProfiles: map[string]struct{}{}}
	for range 3 {
		c2.reportUnsupportedConversions(p)
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
	used := store["snmp.cempmempoolhcused"]
	require.Len(t, used, 1, "only the named pool is emitted")
	assert.Equal(t, int64(200), used[0].value)
	assert.Equal(t, "DP System memory", attrValue(used[0], "cempMemPoolName"))

	free := store["snmp.cempmempoolhcfree"]
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
