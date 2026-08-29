package collector

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
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
}

func (r *recordingWalker) Connect() error { return nil }
func (r *recordingWalker) Close() error   { return nil }
func (r *recordingWalker) Walk(oid string, _ int) (map[string]snmp.PDU, error) {
	r.walkCalls = append(r.walkCalls, oid)
	if pdus, ok := r.responses[oid]; ok {
		return pdus, nil
	}
	return map[string]snmp.PDU{}, nil
}

// walkerFactory returns a ClientFactory that always returns the same walker.
func walkerFactory(w snmp.Walker) snmp.ClientFactory {
	return func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
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
	return NewMetricsCollector(factory, matcher, discardLogger, time.Second, 1)
}

// deviceStore is a test-only accessor to read the collector's internal store.
func (c *MetricsCollector) testDeviceStore(host string) map[string][]observedPoint {
	c.storeMu.RLock()
	defer c.storeMu.RUnlock()
	return c.deviceStore[host]
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
	// No prefix match — returns full OID unchanged.
	assert.Equal(t, "1.2.3.4", extractRowIndex("1.2.3.4", "9.9.9.9"))
}

func TestBuildMetricName(t *testing.T) {
	assert.Equal(t, "snmp.ifouterrors", buildMetricName("ifOutErrors"))
	assert.Equal(t, "snmp.syscpuutil", buildMetricName("sysCPUUtil"))
}

// ---------------------------------------------------------------------------
// Unit tests: isPollReady
// ---------------------------------------------------------------------------

func TestIsPollReady_ZeroAlwaysReady(t *testing.T) {
	c := newCollector(nil, nil)
	assert.True(t, c.isPollReady("host1", "1.2.3", 0))
	assert.True(t, c.isPollReady("host1", "1.2.3", 0))
}

func TestIsPollReady_ThrottleAndExpiry(t *testing.T) {
	c := newCollector(nil, nil)
	// First call: ready.
	assert.True(t, c.isPollReady("host1", "1.2.3", 60))
	// Immediately after: not ready.
	assert.False(t, c.isPollReady("host1", "1.2.3", 60))
	// Simulate time elapsed by backdating the last-poll entry.
	c.pollMu.Lock()
	c.pollState["host1"]["1.2.3"] = time.Now().Add(-61 * time.Second)
	c.pollMu.Unlock()
	// Now it should be ready again.
	assert.True(t, c.isPollReady("host1", "1.2.3", 60))
}

func TestIsPollReady_IndependentPerHost(t *testing.T) {
	c := newCollector(nil, nil)
	assert.True(t, c.isPollReady("host1", "1.2.3", 60))
	assert.True(t, c.isPollReady("host2", "1.2.3", 60)) // different host, same OID: independent
	assert.False(t, c.isPollReady("host1", "1.2.3", 60))
}

// ---------------------------------------------------------------------------
// CollectTarget: no profile match
// ---------------------------------------------------------------------------

func TestCollectTarget_NoProfileMatch(t *testing.T) {
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjectIDOID + ".0")},
	}}
	c := newCollector(walkerFactory(w), nil) // matcher has no profiles
	err := c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "policy1")
	assert.NoError(t, err)
	assert.Nil(t, c.testDeviceStore("10.0.0.1"))
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
	err := c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "policy1")
	require.NoError(t, err)

	store := c.testDeviceStore(host)
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
	err := c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "policy1")
	require.NoError(t, err)

	store := c.testDeviceStore(host)
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
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))

	store := c.testDeviceStore(host)
	assert.Equal(t, int64(1), store["snmp.fastmetric"][0].value)
	assert.Equal(t, int64(100), store["snmp.slowmetric"][0].value)

	// Second run: slowMetric is throttled (poll_time_sec=300, only seconds have passed).
	// The walker returns different slow values but they should NOT be used.
	c.clientFactory = walkerFactory(makeWalker(2, 999))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))

	store = c.testDeviceStore(host)
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
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
	assert.Len(t, c.testDeviceStore(host)["snmp.somemetric"], 1)

	// Second run: metric OID returns empty (OID vanished from device).
	c.clientFactory = walkerFactory(makeWalker(false))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
	assert.Empty(t, c.testDeviceStore(host)["snmp.somemetric"], "polled-but-empty metric should be cleared")
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
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
	firstRunCalls := make([]string, len(w.walkCalls))
	copy(firstRunCalls, w.walkCalls)
	assert.Contains(t, firstRunCalls, descrColOID, "tag column should be walked on first run")

	// Second run: poll_time_sec=300 not elapsed, symbol is throttled.
	w.walkCalls = nil
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

	// Only the table root OID (plus sysObjectID/sysDescr/sysName) should appear — not individual column OIDs.
	for _, call := range w.walkCalls {
		assert.NotEqual(t, errColOID, call, "individual error column should not be walked separately")
		assert.NotEqual(t, descrColOID, call, "individual descr column should not be walked separately")
	}
	assert.Contains(t, w.walkCalls, tableOID)

	store := c.testDeviceStore(host)
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
	return NewMetricsCollector(factory, profiles.NewMatcher(all, discardLogger), discardLogger, time.Second, 1)
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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

	assert.Contains(t, w.walkCalls, tempFOID, "grouped scalar OID must be walked")

	store := c.testDeviceStore(host)
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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

	pts := c.testDeviceStore(host)["snmp.internal-power"]
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
