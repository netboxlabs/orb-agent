package collector

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
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
}

func (r *recordingWalker) Connect() error { return nil }
func (r *recordingWalker) Close() error   { return nil }
func (r *recordingWalker) Walk(oid string, _ int) (map[string]snmp.PDU, error) {
	r.walkCalls = append(r.walkCalls, oid)
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

// testDeviceStore is a test-only accessor to read the collector's internal
// store for a device polled on the default port.
func (c *MetricsCollector) testDeviceStore(policy, host string) map[string][]observedPoint {
	c.storeMu.RLock()
	defer c.storeMu.RUnlock()
	return c.deviceStore[deviceKey{policy: policy, host: host, port: 161}]
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
	err := c.CollectTarget(context.Background(), mustTarget("10.0.0.1"), mustAuth(), "policy1")
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
	err := c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "policy1")
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
	err := c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "policy1")
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
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))

	store := c.testDeviceStore("p", host)
	assert.Equal(t, int64(1), store["snmp.fastmetric"][0].value)
	assert.Equal(t, int64(100), store["snmp.slowmetric"][0].value)

	// Second run: slowMetric is throttled (poll_time_sec=300, only seconds have passed).
	// The walker returns different slow values but they should NOT be used.
	c.clientFactory = walkerFactory(makeWalker(2, 999))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
	assert.Len(t, c.testDeviceStore("p", host)["snmp.somemetric"], 1)

	// Second run: metric OID returns empty (OID vanished from device).
	c.clientFactory = walkerFactory(makeWalker(false))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(ctx, targetA, mustAuth(), "policy-a"))

	c.clientFactory = walkerFactory(makeWalker(22))
	targetB := config.Target{Host: host, Port: 161, ID: "id-b"}
	require.NoError(t, c.CollectTarget(ctx, targetB, mustAuth(), "policy-b"))

	storeA := c.testDeviceStore("policy-a", host)
	storeB := c.testDeviceStore("policy-b", host)
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
	require.NoError(t, c.CollectTarget(ctx, config.Target{Host: host, Port: 161}, mustAuth(), "p"))
	c.clientFactory = walkerFactory(makeWalker(6))
	require.NoError(t, c.CollectTarget(ctx, config.Target{Host: host, Port: 1161}, mustAuth(), "p"))

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
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "policy-a"))

	// Policy B has never polled this OID, so the throttle must not apply and
	// policy A's value must not be carried into policy B's store.
	c.clientFactory = walkerFactory(makeWalker(999))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "policy-b"))

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

	require.NoError(t, c.CollectTarget(ctx, mustTarget(hostA), mustAuth(), "doomed"))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(hostB), mustAuth(), "keeper"))
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

	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
	require.Len(t, c.testDeviceStore("p", host)["snmp.cpuutil"], 1)

	// The device stops answering: the dial itself now fails.
	c.clientFactory = func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return nil, assert.AnError
	}
	require.Error(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
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

	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
	require.Len(t, c.testDeviceStore("p", host)["snmp.cpuutil"], 1)

	// The address is reassigned to a device no profile covers.
	c.clientFactory = walkerFactory(makeWalker("1.3.6.1.4.1.1234"))
	require.NoError(t, c.CollectTarget(ctx, mustTarget(host), mustAuth(), "p"))
	assert.Nil(t, c.testDeviceStore("p", host))
}
