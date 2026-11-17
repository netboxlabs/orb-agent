package collector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

// exportedSets runs one collection and returns metricName's datapoint
// attribute sets, keyed by device_ip.
func exportedSets(t *testing.T, reader *sdkmetric.ManualReader, metricName string) map[string]attribute.Set {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]attribute.Set{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != metricName {
				continue
			}
			g, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok)
			for _, dp := range g.DataPoints {
				ip, ok := dp.Attributes.Value("device_ip")
				require.True(t, ok)
				out[ip.AsString()] = dp.Attributes
			}
		}
	}
	return out
}

// Two targets of one policy carry their own attributes on every series they
// produce, with the type each value was given, beside identity attributes
// that are unchanged by them.
func TestCollectTarget_TargetAttributesReachTheirOwnSeries(t *testing.T) {
	const (
		cpuOID      = "1.3.6.1.4.1.9999.60.1"
		sysObjValue = "1.3.6.1.4.1.9999.60"
	)
	reader := withManualReader(t)
	p := profileWithOID(sysObjValue, "attributes.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 40)},
	}}
	c := newCollector(walkerFactory(w), p)

	a := config.Target{Host: "192.0.2.10", Port: 161, ID: "dev-a", Attributes: config.Attributes{
		"site": "dc-west", "monitored": true, "rack_units": 2, "weight": 1.5,
	}}
	b := config.Target{Host: "192.0.2.11", Port: 1161, Attributes: config.Attributes{"site": "dc-east"}}
	require.NoError(t, c.CollectTarget(context.Background(), a, mustAuth(), "p1", DialOptions{}))
	require.NoError(t, c.CollectTarget(context.Background(), b, mustAuth(), "p1", DialOptions{}))

	sets := exportedSets(t, reader, "snmp.cpuutil")
	require.Len(t, sets, 2)

	setA := sets["192.0.2.10"]
	assert.Equal(t, attribute.NewSet(
		attribute.String("device_ip", "192.0.2.10"),
		attribute.Int("device_port", 161),
		attribute.String("netbox_id", "dev-a"),
		attribute.String("site", "dc-west"),
		attribute.Bool("monitored", true),
		attribute.Int64("rack_units", 2),
		attribute.Float64("weight", 1.5),
	), setA)

	setB := sets["192.0.2.11"]
	assert.Equal(t, attribute.NewSet(
		attribute.String("device_ip", "192.0.2.11"),
		attribute.Int("device_port", 1161),
		attribute.String("site", "dc-east"),
	), setB)
}

// A target with no attributes exports exactly what it did before they
// existed.
func TestCollectTarget_NoAttributesLeavesTheSeriesAlone(t *testing.T) {
	const (
		cpuOID      = "1.3.6.1.4.1.9999.61.1"
		sysObjValue = "1.3.6.1.4.1.9999.61"
	)
	reader := withManualReader(t)
	p := profileWithOID(sysObjValue, "no-attributes.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 40)},
	}}
	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget("192.0.2.12"), mustAuth(), "p1", DialOptions{}))

	sets := exportedSets(t, reader, "snmp.cpuutil")
	assert.Equal(t, attribute.NewSet(
		attribute.String("device_ip", "192.0.2.12"),
		attribute.Int("device_port", 161),
	), sets["192.0.2.12"])
}

// Table rows carry the target's attributes beside their own row tags, and
// the attributes do not take part in telling the rows apart.
func TestCollectTarget_TargetAttributesReachEveryTableRow(t *testing.T) {
	const (
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20"
		descrColOID = "1.3.6.1.2.1.2.2.1.2"
		sysObjValue = "1.3.6.1.4.1.9999.62"
	)
	p := profileWithOID(sysObjValue, "rows.yml", []profiles.MetricEntry{{
		Table:      &profiles.Table{Name: "ifTable", OID: tableOID},
		Symbols:    []profiles.Symbol{{Name: "ifOutErrors", OID: errColOID}},
		MetricTags: []profiles.MetricTag{{Tag: "if_desc", Column: &profiles.TagColumn{OID: descrColOID, Name: "ifDescr"}}},
	}})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
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
	target := config.Target{Host: "192.0.2.13", Port: 161, Attributes: config.Attributes{"site": "dc-west"}}
	require.NoError(t, c.CollectTarget(context.Background(), target, mustAuth(), "p1", DialOptions{}))

	pts := c.testDeviceStore("p1", "192.0.2.13")["snmp.ifouterrors"]
	require.Len(t, pts, 2)
	for _, pt := range pts {
		attrs := exportedAttrs(pt)
		assert.Equal(t, "dc-west", attrs["site"])
		assert.NotEmpty(t, attrs["if_desc"])
		assert.NotEmpty(t, attrs["row_index"])
	}
}

func TestReservedAttributeName_IsTheCollectorsOwnDimensions(t *testing.T) {
	for _, name := range []string{"device_ip", "device_port", "netbox_id", "snmp_context", "row_index", "policy_name", "orb.policy.name"} {
		assert.True(t, ReservedAttributeName(name), name)
	}
	assert.False(t, ReservedAttributeName("site"))
	assert.False(t, ReservedAttributeName("Device_IP"), "keys are case-sensitive")
}

// ProfileAttribute names every attribute key the profile set can put on a
// series: device tags, row tags, joined tags and the attributes a symbol,
// scalar or column, derives from its reading. The tags of a `symbol:` entry
// are never applied, and neither is a tag naming no OID, so they are not
// among them; nor is anything in a profile no device can be served, a row tag
// of an entry none of whose symbols is read, or a device tag of a profile none
// of whose entries is.
func TestProfileAttribute_NamesEveryKeyTheProfilesExport(t *testing.T) {
	enum := profiles.Enum{Values: map[string]int{"up": 1, "down": 2}}
	device := profileWithOID("1.3.6.1.4.1.9999.63", "vendor-a.yml", []profiles.MetricEntry{
		{
			Table: &profiles.Table{Name: "ifTable", OID: "1.3.6.1.2.1.2.2"},
			Symbols: []profiles.Symbol{
				{Name: "ifOperStatus", OID: "1.3.6.1.2.1.2.2.1.8", Enum: enum},
				{Name: "ifPhysAddress", OID: "1.3.6.1.2.1.2.2.1.6", Conversion: "hwaddr"},
			},
			MetricTags: []profiles.MetricTag{
				{Tag: "interface", Column: &profiles.TagColumn{OID: "1.3.6.1.2.1.2.2.1.2", Name: "ifDescr"}},
				{Column: &profiles.TagColumn{OID: "1.3.6.1.2.1.31.1.1.1.1", Name: "ifName"}},
				// Neither names an OID, so the collector applies neither.
				{Tag: "if_position", Index: 1},
				{Tag: "if_alias", Column: &profiles.TagColumn{Name: "ifAlias"}},
			},
		},
		{Symbol: &profiles.Symbol{Name: "chassisState", OID: "1.3.6.1.4.1.9999.63.1.0", Enum: enum}},
		{
			Symbol:     &profiles.Symbol{Name: "fanSpeed", OID: "1.3.6.1.4.1.9999.63.2.0"},
			MetricTags: []profiles.MetricTag{{Tag: "fan_slot", Column: &profiles.TagColumn{OID: "1.3.6.1.4.1.9999.63.3", Name: "fanSlot"}}},
		},
		{
			// The entry's only symbol is never read, so its rows never exist.
			Table:      &profiles.Table{Name: "slotTable", OID: "1.3.6.1.4.1.9999.63.5"},
			Symbols:    []profiles.Symbol{{Name: "slotLoad", OID: "1.3.6.1.4.1.9999.63.5.1.2", Script: "value * 8"}},
			MetricTags: []profiles.MetricTag{{Tag: "slot_name", Column: &profiles.TagColumn{OID: "1.3.6.1.4.1.9999.63.5.1.1", Name: "slotName"}}},
		},
	})
	device.MetricTags = []profiles.MetricTag{
		{Tag: "model", Column: &profiles.TagColumn{OID: "1.3.6.1.2.1.47.1.1.1.1.13.1", Name: "entPhysicalModelName"}},
		{Tag: "chassis_model", Column: &profiles.TagColumn{OID: "1.3.6.1.4.1.9999.63.4.0", Name: "chassisModel"}},
		{Tag: "rack_position"},
	}
	other := profileWithOID("1.3.6.1.4.1.9999.64", "vendor-b.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpu", OID: "1.3.6.1.4.1.9999.64.1"}},
	})
	other.MetricTags = []profiles.MetricTag{{Tag: "model", Column: &profiles.TagColumn{OID: "1.3.6.1.4.1.9999.64.2", Name: "model"}}}
	// No sysobjectid and no redirect to it, so no device is ever served it.
	unmatched := &profiles.Profile{
		FileName:   "custom-base.yml",
		Metrics:    []profiles.MetricEntry{{Symbol: &profiles.Symbol{Name: "rackTemp", OID: "1.3.6.1.4.1.9999.67.2.0"}}},
		MetricTags: []profiles.MetricTag{{Tag: "rack_row", Column: &profiles.TagColumn{OID: "1.3.6.1.4.1.9999.67.1.0", Name: "rackRow"}}},
	}
	// Served, but nothing it declares is read, so its device tags ride on no
	// point.
	idle := profileWithOID("1.3.6.1.4.1.9999.68", "vendor-c.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "psuLoad", OID: "1.3.6.1.4.1.9999.68.1.0", Script: "value * 8"}},
	})
	idle.MetricTags = []profiles.MetricTag{{Tag: "site_code", Column: &profiles.TagColumn{OID: "1.3.6.1.4.1.9999.68.2.0", Name: "siteCode"}}}

	c := newCollectorWithProfiles(nil, unmatched, device, other, idle)
	for _, key := range []string{"model", "interface", "ifName", "ifOperStatus_status", "ifPhysAddress_value", "chassisState_status"} {
		name, profile, ok := c.ProfileAttribute(key)
		assert.True(t, ok, key)
		assert.Equal(t, key, name, key)
		assert.Equal(t, "vendor-a.yml", profile, "%s is named by the first profile that exports it", key)
	}
	for _, key := range []string{"site", "Model", "ifOperStatus", "cpu", "fan_slot", "if_position", "if_alias", "rack_position", "rack_row", "slot_name", "site_code"} {
		_, _, ok := c.ProfileAttribute(key)
		assert.False(t, ok, key)
	}

	// A key landing on a profile's attribute once translated to Prometheus
	// collides with it there.
	name, profile, ok := c.ProfileAttribute("chassis.model")
	require.True(t, ok)
	assert.Equal(t, "chassis_model", name)
	assert.Equal(t, "vendor-a.yml", profile)
}

// A target's attributes reach the collector rendered once for every device
// its entry expands to, and that rendering is the one exported.
func TestCollectTarget_UsesTheTargetsRenderedAttributes(t *testing.T) {
	const (
		cpuOID      = "1.3.6.1.4.1.9999.65.1"
		sysObjValue = "1.3.6.1.4.1.9999.65"
	)
	reader := withManualReader(t)
	p := profileWithOID(sysObjValue, "rendered.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 40)},
	}}
	c := newCollector(walkerFactory(w), p)
	target := config.Target{Host: "192.0.2.14", Port: 161, RenderedAttributes: []attribute.KeyValue{attribute.String("site", "dc-west")}}
	require.NoError(t, c.CollectTarget(context.Background(), target, mustAuth(), "p1", DialOptions{}))

	set := exportedSets(t, reader, "snmp.cpuutil")["192.0.2.14"]
	site, ok := set.Value("site")
	require.True(t, ok)
	assert.Equal(t, "dc-west", site.AsString())
}

// Validation refuses an attribute that takes an identity key, so this only
// happens to a caller that skips it; even then the collector's own value is
// the one exported.
func TestCollectTarget_TheCollectorsIdentityWinsOverAnAttribute(t *testing.T) {
	const (
		cpuOID      = "1.3.6.1.4.1.9999.66.1"
		sysObjValue = "1.3.6.1.4.1.9999.66"
	)
	reader := withManualReader(t)
	p := profileWithOID(sysObjValue, "identity.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: cpuOID}},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		cpuOID:         {cpuOID: intPDU(cpuOID, 40)},
	}}
	c := newCollector(walkerFactory(w), p)
	target := config.Target{Host: "192.0.2.15", Port: 161, ID: "dev-15", Attributes: config.Attributes{
		"device_ip": "198.51.100.1", "device_port": 9, "netbox_id": "spoofed",
	}}
	require.NoError(t, c.CollectTarget(context.Background(), target, mustAuth(), "p1", DialOptions{}))

	set, ok := exportedSets(t, reader, "snmp.cpuutil")["192.0.2.15"]
	require.True(t, ok, "the series is exported under the real device_ip")
	port, _ := set.Value("device_port")
	assert.Equal(t, int64(161), port.AsInt64())
	id, _ := set.Value("netbox_id")
	assert.Equal(t, "dev-15", id.AsString())
}
