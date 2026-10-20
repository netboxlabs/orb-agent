package collector

import (
	"context"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

// assertValidUTF8Attrs fails for any attribute value of the points that is not
// valid UTF-8. One such value fails the marshalling of the whole OTLP export,
// which carries every policy of the process.
func assertValidUTF8Attrs(t *testing.T, pts []observedPoint) {
	t.Helper()
	for _, pt := range pts {
		for _, kv := range pt.attrs {
			assert.True(t, utf8.ValidString(kv.Value.String()), "attribute %s = %q is not valid UTF-8", kv.Key, kv.Value.String())
		}
	}
}

// sysDescr goes through walkScalar and the device tags reuse it; sysLocation
// goes through a tag walk. NUL padding after text is dropped, a binary value
// reads as hex, and neither leaves bytes that are not UTF-8.
func TestCollectTarget_NonUTF8DeviceTagsExportAsValidUTF8(t *testing.T) {
	const (
		host        = "10.0.0.81"
		sysObjValue = "1.3.6.1.4.1.20916"
		nameOID     = "1.3.6.1.2.1.1.5.0"
		locationOID = "1.3.6.1.2.1.1.6.0"
		tempFOID    = "1.3.6.1.4.1.20916.1.11.1.1.1.1.0"
	)
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {sysDescrOID: stringPDU(sysDescrOID, "environment monitor\x00\x00")},
		nameOID:        {nameOID: stringPDU(nameOID, "sensor-1")},
		locationOID:    {locationOID: stringPDU(locationOID, "\x00\x1b!\xbb\xe6\xf0")},
		tempFOID:       {tempFOID: intPDU(tempFOID, 72)},
	}}

	c := newBundledCollector(t, walkerFactory(w))
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "p", DialOptions{}))

	pts := c.testDeviceStore("p", host)["snmp.internal-tempf"]
	require.Len(t, pts, 1)
	assert.Equal(t, "environment monitor", attrValue(pts[0], "SysDescr"))
	assert.Equal(t, "00:1b:21:bb:e6:f0", attrValue(pts[0], "SysLocation"))
	assert.Equal(t, "sensor-1", attrValue(pts[0], "SysName"))
	assertValidUTF8Attrs(t, pts)
}

// A row tag over a binary column with no hwaddr conversion, like the Arista
// recording's ifPhysAddress: each row reads as the hex of its own MAC, also
// one whose bytes are all printable Latin-1. An unset ifAlias, which Dell
// Networking OS answers with NULs, reads as empty, and Latin-1 text as hex.
func TestCollectTarget_NonUTF8RowTagsStayDistinct(t *testing.T) {
	const (
		host        = "10.0.0.82"
		tableOID    = "1.3.6.1.2.1.2.2"
		errColOID   = "1.3.6.1.2.1.2.2.1.20" // ifOutErrors
		macColOID   = "1.3.6.1.2.1.2.2.1.6"  // ifPhysAddress
		aliasColOID = "1.3.6.1.2.1.31.1.1.1.18"
		sysObjValue = "1.3.6.1.4.1.9999.81"
	)
	p := profileWithOID(sysObjValue, "octets.yml", []profiles.MetricEntry{
		{
			Table:   &profiles.Table{Name: "ifTable", OID: tableOID},
			Symbols: []profiles.Symbol{{Name: "ifOutErrors", OID: errColOID}},
			MetricTags: []profiles.MetricTag{
				{Tag: "if_mac", Column: &profiles.TagColumn{OID: macColOID, Name: "ifPhysAddress"}},
				{Tag: "if_alias", Column: &profiles.TagColumn{OID: aliasColOID, Name: "ifAlias"}},
			},
		},
	})
	w := &recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(sysObjValue)},
		sysDescrOID:    {},
		sysNameOID:     {},
		errColOID: {
			errColOID + ".1": counter32PDU(errColOID+".1", 10),
			errColOID + ".2": counter32PDU(errColOID+".2", 20),
		},
		macColOID: {
			macColOID + ".1": stringPDU(macColOID+".1", "\x00\x1b!\xbb\xe6\xf0"),
			macColOID + ".2": stringPDU(macColOID+".2", "\xc4}O\xc4F\xff"),
		},
		aliasColOID: {
			aliasColOID + ".1": stringPDU(aliasColOID+".1", "\x00\x00"),
			aliasColOID + ".2": stringPDU(aliasColOID+".2", "caf\xe9"),
		},
	}}
	c := newCollector(walkerFactory(w), p)
	require.NoError(t, c.CollectTarget(context.Background(), mustTarget(host), mustAuth(), "policy1", DialOptions{}))

	pts := c.testDeviceStore("policy1", host)["snmp.ifouterrors"]
	require.Len(t, pts, 2)
	got := map[string]int64{}
	aliases := map[string]string{}
	for _, pt := range pts {
		mac := attrValue(pt, "if_mac")
		got[mac] = pt.value
		aliases[mac] = attrValue(pt, "if_alias")
	}
	assert.Equal(t, map[string]int64{"00:1b:21:bb:e6:f0": 10, "c4:7d:4f:c4:46:ff": 20}, got)
	assert.Equal(t, map[string]string{"00:1b:21:bb:e6:f0": "", "c4:7d:4f:c4:46:ff": "63:61:66:e9"}, aliases)
	assertValidUTF8Attrs(t, pts)
}

// to_one puts the PDU's own text in the display value; a binary one reads as hex.
func TestPduToValue_ToOneRendersBinaryAsHex(t *testing.T) {
	pdu := stringPDU("1.3.6.1.2.1.2.2.1.6.1", "\x00\x1b!\xbb\xe6\xf0")
	v, display, err := pduToValue(pdu, "to_one")
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)
	assert.Equal(t, "00:1b:21:bb:e6:f0", display)
}
