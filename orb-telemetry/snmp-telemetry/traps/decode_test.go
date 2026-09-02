package traps

import (
	"net/netip"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These carry the wire-format leading dot and are named apart from decode.go's
// unexported snmpTrapOIDInstance/snmpTrapOIDBare, which hold the normalised
// (undotted) form used for internal matching; the two sets share a package
// and would otherwise collide.
const (
	trapOIDInstanceDotted = ".1.3.6.1.6.3.1.1.4.1.0"
	trapOIDBareDotted     = ".1.3.6.1.6.3.1.1.4.1"
	linkDownDotted        = ".1.3.6.1.6.3.1.1.5.3"
)

func v2cPacket(vars ...gosnmp.SnmpPDU) *gosnmp.SnmpPacket {
	return &gosnmp.SnmpPacket{Version: gosnmp.Version2c, PDUType: gosnmp.SNMPv2Trap, Variables: vars}
}

func oidVar(name, value string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.ObjectIdentifier, Value: value}
}

func TestDecode_V2cTakesTheTrapOIDFromPositionTwo(t *testing.T) {
	p := v2cPacket(
		gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(5)},
		oidVar(trapOIDInstanceDotted, linkDownDotted),
	)
	tr, reason := Decode(p)
	require.Empty(t, reason)
	assert.Equal(t, "1.3.6.1.6.3.1.1.5.3", tr.OID, "normalised, no leading dot")
	assert.Equal(t, V2c, tr.Version)
	assert.False(t, tr.Inform)
}

// Both spellings of snmpTrapOID appear in the wild; ktranslate checks both.
func TestDecode_V2cAcceptsTheBareObjectForm(t *testing.T) {
	tr, reason := Decode(v2cPacket(oidVar(trapOIDBareDotted, linkDownDotted)))
	require.Empty(t, reason)
	assert.Equal(t, "1.3.6.1.6.3.1.1.5.3", tr.OID)
}

// .1.3.6.1.6.3.1.1.4.10 has the bare form as a prefix. Matching is by
// equality, never by prefix.
func TestDecode_DoesNotPrefixMatchTheTrapOIDName(t *testing.T) {
	_, reason := Decode(v2cPacket(oidVar(".1.3.6.1.6.3.1.1.4.10", linkDownDotted)))
	assert.Equal(t, DropNoTrapOID, reason)
}

func TestDecode_V2cWithNoTrapOIDVarbind(t *testing.T) {
	_, reason := Decode(v2cPacket(gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(5)}))
	assert.Equal(t, DropNoTrapOID, reason)
}

// Present but the wrong type counts the same as absent: there is no OID to
// name, and a string here is a sender that is confused or hostile.
func TestDecode_V2cTrapOIDOfWrongTypeIsNoTrapOID(t *testing.T) {
	p := v2cPacket(gosnmp.SnmpPDU{Name: trapOIDInstanceDotted, Type: gosnmp.OctetString, Value: []byte("linkDown")})
	_, reason := Decode(p)
	assert.Equal(t, DropNoTrapOID, reason)
}

func TestDecode_FirstMatchingTrapOIDWins(t *testing.T) {
	p := v2cPacket(
		oidVar(trapOIDInstanceDotted, linkDownDotted),
		oidVar(trapOIDInstanceDotted, ".1.3.6.1.6.3.1.1.5.4"),
	)
	tr, reason := Decode(p)
	require.Empty(t, reason)
	assert.Equal(t, "1.3.6.1.6.3.1.1.5.3", tr.OID)
}

func TestDecode_InformIsATrapThatWantsAnAck(t *testing.T) {
	p := v2cPacket(oidVar(trapOIDInstanceDotted, linkDownDotted))
	p.PDUType = gosnmp.InformRequest
	tr, reason := Decode(p)
	require.Empty(t, reason)
	assert.True(t, tr.Inform)
}

// gosnmp delivers GetRequest, GetResponse and the rest to a trap handler.
func TestDecode_RejectsNonTrapPDUs(t *testing.T) {
	for _, pdu := range []gosnmp.PDUType{gosnmp.GetRequest, gosnmp.GetResponse, gosnmp.GetNextRequest, gosnmp.SetRequest, gosnmp.Report} {
		p := v2cPacket(oidVar(trapOIDInstanceDotted, linkDownDotted))
		p.PDUType = pdu
		_, reason := Decode(p)
		assert.Equal(t, DropUnsupportedPDU, reason, "pdu %#x", pdu)
	}
}

// RFC 3584 section 3.1(3): generic-trap 0 to 5 map onto 1.3.6.1.6.3.1.1.5.<g+1>.
func TestDecode_V1GenericTrapsMapPerRFC3584(t *testing.T) {
	for generic, want := range map[int]string{
		0: "1.3.6.1.6.3.1.1.5.1", 1: "1.3.6.1.6.3.1.1.5.2", 2: "1.3.6.1.6.3.1.1.5.3",
		3: "1.3.6.1.6.3.1.1.5.4", 4: "1.3.6.1.6.3.1.1.5.5", 5: "1.3.6.1.6.3.1.1.5.6",
	} {
		p := &gosnmp.SnmpPacket{Version: gosnmp.Version1, PDUType: gosnmp.Trap, SnmpTrap: gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.9", GenericTrap: generic, SpecificTrap: 0}}
		tr, reason := Decode(p)
		require.Empty(t, reason, "generic %d", generic)
		assert.Equal(t, want, tr.OID, "generic %d", generic)
		assert.Equal(t, V1, tr.Version)
	}
}

// RFC 3584 section 3.1(2): generic-trap 6 becomes <enterprise>.0.<specific>,
// unconditionally, including when the enterprise already ends in a zero arc.
func TestDecode_V1EnterpriseSpecificPerRFC3584(t *testing.T) {
	p := &gosnmp.SnmpPacket{Version: gosnmp.Version1, PDUType: gosnmp.Trap, SnmpTrap: gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.9", GenericTrap: 6, SpecificTrap: 5}}
	tr, reason := Decode(p)
	require.Empty(t, reason)
	assert.Equal(t, "1.3.6.1.4.1.9.0.5", tr.OID)

	p.Enterprise = ".1.3.6.1.4.1.9.0"
	tr, reason = Decode(p)
	require.Empty(t, reason)
	assert.Equal(t, "1.3.6.1.4.1.9.0.0.5", tr.OID, "the zero arc is kept; section 3.2 reverses it cleanly")
}

// gosnmp parses generic-trap and specific-trap as unchecked signed ints. RFC
// 3584 defines nothing outside 0 to 6, so those are malformed rather than a
// manufactured label.
func TestDecode_V1OutOfRangeFieldsAreMalformed(t *testing.T) {
	for _, tc := range []struct {
		name              string
		generic, specific int
		enterprise        string
	}{
		{"generic 7", 7, 0, ".1.3.6.1.4.1.9"},
		{"generic negative", -1, 0, ".1.3.6.1.4.1.9"},
		{"specific negative", 6, -1, ".1.3.6.1.4.1.9"},
		{"enterprise empty", 6, 1, ""},
	} {
		p := &gosnmp.SnmpPacket{Version: gosnmp.Version1, PDUType: gosnmp.Trap, SnmpTrap: gosnmp.SnmpTrap{Enterprise: tc.enterprise, GenericTrap: tc.generic, SpecificTrap: tc.specific}}
		_, reason := Decode(p)
		assert.Equal(t, DropMalformed, reason, tc.name)
	}
}

func TestDecode_V1CarriesAgentAddrWhenSet(t *testing.T) {
	p := &gosnmp.SnmpPacket{Version: gosnmp.Version1, PDUType: gosnmp.Trap, SnmpTrap: gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.9", GenericTrap: 2, AgentAddress: "10.0.0.7"}}
	tr, reason := Decode(p)
	require.Empty(t, reason)
	assert.Equal(t, netip.MustParseAddr("10.0.0.7"), tr.AgentAddr)

	p.AgentAddress = "0.0.0.0"
	tr, _ = Decode(p)
	assert.False(t, tr.AgentAddr.IsValid(), "an unspecified agent-addr is no address")
}

// F1: gosnmp's engine-discovery exemption lets a v3 packet with an empty
// username and engine ID through unauthenticated. No legitimate trap has that
// shape, so it is rejected here regardless of what gosnmp did.
func TestDecode_V3EmptyIdentityIsUnauthenticated(t *testing.T) {
	for _, tc := range []struct{ user, engine string }{{"", ""}, {"", "engine"}, {"user", ""}} {
		p := &gosnmp.SnmpPacket{
			Version: gosnmp.Version3, PDUType: gosnmp.SNMPv2Trap,
			SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: tc.user, AuthoritativeEngineID: tc.engine},
			Variables:          []gosnmp.SnmpPDU{oidVar(trapOIDInstanceDotted, linkDownDotted)},
		}
		_, reason := Decode(p)
		assert.Equal(t, DropV3Unauthenticated, reason, "user=%q engine=%q", tc.user, tc.engine)
	}
}

func TestDecode_V3WithIdentityDecodes(t *testing.T) {
	p := &gosnmp.SnmpPacket{
		Version: gosnmp.Version3, PDUType: gosnmp.SNMPv2Trap,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "u", AuthoritativeEngineID: "\x80\x00\x00\x00\x01"},
		Variables:          []gosnmp.SnmpPDU{oidVar(trapOIDInstanceDotted, linkDownDotted)},
	}
	tr, reason := Decode(p)
	require.Empty(t, reason)
	assert.Equal(t, V3, tr.Version)
	assert.Equal(t, "1.3.6.1.6.3.1.1.5.3", tr.OID)
}

func TestDecode_V3WithoutUSMParamsIsUnauthenticated(t *testing.T) {
	p := &gosnmp.SnmpPacket{Version: gosnmp.Version3, PDUType: gosnmp.SNMPv2Trap, Variables: []gosnmp.SnmpPDU{oidVar(trapOIDInstanceDotted, linkDownDotted)}}
	_, reason := Decode(p)
	assert.Equal(t, DropV3Unauthenticated, reason)
}
