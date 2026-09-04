package traps

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

// BER helpers for hand-built SNMP datagrams. Short-form lengths only, which
// keeps every packet under 128 bytes and the encoder trivial.

func tlv(tag byte, content []byte) []byte {
	if len(content) > 127 {
		panic("short form only")
	}
	return append([]byte{tag, byte(len(content))}, content...)
}

func berInt(n int) []byte {
	if n < 0 || n > 127 {
		panic("small non-negative ints only")
	}
	return tlv(0x02, []byte{byte(n)})
}

func berOctets(s string) []byte { return tlv(0x04, []byte(s)) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	// 1.3.6.1.6.3.1.1.4.1.0, snmpTrapOID.0
	oidSnmpTrapOID0 = []byte{0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01, 0x00}
	// 1.3.6.1.6.3.1.1.5.3, linkDown
	oidLinkDown = []byte{0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05, 0x03}
	// 1.3.6.1.4.1.9, an enterprise arc
	oidEnterprise = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x09}
)

// oidEnterpriseWidget is 1.3.6.1.4.1.9.9.999.0.1, an OID no bundled profile names.
var oidEnterpriseWidget = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x09, 0x09, 0x87, 0x67, 0x00, 0x01}

// v2cTrapWithOID is v2cTrap with the trap OID chosen by the test.
func v2cTrapWithOID(community string, trapOID []byte) []byte {
	varbinds := tlv(0x30, tlv(0x30, cat(tlv(0x06, oidSnmpTrapOID0), tlv(0x06, trapOID))))
	pdu := tlv(0xa7, cat(berInt(1), berInt(0), berInt(0), varbinds))
	return tlv(0x30, cat(berInt(1), berOctets(community), pdu))
}

func linkDownVarbinds() []byte {
	return tlv(0x30, tlv(0x30, cat(tlv(0x06, oidSnmpTrapOID0), tlv(0x06, oidLinkDown))))
}

// v2cTrap is an SNMPv2-Trap-PDU (0xa7) under version 1 (which is v2c on the wire).
func v2cTrap(community string) []byte {
	pdu := tlv(0xa7, cat(berInt(1), berInt(0), berInt(0), linkDownVarbinds()))
	return tlv(0x30, cat(berInt(1), berOctets(community), pdu))
}

// trapWithVersion is v2cTrap with the version integer chosen by the test:
// 0 is v1, 1 is v2c, 3 is v3, and anything else is a version this backend
// does not speak.
func trapWithVersion(version int, community string) []byte {
	pdu := tlv(0xa7, cat(berInt(1), berInt(0), berInt(0), linkDownVarbinds()))
	return tlv(0x30, cat(berInt(version), berOctets(community), pdu))
}

// v2cInform is the same payload as an InformRequest-PDU (0xa6).
func v2cInform(community string) []byte {
	pdu := tlv(0xa6, cat(berInt(1), berInt(0), berInt(0), linkDownVarbinds()))
	return tlv(0x30, cat(berInt(1), berOctets(community), pdu))
}

// v2cGet is a GetRequest-PDU (0xa0), which is not a trap at all.
func v2cGet(community string) []byte {
	pdu := tlv(0xa0, cat(berInt(1), berInt(0), berInt(0), linkDownVarbinds()))
	return tlv(0x30, cat(berInt(1), berOctets(community), pdu))
}

// v1Trap is a Trap-PDU (0xa4) under version 0: enterprise, agent-addr,
// generic-trap, specific-trap, time-stamp, varbinds.
func v1Trap(community string, agentAddr [4]byte, generic, specific int) []byte {
	pdu := tlv(0xa4, cat(
		tlv(0x06, oidEnterprise),
		tlv(0x40, agentAddr[:]),
		berInt(generic),
		berInt(specific),
		tlv(0x43, []byte{0x00}),
		tlv(0x30, nil),
	))
	return tlv(0x30, cat(berInt(0), berOctets(community), pdu))
}

// v3Options describes a version 3 datagram to build. Every field is on the
// wire rather than derived, because the receiver's v3 guards are all about
// what a sender can choose to write there.
type v3Options struct {
	// username is a parameter because gosnmp looks the datagram's username up
	// in its credential table before it parses anything else, so only a name
	// the registry knows reaches the parser at all.
	username string
	// engineID is a parameter because F1 has two shapes. Empty gives the RFC
	// 3414 engine discovery shape; non-empty gives its residual.
	engineID string
	// secModel is msgSecurityModel. 3 is the user security model, the only one
	// gosnmp authenticates (F15).
	secModel int
	// flags is msgFlags. 0x01 is the auth bit, 0x03 authPriv.
	flags byte
	// authParamLen sizes msgAuthenticationParameters. SHA wants 12 bytes, and
	// gosnmp writes that many back into the buffer when the auth bit is set.
	authParamLen int
	// truncateAfterUSM cuts the datagram off right after the USM parameter
	// block, leaving no scoped PDU (F16).
	truncateAfterUSM bool
}

// v3Packet builds a version 3 datagram with a plaintext scoped PDU carrying a
// linkDown trap, unless it is truncated.
func v3Packet(o v3Options) []byte {
	authParams := make([]byte, o.authParamLen)
	usm := tlv(0x30, cat(berOctets(o.engineID), berInt(0), berInt(0), berOctets(o.username), tlv(0x04, authParams), berOctets("")))
	globalData := tlv(0x30, cat(berInt(1), tlv(0x02, []byte{0x7f}), tlv(0x04, []byte{o.flags}), berInt(o.secModel)))
	body := cat(berInt(3), globalData, tlv(0x04, usm))
	if !o.truncateAfterUSM {
		pdu := tlv(0xa7, cat(berInt(1), berInt(0), berInt(0), linkDownVarbinds()))
		body = cat(body, tlv(0x30, cat(berOctets(""), berOctets(""), pdu)))
	}
	return tlv(0x30, body)
}

// v3Unauthenticated is the noAuthNoPriv shape under the user security model:
// no authentication parameters, and gosnmp verifies no digest when the flags
// do not ask it to, so a sender naming a known user is not authenticated
// either way.
func v3Unauthenticated(username, engineID string) []byte {
	return v3Packet(v3Options{username: username, engineID: engineID, secModel: 3})
}

// v3AuthPrivTrap marshals a genuinely authenticated and encrypted version 3
// trap through gosnmp's own marshaller, so the acceptance path is exercised
// against a packet built the way a device builds one, with a real digest over
// the wire bytes and a real encrypted scoped PDU, rather than against a shape
// assembled by hand here.
func v3AuthPrivTrap(t *testing.T, u V3User, engineID string) []byte {
	t.Helper()
	return v3AuthPrivTrapAt(t, u, engineID, 1, 1)
}

// v3AuthPrivTrapAt is v3AuthPrivTrap with the sending engine's boots and time
// chosen by the test, which is what the receiver's time window judges.
func v3AuthPrivTrapAt(t *testing.T, u V3User, engineID string, boots, engineTime uint32) []byte {
	t.Helper()
	return v3TrapAt(t, u, engineID, boots, engineTime, gosnmp.AuthPriv)
}

// v3AuthNoPrivTrap is v3AuthPrivTrap at the authNoPriv level: a real digest
// over the wire bytes and a plaintext scoped PDU.
func v3AuthNoPrivTrap(t *testing.T, u V3User, engineID string) []byte {
	t.Helper()
	return v3TrapAt(t, u, engineID, 1, 1, gosnmp.AuthNoPriv)
}

func v3TrapAt(t *testing.T, u V3User, engineID string, boots, engineTime uint32, flags gosnmp.SnmpV3MsgFlags) []byte {
	t.Helper()
	authProto, err := snmp.AuthProtocol(u.AuthProtocol)
	require.NoError(t, err)
	privProto, err := snmp.PrivProtocol(u.PrivProtocol)
	require.NoError(t, err)

	logger := gosnmp.NewLogger(nil)
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 u.Username,
		AuthenticationProtocol:   authProto,
		AuthenticationPassphrase: u.AuthPassphrase,
		PrivacyProtocol:          privProto,
		PrivacyPassphrase:        u.PrivPassphrase,
		AuthoritativeEngineID:    engineID,
		AuthoritativeEngineBoots: boots,
		AuthoritativeEngineTime:  engineTime,
		Logger:                   logger,
	}
	require.NoError(t, sp.InitSecurityKeys())

	if flags&gosnmp.AuthPriv != gosnmp.AuthPriv {
		sp.PrivacyProtocol = gosnmp.NoPriv
		sp.PrivacyPassphrase = ""
	}
	pkt := &gosnmp.SnmpPacket{
		Version:            gosnmp.Version3,
		MsgFlags:           flags,
		SecurityModel:      gosnmp.UserSecurityModel,
		SecurityParameters: sp,
		MsgID:              1,
		ContextEngineID:    engineID,
		PDUType:            gosnmp.SNMPv2Trap,
		RequestID:          1,
		Logger:             logger,
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(0)},
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
		},
	}
	out, err := pkt.MarshalMsg()
	require.NoError(t, err)
	return out
}
