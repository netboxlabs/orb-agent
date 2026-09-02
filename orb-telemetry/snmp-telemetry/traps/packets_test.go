package traps

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

func linkDownVarbinds() []byte {
	return tlv(0x30, tlv(0x30, cat(tlv(0x06, oidSnmpTrapOID0), tlv(0x06, oidLinkDown))))
}

// v2cTrap is an SNMPv2-Trap-PDU (0xa7) under version 1 (which is v2c on the wire).
func v2cTrap(community string) []byte {
	pdu := tlv(0xa7, cat(berInt(1), berInt(0), berInt(0), linkDownVarbinds()))
	return tlv(0x30, cat(berInt(1), berOctets(community), pdu))
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

// v3Unauthenticated is the engine discovery shape: version 3, an empty
// authoritative engine ID, noAuthNoPriv flags, no authentication parameters,
// and a plaintext scoped PDU carrying a trap. The username is a parameter
// because gosnmp looks the datagram's username up in its credential table
// before it parses anything else, so only a name the registry knows reaches
// the parser at all. F1: gosnmp then accepts the packet without
// authenticating it.
func v3Unauthenticated(username string) []byte {
	usm := tlv(0x30, cat(berOctets(""), berInt(0), berInt(0), berOctets(username), berOctets(""), berOctets("")))
	globalData := tlv(0x30, cat(berInt(1), tlv(0x02, []byte{0x7f}), tlv(0x04, []byte{0x00}), berInt(3)))
	pdu := tlv(0xa7, cat(berInt(1), berInt(0), berInt(0), linkDownVarbinds()))
	scoped := tlv(0x30, cat(berOctets(""), berOctets(""), pdu))
	return tlv(0x30, cat(berInt(3), globalData, tlv(0x04, usm), scoped))
}
