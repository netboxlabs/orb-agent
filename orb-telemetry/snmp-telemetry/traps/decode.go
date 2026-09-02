package traps

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// Version is the SNMP version a trap arrived with, as a metric label value.
type Version string

// The three SNMP protocol versions Decode recognises.
const (
	V1  Version = "1"
	V2c Version = "2c"
	V3  Version = "3"
)

// Trap is what Decode extracts from a packet: enough to name and count it.
type Trap struct {
	// OID is the trap's identity, normalised with no leading dot. For v1 it is
	// synthesised per RFC 3584 section 3.1 so that one OID space serves every
	// version.
	OID     string
	Version Version
	// Inform is set for an InformRequest, which the sender expects acknowledged.
	Inform bool
	// AgentAddr is the v1 agent-addr field when it names an address, and
	// invalid otherwise. v2c and v3 carry no such field.
	AgentAddr netip.Addr
}

// DropReason says why a datagram produced no count. It is a metric label
// value, so the set is closed.
type DropReason string

// The closed set of reasons Decode can drop a datagram for.
const (
	DropUnknownSource     DropReason = "unknown_source"
	DropOversized         DropReason = "oversized"
	DropMalformed         DropReason = "malformed"
	DropUnsupportedPDU    DropReason = "unsupported_pdu"
	DropV3Unauthenticated DropReason = "v3_unauthenticated"
	DropNoTrapOID         DropReason = "no_trap_oid"
)

const (
	snmpTrapOIDInstance = "1.3.6.1.6.3.1.1.4.1.0"
	snmpTrapOIDBare     = "1.3.6.1.6.3.1.1.4.1"
	genericTrapBase     = "1.3.6.1.6.3.1.1.5."
)

// normalizeOID strips the leading dot gosnmp puts on every OID it parses, so
// what Decode emits matches the bundled definitions and the collector's own
// spelling.
func normalizeOID(oid string) string {
	return strings.TrimPrefix(strings.TrimSpace(oid), ".")
}

// Decode turns a parsed packet into a trap identity, or says why it cannot.
// It is a pure function over the packet and never touches the network.
func Decode(p *gosnmp.SnmpPacket) (Trap, DropReason) {
	switch p.PDUType {
	case gosnmp.Trap, gosnmp.SNMPv2Trap, gosnmp.InformRequest:
	default:
		return Trap{}, DropUnsupportedPDU
	}

	switch p.Version {
	case gosnmp.Version1:
		return decodeV1(p)
	case gosnmp.Version3:
		// F1: gosnmp skips authentication for a packet whose USM username and
		// authoritative engine ID are both empty, the RFC 3414 engine discovery
		// shape. No legitimate trap has it, and a trap that reached here with
		// it was not authenticated whatever gosnmp returned.
		sp, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if !ok || sp.UserName == "" || sp.AuthoritativeEngineID == "" {
			return Trap{}, DropV3Unauthenticated
		}
		return decodeV2(p, V3)
	default:
		return decodeV2(p, V2c)
	}
}

// decodeV2 reads snmpTrapOID.0 from the varbinds. RFC 3416 section 4.2.6 puts
// it in position two, but the search itself is a plain forward scan: the
// first varbind named by either spelling wins, whatever position it is at.
// The name is matched by equality against both forms, never by prefix,
// because 1.3.6.1.6.3.1.1.4.10 has the bare form as a prefix.
func decodeV2(p *gosnmp.SnmpPacket, v Version) (Trap, DropReason) {
	tr := Trap{Version: v, Inform: p.PDUType == gosnmp.InformRequest}
	for _, vb := range p.Variables {
		if oid, ok := trapOIDValue(vb); ok {
			tr.OID = oid
			return tr, ""
		}
	}
	return Trap{}, DropNoTrapOID
}

// trapOIDValue reports the trap OID a varbind carries, if the varbind is
// snmpTrapOID.0 in either spelling and its value is an OID.
func trapOIDValue(vb gosnmp.SnmpPDU) (string, bool) {
	name := normalizeOID(vb.Name)
	if name != snmpTrapOIDInstance && name != snmpTrapOIDBare {
		return "", false
	}
	if vb.Type != gosnmp.ObjectIdentifier {
		return "", false
	}
	value, ok := vb.Value.(string)
	if !ok || value == "" {
		return "", false
	}
	return normalizeOID(value), true
}

// decodeV1 synthesises the v2 trap OID from the v1 fields per RFC 3584
// section 3.1: generic-trap 0 to 5 become 1.3.6.1.6.3.1.1.5.<generic+1>, and
// generic-trap 6 becomes <enterprise>.0.<specific>. gosnmp parses both fields
// as unchecked signed integers, and the RFC defines nothing outside that
// range, so anything else is malformed rather than a manufactured label.
func decodeV1(p *gosnmp.SnmpPacket) (Trap, DropReason) {
	tr := Trap{Version: V1}
	if addr, err := netip.ParseAddr(p.AgentAddress); err == nil && !addr.IsUnspecified() {
		tr.AgentAddr = addr.Unmap()
	}
	switch {
	case p.GenericTrap >= 0 && p.GenericTrap <= 5:
		tr.OID = genericTrapBase + strconv.Itoa(p.GenericTrap+1)
	case p.GenericTrap == 6:
		enterprise := normalizeOID(p.Enterprise)
		if enterprise == "" || p.SpecificTrap < 0 {
			return Trap{}, DropMalformed
		}
		tr.OID = enterprise + ".0." + strconv.Itoa(p.SpecificTrap)
	default:
		return Trap{}, DropMalformed
	}
	return tr, ""
}
