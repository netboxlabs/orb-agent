package mapping

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// decodeInetAddressIndex parses the trailing sub-OIDs of an
// ipAddressTable column row index per RFC 4001 InetAddress.
//
// Layout: <addrType>.<addrLen>.<addrBytes...>
//
//	addrType: 1 (ipv4) | 2 (ipv6); other values (3 ipv4z, 4 ipv6z, 16 dns)
//	are rejected — see spec §Out of scope.
//	addrLen:  4 for ipv4, 16 for ipv6 (anything else is malformed).
//
// Returns the canonical address with a family-disambiguating prefix
// ("ipv4:" or "ipv6:") so legacy-table indices (bare "a.b.c.d") and
// modern-table indices for the same address do not collide in the
// per-target group map. Returns ok=false on malformed input.
func decodeInetAddressIndex(suffix []string) (string, bool) {
	if len(suffix) < 2 {
		return "", false
	}
	addrType, err := strconv.Atoi(suffix[0])
	if err != nil {
		return "", false
	}
	addrLen, err := strconv.Atoi(suffix[1])
	if err != nil {
		return "", false
	}
	body := suffix[2:]
	if len(body) != addrLen {
		return "", false
	}

	switch addrType {
	case 1: // ipv4
		if addrLen != 4 {
			return "", false
		}
		bytes, ok := parseDecimalBytes(body)
		if !ok {
			return "", false
		}
		return "ipv4:" + net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).To4().String(), true
	case 2: // ipv6
		if addrLen != 16 {
			return "", false
		}
		bytes, ok := parseDecimalBytes(body)
		if !ok {
			return "", false
		}
		// Use netip.AddrFrom16 to preserve the IPv6 textual form even
		// for IPv4-mapped addresses (e.g. ::ffff:10.0.0.1). net.IP.String
		// would render those as dotted IPv4, which would silently
		// reclassify the row as IPv4 in IPAddressMapper's family check
		// downstream.
		var arr [16]byte
		copy(arr[:], bytes)
		return "ipv6:" + netip.AddrFrom16(arr).String(), true
	default:
		// 3 ipv4z, 4 ipv6z, 16 dns, or unknown — explicitly skipped.
		return "", false
	}
}

func parseDecimalBytes(parts []string) ([]byte, bool) {
	out := make([]byte, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return nil, false
		}
		out[i] = byte(v)
	}
	return out, true
}

// stripIndexFamilyPrefix returns the canonical address from an index that
// may carry the "ipv4:" / "ipv6:" disambiguation prefix. Legacy indices
// (no prefix) pass through unchanged.
func stripIndexFamilyPrefix(index string) string {
	if strings.HasPrefix(index, "ipv4:") {
		return index[len("ipv4:"):]
	}
	if strings.HasPrefix(index, "ipv6:") {
		return index[len("ipv6:"):]
	}
	return index
}

// errMalformedInetAddress signals a malformed inet_address-indexed row
// during framework-level grouping.
var errMalformedInetAddress = errors.New("malformed InetAddress index")

// decodeIPv6AddrPrefixIndex parses the row index of IPV6-MIB
// ipv6AddrPfxLength, which is <ifIndex>.<16 address bytes>. That is a
// composite index rather than the RFC 4001 InetAddress
// decodeInetAddressIndex reads, so it needs its own parser instead of a
// flag on that one.
//
// The canonical address it returns carries the same "ipv6:" prefix
// decodeInetAddressIndex produces, so an annotation row lands in the same
// PDU group as the ipAddressTable row it describes and no separate
// joining step is needed. The ifIndex is returned alongside it so the
// caller can check the annotation against the row's own binding.
func decodeIPv6AddrPrefixIndex(suffix []string) (string, string, bool) {
	const addrLen = 16
	if len(suffix) != addrLen+1 {
		return "", "", false
	}
	// The ifIndex is kept as text: it is only ever compared against
	// ipAddressIfIndex, which arrives as text too.
	if _, err := strconv.Atoi(suffix[0]); err != nil {
		return "", "", false
	}
	body, ok := parseDecimalBytes(suffix[1:])
	if !ok {
		return "", "", false
	}
	var arr [addrLen]byte
	copy(arr[:], body)
	return suffix[0], "ipv6:" + netip.AddrFrom16(arr).String(), true
}

// ipv6AddrPrefixIfIndex returns the ifIndex component of an
// ipv6AddrPfxLength row OID, or "" when the OID does not belong to the
// column or its index is malformed.
func ipv6AddrPrefixIfIndex(objectID, columnOID string) string {
	if !strings.HasPrefix(objectID, columnOID+".") {
		return ""
	}
	ifIndex, _, ok := decodeIPv6AddrPrefixIndex(strings.Split(objectID[len(columnOID)+1:], "."))
	if !ok {
		return ""
	}
	return ifIndex
}
