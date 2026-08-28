package targets

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// Expand takes a target string and returns a slice of individual IP addresses or hostnames.
// It supports the following formats:
// - CIDR notation (e.g., 10.10.10.0/24)
// - IP range notation (e.g., 10.10.10.0-100 or 10.10.10.0-10.10.10.100)
// - Single IP address (e.g., 192.168.1.1)
// - Hostname (e.g., example.com)
func Expand(target string) ([]string, error) {
	// Attempt IP range expansion first so we can gracefully skip hostnames that contain hyphens.
	if strings.Contains(target, "-") && (strings.Contains(target, ":") || !hasLetters(target)) {
		ips, err := expandIPRange(target)
		if err == nil {
			return ips, nil
		}
		if !errors.Is(err, errNotRange) {
			return nil, err
		}
	}

	// Try parsing as CIDR (only when not handled as a range above)
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}

	// Try parsing as single IP
	if _, err := netip.ParseAddr(target); err == nil {
		return []string{target}, nil
	}

	// If not an IP, assume it's a hostname
	return []string{target}, nil
}

// expandCIDR expands a CIDR notation into individual IP addresses
func expandCIDR(cidr string) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}

	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 addresses are supported")
	}

	const maxPrealloc = 1_048_576 // avoid huge upfront allocations for very large networks

	prefix = prefix.Masked()
	startVal := addrToUint32(prefix.Addr())
	hostBits := 32 - prefix.Bits()
	count := uint64(1) << hostBits
	endVal := uint32(uint64(startVal) + count - 1)

	rangeLen := uint64(endVal-startVal) + 1
	capacity := 0
	if rangeLen <= maxPrealloc {
		capacity = int(rangeLen)
	}

	ips := make([]string, 0, capacity)
	for val := startVal; ; val++ {
		ips = append(ips, uint32ToAddr(val).String())
		if val == endVal {
			break
		}
	}

	return ips, nil
}

// errNotRange indicates the input does not represent an IP range and should be treated as a hostname.
var errNotRange = errors.New("not an IP range")

// expandIPRange expands an IP range notation (e.g., 10.10.10.0-100 or 10.10.10.0-10.10.10.100) into individual IP addresses.
// If the input does not resemble an IP range (e.g., it's a hostname with a hyphen), it returns errNotRange so callers can fall back.
func expandIPRange(rangeStr string) ([]string, error) {
	baseRaw, endRaw, ok := strings.Cut(rangeStr, "-")
	if !ok {
		return nil, errNotRange
	}
	if strings.Contains(endRaw, "-") {
		if looksLikeIPNotation(strings.TrimSpace(baseRaw)) {
			return nil, fmt.Errorf("invalid IP range format")
		}
		return nil, errNotRange
	}

	baseIP, looksLikeBase, err := parseRangeAddrPart(baseRaw)
	if !looksLikeBase {
		return nil, errNotRange
	}
	if err != nil {
		return nil, fmt.Errorf("invalid base IP address: %w", err)
	}

	endRaw = strings.TrimSpace(endRaw)
	endNum, err := strconv.Atoi(stripCIDR(endRaw))
	if err == nil {
		return expandLastOctetRange(baseIP, endNum)
	}

	endIP, looksLikeEnd, parseErr := parseRangeAddrPart(endRaw)
	if !looksLikeEnd {
		return nil, errNotRange
	}
	if parseErr != nil {
		return nil, fmt.Errorf("invalid end IP address: %w", parseErr)
	}

	return expandFullIPRange(baseIP, endIP)
}

// expandLastOctetRange handles ranges like 10.10.10.0-100.
func expandLastOctetRange(baseIP netip.Addr, endNum int) ([]string, error) {
	if endNum < 0 || endNum > 255 {
		return nil, fmt.Errorf("end number must be between 0 and 255")
	}

	base4 := baseIP.As4()
	baseNum := int(base4[3])
	if endNum < baseNum {
		return nil, fmt.Errorf("end number must be greater than or equal to the last octet of the base IP")
	}

	ips := make([]string, 0, endNum-baseNum+1)
	for i := baseNum; i <= endNum; i++ {
		ip4 := base4
		ip4[3] = byte(i)
		ips = append(ips, netip.AddrFrom4(ip4).String())
	}

	return ips, nil
}

// expandFullIPRange handles ranges like 10.10.10.0-10.10.10.100 (CIDR suffixes are ignored).
func expandFullIPRange(baseIP, endIP netip.Addr) ([]string, error) {
	baseVal := addrToUint32(baseIP)
	endVal := addrToUint32(endIP)

	if endVal < baseVal {
		return nil, fmt.Errorf("end IP must be greater than or equal to the base IP")
	}

	rangeLen := uint64(endVal-baseVal) + 1
	capacity := 0
	if rangeLen <= 1_048_576 {
		capacity = int(rangeLen)
	}
	ips := make([]string, 0, capacity)
	for val := baseVal; ; val++ {
		ips = append(ips, uint32ToAddr(val).String())
		if val == endVal {
			break
		}
	}

	return ips, nil
}

// parseRangeAddrPart parses a part of a range, returning whether the part resembled an IP and the parsed IPv4 address if possible.
func parseRangeAddrPart(part string) (netip.Addr, bool, error) {
	clean := stripCIDR(strings.TrimSpace(part))
	if clean == "" {
		return netip.Addr{}, false, nil
	}

	parsed, err := netip.ParseAddr(clean)
	if err == nil {
		if !parsed.Is4() {
			return netip.Addr{}, true, fmt.Errorf("only IPv4 addresses are supported")
		}
		return parsed, true, nil
	}

	if isIPv4Like(clean) {
		return netip.Addr{}, true, fmt.Errorf("invalid IP address")
	}

	return netip.Addr{}, false, nil
}

// looksLikeIPNotation returns true if the string resembles an IP (even if invalid).
func looksLikeIPNotation(part string) bool {
	_, looksLike, _ := parseRangeAddrPart(part)
	return looksLike
}

// stripCIDR removes any CIDR suffix from an IP/CIDR string.
func stripCIDR(value string) string {
	if idx := strings.Index(value, "/"); idx != -1 {
		return value[:idx]
	}
	return value
}

// isIPv4Like checks whether a string resembles an IPv4 address (digits and three dots).
func isIPv4Like(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// hasLetters reports whether the string contains alphabetic characters.
func hasLetters(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func addrToUint32(ip netip.Addr) uint32 {
	ip4 := ip.As4()
	return binary.BigEndian.Uint32(ip4[:])
}

func uint32ToAddr(val uint32) netip.Addr {
	var ip4 [4]byte
	binary.BigEndian.PutUint32(ip4[:], val)
	return netip.AddrFrom4(ip4)
}
