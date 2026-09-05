package targets

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
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
	if isRangeCandidate(target) {
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

// maxPrealloc avoids huge upfront allocations for very large networks.
const maxPrealloc = 1_048_576

// MaxExpand caps how many addresses one target may expand to.
//
// Callers are expected to sum Count across a policy's targets and reject before
// calling Expand, but Expand enforces the cap itself as well: it is the only
// enumerator, and an unguarded /8 allocates hundreds of megabytes inside
// whatever goroutine called it.
const MaxExpand = 1024

// isRangeCandidate reports whether a target should be tried as an IP range.
// Expand and Count must use the same predicate or they will disagree about
// which branch a target takes, and Count exists precisely to be trustworthy
// about a target Expand has not enumerated yet.
func isRangeCandidate(target string) bool {
	if !strings.Contains(target, "-") {
		return false
	}
	// A complete address is never a range, whatever punctuation it contains. An
	// IPv6 zone is an interface name and may hold a hyphen — fe80::1%br-lan is
	// an ordinary bridge — and the heuristic below reads the colon and the hyphen
	// as range syntax, then fails the whole policy with "only IPv4 addresses are
	// supported" for an endpoint ensurePort goes out of its way to support.
	if _, err := netip.ParseAddr(target); err == nil {
		return false
	}
	return strings.Contains(target, ":") || !hasLetters(target)
}

// IsSingleEndpoint reports whether Expand passes target through unchanged as one
// endpoint — a bare address or a hostname — rather than expanding it.
//
// It mirrors Expand's branch decisions exactly, without enumerating, so callers
// deciding "may I append a port to this?" cannot disagree with what Expand will
// actually do. A syntactic guess did disagree: "10.0.0.1-switch.example.com" is a
// legal hostname that Expand passes through, because it contains letters, while
// anything that merely began with an address and a hyphen was assumed to be a
// range.
func IsSingleEndpoint(target string) bool {
	if isRangeCandidate(target) {
		_, _, err := rangeBounds(target)
		if err == nil {
			return false // a real range
		}
		if !errors.Is(err, errNotRange) {
			return false // malformed range syntax; not one endpoint either
		}
		// errNotRange: Expand falls through to the hostname branch, as here.
	}
	if strings.Contains(target, "/") {
		return false // a prefix, valid or not
	}
	return true
}

// Count returns how many addresses a target expands to, without enumerating.
// It is the guard callers apply before Expand: enumerating a /8 allocates
// hundreds of megabytes, so the size has to be knowable from the bounds alone.
//
// Count and Expand share every bounds computation, so a target that Count
// accepts at size N yields exactly N addresses from Expand, and a target Count
// rejects is rejected identically by Expand.
func Count(target string) (uint64, error) {
	if isRangeCandidate(target) {
		start, end, err := rangeBounds(target)
		if err == nil {
			return uint64(end-start) + 1, nil
		}
		if !errors.Is(err, errNotRange) {
			return 0, err
		}
	}

	if strings.Contains(target, "/") {
		start, end, err := cidrBounds(target)
		if err != nil {
			return 0, err
		}
		return uint64(end-start) + 1, nil
	}

	// A single address or a hostname. Expand passes hostnames through verbatim
	// rather than resolving them, so this is one target either way.
	return 1, nil
}

// cidrBounds returns the inclusive host range of an IPv4 prefix.
//
// A prefix names a subnet, so its network and broadcast addresses are not hosts
// and are excluded — matching device-discovery, and avoiding a probe aimed at a
// broadcast address. A /31 and /32 have no such pair to exclude: stripping them
// would put end below start, which the enumeration cannot represent.
func cidrBounds(cidr string) (start, end uint32, err error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid CIDR notation: %w", err)
	}

	if !prefix.Addr().Is4() {
		return 0, 0, fmt.Errorf(
			"only IPv4 prefixes can be enumerated; an IPv6 prefix such as a /64 spans 2^64 addresses")
	}

	prefix = prefix.Masked()
	start = addrToUint32(prefix.Addr())
	count := uint64(1) << (32 - prefix.Bits())
	end = uint32(uint64(start) + count - 1)

	if prefix.Bits() <= 30 {
		start++
		end--
	}

	return start, end, nil
}

// expandCIDR expands a CIDR notation into individual host addresses.
func expandCIDR(cidr string) ([]string, error) {
	start, end, err := cidrBounds(cidr)
	if err != nil {
		return nil, err
	}
	return checkedEnumerate(cidr, start, end)
}

// checkedEnumerate refuses a range wider than MaxExpand before allocating.
func checkedEnumerate(target string, start, end uint32) ([]string, error) {
	if total := uint64(end-start) + 1; total > MaxExpand {
		return nil, fmt.Errorf(
			"%s expands to %d addresses, more than the %d supported per target",
			target, total, MaxExpand)
	}
	return enumerate(start, end), nil
}

// enumerate walks an inclusive uint32 range.
//
// The counter is uint64 deliberately. With end == MaxUint32 a uint32 counter
// wraps to zero and the loop condition never goes false, which turns
// 255.255.255.255/32 into an unbounded append.
func enumerate(start, end uint32) []string {
	total := uint64(end-start) + 1
	capacity := 0
	if total <= maxPrealloc {
		capacity = int(total)
	}

	ips := make([]string, 0, capacity)
	for val := uint64(start); val <= uint64(end); val++ {
		ips = append(ips, uint32ToAddr(uint32(val)).String())
	}
	return ips
}

// errNotRange indicates the input does not represent an IP range and should be treated as a hostname.
var errNotRange = errors.New("not an IP range")

// expandIPRange expands an IP range notation (e.g., 10.10.10.0-100 or
// 10.10.10.0-10.10.10.100) into individual IP addresses. If the input does not
// resemble an IP range (e.g., a hostname with a hyphen), it returns errNotRange
// so callers can fall back.
func expandIPRange(rangeStr string) ([]string, error) {
	start, end, err := rangeBounds(rangeStr)
	if err != nil {
		return nil, err
	}
	return checkedEnumerate(rangeStr, start, end)
}

// rangeBounds returns the inclusive range an IP-range target covers.
//
// A range keeps every address the operator wrote, including a .0 or a .255,
// because they enumerated it explicitly. This deliberately differs from a CIDR
// spanning the same addresses, which excludes network and broadcast: the two
// forms answer different questions, so 10.0.0.0-255 yields 256 where
// 10.0.0.0/24 yields 254.
func rangeBounds(rangeStr string) (start, end uint32, err error) {
	baseRaw, endRaw, ok := strings.Cut(rangeStr, "-")
	if !ok {
		return 0, 0, errNotRange
	}
	if strings.Contains(endRaw, "-") {
		if looksLikeIPNotation(strings.TrimSpace(baseRaw)) {
			return 0, 0, fmt.Errorf("invalid IP range format")
		}
		return 0, 0, errNotRange
	}

	baseIP, looksLikeBase, err := parseRangeAddrPart(baseRaw)
	if !looksLikeBase {
		return 0, 0, errNotRange
	}
	if err != nil {
		return 0, 0, fmt.Errorf("invalid base IP address: %w", err)
	}

	endRaw = strings.TrimSpace(endRaw)
	if endNum, convErr := strconv.Atoi(stripCIDR(endRaw)); convErr == nil {
		return lastOctetBounds(baseIP, endNum)
	}

	endIP, looksLikeEnd, parseErr := parseRangeAddrPart(endRaw)
	if !looksLikeEnd {
		return 0, 0, errNotRange
	}
	if parseErr != nil {
		return 0, 0, fmt.Errorf("invalid end IP address: %w", parseErr)
	}

	return fullRangeBounds(baseIP, endIP)
}

// lastOctetBounds handles ranges like 10.10.10.0-100.
func lastOctetBounds(baseIP netip.Addr, endNum int) (start, end uint32, err error) {
	if endNum < 0 || endNum > 255 {
		return 0, 0, fmt.Errorf("end number must be between 0 and 255")
	}

	base4 := baseIP.As4()
	baseNum := int(base4[3])
	if endNum < baseNum {
		return 0, 0, fmt.Errorf("end number must be greater than or equal to the last octet of the base IP")
	}

	start = addrToUint32(baseIP)
	return start, start + uint32(endNum-baseNum), nil
}

// fullRangeBounds handles ranges like 10.10.10.0-10.10.10.100 (CIDR suffixes on
// either endpoint are ignored by parseRangeAddrPart).
func fullRangeBounds(baseIP, endIP netip.Addr) (start, end uint32, err error) {
	start = addrToUint32(baseIP)
	end = addrToUint32(endIP)

	if end < start {
		return 0, 0, fmt.Errorf("end IP must be greater than or equal to the base IP")
	}

	return start, end, nil
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

// Span reports the inclusive address range a target covers, when it covers one.
//
// It exists so a caller can measure the *union* of several targets instead of
// their sum: a policy that names a subnet and then pins three hosts inside it to
// give them their own credentials describes the same endpoints as the subnet
// alone, and summing the two double-counts the overlap.
//
// enumerable is false for a hostname, which stands for one endpoint that cannot
// be compared with any address.
func Span(target string) (start, end uint32, enumerable bool, err error) {
	if isRangeCandidate(target) {
		start, end, err = rangeBounds(target)
		if err == nil {
			return start, end, true, nil
		}
		if !errors.Is(err, errNotRange) {
			return 0, 0, false, err
		}
	}

	if strings.Contains(target, "/") {
		start, end, err = cidrBounds(target)
		if err != nil {
			return 0, 0, false, err
		}
		return start, end, true, nil
	}

	// A bare IPv4 address is a one-element span, which is what lets it merge
	// into a subnet that already contains it.
	//
	// Unmapped first: an IPv4-mapped form such as ::ffff:10.0.0.1 is not Is4, so
	// without this it counted as an endpoint of its own while canonicalHost and
	// dedupeKey collapsed it with the plain address — and a /22 plus three pinned
	// mapped hosts inside it was rejected as 1025 endpoints that expansion
	// resolves to 1022.
	if addr, perr := netip.ParseAddr(target); perr == nil {
		if addr = addr.Unmap(); addr.Is4() {
			v := addrToUint32(addr)
			return v, v, true, nil
		}
	}

	// A hostname, or an IPv6 literal: one endpoint, not comparable to a range.
	return 0, 0, false, nil
}

// UnionSize returns how many distinct addresses a set of spans covers.
//
// Spans must already be grouped by whatever identity the caller deduplicates on,
// or the count is lower than the number of endpoints. gnmi-discovery groups by
// port, since the same address at two ports is two of its endpoints;
// gnmi-telemetry merges across ports, since its identity is the host and a
// policy subscribes to a device once.
func UnionSize(spans [][2]uint32) uint64 {
	if len(spans) == 0 {
		return 0
	}
	sorted := append([][2]uint32(nil), spans...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i][0] < sorted[j][0] })

	var total uint64
	curStart, curEnd := sorted[0][0], sorted[0][1]
	for _, s := range sorted[1:] {
		// Adjacent as well as overlapping: [1,5] and [6,9] are one run of 9, and
		// counting them separately would still be correct here, but merging keeps
		// the interval list short.
		if uint64(s[0]) <= uint64(curEnd)+1 {
			if s[1] > curEnd {
				curEnd = s[1]
			}
			continue
		}
		total += uint64(curEnd-curStart) + 1
		curStart, curEnd = s[0], s[1]
	}
	return total + uint64(curEnd-curStart) + 1
}
