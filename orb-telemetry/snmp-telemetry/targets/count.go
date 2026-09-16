package targets

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Count reports how many addresses Expand returns for target without
// materialising any of them, so a caller can bound a target before paying to
// expand it.
//
// It follows Expand's dispatch and calls the same parsing helpers, so the two
// cannot disagree about what a target means. A target Expand rejects is
// rejected here with the same error. Keep the two in step: count_test.go
// cross-checks Count against Expand for every accepted shape.
func Count(target string) (uint64, error) {
	// Attempt IP range counting first, mirroring Expand's fallback for hostnames that contain hyphens.
	if strings.Contains(target, "-") && (strings.Contains(target, ":") || !hasLetters(target)) {
		count, err := countIPRange(target)
		if err == nil {
			return count, nil
		}
		if !errors.Is(err, errNotRange) {
			return 0, err
		}
	}

	if strings.Contains(target, "/") {
		return countCIDR(target)
	}

	// A single address and a hostname both expand to themselves.
	return 1, nil
}

// countCIDR counts what expandCIDR would produce for a CIDR notation.
//
// It reads the bounds through cidrBounds, the same helper expandCIDR
// enumerates, rather than deriving the size from the prefix length a second
// time. A prefix excludes its network and broadcast addresses, and a size
// computed here from the notation alone would silently charge the budget guard
// two addresses no poll is ever sent to.
func countCIDR(cidr string) (uint64, error) {
	start, end, err := cidrBounds(cidr)
	if err != nil {
		return 0, err
	}

	return uint64(end-start) + 1, nil
}

// countIPRange counts what expandIPRange would produce, using the same
// normalisation of each endpoint so a CIDR suffix is stripped here too.
func countIPRange(rangeStr string) (uint64, error) {
	baseRaw, endRaw, ok := strings.Cut(rangeStr, "-")
	if !ok {
		return 0, errNotRange
	}
	if strings.Contains(endRaw, "-") {
		if looksLikeIPNotation(strings.TrimSpace(baseRaw)) {
			return 0, fmt.Errorf("invalid IP range format")
		}
		return 0, errNotRange
	}

	baseIP, looksLikeBase, err := parseRangeAddrPart(baseRaw)
	if !looksLikeBase {
		return 0, errNotRange
	}
	if err != nil {
		return 0, fmt.Errorf("invalid base IP address: %w", err)
	}

	endRaw = strings.TrimSpace(endRaw)
	endNum, err := strconv.Atoi(stripCIDR(endRaw))
	if err == nil {
		return countLastOctetRange(baseIP, endNum)
	}

	endIP, looksLikeEnd, parseErr := parseRangeAddrPart(endRaw)
	if !looksLikeEnd {
		return 0, errNotRange
	}
	if parseErr != nil {
		return 0, fmt.Errorf("invalid end IP address: %w", parseErr)
	}

	return countFullIPRange(baseIP, endIP)
}

// countLastOctetRange counts a range such as 10.10.10.0-100.
func countLastOctetRange(baseIP netip.Addr, endNum int) (uint64, error) {
	if endNum < 0 || endNum > 255 {
		return 0, fmt.Errorf("end number must be between 0 and 255")
	}

	baseNum := int(baseIP.As4()[3])
	if endNum < baseNum {
		return 0, fmt.Errorf("end number must be greater than or equal to the last octet of the base IP")
	}

	return uint64(endNum-baseNum) + 1, nil
}

// countFullIPRange counts a range such as 10.10.10.0-10.10.10.100.
func countFullIPRange(baseIP, endIP netip.Addr) (uint64, error) {
	baseVal := addrToUint32(baseIP)
	endVal := addrToUint32(endIP)

	if endVal < baseVal {
		return 0, fmt.Errorf("end IP must be greater than or equal to the base IP")
	}

	return uint64(endVal-baseVal) + 1, nil
}
