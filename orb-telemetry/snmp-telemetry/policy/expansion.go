package policy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// maxTargetAddresses bounds how many addresses one policy target may expand to.
// Expansion materialises every address before a single poll job exists, and
// each address then becomes a permanent recurring job, so a prefix such as a /8
// costs roughly a gigabyte of strings up front and 16 million jobs after that.
// A /16 is far beyond any reasonable polling policy; the limit is a guard
// against the pathological cases, not a recommended size.
const maxTargetAddresses = 65536

// targetAddressCount reports how many addresses a target expands to, computed
// from the notation rather than by expanding it. Anything that is not an IPv4
// prefix or an IPv4 range counts as one: a hostname expands to itself, and a
// malformed target is left to targets.Expand, which says what is wrong with it.
func targetAddressCount(target string) uint64 {
	if base, end, ok := strings.Cut(target, "-"); ok {
		from, fromErr := netip.ParseAddr(strings.TrimSpace(base))
		to, toErr := netip.ParseAddr(strings.TrimSpace(end))
		if fromErr != nil || toErr != nil || !from.Is4() || !to.Is4() || to.Less(from) {
			// Includes the "10.0.0.0-100" form, whose last octet bounds it at 256.
			return 1
		}
		return uint64(addrToUint32(to)-addrToUint32(from)) + 1
	}

	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err != nil || !prefix.Addr().Is4() {
			return 1
		}
		return uint64(1) << (32 - prefix.Bits())
	}

	return 1
}

// checkTargetExpansion rejects a target that expands past maxTargetAddresses.
func checkTargetExpansion(target string) error {
	count := targetAddressCount(target)
	if count > maxTargetAddresses {
		return fmt.Errorf("target %s expands to %d addresses, more than the limit of %d", target, count, maxTargetAddresses)
	}
	return nil
}

func addrToUint32(addr netip.Addr) uint32 {
	a4 := addr.As4()
	return binary.BigEndian.Uint32(a4[:])
}
