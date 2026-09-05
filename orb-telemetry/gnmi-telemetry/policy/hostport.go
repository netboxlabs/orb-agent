package policy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
)

// resolvedPort returns the port to use for a target. Inheritance has already
// folded the scope's value into the target, so the precedence chain
// inline > target > scope > default reduces to this plus ensurePort's refusal
// to overwrite an inline suffix.
func resolvedPort(port uint16) uint16 {
	if port == 0 {
		return config.DefaultGNMIPort
	}
	return port
}

// ensurePort appends port to h unless h already carries one.
func ensurePort(h string, port uint16) string {
	if h == "" {
		return h
	}
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h // already host:port (handles bracketed IPv6 too)
	}
	// SplitHostPort failed. Append the default port only when the input clearly
	// has no port; never rewrite a value that already carries colons but isn't a
	// recognizable IPv6 literal (a malformed host:port like "a:b:c"), so the
	// dial/validation error points at the real bad value.
	//
	// net.ParseIP rejects a zone id, so validate against the zone-stripped host
	// (fe80::1%eth0 -> fe80::1) while still bracketing the original (with zone).
	ipPart := h
	if i := strings.IndexByte(h, '%'); i >= 0 {
		ipPart = h[:i]
	}
	switch {
	case strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]"):
		return fmt.Sprintf("%s:%d", h, port) // bracketed IPv6, no port
	case net.ParseIP(ipPart) != nil && strings.Contains(h, ":"):
		return fmt.Sprintf("[%s]:%d", h, port) // bare IPv6 literal (incl. zone) -> bracket
	case strings.Contains(h, ":"):
		return h // malformed host:port -> leave untouched
	default:
		return fmt.Sprintf("%s:%d", h, port) // hostname / IPv4, no port
	}
}

// splitEffectivePort returns a target's host without its port, and the port it
// will actually be reached on: an inline suffix wins over the port field, which
// wins over the scope's value and the default.
//
// Both halves have to come from the same decision. Taking the host from
// hostWithoutPort while taking the port from the field alone made
// "10.0.0.5:6030" and "10.0.0.5:57400" collide on one key — two real endpoints
// rejected as a duplicate — and let an inline ":6030" and a "port: 6030" on the
// same host produce two keys for one endpoint.
func splitEffectivePort(host string, field uint16) (bare string, port uint16, inline bool) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, cerr := strconv.ParseUint(p, 10, 16); cerr == nil {
			return strings.Trim(h, "[]"), uint16(n), true
		}
	}
	// Brackets come off here too, not only on the branch above. bare is what
	// Count, Span, IsSingleEndpoint and canonicalHost are all asked about, and it
	// was normalized on one path and not the other: canonicalHost trims its own
	// input, so "[10.0.0.1]" collapsed with the plain address for identity while
	// Span refused to parse it and counted it as a separate endpoint.
	return strings.Trim(host, "[]"), resolvedPort(field), false
}

// checkInlinePort rejects an inline port that is not a number in range.
//
// net.SplitHostPort accepts a service name, and Go's dialer resolves one through
// /etc/services — net.LookupPort("tcp", "http") is 80 — so "10.0.0.1:http"
// reaches a device on port 80 while every check here read it as an unported host
// named "10.0.0.1:http". A pinned target written that way never matched the
// numeric candidate a range produced, so the device got two subscriptions with
// two sets of credentials. The same silence swallowed an out-of-range number and
// a trailing colon: "10.0.0.1:99999" and "10.0.0.1:" both became hostnames, to be
// resolved by DNS and fail as lookups.
//
// Rejected rather than resolved. Resolving would make a policy's meaning depend
// on the /etc/services of whichever host parsed it, so the same policy could
// validate differently in the agent container than where it was written. Every
// documented form is numeric and the port field is a uint16, so nothing
// legitimate is refused.
func checkInlinePort(host string) error {
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		// No inline port, or an IPv6 literal written without brackets.
		return nil
	}
	if _, cerr := strconv.ParseUint(port, 10, 16); cerr != nil {
		return fmt.Errorf(
			"target %q: inline port %q must be a number between 0 and 65535", host, port,
		)
	}
	return nil
}

// canonicalHost normalizes a bare host for comparison: an IP literal to the one
// spelling Go prints for it, a name to lower case.
//
// Validation and expansion must agree on what "the same endpoint" means, and
// they did not. Validation lowercased the raw text while expansion canonicalized
// through net.ParseIP, so `2001:db8::1` and `2001:0db8::1` passed validation as
// two targets with two sets of credentials and were then collapsed into one by
// the expansion dedupe — leaving the effective configuration to depend on which
// entry came first, with only a warning. Both layers now call this.
//
// Lower-casing a name rather than resolving it is deliberate: Expand never
// resolves DNS, so a name and an address cannot be known to be the same device,
// but DNS names are case-insensitive.
func canonicalHost(h string) string {
	h = strings.Trim(h, "[]")

	// A zone identifier is an interface name, and net.ParseIP refuses any address
	// carrying one — so the whole value fell to the lower-casing path meant for
	// hostnames, and got both halves wrong. Linux interface names are
	// case-sensitive, so fe80::1%Eth0 and fe80::1%eth0 are two different links
	// and were being rejected as one duplicate; meanwhile the address half was
	// never canonicalized, so fe80::0001%eth0 and fe80::1%eth0 were treated as
	// two endpoints when they are one.
	if addr, zone, ok := strings.Cut(h, "%"); ok {
		if ip := net.ParseIP(addr); ip != nil {
			return ip.String() + "%" + zone
		}
		return strings.ToLower(addr) + "%" + zone
	}

	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}

	// A prefix names a subnet, and 10.0.0.1/22 names the same subnet as
	// 10.0.0.0/22. Without masking, the two are separate entries that expand to
	// the same 1022 addresses, and the second expansion is discarded wholesale.
	if prefix, err := netip.ParsePrefix(h); err == nil {
		return prefix.Masked().String()
	}

	return strings.ToLower(h)
}
