package mapping

import (
	"regexp"
	"strconv"
	"strings"
)

// sviVlanNameRe matches the interface-name shapes whose trailing integer is
// documented to BE the 802.1Q VLAN ID. Anchored at both ends, one optional
// separator, and the token list is a whitelist rather than a heuristic: a
// trailing-integer parser mis-selects roughly two thirds of the interfaces it
// picks, while this gate selected 234 of 1621 IP-bearing interfaces across 301
// operating-system families with no false positives.
//
// Deliberately absent: br, v, vgi, bvi, ve, irb and rvi. Those are SVI-shaped
// but their integer is a bridge-group id, a virtual-interface id or an operator
// label, and a device whose VLAN table happens to contain the same number would
// corroborate the wrong association rather than catch it.
var sviVlanNameRe = regexp.MustCompile(
	`(?i)^(?:interface[\s_-]+)?(?:vlan-interface|vlan[\s_-]?id|vlanif|vlan|svi|bdi|vl)[\s_-]*0*(\d{1,5})$`,
)

// sviVlanID parses the VLAN ID from an SVI-style interface name. Returns false
// when the name is not an SVI shape, contains a dot, or the parsed value falls
// outside the 1..4094 range NetBox accepts.
//
// The dot exclusion is load-bearing rather than tidiness: a dotted name cannot
// be told apart from stack.slot.port notation or a loopback unit, and no device
// measured reports the 802.1Q encapsulation of a routed subinterface, so there
// is nothing to check such a guess against.
func sviVlanID(name string) (int, bool) {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, ".") {
		return 0, false
	}
	m := sviVlanNameRe.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	vid, err := strconv.Atoi(m[1])
	if err != nil || vid < 1 || vid > 4094 {
		return 0, false
	}
	return vid, true
}
