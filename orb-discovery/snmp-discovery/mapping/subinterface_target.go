package mapping

import (
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// interfacesByName indexes interfaces by their emitted name, keeping every
// match. A name is not unique on a stack: virtual-chassis members commonly
// repeat a management port name (me0, mgmt0), so a lookup that returned the
// first hit would bind a relationship to an arbitrary member. Callers treat
// a multi-entry result as ambiguous instead.
func interfacesByName(ifaces []*diode.Interface) map[string][]*diode.Interface {
	byName := make(map[string][]*diode.Interface, len(ifaces))
	for _, iface := range ifaces {
		if iface != nil && iface.Name != nil {
			byName[*iface.Name] = append(byName[*iface.Name], iface)
		}
	}
	return byName
}

// parentInterfaceFor resolves the interface a subinterface name hangs off,
// using the same name derivation as ResolveSubinterfaceParents. Several MIBs
// name a Junos logical unit (xe-0/0/17.0, ae8.0) where NetBox models the
// relationship on the underlying port, so the callers that build those
// relationships have to agree on how a unit maps back to its port.
//
// The three outcomes are distinguished by isSub:
//
//   - isSub false: name carries no unit suffix; there is nothing to resolve
//     and the caller should use the interface it already has.
//   - isSub true, parent non-nil: exactly one interface carries the parent
//     name, and it is the port the caller wants.
//   - isSub true, parent nil: the parent is not in the walk, or its name
//     matches more than one interface. reason says which; what to do about
//     it is the caller's policy, since it differs by relationship.
func parentInterfaceFor(
	name string,
	byName map[string][]*diode.Interface,
) (parent *diode.Interface, isSub bool, reason string) {
	parentName := logicalUnitParentName(name)
	if parentName == "" {
		return nil, false, ""
	}
	switch parents := byName[parentName]; len(parents) {
	case 1:
		return parents[0], true, ""
	case 0:
		return nil, true, "parent interface is not in the walk"
	default:
		return nil, true, "parent interface name is ambiguous on this device"
	}
}

// logicalUnitParentName returns the interface a LOGICAL UNIT runs on, or ""
// when the name does not denote one.
//
// A unit is a numeric suffix after a dot: xe-0/0/17.0, ae8.0,
// GigabitEthernet0/0.100, re0:mgmt-0.0. This is deliberately narrower than
// ExtractParentInterfaceName, which also treats a colon as a separator for
// Interface.parent. A colon on Junos names a channelized lane —
// et-0/0/0:0 is a physical port in its own right, not a unit of
// et-0/0/0 — and a lane is the switchport (and the aggregation port), so
// moving its relationships to the un-channelized name would put them on
// the wrong interface wherever a device publishes both.
//
// The dot derivation itself stays shared, so a descriptive ifDescr string
// is rejected here exactly as it is for Interface.parent.
func logicalUnitParentName(name string) string {
	idx := strings.LastIndex(name, ".")
	if idx <= 0 || idx == len(name)-1 {
		return ""
	}
	for _, r := range name[idx+1:] {
		if r < '0' || r > '9' {
			return ""
		}
	}
	if ExtractParentInterfaceName(name) != name[:idx] {
		return ""
	}
	return name[:idx]
}
