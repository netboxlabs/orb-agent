package mapping

import "github.com/netboxlabs/diode-sdk-go/diode"

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
	parentName := ExtractParentInterfaceName(name)
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

// isLogicalIfType reports whether an IANAifType value, in the numeric form
// the agent reports it, names an interface that exists only in software and
// therefore hands its switchport configuration to the interface underneath
// it: propVirtual and the l2vlan / l3ipvlan units (53 / 135 / 136), a
// bridge (209), and the aggregate units Junos reports as ieee8023adLag
// (161). InterfaceTypeMap is the same table the interface mapper types
// interfaces from, read here at tier 2 — by ifType alone, with no name
// heuristic ahead of it.
//
// An ifType the walk did not carry, or one the table does not name, is not
// logical: an interface is only moved on evidence the device gave.
func isLogicalIfType(ifType string) bool {
	switch InterfaceTypeMap[ifType] {
	case "virtual", "bridge", "lag":
		return true
	}
	return false
}
