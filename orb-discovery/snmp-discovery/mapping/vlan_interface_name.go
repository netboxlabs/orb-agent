package mapping

import (
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// numericVlanID reports the VLAN an interface stands for on switches that name
// each VLAN interface by its bare VLAN ID and number it vlanIfIndexBase +
// VID - 1. name is the one the agent would send, so the test follows
// interface_name_source, and where both name columns carry the VID it holds
// when a walk lost one of them.
func numericVlanID(index ObjectIDIndex, name string) (int, bool) {
	ifIndex, err := strconv.Atoi(string(index))
	if err != nil {
		return 0, false
	}
	vid := ifIndex - vlanIfIndexBase + 1
	if vid < 1 || vid > 4094 || name != strconv.Itoa(vid) {
		return 0, false
	}
	return vid, true
}

// nameVlanInterface applies vlan_interface_name_prefix to an interface named by
// its bare VLAN ID. It returns false when the interface must be left out of the
// run: without its ifType it cannot be told apart from a port that happens to
// fit the numbering, and sending the bare number would undo the rename in
// NetBox.
func (m *InterfaceMapper) nameVlanInterface(
	iface *diode.Interface, index ObjectIDIndex, vid int, ifType, prefix string, registry *EntityRegistry,
) bool {
	switch {
	case ifType == ifTypePropVirtual && prefix == "":
		registry.unnamedVlanInterfaces++
	case ifType == ifTypePropVirtual:
		name := prefix + strconv.Itoa(vid)
		iface.Name = &name
		registry.namedVlanInterfaces[iface] = struct{}{}
	case ifType == "" && prefix != "":
		m.logger.Warn("interface: leaving a VLAN interface out of this run; its ifType was not returned",
			"ifIndex", string(index), "vlan", vid)
		forgetName(iface)
		return false
	}
	return true
}

// leaveOutCollidingVlanInterfaces leaves out a VLAN interface whose new name
// another interface on the target already has. An exact match would merge the
// two into one NetBox interface, and one differing only in case would sit
// beside it as a near-duplicate. It runs before a stack is split into member
// devices, so on a stack it compares across members; a prefix cannot render a
// member's unit-numbered port name, and VLAN interfaces stay on the master.
func (m *ObjectIDMapper) leaveOutCollidingVlanInterfaces(entities map[diode.Entity]bool) {
	if len(m.registry.namedVlanInterfaces) == 0 {
		return
	}
	taken := map[string]string{}
	for entity := range entities {
		iface, ok := entity.(*diode.Interface)
		if !ok || iface.Name == nil {
			continue
		}
		if _, named := m.registry.namedVlanInterfaces[iface]; !named {
			taken[strings.ToLower(*iface.Name)] = *iface.Name
		}
	}
	for iface := range m.registry.namedVlanInterfaces {
		other, clash := taken[strings.ToLower(*iface.Name)]
		if !clash {
			continue
		}
		delete(entities, iface)
		delete(m.registry.verifiedInterfaces, iface)
		m.logger.Warn("interface: leaving a VLAN interface out of this run; its name collides with another interface",
			"name", *iface.Name, "other", other)
		forgetName(iface)
	}
}

// forgetName drops the name of an interface left out of the run, so no lookup
// by name, such as a subinterface's parent, can bind to an interface the run
// does not send. The entity stays in the registry: its ifIndex still resolves
// the VRF of the address it carried.
func forgetName(iface *diode.Interface) {
	iface.Name = nil
}

// reportUnnamedVlanInterfaces says once per run that the device names VLAN
// interfaces by their bare VLAN ID and the prefix is not set.
func (m *ObjectIDMapper) reportUnnamedVlanInterfaces() {
	if n := m.registry.unnamedVlanInterfaces; n > 0 {
		m.logger.Info("interface: VLAN interfaces are named by their bare VLAN ID; "+
			"defaults.vlan_interface_name_prefix sends them as prefix + VLAN ID, "+
			"which renames them in NetBox, so read the interface docs first", "count", n)
	}
}
