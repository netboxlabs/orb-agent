package mapping

import (
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// numericVlanID reports the VLAN an interface stands for on switches that name
// each VLAN interface by its bare VLAN ID and number it vlanIfIndexBase +
// VID - 1. name is the one the agent would send, so the test follows
// interface_name_source and holds when a walk lost one of the name columns.
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
		return false
	}
	return true
}

// leaveOutCollidingVlanInterfaces leaves out a VLAN interface whose new name
// another interface on the device already has, in any case: NetBox would merge
// the two into one interface.
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
	}
}

// reportUnnamedVlanInterfaces says once per run that the device names VLAN
// interfaces by their bare VLAN ID and the prefix is not set.
func (m *ObjectIDMapper) reportUnnamedVlanInterfaces() {
	if n := m.registry.unnamedVlanInterfaces; n > 0 {
		m.logger.Info("interface: VLAN interfaces are named by their bare VLAN ID; "+
			"set defaults.vlan_interface_name_prefix to send them as prefix + VLAN ID", "count", n)
	}
}
