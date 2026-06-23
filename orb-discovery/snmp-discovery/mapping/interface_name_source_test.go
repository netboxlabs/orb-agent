package mapping

import (
	"testing"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
)

func TestResolveInterfaceName(t *testing.T) {
	auto := config.InterfaceNameSourceAuto
	ifname := config.InterfaceNameSourceIfName
	ifdescr := config.InterfaceNameSourceIfDescr
	descr := "Unit: 1 Slot: 0 Port: 1 Gigabit - Level" // looksDescriptive == true
	cases := []struct {
		name    string
		source  string
		ifDescr string
		ifName  string
		want    string
	}{
		// auto: ifDescr preferred unless descriptive while ifName is clean.
		{"auto clean ifdescr wins", auto, "GigabitEthernet0/1", "Gi0/1", "GigabitEthernet0/1"},
		{"auto descriptive ifdescr yields to clean ifname", auto, descr, "Gi0/1", "Gi0/1"},
		{"auto empty ifdescr uses ifname", auto, "", "Gi0/1", "Gi0/1"},
		{"auto empty ifname uses ifdescr", auto, "GigabitEthernet0/1", "", "GigabitEthernet0/1"},
		{"auto both descriptive keeps ifdescr", auto, descr, "Slot: 2 Port: 3 - foo", descr},
		{"auto both empty", auto, "", "", ""},
		// Sentinel ifName must not be promoted over a descriptive ifDescr:
		// the legacy inline path treated DefaultInterfaceName ("unknown")
		// as the not-yet-populated sentinel and let ifDescr overwrite it.
		{"auto sentinel ifname keeps descriptive ifdescr", auto, descr, DefaultInterfaceName, descr},
		// ifname: ifName wins; fall back to ifDescr when empty.
		{"ifname wins", ifname, "GigabitEthernet0/1", "Gi0/1", "Gi0/1"},
		{"ifname empty falls back to ifdescr", ifname, "GigabitEthernet0/1", "", "GigabitEthernet0/1"},
		{"ifname both empty", ifname, "", "", ""},
		// ifdescr: ifDescr wins even when descriptive; fall back when empty.
		{"ifdescr wins even when descriptive", ifdescr, descr, "Gi0/1", descr},
		{"ifdescr empty falls back to ifname", ifdescr, "", "Gi0/1", "Gi0/1"},
		// unknown source behaves as auto (defensive).
		{"unknown source behaves as auto", "bogus", descr, "Gi0/1", "Gi0/1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveInterfaceName(tc.source, tc.ifDescr, tc.ifName))
		})
	}
}
