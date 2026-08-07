package mapping

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The accept table is the measured distribution of SVI naming across a
// 1877-device corpus, most common first. The reject table is the set of
// look-alikes a trailing-integer parser gets wrong.
func TestSviVlanID(t *testing.T) {
	accept := map[string]int{
		"Vlan100":          100,
		"vlan100":          100,
		"VLAN100":          100,
		"vlan 600":         600,
		"vlan_7":           7,
		"vlan-249":         249,
		"Vlanif24":         24,
		"Vlan-interface12": 12,
		"VLAN ID 0051":     51,
		"Vl52":             52,
		"Interface vlan30": 30,
		"BDI100":           100,
		"svi9":             9,
		"vlan1":            1,
		"vlan4094":         4094,
	}
	for name, want := range accept {
		got, ok := sviVlanID(name)
		assert.True(t, ok, "must accept %q", name)
		assert.Equal(t, want, got, "wrong vid for %q", name)
	}

	reject := []string{
		// Not SVI tokens at all.
		"Loopback0", "Tunnel10", "Port-channel20", "Serial0/0/0:1",
		"eth0", "GigabitEthernet1/0/1", "StackPort1", "Po1",
		// Dotted: excluded wholesale, so a subinterface can never be read
		// as a VLAN and stack.slot.port notation cannot collide.
		"GigabitEthernet0/1.100", "port1.0.5", "lo0.100", "ge-0/0/0.0", "irb.100", "vlan.7",
		// Out of range.
		"vlan0", "vlan4095", "vlan99999",
		// Tokens whose integer is a bridge-group or operator label, not a VID.
		"ve55", "Bvi1", "br0", "v190", "vgi1", "rvi7",
		// Real VID is the middle number, so a trailing parse is wrong.
		"vlan307-v0",
		// SVI-ish but carries no number.
		"802.1Q VLAN", "L3IPVLAN Interface", "vlan", "vlanMgmt", "bridge",
	}
	for _, name := range reject {
		_, ok := sviVlanID(name)
		assert.False(t, ok, "must reject %q", name)
	}
}

func TestSviVlanID_EmptyAndWhitespace(t *testing.T) {
	for _, name := range []string{"", "   ", "\t"} {
		_, ok := sviVlanID(name)
		assert.False(t, ok)
	}
}
