package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
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

func TestResolveSviVlans(t *testing.T) {
	vlan10 := &diode.VLAN{Vid: int64Ptr(10), Name: strPtr("office")}
	vlan20 := &diode.VLAN{Vid: int64Ptr(20), Name: strPtr("voice")}
	entities := []diode.Entity{vlan10, vlan20}

	oids := ObjectIDValueMap{
		// ifIndex 1: ifName carries the SVI name, ifDescr is generic. This is
		// the shape the resolved Interface.Name would lose.
		".1.3.6.1.2.1.2.2.1.2.1":    {Value: "802.1Q VLAN"},
		".1.3.6.1.2.1.31.1.1.1.1.1": {Value: "vlan 10"},
		// ifIndex 2: only ifDescr is present.
		".1.3.6.1.2.1.2.2.1.2.2": {Value: "Vlan20"},
		// ifIndex 3: SVI name, but VLAN 30 is not in the device's VLAN set.
		".1.3.6.1.2.1.31.1.1.1.1.3": {Value: "Vlan30"},
		// ifIndex 4: not an SVI.
		".1.3.6.1.2.1.31.1.1.1.1.4": {Value: "GigabitEthernet1/0/1"},
	}

	got := ResolveSviVlans(oids, entities, slog.Default())

	assert.Same(t, vlan10, got[1], "ifName must be consulted, not just ifDescr")
	assert.Same(t, vlan20, got[2], "ifDescr alone must resolve")
	assert.NotContains(t, got, 3, "an uncorroborated VID must not resolve")
	assert.NotContains(t, got, 4, "a non-SVI name must not resolve")
	assert.Len(t, got, 2)
}

func TestResolveSviVlans_SkipsVlansWithoutADeviceName(t *testing.T) {
	// A stub VLAN carries a fabricated name. Referencing it would make the
	// association rename the operator's VLAN, because a matched reference is
	// applied as an update carrying the whole payload.
	stub := &diode.VLAN{Vid: int64Ptr(1)}
	oids := ObjectIDValueMap{".1.3.6.1.2.1.31.1.1.1.1.1": {Value: "Vlan1"}}

	got := ResolveSviVlans(oids, []diode.Entity{stub}, slog.Default())
	assert.Empty(t, got, "a VLAN with no name is a stub and must not be referenced")
}
