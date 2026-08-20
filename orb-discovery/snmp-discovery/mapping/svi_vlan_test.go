package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
)

// The accept table is the SVI naming this resolver recognizes, drawn from a
// 1877-device corpus, most common first. It is not a claim that every entry was
// observed there: any form added without a device behind it belongs in the
// reject table until one turns up. The reject table is the set of look-alikes a
// trailing-integer parser gets wrong.
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
		// A bridge-domain id is not a VLAN id: BDI100 can route a service
		// instance whose encapsulation is dot1q 10.
		"BDI100", "Bdi100", "bdi7",
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
		// The dot1qVlanStaticName rows that produced the two VLAN entities
		// above. Eligibility is read from these, so they travel with the
		// entities exactly as they do on a real target.
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": {Value: "office"},
		".1.3.6.1.2.1.17.7.1.4.3.1.1.20": {Value: "voice"},
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

// The eligibility signal is whether the DEVICE named the VID, not whether
// the entity carries a name: every producer of a *diode.VLAN with a
// non-nil Vid sets Name, defaulting a nameless VID to the "VLAN<vid>"
// placeholder, so the entity's own name cannot tell an operator's name
// from one the agent synthesised.
func TestResolveSviVlans_SkipsAVlanTheDeviceDidNotName(t *testing.T) {
	const (
		ifName1        = ".1.3.6.1.2.1.31.1.1.1.1.1"
		dot1qName1     = ".1.3.6.1.2.1.17.7.1.4.3.1.1.1"
		dot1qRowStatus = ".1.3.6.1.2.1.17.7.1.4.3.1.5.1"
	)

	t.Run("a placeholder name is not a device name", func(t *testing.T) {
		// Exactly the shape emitVLANs produces for a VID whose name row is
		// NUL padding, and the shape ensureVLAN stubs. Referencing it would
		// rename the operator's VLAN, because a matched reference is applied
		// as an update carrying the whole payload.
		placeholder := &diode.VLAN{Vid: int64Ptr(1), Name: strPtr("VLAN1")}
		oids := ObjectIDValueMap{
			ifName1:    {Value: "Vlan1"},
			dot1qName1: {Value: "\x00\x00"},
		}

		got := ResolveSviVlans(oids, []diode.Entity{placeholder}, slog.Default())
		assert.Empty(t, got, "the agent invented that name; it must not be attached")
	})

	t.Run("a vid known only from a status row is not named", func(t *testing.T) {
		// No name column at all — the VID exists only because the device
		// reported a row status for it.
		placeholder := &diode.VLAN{Vid: int64Ptr(1), Name: strPtr("VLAN1")}
		oids := ObjectIDValueMap{
			ifName1:        {Value: "Vlan1"},
			dot1qRowStatus: {Value: "1"},
		}

		got := ResolveSviVlans(oids, []diode.Entity{placeholder}, slog.Default())
		assert.Empty(t, got)
	})

	t.Run("a device-named vid resolves", func(t *testing.T) {
		named := &diode.VLAN{Vid: int64Ptr(1), Name: strPtr("default")}
		oids := ObjectIDValueMap{
			ifName1:    {Value: "Vlan1"},
			dot1qName1: {Value: "default"},
		}

		got := ResolveSviVlans(oids, []diode.Entity{named}, slog.Default())
		assert.Same(t, named, got[1])
	})

	t.Run("a vtp-sourced name is device-supplied", func(t *testing.T) {
		// The VTP catalog is where devices that do not populate
		// dot1qVlanStaticName publish their VLAN names. It comes from the
		// device, so it qualifies — including when the dot1q row is present
		// but empty.
		named := &diode.VLAN{Vid: int64Ptr(1), Name: strPtr("default")}
		oids := ObjectIDValueMap{
			ifName1:                             {Value: "Vlan1"},
			dot1qName1:                          {Value: "\x00\x00"},
			".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.1": {Value: "default"},
		}

		got := ResolveSviVlans(oids, []diode.Entity{named}, slog.Default())
		assert.Same(t, named, got[1])
	})
}

// ifName and ifDescr can each name the interface. When both parse to a VLAN id
// and the ids differ, collection order must not decide the answer: the device's
// own columns disagree, so there is nothing to corroborate. Both VLANs are in
// the device's VLAN database here, so the corroboration check alone would have
// accepted whichever came first.
func TestResolveSviVlans_RefusesWhenTheNameColumnsDisagree(t *testing.T) {
	vlan10 := &diode.VLAN{Vid: int64Ptr(10), Name: strPtr("office")}
	vlan20 := &diode.VLAN{Vid: int64Ptr(20), Name: strPtr("voice")}
	entities := []diode.Entity{vlan10, vlan20}

	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": {Value: "office"},
		".1.3.6.1.2.1.17.7.1.4.3.1.1.20": {Value: "voice"},
		// ifIndex 1: the two columns name different VLANs.
		".1.3.6.1.2.1.31.1.1.1.1.1": {Value: "Vlan10"},
		".1.3.6.1.2.1.2.2.1.2.1":    {Value: "Vlan20"},
		// ifIndex 2: the two columns agree by different spellings.
		".1.3.6.1.2.1.31.1.1.1.1.2": {Value: "Vl20"},
		".1.3.6.1.2.1.2.2.1.2.2":    {Value: "Vlan20"},
		// ifIndex 3: one column is an SVI, the other is not a VLAN name at all.
		".1.3.6.1.2.1.31.1.1.1.1.3": {Value: "Vlan10"},
		".1.3.6.1.2.1.2.2.1.2.3":    {Value: "802.1Q VLAN"},
	}

	got := ResolveSviVlans(oids, entities, slog.Default())

	assert.NotContains(t, got, 1, "disagreeing name columns must not resolve")
	assert.Same(t, vlan20, got[2], "agreement through different spellings must resolve")
	assert.Same(t, vlan10, got[3], "an unparseable second column is not a disagreement")
	assert.Len(t, got, 2)
}
