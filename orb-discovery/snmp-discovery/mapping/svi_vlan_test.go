package mapping

import (
	"log/slog"
	"strconv"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
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

// The eligibility signal is whether the DEVICE configures the VID, read from
// its VLAN name columns, not whether the entity carries a name: every producer
// of a *diode.VLAN with a non-nil Vid sets Name, defaulting a nameless VID to
// the "VLAN<vid>" placeholder, so the entity cannot tell a configured VLAN from
// one stubbed for a VID seen only in a row status.
func TestResolveSviVlans_OnlyAVlanTheDeviceConfigures(t *testing.T) {
	const (
		ifName1        = ".1.3.6.1.2.1.31.1.1.1.1.1"
		dot1qName1     = ".1.3.6.1.2.1.17.7.1.4.3.1.1.1"
		dot1qRowStatus = ".1.3.6.1.2.1.17.7.1.4.3.1.5.1"
	)

	t.Run("a configured vid with an empty name resolves", func(t *testing.T) {
		// The shape emitVLANs produces for a VID whose name row is NUL
		// padding: the device configures the VLAN but names it nothing. The
		// VLAN entity already goes out under the placeholder, and the prefix
		// refers to that same entity, so attaching it sends no name the run
		// was not sending anyway.
		placeholder := &diode.VLAN{Vid: int64Ptr(1), Name: strPtr("VLAN1")}
		oids := ObjectIDValueMap{
			ifName1:    {Value: "Vlan1"},
			dot1qName1: {Value: "\x00\x00"},
		}

		got := ResolveSviVlans(oids, []diode.Entity{placeholder}, slog.Default())
		assert.Same(t, placeholder, got[1])
	})

	t.Run("a vid with only a row status resolves", func(t *testing.T) {
		// No name column at all, but the static table has the VLAN's row,
		// and emitVLANs sends it under the placeholder all the same.
		placeholder := &diode.VLAN{Vid: int64Ptr(1), Name: strPtr("VLAN1")}
		oids := ObjectIDValueMap{
			ifName1:        {Value: "Vlan1"},
			dot1qRowStatus: {Value: "1"},
		}

		got := ResolveSviVlans(oids, []diode.Entity{placeholder}, slog.Default())
		assert.Same(t, placeholder, got[1])
	})

	t.Run("a vid only a vendor catalog lists resolves", func(t *testing.T) {
		placeholder := &diode.VLAN{Vid: int64Ptr(7), Name: strPtr("VLAN7")}
		oids := ObjectIDValueMap{
			".1.3.6.1.2.1.31.1.1.1.1.7":       {Value: "Vlanif7"},
			".1.3.6.1.4.1.2011.5.6.1.1.1.1.7": {Value: "7"},
		}

		got := ResolveSviVlans(oids, []diode.Entity{placeholder}, slog.Default())
		assert.Same(t, placeholder, got[7])
	})

	t.Run("a vid only an interface references does not resolve", func(t *testing.T) {
		// The shape ensureVLAN stubs for a VID seen in a port's membership:
		// nothing in the device's VLAN tables says it exists.
		stub := &diode.VLAN{Vid: int64Ptr(1), Name: strPtr("VLAN1")}
		oids := ObjectIDValueMap{ifName1: {Value: "Vlan1"}}

		got := ResolveSviVlans(oids, []diode.Entity{stub}, slog.Default())
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

// One VID can appear under more than one VTP management domain. Those are
// different Layer 2 domains, and NetBox permits one VID in several VLAN groups,
// so an SVI naming that VID does not say which domain it means. Emission still
// picks one name deterministically for display; corroboration must abstain.
func TestResolveSviVlans_RefusesAVidNamedDifferentlyAcrossVtpDomains(t *testing.T) {
	vlan20 := &diode.VLAN{Vid: int64Ptr(20), Name: strPtr("voice")}
	vlan30 := &diode.VLAN{Vid: int64Ptr(30), Name: strPtr("mgmt")}
	entities := []diode.Entity{vlan20, vlan30}

	oids := ObjectIDValueMap{
		// VID 20 under two domains with different names: ambiguous.
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.20": {Value: "voice"},
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.2.20": {Value: "voice-legacy"},
		// VID 30 under two domains with the same name: not ambiguous.
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.30": {Value: "mgmt"},
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.2.30": {Value: "mgmt"},
		// SVIs naming each of them.
		".1.3.6.1.2.1.31.1.1.1.1.1": {Value: "Vlan20"},
		".1.3.6.1.2.1.31.1.1.1.1.2": {Value: "Vlan30"},
	}

	got := ResolveSviVlans(oids, entities, slog.Default())

	assert.NotContains(t, got, 1, "a vid named differently across domains must not resolve")
	assert.Same(t, vlan30, got[2], "domains agreeing on the name still resolve")
	assert.Len(t, got, 1)
}

// numericSvi is a walk carrying the VLAN interface of vid at its usual place,
// ifIndex 100000 + vid - 1, named with the bare VID in ifName and ifDescr and
// typed propVirtual(53), with vid configured but unnamed. The sysObjectID is a
// Cisco small-business one; the rule does not read it.
func numericSvi(vid int) (ObjectIDValueMap, int, *diode.VLAN) {
	idx := 100000 + vid - 1
	id, name := strconv.Itoa(idx), strconv.Itoa(vid)
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.1.2.0":                  {Value: ".1.3.6.1.4.1.9.6.1.1004.28.5"},
		".1.3.6.1.2.1.17.7.1.4.3.1.1." + name: {Value: ""},
		".1.3.6.1.2.1.31.1.1.1.1." + id:       {Value: name},
		".1.3.6.1.2.1.2.2.1.2." + id:          {Value: name},
		".1.3.6.1.2.1.2.2.1.3." + id:          {Value: "53"},
	}
	return oids, idx, &diode.VLAN{Vid: int64Ptr(int64(vid)), Name: strPtr("VLAN" + name)}
}

// Eltex MES, Cisco small-business and UniFi switches name each VLAN's
// interface with the bare VLAN ID. A bare number is no SVI name in general, so
// it is read only where the whole recorded layout holds, whatever the vendor.
func TestResolveSviVlans_NumericSvi(t *testing.T) {
	for name, sysObjectID := range map[string]string{
		"eltex":                 ".1.3.6.1.4.1.35265.1.192",
		"cisco small business":  ".1.3.6.1.4.1.9.6.1.1004.28.5",
		"cisco catalyst 1300":   ".1.3.6.1.4.1.9.1.3232",
		"unifi, no vendor arc":  ".1.3.6.1.4.1",
		"no sysObjectID at all": "",
	} {
		t.Run(name, func(t *testing.T) {
			oids, idx, vlan := numericSvi(158)
			if sysObjectID == "" {
				delete(oids, ".1.3.6.1.2.1.1.2.0")
			} else {
				oids[".1.3.6.1.2.1.1.2.0"] = Value{Value: sysObjectID}
			}
			got := ResolveSviVlans(oids, []diode.Entity{vlan}, slog.Default())
			assert.Same(t, vlan, got[idx])
		})
	}

	for name, edit := range map[string]func(ObjectIDValueMap){
		"another interface type": func(o ObjectIDValueMap) { o[".1.3.6.1.2.1.2.2.1.3.100157"] = Value{Value: "6"} },
		"no interface type":      func(o ObjectIDValueMap) { delete(o, ".1.3.6.1.2.1.2.2.1.3.100157") },
		"ifName absent":          func(o ObjectIDValueMap) { delete(o, ".1.3.6.1.2.1.31.1.1.1.1.100157") },
		"ifDescr absent":         func(o ObjectIDValueMap) { delete(o, ".1.3.6.1.2.1.2.2.1.2.100157") },
		"ifDescr says otherwise": func(o ObjectIDValueMap) { o[".1.3.6.1.2.1.2.2.1.2.100157"] = Value{Value: "uplink"} },
		"ifDescr says vlan":      func(o ObjectIDValueMap) { o[".1.3.6.1.2.1.2.2.1.2.100157"] = Value{Value: "vlan"} },
		"a leading zero":         func(o ObjectIDValueMap) { o[".1.3.6.1.2.1.31.1.1.1.1.100157"] = Value{Value: "0158"} },
		"the vlan is not on the device": func(o ObjectIDValueMap) {
			delete(o, ".1.3.6.1.2.1.17.7.1.4.3.1.1.158")
		},
	} {
		t.Run(name, func(t *testing.T) {
			oids, _, vlan := numericSvi(158)
			edit(oids)
			assert.Empty(t, ResolveSviVlans(oids, []diode.Entity{vlan}, slog.Default()))
		})
	}

	t.Run("names padded by the agent", func(t *testing.T) {
		oids, idx, vlan := numericSvi(158)
		oids[".1.3.6.1.2.1.31.1.1.1.1.100157"] = Value{Value: "158 "}
		oids[".1.3.6.1.2.1.2.2.1.2.100157"] = Value{Value: "158\x00"}
		assert.Same(t, vlan, ResolveSviVlans(oids, []diode.Entity{vlan}, slog.Default())[idx])
	})

	t.Run("a number at another index", func(t *testing.T) {
		// The name says 158, but the index belongs to VLAN 200.
		oids, _, vlan := numericSvi(158)
		for _, col := range []string{".1.3.6.1.2.1.31.1.1.1.1.", ".1.3.6.1.2.1.2.2.1.2.", ".1.3.6.1.2.1.2.2.1.3."} {
			oids[col+"100199"] = oids[col+"100157"]
			delete(oids, col+"100157")
		}
		assert.Empty(t, ResolveSviVlans(oids, []diode.Entity{vlan}, slog.Default()))
	})
}

// The reporter's shape end to end: two point-to-point SVIs on unnamed VLANs,
// each prefix taking its own VLAN.
func TestDerivePrefixes_NumericSvis(t *testing.T) {
	sviName := "svi-name"
	oids158, idx158, vlan158 := numericSvi(158)
	oids159, idx159, vlan159 := numericSvi(159)
	for k, v := range oids159 {
		oids158[k] = v
	}
	svis := ResolveSviVlans(oids158, []diode.Entity{vlan158, vlan159}, slog.Default())

	if158, if159 := &diode.Interface{Name: strPtr("158")}, &diode.Interface{Name: strPtr("159")}
	addr := func(a string, iface *diode.Interface) *diode.IPAddress {
		return &diode.IPAddress{Address: &a, AssignedObject: iface}
	}
	out := DerivePrefixes(
		[]diode.Entity{addr("192.0.2.58/30", if158), addr("192.0.2.62/30", if159)},
		nil, svis, map[*diode.Interface]int{if158: idx158, if159: idx159},
		nil, &config.Options{EmitPrefixVlan: &sviName}, slog.Default(),
	)
	byPrefix := map[string]*diode.VLAN{}
	for _, e := range out {
		p := e.(*diode.Prefix)
		byPrefix[p.GetPrefix()] = p.Vlan
	}
	assert.Same(t, vlan158, byPrefix["192.0.2.56/30"])
	assert.Same(t, vlan159, byPrefix["192.0.2.60/30"])
}

// The layout maps an ifIndex outside 100000..104093 to a VID NetBox does not
// accept, so it names no VLAN however it is named.
func TestNumericSviVlanID_StaysInTheVlanRange(t *testing.T) {
	for idx, name := range map[int]string{99999: "0", 104094: "4095"} {
		id := strconv.Itoa(idx)
		oids := ObjectIDValueMap{
			".1.3.6.1.2.1.31.1.1.1.1." + id: {Value: name},
			".1.3.6.1.2.1.2.2.1.2." + id:    {Value: name},
			".1.3.6.1.2.1.2.2.1.3." + id:    {Value: "53"},
		}
		_, ok := numericSviVlanID(oids, idx)
		assert.False(t, ok, "ifIndex %d", idx)
	}
}

// deviceVlanVids must name exactly the VLANs emitVLANs emits from the
// device's tables, or the association would refuse a VLAN that is sent, or
// attach one that is not.
func TestDeviceVlanVids_MatchesEmitVLANs(t *testing.T) {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10":    {Value: "office"},
		".1.3.6.1.2.1.17.7.1.4.3.1.1.11":    {Value: ""},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.12":    {Value: "1"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.13":  {Value: "13"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.2.14":  {Value: ""},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.15": {Value: "1"},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.16":    {Value: "bogus"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.0":   {Value: "0"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.0":  {Value: "1"},
		".1.3.6.1.2.1.17.7.1.4.3.1.1.4095":  {Value: "reserved"},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.4095":  {Value: "1"},
	}
	emitted := map[int]struct{}{}
	for _, e := range NewVlanMapper(slog.Default(), config.Options{}).emitVLANs(oids, nil) {
		emitted[int(*e.(*diode.VLAN).Vid)] = struct{}{}
	}
	vids := deviceVlanVids(oids)
	assert.Equal(t, emitted, vids)
	assert.Equal(t, map[int]struct{}{10: {}, 11: {}, 12: {}, 13: {}, 14: {}, 15: {}}, vids,
		"VIDs outside 1..4094 are not VLANs NetBox accepts")
}
