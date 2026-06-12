package mapping

import (
	"log/slog"
	"strconv"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oidIdx encodes a VRF name into its length-prefixed OID index form.
// Iterates BYTES, not runes — RFC 4382 indexes are octet strings, so a
// multi-byte UTF-8 name contributes one sub-identifier per byte.
func oidIdx(name string) string {
	b := []byte(name)
	out := strconv.Itoa(len(b))
	for _, c := range b {
		out += "." + strconv.Itoa(int(c))
	}
	return out
}

func octets(v string) Value {
	return Value{Value: v, Type: 4} // OctetString
}

func TestDecodeRouteDistinguisher(t *testing.T) {
	logger := slog.Default()
	// Type 0: 2-byte ASN 65000 : number 100
	rd0 := string([]byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 100})
	assert.Equal(t, "65000:100", decodeRouteDistinguisher(rd0, logger))
	// Type 1: 10.1.1.1 : 55
	rd1 := string([]byte{0, 1, 10, 1, 1, 1, 0, 55})
	assert.Equal(t, "10.1.1.1:55", decodeRouteDistinguisher(rd1, logger))
	// Type 2: 4-byte ASN 4200000000 : 7
	rd2 := string([]byte{0, 2, 0xfa, 0x56, 0xea, 0x00, 0, 7})
	assert.Equal(t, "4200000000:7", decodeRouteDistinguisher(rd2, logger))
	// Display-string passthroughs
	assert.Equal(t, "65000:100", decodeRouteDistinguisher("65000:100", logger))
	assert.Equal(t, "10.1.1.1:55", decodeRouteDistinguisher("10.1.1.1:55", logger))
	// Unset / undecodable forms stay off the wire
	assert.Equal(t, "", decodeRouteDistinguisher("", logger))
	assert.Equal(t, "", decodeRouteDistinguisher(string(make([]byte, 8)), logger))
	assert.Equal(t, "", decodeRouteDistinguisher("not-an-rd", logger))
	assert.Equal(t, "", decodeRouteDistinguisher(string([]byte{0, 9, 1, 2, 3, 4, 5, 6}), logger))
}

func TestDecodeOctetStringIndexWithTail(t *testing.T) {
	// Length-prefixed: 3."R"."E"."D".42 → name RED, tail [42]
	name, tail, ok := decodeOctetStringIndexWithTail("3.82.69.68.42", 1)
	require.True(t, ok)
	assert.Equal(t, "RED", name)
	assert.Equal(t, []int{42}, tail)
	// IMPLIED (no length prefix): "R"."E"."D".42
	name, tail, ok = decodeOctetStringIndexWithTail("82.69.68.42", 1)
	require.True(t, ok)
	assert.Equal(t, "RED", name)
	assert.Equal(t, []int{42}, tail)
	// No tail variant
	name, ok2 := decodeOctetStringIndex("3.82.69.68")
	require.True(t, ok2)
	assert.Equal(t, "RED", name)
	// Non-printable octets fail the row
	_, _, ok = decodeOctetStringIndexWithTail("2.1.2.42", 1)
	assert.False(t, ok)
	// Garbage
	_, _, ok = decodeOctetStringIndexWithTail("abc.def", 1)
	assert.False(t, ok)
	_, _, ok = decodeOctetStringIndexWithTail("", 1)
	assert.False(t, ok)
}

func stdTierOids() ObjectIDValueMap {
	red := oidIdx("RED")
	mgm := oidIdx("MGM")
	return ObjectIDValueMap{
		// RD rows: RED has a type-0 RD, MGM an all-zero (unset) one.
		oidMplsL3VpnVrfRD + "." + red: octets(string([]byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 100})),
		oidMplsL3VpnVrfRD + "." + mgm: octets(string(make([]byte, 8))),
		// Membership: RED on ifIndex 10 and 11, MGM on 20.
		oidMplsL3VpnIfConf + "." + red + ".10": octets("1"),
		oidMplsL3VpnIfConf + "." + red + ".11": octets("1"),
		oidMplsL3VpnIfConf + "." + mgm + ".20": octets("1"),
	}
}

func TestTranslateVrfs_StdTier(t *testing.T) {
	entities, byIfIndex := TranslateVrfs(stdTierOids(), &config.Defaults{Tags: []string{"orb"}}, slog.Default())
	require.Len(t, entities, 2)
	// Sorted by name: MGM, RED.
	mgm, ok := entities[0].(*diode.VRF)
	require.True(t, ok)
	assert.Equal(t, "MGM", *mgm.Name)
	assert.Nil(t, mgm.Rd)
	red, ok := entities[1].(*diode.VRF)
	require.True(t, ok)
	assert.Equal(t, "RED", *red.Name)
	require.NotNil(t, red.Rd)
	assert.Equal(t, "65000:100", *red.Rd)
	require.Len(t, red.Tags, 1)
	assert.Equal(t, "orb", *red.Tags[0].Name)

	assert.Same(t, red, byIfIndex[10])
	assert.Same(t, red, byIfIndex[11])
	assert.Same(t, mgm, byIfIndex[20])
}

func TestTranslateVrfs_MembershipOnlyVrfStillEmitted(t *testing.T) {
	blu := oidIdx("BLU")
	oids := ObjectIDValueMap{
		oidMplsL3VpnIfConf + "." + blu + ".7": octets("1"),
	}
	entities, byIfIndex := TranslateVrfs(oids, nil, slog.Default())
	require.Len(t, entities, 1)
	vrf := entities[0].(*diode.VRF)
	assert.Equal(t, "BLU", *vrf.Name)
	assert.Nil(t, vrf.Rd)
	assert.Same(t, vrf, byIfIndex[7])
}

func TestTranslateVrfs_LegacyTierFallback(t *testing.T) {
	grn := oidIdx("GRN")
	oids := ObjectIDValueMap{
		oidMplsVpnVrfRDLegacy + "." + grn:         octets("65000:200"),
		oidMplsVpnIfConfLegacy + "." + grn + ".5": octets("1"),
	}
	entities, byIfIndex := TranslateVrfs(oids, nil, slog.Default())
	require.Len(t, entities, 1)
	vrf := entities[0].(*diode.VRF)
	assert.Equal(t, "GRN", *vrf.Name)
	require.NotNil(t, vrf.Rd)
	assert.Equal(t, "65000:200", *vrf.Rd)
	assert.Same(t, vrf, byIfIndex[5])
}

func TestTranslateVrfs_CiscoTierFallback(t *testing.T) {
	oids := ObjectIDValueMap{
		oidCvVrfName + ".1":          octets("mgmt-vrf"),
		oidCvVrfName + ".2":          octets("cust"),
		oidCvVrfInterface + ".1.30":  octets("1"),
		oidCvVrfInterface + ".2.31":  octets("1"),
		oidCvVrfInterface + ".2.32":  octets("1"),
		oidCvVrfInterface + ".9.99":  octets("1"), // orphan vrfId: dropped
		oidCvVrfInterface + ".bad.x": octets("1"), // undecodable: skipped
	}
	entities, byIfIndex := TranslateVrfs(oids, nil, slog.Default())
	require.Len(t, entities, 2)
	cust := entities[0].(*diode.VRF)
	assert.Equal(t, "cust", *cust.Name)
	assert.Nil(t, cust.Rd)
	assert.Same(t, cust, byIfIndex[31])
	assert.Same(t, cust, byIfIndex[32])
	mgmt := entities[1].(*diode.VRF)
	assert.Equal(t, "mgmt-vrf", *mgmt.Name)
	assert.Same(t, mgmt, byIfIndex[30])
	_, orphan := byIfIndex[99]
	assert.False(t, orphan)
}

func TestTranslateVrfs_StdTierWinsOverLowerTiers(t *testing.T) {
	red := oidIdx("RED")
	oids := stdTierOids()
	// Lower-tier rows present too — must be ignored once tier 1 yields.
	oids[oidCvVrfName+".1"] = octets("shadow")
	oids[oidMplsVpnVrfRDLegacy+"."+red] = octets("1:1")
	entities, _ := TranslateVrfs(oids, nil, slog.Default())
	names := make([]string, 0, len(entities))
	for _, e := range entities {
		names = append(names, *(e.(*diode.VRF)).Name)
	}
	assert.Equal(t, []string{"MGM", "RED"}, names)
}

func TestTranslateVrfs_NoRowsNoEntities(t *testing.T) {
	entities, byIfIndex := TranslateVrfs(ObjectIDValueMap{"1.3.6.1.2.1.1.1.0": octets("x")}, nil, slog.Default())
	assert.Nil(t, entities)
	assert.Nil(t, byIfIndex)
}

func TestAttachVrfs_OverwritesDefaultsAndSkipsNonMembers(t *testing.T) {
	vrfName := "RED"
	vrf := &diode.VRF{Name: &vrfName}
	ifaceMember := &diode.Interface{}
	ifaceOther := &diode.Interface{}
	defName := "from-defaults"
	ipMember := &diode.IPAddress{
		AssignedObject: ifaceMember,
		Vrf:            &diode.VRF{Name: &defName},
	}
	ipOther := &diode.IPAddress{
		AssignedObject: ifaceOther,
		Vrf:            &diode.VRF{Name: &defName},
	}
	ipUnassigned := &diode.IPAddress{}
	entities := []diode.Entity{ipMember, ipOther, ipUnassigned, vrf}

	AttachVrfs(entities,
		map[int]*diode.VRF{10: vrf},
		map[*diode.Interface]int{ifaceMember: 10, ifaceOther: 20},
		slog.Default(),
	)

	// Discovered VRF overwrote the defaults-derived one on the member.
	assert.Same(t, vrf, ipMember.Vrf)
	// Non-member keeps its defaults VRF.
	assert.Equal(t, "from-defaults", *ipOther.Vrf.Name)
	assert.Nil(t, ipUnassigned.Vrf)
}

func TestAttachVrfs_SameAddressTwoVrfsKeepsFirstInAddressMap(t *testing.T) {
	redName, blueName := "RED", "BLUE"
	red := &diode.VRF{Name: &redName}
	blue := &diode.VRF{Name: &blueName}
	ifaceRed := &diode.Interface{}
	ifaceBlue := &diode.Interface{}
	addr := "10.0.0.1/24"
	addrCopy := addr
	ipRed := &diode.IPAddress{Address: &addr, AssignedObject: ifaceRed}
	ipBlue := &diode.IPAddress{Address: &addrCopy, AssignedObject: ifaceBlue}

	vrfByAddress := AttachVrfs(
		[]diode.Entity{ipRed, ipBlue},
		map[int]*diode.VRF{1: red, 2: blue},
		map[*diode.Interface]int{ifaceRed: 1, ifaceBlue: 2},
		slog.Default(),
	)

	// Each IP keeps its own interface's VRF...
	assert.Same(t, red, ipRed.Vrf)
	assert.Same(t, blue, ipBlue.Vrf)
	// ...but the address map keeps the first VRF seen, so primary-IP sync
	// and prefix derivation stay deterministic.
	assert.Same(t, red, vrfByAddress[addr])
}

func TestAttachVrfs_SyncsPrimaryIPSnapshotsAndVCMasterRefs(t *testing.T) {
	vrfName := "MGMT"
	vrf := &diode.VRF{Name: &vrfName}
	iface := &diode.Interface{}
	addr := "10.0.0.1/24"
	ip := &diode.IPAddress{Address: &addr, AssignedObject: iface}
	// Snapshot copies taken at map time (distinct structs, same address),
	// as assignPrimaryIP / the VC master-ref stubs produce them.
	devSnapshot := &diode.IPAddress{Address: &addr}
	vcStub := &diode.IPAddress{Address: &addr}
	memberStub := &diode.IPAddress{Address: &addr}
	dev := &diode.Device{PrimaryIp4: devSnapshot}
	vc := &diode.VirtualChassis{Master: &diode.Device{PrimaryIp4: vcStub}}
	member := &diode.Device{
		VirtualChassis: &diode.VirtualChassis{
			Master: &diode.Device{PrimaryIp4: memberStub},
		},
	}
	otherAddr := "192.0.2.9/32"
	untouched := &diode.IPAddress{Address: &otherAddr}
	devOther := &diode.Device{PrimaryIp4: untouched}

	AttachVrfs(
		[]diode.Entity{dev, vc, member, devOther, ip},
		map[int]*diode.VRF{1: vrf},
		map[*diode.Interface]int{iface: 1},
		slog.Default(),
	)

	require.Same(t, vrf, ip.Vrf)
	assert.Same(t, vrf, devSnapshot.Vrf, "Device.PrimaryIp4 snapshot must re-sync")
	assert.Same(t, vrf, vcStub.Vrf, "VirtualChassis master-ref stub must re-sync")
	assert.Same(t, vrf, memberStub.Vrf, "member VC master-ref stub must re-sync")
	assert.Nil(t, untouched.Vrf, "non-member primary IP stays untouched")
}

func TestDecodeRouteDistinguisher_PaddedDisplayForms(t *testing.T) {
	logger := slog.Default()
	// 8-char padded display forms must not fall into the binary path.
	assert.Equal(t, "65000:1", decodeRouteDistinguisher(" 65000:1", logger))
	assert.Equal(t, "65000:1", decodeRouteDistinguisher("65000:1\x00", logger))
	assert.Equal(t, "65000:10", decodeRouteDistinguisher("65000:10", logger))
	// REGRESSION PIN: binary RDs lead with 0x00 type bytes (and may end
	// in 0x00 data bytes) — display-form trimming must never reach the
	// binary path's input.
	rdLeadingAndTrailingNul := string([]byte{0, 0, 0xfd, 0xe8, 0, 0, 1, 0})
	assert.Equal(t, "65000:256", decodeRouteDistinguisher(rdLeadingAndTrailingNul, logger))
}

func TestTranslateVrfs_LowerTierCannotAddNamesWhenTier1HasRecords(t *testing.T) {
	red := oidIdx("RED")
	// Tier 1 enumerates RED with no membership anywhere; the cisco tier
	// knows an internal iVRF the standards arc deliberately omits — it
	// may refine RED's membership but must NOT introduce new VRFs.
	oids := ObjectIDValueMap{
		oidMplsL3VpnVrfRD + "." + red: octets("65000:100"),
		oidCvVrfName + ".1":           octets("RED"),
		oidCvVrfName + ".2":           octets("__internal_ivrf"),
		oidCvVrfInterface + ".1.6":    octets("1"),
		oidCvVrfInterface + ".2.7":    octets("1"),
	}
	entities, byIfIndex := TranslateVrfs(oids, nil, slog.Default())
	require.Len(t, entities, 1)
	vrf := entities[0].(*diode.VRF)
	assert.Equal(t, "RED", *vrf.Name)
	assert.Same(t, vrf, byIfIndex[6], "matching-name membership merges in")
	_, leaked := byIfIndex[7]
	assert.False(t, leaked, "non-matching lower-tier VRF must not leak")
}

func TestOctetsToString_UTF8NamesAccepted(t *testing.T) {
	// "café" — RFC 4382 names are SnmpAdminString (UTF-8).
	name, ok := octetsToString([]int{0x63, 0x61, 0x66, 0xc3, 0xa9})
	require.True(t, ok)
	assert.Equal(t, "café", name)
	// Control characters and invalid UTF-8 still fail the row.
	_, ok = octetsToString([]int{0x63, 0x01})
	assert.False(t, ok)
	_, ok = octetsToString([]int{0xc3, 0x28})
	assert.False(t, ok)
}

func TestTranslateVrfs_SplitArcAgentMergesMembership(t *testing.T) {
	red := oidIdx("RED")
	// Tier-1 exposes only the RD table; membership lives on the legacy arc.
	oids := ObjectIDValueMap{
		oidMplsL3VpnVrfRD + "." + red:             octets("65000:100"),
		oidMplsVpnIfConfLegacy + "." + red + ".4": octets("1"),
	}
	entities, byIfIndex := TranslateVrfs(oids, nil, slog.Default())
	require.Len(t, entities, 1)
	vrf := entities[0].(*diode.VRF)
	assert.Equal(t, "RED", *vrf.Name)
	require.NotNil(t, vrf.Rd)
	assert.Equal(t, "65000:100", *vrf.Rd, "tier-1 RD must survive the merge")
	assert.Same(t, vrf, byIfIndex[4], "legacy-arc membership must merge in")
}

func TestVrfWalkGating(t *testing.T) {
	mappings := []config.MappingEntry{
		{OID: "1.3.6.1.2.1.10.166.11.1.2.2.1.4", Entity: "vrf", Field: "x"},
		{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
	}
	logger := slog.Default()

	off, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{})
	require.NoError(t, err)
	_, walked := off.GenericObjectIDs()["1.3.6.1.2.1.10.166.11.1.2.2.1.4"]
	assert.False(t, walked, "vrf column must not be walked with discover_vrfs off")

	enabled := true
	on, err := NewConfig(mappings, logger, nil, nil, nil, config.Options{DiscoverVrfs: &enabled})
	require.NoError(t, err)
	_, walked = on.GenericObjectIDs()["1.3.6.1.2.1.10.166.11.1.2.2.1.4"]
	assert.True(t, walked, "vrf column must be walked with discover_vrfs on")
}
