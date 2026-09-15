package mapping

import (
	"encoding/hex"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// extractHuaweiVlanCatalog is a pure reduction of the walked rows: every
// index row registers its VID, names arrive trimmed, an empty or NUL-only
// name is no name, RowStatus is carried where present, and rows with a
// malformed suffix or value are skipped rather than failing the walk.
func TestExtractHuaweiVlanCatalog(t *testing.T) {
	cat := extractHuaweiVlanCatalog(ObjectIDValueMap{
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.10":  {Value: "10", Type: Gauge32},
		".1.3.6.1.4.1.2011.5.6.1.1.1.2.10":  {Value: "office\x00\x00", Type: OctetString},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.10": {Value: "1", Type: Integer},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.20":  {Value: "20", Type: Gauge32},
		".1.3.6.1.4.1.2011.5.6.1.1.1.2.20":  {Value: "\x00\x00", Type: OctetString},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.30": {Value: "2", Type: Integer},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.x":   {Value: "x", Type: Gauge32},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.40": {Value: "notInt", Type: Integer},
		".1.3.6.1.2.1.17.7.1.4.3.1.1.50":    {Value: "not-huawei", Type: OctetString},
		".1.3.6.1.4.1.2011.5.6.1.1.1.3.10":  {Value: "\xff", Type: OctetString}, // hwVlanPorts: not read
	})
	assert.Equal(t, map[int]bool{10: true, 20: true, 30: true}, cat.Vids,
		"index, name and status rows all register their VID; malformed suffixes and foreign OIDs do not")
	assert.Equal(t, map[int]string{10: "office"}, cat.Names,
		"NUL padding is stripped and a NUL-only name is no name")
	assert.Equal(t, map[int]int{10: 1, 30: 2}, cat.RowStatus,
		"a non-integer status is skipped")
	assert.False(t, cat.empty())
	assert.True(t, extractHuaweiVlanCatalog(ObjectIDValueMap{}).empty())
}

// The generic path sees the vendor tables only through vendorVlanCatalog, so
// a host with none walked must read as empty — that is what keeps a router
// or WLC at the debug-level "nothing to do" log rather than the warning.
func TestVendorVlanCatalog_EmptyWithoutVendorRows(t *testing.T) {
	cat := vendorVlanCatalog(ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": {Value: "office"},
		".1.3.6.1.2.1.1.2.0":             {Value: ".1.3.6.1.4.1.2011.2.80.8"},
	})
	assert.True(t, cat.empty())
}

// huaweiOltVlanWalk is the HUAWEI-VLAN-MIB catalog as a SmartAX MA5608T
// reports it: every VLAN has an hwVlanIndex row whose value repeats the
// index, only the VLANs an operator described have an hwVlanName row, and
// nothing under Q-BRIDGE-MIB answers at all.
func huaweiOltVlanWalk() ObjectIDValueMap {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.1.2.0": {Value: ".1.3.6.1.4.1.2011.2.80.8", Type: ObjectIdentifier},
	}
	for _, vid := range []string{"1", "50", "158", "159", "632", "634", "647", "664", "682", "683", "684", "685", "941"} {
		oids[".1.3.6.1.4.1.2011.5.6.1.1.1.1."+vid] = Value{Value: vid, Type: Gauge32}
	}
	for vid, name := range map[string]string{
		"50":  "Clients",
		"682": "Zajcevo_1455_Tr_High_VLAN682",
		"683": "CKAD_Minskoe_1377_Tr_Low_VLAN683",
		"684": "Zajcevo_1455_Neo_High_VLAN684",
		"685": "Minskoe_1377_Neo_Low_VLAN685",
	} {
		oids[".1.3.6.1.4.1.2011.5.6.1.1.1.2."+vid] = Value{Value: name, Type: OctetString}
	}
	return oids
}

// A Huawei OLT with no Q-BRIDGE-MIB used to complete discovery with zero
// VLANs. Every VLAN the device lists has to come out, named where the
// device named it and under the VLAN<vid> default where it did not — the
// same default a nameless dot1q row gets.
func TestEmitVLANs_HuaweiCatalogWithoutQBridge(t *testing.T) {
	m := NewVlanMapper(slog.Default(), config.Options{})
	got := map[int]string{}
	for _, e := range m.emitVLANs(huaweiOltVlanWalk(), nil) {
		v, ok := e.(*diode.VLAN)
		require.True(t, ok)
		got[int(*v.Vid)] = *v.Name
	}
	assert.Equal(t, map[int]string{
		1: "VLAN1", 50: "Clients", 158: "VLAN158", 159: "VLAN159",
		632: "VLAN632", 634: "VLAN634", 647: "VLAN647", 664: "VLAN664",
		682: "Zajcevo_1455_Tr_High_VLAN682", 683: "CKAD_Minskoe_1377_Tr_Low_VLAN683",
		684: "Zajcevo_1455_Neo_High_VLAN684", 685: "Minskoe_1377_Neo_Low_VLAN685",
		941: "VLAN941",
	}, got)
}

// With create_unknown_vlans off, an index-only row is a nameless VLAN and
// is suppressed exactly like a status-only dot1q row; the described ones
// still come out.
func TestEmitVLANs_HuaweiCatalog_CreateUnknownVlansFalse(t *testing.T) {
	m := NewVlanMapper(slog.Default(), config.Options{CreateUnknownVlans: ptrBool(false)})
	got := map[int]string{}
	for _, e := range m.emitVLANs(huaweiOltVlanWalk(), nil) {
		v := e.(*diode.VLAN)
		got[int(*v.Vid)] = *v.Name
	}
	assert.Equal(t, map[int]string{
		50: "Clients", 682: "Zajcevo_1455_Tr_High_VLAN682", 683: "CKAD_Minskoe_1377_Tr_Low_VLAN683",
		684: "Zajcevo_1455_Neo_High_VLAN684", 685: "Minskoe_1377_Neo_Low_VLAN685",
	}, got)
}

// hwVlanRowStatus is a standard RowStatus and feeds the same status
// derivation dot1qVlanStaticRowStatus does; a defaults.vlan.status still
// wins over it.
func TestEmitVLANs_HuaweiRowStatusDerivesStatus(t *testing.T) {
	oids := ObjectIDValueMap{
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.10":  {Value: "10", Type: Gauge32},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.10": {Value: "1", Type: Integer},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.20":  {Value: "20", Type: Gauge32},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.20": {Value: "2", Type: Integer},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.30":  {Value: "30", Type: Gauge32},
	}
	m := NewVlanMapper(slog.Default(), config.Options{})
	status := map[int]string{}
	for _, e := range m.emitVLANs(oids, nil) {
		v := e.(*diode.VLAN)
		if v.Status != nil {
			status[int(*v.Vid)] = *v.Status
		} else {
			status[int(*v.Vid)] = ""
		}
	}
	assert.Equal(t, map[int]string{10: "active", 20: "reserved", 30: ""}, status)

	for _, e := range m.emitVLANs(oids, &config.Defaults{VLAN: config.VLANDefaults{Status: "deprecated"}}) {
		assert.Equal(t, "deprecated", *e.(*diode.VLAN).Status)
	}
}

// If a Huawei platform ever answers both catalogs, the standard column is
// authoritative for the name — the same rule VTP is held to — and a VID
// only the vendor table lists is still emitted.
func TestEmitVLANs_Dot1qWinsOverHuaweiForTheSameVid(t *testing.T) {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10":   {Value: "from-dot1q"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.10": {Value: "10"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.2.10": {Value: "from-huawei"},
		".1.3.6.1.2.1.17.7.1.4.3.1.1.20":   {Value: "\x00\x00"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.2.20": {Value: "named-only-by-huawei"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.30": {Value: "30"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.2.30": {Value: "huawei-only\x00\x00"},
	}
	m := NewVlanMapper(slog.Default(), config.Options{})
	got := map[int]string{}
	for _, e := range m.emitVLANs(oids, nil) {
		v := e.(*diode.VLAN)
		got[int(*v.Vid)] = *v.Name
	}
	assert.Equal(t, map[int]string{10: "from-dot1q", 20: "named-only-by-huawei", 30: "huawei-only"}, got,
		"dot1q wins a real conflict, an empty dot1q name does not erase the vendor name, NUL padding is stripped")
}

// End to end through the post-pass: the OLT has no dot1dBasePortIfIndex,
// so the VLAN entities come out and no interface is touched.
func TestVlanMapper_PostMap_HuaweiOlt_EmitsVLANsWithoutInterfaceMutation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	iface := &diode.Interface{Name: StringPtr("GPON 0/1/0")}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	registry.entities[InterfaceEntityType]["1"] = iface
	registry.MarkInterfaceVerified(iface)

	vm := NewVlanMapper(logger, config.Options{})
	emitted := vm.PostMap(huaweiOltVlanWalk(), registry, &config.Defaults{Site: "olt-site"})

	vlans := 0
	for _, e := range emitted {
		if v, ok := e.(*diode.VLAN); ok {
			vlans++
			require.NotNil(t, v.Vid)
			require.NotNil(t, v.Name)
		}
	}
	assert.Equal(t, 13, vlans, "one entity per hwVlanIndex row")
	assert.Nil(t, iface.Mode)
	assert.Nil(t, iface.UntaggedVlan)
	assert.Nil(t, iface.TaggedVlans)
}

// When both tables report a VID, dot1qVlanStaticRowStatus decides the
// status, exactly as dot1qVlanStaticName decides the name. The rule is
// enforced by the order emitVLANs applies the two sources, not by which
// row a map iteration happens to yield last, so the emitted status cannot
// flap between polls. Run many times because the failure mode is
// order-dependent and a single pass can pass by luck.
func TestEmitVLANs_Dot1qRowStatusWinsOverHuaweiDeterministically(t *testing.T) {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10":    {Value: "office"},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.10":    {Value: "1"}, // active
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.10":  {Value: "10"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.10": {Value: "2"}, // notInService
		// Only the vendor table reports 20: its status is the only one.
		".1.3.6.1.4.1.2011.5.6.1.1.1.1.20":  {Value: "20"},
		".1.3.6.1.4.1.2011.5.6.1.1.1.13.20": {Value: "2"},
		// Only dot1q reports 30.
		".1.3.6.1.2.1.17.7.1.4.3.1.1.30": {Value: "lab"},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.30": {Value: "2"},
	}
	m := NewVlanMapper(slog.Default(), config.Options{})
	for i := 0; i < 200; i++ {
		got := map[int]string{}
		for _, e := range m.emitVLANs(oids, nil) {
			v := e.(*diode.VLAN)
			got[int(*v.Vid)] = *v.Status
		}
		require.Equal(t, map[int]string{10: "active", 20: "reserved", 30: "reserved"}, got,
			"iteration %d: dot1q status must win for 10; single-source VIDs keep their own", i)
	}
}

// ma5608tPortBitmap is hwVlanPorts as the reporting MA5608T returns it: the
// bitmap spelled out as hexadecimal text, 26 slots x 8 octets = 208 octets =
// 416 characters, with the given octets set. The device's uplink board is
// slot 2, so octet 16 (slot 2, ports 0-7) is where its bits live.
func ma5608tPortBitmap(set map[int]byte) string {
	octets := make([]byte, 26*hwVlanPortsOctetsPerSlot)
	for i, b := range set {
		octets[i] = b
	}
	return strings.ToUpper(hex.EncodeToString(octets))
}

// ma5608tIfNames is the ifName walk from the same device: four uplink
// ethernet ports and a clock port on slot 2, sixteen GPON ports on slot 0,
// and the logical interfaces that must never be mistaken for ports.
func ma5608tIfNames() ObjectIDValueMap {
	oids := ObjectIDValueMap{
		oidIfName + "128":        {Value: "InLoopBack0"},
		oidIfName + "262":        {Value: "null0"},
		oidIfName + "263":        {Value: "meth0"},
		oidIfName + "264":        {Value: "vlanif50"},
		oidIfName + "265":        {Value: "vlanif682"},
		oidIfName + "269":        {Value: "loopback0"},
		oidIfName + "234897408":  {Value: "ethernet0/2/0"},
		oidIfName + "234897472":  {Value: "ethernet0/2/1"},
		oidIfName + "234897536":  {Value: "ethernet0/2/2"},
		oidIfName + "234897600":  {Value: "ethernet0/2/3"},
		oidIfName + "3221242112": {Value: "bits0/2/4"},
	}
	for p := 0; p < 16; p++ {
		oids[oidIfName+strconv.Itoa(4194304000+p*256)] = Value{Value: "GPON 0/0/" + strconv.Itoa(p)}
	}
	return oids
}

func TestDecodeHuaweiPortList(t *testing.T) {
	// The reporting device: VLAN 682 on ethernet 0/2/2 and 0/2/3. Octet 16
	// = 0x0C = bits 2 and 3, and the MIB's low-bit-first order puts those on
	// ports 2 and 3 of slot 2. Read MSB-first (the RFC PortList order) the
	// same octet would name ports 4 and 5 — a clock port and a port the
	// board does not have, which is how the two orders were told apart.
	got, err := decodeHuaweiPortList(ma5608tPortBitmap(map[int]byte{16: 0x0C}))
	require.NoError(t, err)
	assert.Equal(t, []slotPort{{2, 2}, {2, 3}}, got)

	// Lower-case hex text decodes the same.
	got, err = decodeHuaweiPortList(strings.ToLower(ma5608tPortBitmap(map[int]byte{16: 0x0C})))
	require.NoError(t, err)
	assert.Equal(t, []slotPort{{2, 2}, {2, 3}}, got)

	// Raw octets, as the MIB declares them: slot 7 port 0 and slot 7 port 63.
	raw := make([]byte, 8*8)
	raw[7*8] = 0x01
	raw[7*8+7] = 0x80
	got, err = decodeHuaweiPortList(string(raw))
	require.NoError(t, err)
	assert.Equal(t, []slotPort{{7, 0}, {7, 63}}, got)

	// All zero is a VLAN with no uplink ports (the reporter's VLAN 50).
	got, err = decodeHuaweiPortList(ma5608tPortBitmap(nil))
	require.NoError(t, err)
	assert.Empty(t, got)

	// Not a whole number of slots: refused, not truncated.
	_, err = decodeHuaweiPortList(string(make([]byte, 12)))
	assert.Error(t, err)
	_, err = decodeHuaweiPortList("0C0C0C")
	assert.Error(t, err, "3 octets of hex text is not a slot either")
}

func TestHuaweiPortIndex(t *testing.T) {
	idx, ok := huaweiPortIndex(ma5608tIfNames())
	require.True(t, ok)
	assert.Equal(t, 234897536, idx[slotPort{2, 2}])
	assert.Equal(t, 3221242112, idx[slotPort{2, 4}], "the BITS clock port is a physical port too")
	assert.Equal(t, 4194307840, idx[slotPort{0, 15}], "GPON names carry a space before frame/slot/port")
	assert.Len(t, idx, 21, "logical interfaces (vlanif, meth0, loopbacks) are not ports")

	// No physical port names at all: nothing to translate with.
	_, ok = huaweiPortIndex(ObjectIDValueMap{oidIfName + "1": {Value: "vlanif10"}})
	assert.False(t, ok)

	// Two frames would put the same slot/port on two interfaces, and the
	// bitmap cannot say which frame it means.
	two := ma5608tIfNames()
	two[oidIfName+"999"] = Value{Value: "ethernet1/2/2"}
	_, ok = huaweiPortIndex(two)
	assert.False(t, ok)
}

func TestHuaweiTaggedMembership_ReportingDevice(t *testing.T) {
	oids := ma5608tIfNames()
	oids[oidHwVlanPorts+"682"] = Value{Value: ma5608tPortBitmap(map[int]byte{16: 0x0C})}
	oids[oidHwVlanPorts+"683"] = Value{Value: ma5608tPortBitmap(map[int]byte{16: 0x08})}
	oids[oidHwVlanPorts+"50"] = Value{Value: ma5608tPortBitmap(nil)}

	got := huaweiTaggedMembership(oids, slog.Default())
	assert.Equal(t, map[int][]int{
		234897536: {682},      // ethernet0/2/2
		234897600: {682, 683}, // ethernet0/2/3
	}, got, "VLAN 50 has no uplink ports and contributes nothing")
}

// A set bit that names a port the device does not have means the bitmap is
// being read wrongly, and the whole device is refused rather than the one
// VLAN: one wrong association is worse than none. The RFC PortList reading
// of the reporter's octet is exactly this case.
func TestHuaweiTaggedMembership_RefusesUnresolvablePort(t *testing.T) {
	oids := ma5608tIfNames()
	// 0x30 = bits 4 and 5 = ports 0/2/4 (clock) and 0/2/5 (absent).
	oids[oidHwVlanPorts+"682"] = Value{Value: ma5608tPortBitmap(map[int]byte{16: 0x30})}
	oids[oidHwVlanPorts+"683"] = Value{Value: ma5608tPortBitmap(map[int]byte{16: 0x01})}
	assert.Nil(t, huaweiTaggedMembership(oids, slog.Default()),
		"683 alone would resolve, but the device is refused as a whole")

	// A malformed value refuses the device too.
	oids = ma5608tIfNames()
	oids[oidHwVlanPorts+"682"] = Value{Value: "0C0C0C"}
	assert.Nil(t, huaweiTaggedMembership(oids, slog.Default()))

	// No ifName rows to translate with.
	oids = ObjectIDValueMap{oidHwVlanPorts + "682": {Value: ma5608tPortBitmap(map[int]byte{16: 0x0C})}}
	assert.Nil(t, huaweiTaggedMembership(oids, slog.Default()))

	// Membership rows absent entirely (a catalog-only device): nil, no log.
	assert.Nil(t, huaweiTaggedMembership(ma5608tIfNames(), slog.Default()))
}

// End to end through the post-pass on a device with no BRIDGE-MIB: the
// catalog VLANs come out, the uplink ports carrying VLANs get mode tagged
// with the catalog's own VLAN entities in tagged_vlans and no untagged
// VLAN, and every other interface is untouched.
func TestVlanMapper_PostMap_HuaweiOlt_TagsUplinkPortsFromHwVlanPorts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	ifaces := map[string]*diode.Interface{}
	for _, ifIndex := range []string{"234897408", "234897472", "234897536", "234897600", "3221242112", "4194304000", "264"} {
		iface := &diode.Interface{Name: StringPtr("if" + ifIndex)}
		registry.entities[InterfaceEntityType][ObjectIDIndex(ifIndex)] = iface
		registry.MarkInterfaceVerified(iface)
		ifaces[ifIndex] = iface
	}

	oids := huaweiOltVlanWalk()
	for oid, v := range ma5608tIfNames() {
		oids[oid] = v
	}
	oids[oidHwVlanPorts+"682"] = Value{Value: ma5608tPortBitmap(map[int]byte{16: 0x0C})}
	oids[oidHwVlanPorts+"683"] = Value{Value: ma5608tPortBitmap(map[int]byte{16: 0x08})}
	oids[oidHwVlanPorts+"50"] = Value{Value: ma5608tPortBitmap(nil)}

	vm := NewVlanMapper(logger, config.Options{})
	emitted := vm.PostMap(oids, registry, &config.Defaults{Site: "olt-site"})

	byVid := map[int]*diode.VLAN{}
	for _, e := range emitted {
		if v, ok := e.(*diode.VLAN); ok {
			byVid[int(*v.Vid)] = v
		}
	}
	require.Len(t, byVid, 13, "membership never adds VLANs the catalog did not list")

	eth2 := ifaces["234897536"]
	require.NotNil(t, eth2.Mode)
	assert.Equal(t, "tagged", *eth2.Mode)
	require.Len(t, eth2.TaggedVlans, 1)
	assert.Same(t, byVid[682], eth2.TaggedVlans[0], "the interface references the emitted VLAN entity, not a copy")
	assert.Equal(t, "Zajcevo_1455_Tr_High_VLAN682", *eth2.TaggedVlans[0].Name)
	assert.Nil(t, eth2.UntaggedVlan, "no PVID source on this platform")

	eth3 := ifaces["234897600"]
	assert.Equal(t, "tagged", *eth3.Mode)
	require.Len(t, eth3.TaggedVlans, 2)
	assert.Equal(t, int64(682), *eth3.TaggedVlans[0].Vid)
	assert.Equal(t, int64(683), *eth3.TaggedVlans[1].Vid)

	for _, ifIndex := range []string{"234897408", "234897472", "3221242112", "4194304000", "264"} {
		iface := ifaces[ifIndex]
		assert.Nil(t, iface.Mode, "%s carries no VLAN and must be untouched", ifIndex)
		assert.Nil(t, iface.TaggedVlans, ifIndex)
		assert.Nil(t, iface.UntaggedVlan, ifIndex)
	}
}
