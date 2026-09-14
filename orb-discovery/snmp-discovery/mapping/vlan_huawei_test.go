package mapping

import (
	"log/slog"
	"os"
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
