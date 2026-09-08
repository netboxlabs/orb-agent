package mapping

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// captureRows builds the Q-BRIDGE rows a switch publishing its port lists as
// text reports, the shape a Junos QFX shows on its defaults: bridge ports
// numbered from 4097, comma-separated port lists led by a zero entry, and a
// PVID of 0 on the trunks. Two trunks carry six VLANs each and one access
// port sits untagged in VLAN 4004. The lists also name bridge ports the
// translation table never maps, as the real switch does.
func captureRows() ObjectIDValueMap {
	out := ObjectIDValueMap{}
	put := func(oid, val string, t Asn1BER) { out[oid] = Value{Value: val, Type: t} }
	// sysObjectID under the Juniper enterprise, the vendor whose default is the text form.
	put(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.2636.1.1.1.4.82.5", ObjectIdentifier)
	for bp, ifIndex := range map[string]string{"4097": "513", "4098": "520", "4099": "518"} {
		put(".1.3.6.1.2.1.17.1.4.1.2."+bp, ifIndex, Integer)
		put(".1.3.6.1.2.1.2.2.1.7."+ifIndex, "1", Integer)
		put(".1.3.6.1.2.1.2.2.1.3."+ifIndex, "6", Integer)
	}
	put(".1.3.6.1.2.1.17.7.1.4.5.1.1.4097", "0", Integer)
	put(".1.3.6.1.2.1.17.7.1.4.5.1.1.4098", "4004", Integer)
	put(".1.3.6.1.2.1.17.7.1.4.5.1.1.4099", "0", Integer)
	for vid, egress := range map[string]string{
		"23":   "0,4097,4099",
		"3856": "4106,0,4097,4099",
		"3884": "4102,4104,0,4097,4099",
		"4002": "0,4097,4099,4101,4105",
		"4004": "0,4097,4099,4098",
		"4005": "0,4097,4099,4103",
	} {
		put(".1.3.6.1.2.1.17.7.1.4.3.1.2."+vid, egress, OctetString)
		put(".1.3.6.1.2.1.17.7.1.4.3.1.5."+vid, "1", Integer)
	}
	for vid, untagged := range map[string]string{"23": "", "3856": "4106", "3884": "4102,4104", "4002": "4101,4105", "4004": "4098", "4005": "4103"} {
		put(".1.3.6.1.2.1.17.7.1.4.3.1.4."+vid, untagged, OctetString)
	}
	return out
}

// interfacesFor registers one verified interface per ifIndex and returns them.
func interfacesFor(registry *EntityRegistry, names map[int]string) map[int]*diode.Interface {
	out := map[int]*diode.Interface{}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	for ifIndex, name := range names {
		iface := &diode.Interface{Name: StringPtr(name)}
		registry.entities[InterfaceEntityType][ObjectIDIndex(strconv.Itoa(ifIndex))] = iface
		registry.MarkInterfaceVerified(iface)
		out[ifIndex] = iface
	}
	return out
}

func taggedVids(iface *diode.Interface) []int {
	var out []int
	for _, v := range iface.TaggedVlans {
		if v != nil && v.Vid != nil {
			out = append(out, int(*v.Vid))
		}
	}
	return out
}

// A switch that publishes its Q-BRIDGE port lists as text, the platform's
// default, with a PVID of 0 on its trunks: the trunks come out tagged in
// every VLAN they carry and the access port untagged in its one. Read as
// bitmaps, the lists named ports at random and the trunks reported a PVID
// of 0 as their VLAN.
func TestVlanMapper_PostMap_ASCIIPortLists(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{513: "xe-0/0/0", 518: "xe-0/0/1", 520: "xe-0/0/2"})
	rows := captureRows()

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(rows, registry, &config.Defaults{VLAN: config.VLANDefaults{Status: "active"}})

	trunk := ifaces[513]
	if trunk.Mode == nil || *trunk.Mode != "tagged" {
		t.Errorf("xe-0/0/0 mode: got %v, want tagged", trunk.Mode)
	}
	if got, want := taggedVids(trunk), []int{23, 3856, 3884, 4002, 4004, 4005}; !equalInts(got, want) {
		t.Errorf("xe-0/0/0 tagged: got %v, want %v", got, want)
	}
	if trunk.UntaggedVlan != nil {
		t.Errorf("xe-0/0/0 untagged: got %+v, want none (PVID 0)", trunk.UntaggedVlan)
	}
	access := ifaces[520]
	if access.Mode == nil || *access.Mode != "access" {
		t.Errorf("xe-0/0/2 mode: got %v, want access", access.Mode)
	}
	if access.UntaggedVlan == nil || access.UntaggedVlan.Vid == nil || *access.UntaggedVlan.Vid != 4004 {
		t.Errorf("xe-0/0/2 untagged: got %+v, want 4004", access.UntaggedVlan)
	}
}

// The same switch with one trunk trimmed to a single VLAN, which is the shape
// the reporter saw: one tagged VLAN, PVID 0, is a trunk with that one VLAN
// tagged, not an access port with no VLAN.
func TestVlanMapper_PostMap_SingleTaggedVlan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{518: "xe-0/0/1"})
	rows := captureRows()
	// Bridge port 4099 is xe-0/0/1. Leave it only in VLAN 4005's egress list.
	for vid, keep := range map[string]bool{"23": false, "3856": false, "3884": false, "4002": false, "4004": false, "4005": true} {
		oid := ".1.3.6.1.2.1.17.7.1.4.3.1.2." + vid
		v := rows[oid]
		if !keep {
			v.Value = strings.ReplaceAll(v.Value, ",4099", "")
		}
		rows[oid] = v
	}

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(rows, registry, &config.Defaults{VLAN: config.VLANDefaults{Status: "active"}})

	iface := ifaces[518]
	if iface.Mode == nil || *iface.Mode != "tagged" {
		t.Errorf("xe-0/0/1 mode: got %v, want tagged", iface.Mode)
	}
	if got := taggedVids(iface); !equalInts(got, []int{4005}) {
		t.Errorf("xe-0/0/1 tagged: got %v, want [4005]", got)
	}
	if iface.UntaggedVlan != nil {
		t.Errorf("xe-0/0/1 untagged: got %+v, want none", iface.UntaggedVlan)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The same rows from a device of another vendor are read as bitmaps: text
// lists are a Junos default, and a value of digit and comma bytes is a legal
// bitmap anywhere else.
func TestVlanMapper_PostMap_TextListsNeedTheVendor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{513: "xe-0/0/0"})
	rows := captureRows()
	rows[".1.3.6.1.2.1.1.2.0"] = Value{Value: ".1.3.6.1.4.1.30065.1.3011.7050", Type: ObjectIdentifier}

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(rows, registry, &config.Defaults{VLAN: config.VLANDefaults{Status: "active"}})

	if got := taggedVids(ifaces[513]); len(got) != 0 {
		t.Errorf("xe-0/0/0 tagged: got %v, want none from a bitmap reading", got)
	}
}
