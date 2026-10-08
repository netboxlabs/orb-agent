package mapping_test

import (
	"bytes"
	"log/slog"
	"strconv"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

// vlanIfaceEntries mirrors the shipped interface and ipAddrTable entries,
// trimmed to the columns these tests set.
func vlanIfaceEntries() []config.MappingEntry {
	return []config.MappingEntry{
		{
			OID: ".1.3.6.1.2.1.2.2.1", Entity: "interface", Field: "_id", IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
				{OID: ".1.3.6.1.2.1.2.2.1.3", Entity: "interface", Field: "type"},
				{OID: ".1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
			},
		},
		{
			OID: ".1.3.6.1.2.1.4.20.1", Entity: "ipAddress", Field: "_id", IdentifierSize: 4,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
				{OID: ".1.3.6.1.2.1.4.20.1.3", Entity: "ipAddress", Field: "addressPrefixSize"},
				{
					OID: ".1.3.6.1.2.1.4.20.1.2", Entity: "ipAddress", Field: "assignedObject",
					Relationship: config.Relationship{Type: "interface", Field: "_id"},
				},
			},
		},
	}
}

// iface is one ifTable row. An empty column is left out of the walk.
type iface struct {
	ifIndex                int
	ifDescr, ifName, ifTyp string
}

func (i iface) rows(out mapping.ObjectIDValueMap) {
	idx := strconv.Itoa(i.ifIndex)
	put := func(oid, v string, typ mapping.Asn1BER) {
		if v != "" {
			out[oid+idx] = mapping.Value{Value: v, Type: typ, IdentifierSize: 1}
		}
	}
	put(".1.3.6.1.2.1.2.2.1.2.", i.ifDescr, mapping.Asn1BER(mapping.OctetString))
	put(".1.3.6.1.2.1.2.2.1.3.", i.ifTyp, mapping.Asn1BER(mapping.Integer))
	put(".1.3.6.1.2.1.31.1.1.1.1.", i.ifName, mapping.Asn1BER(mapping.OctetString))
}

// addIP binds 192.0.2.1/24 to ifIndex.
func addIP(out mapping.ObjectIDValueMap, ifIndex int) {
	const a = "192.0.2.1"
	out[".1.3.6.1.2.1.4.20.1.1."+a] = mapping.Value{Value: a, Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4}
	out[".1.3.6.1.2.1.4.20.1.3."+a] = mapping.Value{Value: "255.255.255.0", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4}
	out[".1.3.6.1.2.1.4.20.1.2."+a] = mapping.Value{Value: strconv.Itoa(ifIndex), Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 4}
}

type vlanRun struct {
	ifaces []*diode.Interface // top-level interfaces
	ip     *diode.IPAddress
	log    string
}

func mapVlanIfaces(t *testing.T, defaults config.Defaults, opts config.Options, ifaces []iface, ipOn int) vlanRun {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	objectIDs := mapping.ObjectIDValueMap{}
	for _, i := range ifaces {
		i.rows(objectIDs)
	}
	if ipOn != 0 {
		addIP(objectIDs, ipOn)
	}
	cfg, err := mapping.NewConfig(vlanIfaceEntries(), logger, &FakeManufacturers{}, &FakeDeviceLookup{}, nil, opts)
	require.NoError(t, err)
	if defaults.Interface.Type == "" {
		defaults.Interface.Type = "other"
	}
	var run vlanRun
	for _, e := range mapping.NewObjectIDMapper(cfg, logger, &defaults, "").MapObjectIDsToEntity(objectIDs) {
		switch v := e.(type) {
		case *diode.Interface:
			run.ifaces = append(run.ifaces, v)
		case *diode.IPAddress:
			run.ip = v
		}
	}
	run.log = buf.String()
	return run
}

// names returns every interface name the run sends, the IP's included.
func (r vlanRun) names() []string {
	var out []string
	for _, i := range r.ifaces {
		out = append(out, i.GetName())
	}
	if r.ip != nil && r.ip.AssignedObject != nil {
		out = append(out, r.ip.AssignedObject.(*diode.Interface).GetName())
	}
	return out
}

func (r vlanRun) ipInterface() string {
	if r.ip == nil || r.ip.AssignedObject == nil {
		return ""
	}
	return r.ip.AssignedObject.(*diode.Interface).GetName()
}

var (
	svi5 = iface{100004, "5", "5", "53"}
	gi1  = iface{1, "GigabitEthernet1", "gi1", "6"}
)

func TestVlanInterfaceName_PrefixNamesTheVlanInterface(t *testing.T) {
	run := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"}, config.Options{},
		[]iface{svi5, gi1}, 100004)
	assert.Equal(t, "Vlan5", run.ipInterface())
	assert.ElementsMatch(t, []string{"GigabitEthernet1", "Vlan5"}, run.names())
	assert.Equal(t, "virtual", run.ip.AssignedObject.(*diode.Interface).GetType())
}

func TestVlanInterfaceName_PrefixKeepsItsSpace(t *testing.T) {
	run := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "vlan "}, config.Options{},
		[]iface{svi5}, 100004)
	assert.Equal(t, "vlan 5", run.ipInterface())
}

// Without the prefix the device's own name is sent, and the run says once that
// such interfaces were found.
func TestVlanInterfaceName_UnsetKeepsTheDeviceName(t *testing.T) {
	run := mapVlanIfaces(t, config.Defaults{}, config.Options{},
		[]iface{svi5, {100009, "10", "10", "53"}, gi1}, 100004)
	assert.Equal(t, "5", run.ipInterface())
	assert.Contains(t, run.names(), "10")
	assert.Contains(t, run.log, "vlan_interface_name_prefix")
	assert.Contains(t, run.log, "count=2")

	quiet := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"}, config.Options{},
		[]iface{svi5}, 100004)
	assert.NotContains(t, quiet.log, "vlan_interface_name_prefix")
	none := mapVlanIfaces(t, config.Defaults{}, config.Options{}, []iface{gi1}, 0)
	assert.NotContains(t, none.log, "vlan_interface_name_prefix")
}

func TestVlanInterfaceName_EveryVidInRange(t *testing.T) {
	for _, tc := range []struct {
		row  iface
		want string
	}{
		{iface{100000, "1", "1", "53"}, "Vlan1"},
		{iface{104093, "4094", "4094", "53"}, "Vlan4094"},
	} {
		run := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"}, config.Options{},
			[]iface{tc.row}, tc.row.ifIndex)
		assert.Equal(t, tc.want, run.ipInterface())
	}
}

// Anything short of the whole shape keeps its name.
func TestVlanInterfaceName_OnlyTheShapeIsRenamed(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  iface
		want string
	}{
		{"not propVirtual", iface{100004, "5", "5", "6"}, "5"},
		{"name is not the VID", iface{100004, "05", "05", "53"}, "05"},
		{"ifIndex off the scheme", iface{100005, "5", "5", "53"}, "5"},
		{"VID 0", iface{99999, "0", "0", "53"}, "0"},
		{"VID 4095", iface{104094, "4095", "4095", "53"}, "4095"},
		{"a word for a name", iface{100004, "vlan", "vlan", "53"}, "vlan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"}, config.Options{},
				[]iface{tc.row}, tc.row.ifIndex)
			assert.Equal(t, tc.want, run.ipInterface())
		})
	}
}

// The test is on the name the agent would send, so it follows
// interface_name_source and survives a walk that lost one name column.
func TestVlanInterfaceName_FollowsTheResolvedName(t *testing.T) {
	ifname := config.InterfaceNameSourceIfName
	descrIsAWord := iface{100004, "vlan", "5", "53"}

	run := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"},
		config.Options{InterfaceNameSource: &ifname}, []iface{descrIsAWord}, 100004)
	assert.Equal(t, "Vlan5", run.ipInterface())

	run = mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"}, config.Options{},
		[]iface{descrIsAWord}, 100004)
	assert.Equal(t, "vlan", run.ipInterface(), "auto sends ifDescr, which is not the VID")

	for _, row := range []iface{{100004, "5", "", "53"}, {100004, "", "5", "53"}} {
		run = mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"}, config.Options{},
			[]iface{row}, 100004)
		assert.Equal(t, "Vlan5", run.ipInterface(), "one name column missing: %+v", row)
	}
}

// Without its ifType the interface cannot be told apart from a port that
// happens to fit the scheme, and sending the bare number would undo the rename
// in NetBox, so it is left out of the run: not sent, its address unassigned.
func TestVlanInterfaceName_MissingTypeLeavesTheInterfaceOut(t *testing.T) {
	noType := iface{100004, "5", "5", ""}
	run := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Vlan"}, config.Options{},
		[]iface{noType, gi1}, 100004)
	require.NotNil(t, run.ip)
	if run.ip.AssignedObject != nil {
		t.Fatalf("the address must be left unassigned, got %#v", run.ip.AssignedObject)
	}
	assert.Equal(t, []string{"GigabitEthernet1"}, run.names())
	assert.Contains(t, run.log, "ifType")

	// Without the prefix nothing changes: the name was never going to change.
	run = mapVlanIfaces(t, config.Defaults{}, config.Options{}, []iface{noType}, 100004)
	assert.Equal(t, "5", run.ipInterface())
}

// A prefix that renders another interface's name, in any case, would merge the
// two in NetBox, so the VLAN interface is left out and the run says why.
func TestVlanInterfaceName_CollisionLeavesTheVlanInterfaceOut(t *testing.T) {
	for _, other := range []string{"Po1", "PO1"} {
		lag := iface{1000, other, other, "161"}
		svi1 := iface{100000, "1", "1", "53"}
		run := mapVlanIfaces(t, config.Defaults{VlanInterfaceNamePrefix: "Po"}, config.Options{},
			[]iface{lag, svi1}, 100000)
		require.NotNil(t, run.ip)
		if run.ip.AssignedObject != nil {
			t.Fatalf("%s: the address must be left unassigned, got %#v", other, run.ip.AssignedObject)
		}
		assert.Equal(t, []string{other}, run.names())
		assert.Contains(t, run.log, "collides")
		assert.Contains(t, run.log, other)
	}
}

// Exclusion patterns see the name that is sent.
func TestVlanInterfaceName_ExclusionSeesTheNewName(t *testing.T) {
	run := mapVlanIfaces(t,
		config.Defaults{VlanInterfaceNamePrefix: "Vlan", InterfaceExcludePatterns: []string{"^Vlan"}},
		config.Options{}, []iface{svi5, gi1}, 100004)
	assert.Nil(t, run.ip, "the address on an excluded interface is dropped")
	assert.Equal(t, []string{"GigabitEthernet1"}, run.names())
}
