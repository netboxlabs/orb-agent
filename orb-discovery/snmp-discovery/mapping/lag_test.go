package mapping

import (
	"log/slog"
	"os"
	"strconv"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// lagIface builds a registry-shaped interface for the attach tests.
func lagIface(name, typ string, dev *diode.Device) *diode.Interface {
	return &diode.Interface{Name: strPtr(name), Type: strPtr(typ), Device: dev}
}

// lagIfTypes adds the IF-MIB ifType rows a real walk carries, keyed by
// ifIndex in the numeric form the agent reports. Membership placement
// reads these rather than the NetBox type on the interface, so a fixture
// that omits them describes a device that answered nothing about its
// interfaces.
func lagIfTypes(oids ObjectIDValueMap, byIfIndex map[int]int) ObjectIDValueMap {
	for ifIndex, ifType := range byIfIndex {
		oids[oidIfType+strconv.Itoa(ifIndex)] = Value{Value: strconv.Itoa(ifType)}
	}
	return oids
}

// Junos EX with three aggregation ports, indexed by logical unit as the
// real device reports them: two units of one physical port on ae120 and
// one unit of another on ae0. The physical ports and aggregates are in
// the interface set like any other row.
func fixtureJunosLagMembers() (map[*diode.Interface]int, map[string]*diode.Interface) {
	dev := &diode.Device{Name: strPtr("ex4550-lab")}
	ifaces := map[string]*diode.Interface{
		"xe-0/0/24":      lagIface("xe-0/0/24", "10gbase-x-sfpp", dev),
		"xe-0/0/28":      lagIface("xe-0/0/28", "10gbase-x-sfpp", dev),
		"xe-0/0/24.0":    lagIface("xe-0/0/24.0", "virtual", dev),
		"xe-0/0/24.1876": lagIface("xe-0/0/24.1876", "virtual", dev),
		"xe-0/0/28.0":    lagIface("xe-0/0/28.0", "virtual", dev),
		"ae0":            lagIface("ae0", "lag", dev),
		"ae120":          lagIface("ae120", "lag", dev),
		"ae0.0":          lagIface("ae0.0", "virtual", dev),
	}
	byIface := map[*diode.Interface]int{
		ifaces["xe-0/0/24"]: 524, ifaces["xe-0/0/28"]: 526,
		ifaces["xe-0/0/24.0"]: 528, ifaces["xe-0/0/28.0"]: 534, ifaces["xe-0/0/24.1876"]: 546,
		ifaces["ae0"]: 576, ifaces["ae120"]: 584, ifaces["ae0.0"]: 586,
	}
	return byIface, ifaces
}

func fixtureJunosLagOids() ObjectIDValueMap {
	return lagIfTypes(ObjectIDValueMap{
		oidDot3adAggPortSelectedAggID + "528": {Value: "584"},
		oidDot3adAggPortSelectedAggID + "534": {Value: "576"},
		oidDot3adAggPortSelectedAggID + "546": {Value: "584"},
		oidDot3adAggPortAttachedAggID + "528": {Value: "584"},
		oidDot3adAggPortAttachedAggID + "534": {Value: "576"},
		oidDot3adAggPortAttachedAggID + "546": {Value: "584"},
	}, map[int]int{
		524: 6, 526: 6, // physical ports
		528: 53, 534: 53, 546: 53, // the units the MIB names
		576: 161, 584: 161, 586: 161, // aggregates and an aggregate unit
	})
}

func TestLagMembershipRows_AttachedWinsAndZeroDropped(t *testing.T) {
	oids := ObjectIDValueMap{
		oidDot3adAggPortSelectedAggID + "10": {Value: "100"},
		oidDot3adAggPortAttachedAggID + "10": {Value: "0"},   // detaching: attached says none
		oidDot3adAggPortSelectedAggID + "11": {Value: "100"}, // only the selection column answers
		oidDot3adAggPortAttachedAggID + "12": {Value: "200\x00"},
		oidDot3adAggPortAttachedAggID + "13": {Value: "not-a-number"},
		oidDot3adAggPortAttachedAggID + "9":  {Value: "300"},
	}
	rows := lagMembershipRows(oids)
	assert.Equal(t, [][2]int{{9, 300}, {11, 100}, {12, 200}}, rows,
		"sorted by member; attached column wins over selected; zero and garbage dropped")
}

func TestAttachLagMembership_JunosUnitsNormalisedToPhysicalParent(t *testing.T) {
	byIface, ifaces := fixtureJunosLagMembers()
	n := AttachLagMembership(fixtureJunosLagOids(), byIface, slog.Default())

	assert.Equal(t, 2, n, "three unit rows collapse to two physical relationships")
	require.NotNil(t, ifaces["xe-0/0/24"].Lag)
	assert.Equal(t, "ae120", *ifaces["xe-0/0/24"].Lag.Name)
	assert.Equal(t, "lag", *ifaces["xe-0/0/24"].Lag.Type)
	assert.Same(t, ifaces["ae120"].Device, ifaces["xe-0/0/24"].Lag.Device)
	require.NotNil(t, ifaces["xe-0/0/28"].Lag)
	assert.Equal(t, "ae0", *ifaces["xe-0/0/28"].Lag.Name)

	for _, unit := range []string{"xe-0/0/24.0", "xe-0/0/24.1876", "xe-0/0/28.0"} {
		assert.Nil(t, ifaces[unit].Lag, "%s: a virtual unit never carries the LAG parent", unit)
	}
	assert.Nil(t, ifaces["ae0"].Lag)
	assert.Nil(t, ifaces["ae120"].Lag)
}

func TestAttachLagMembership_PhysicalMemberUsedDirectly(t *testing.T) {
	dev := &diode.Device{Name: strPtr("cat9300")}
	gi1 := lagIface("GigabitEthernet1/0/1", "1000base-t", dev)
	gi2 := lagIface("GigabitEthernet1/0/2", "1000base-t", dev)
	po1 := lagIface("Port-channel1", "lag", dev)
	byIface := map[*diode.Interface]int{gi1: 1, gi2: 2, po1: 5001}
	oids := lagIfTypes(ObjectIDValueMap{
		oidDot3adAggPortAttachedAggID + "1": {Value: "5001"},
		oidDot3adAggPortAttachedAggID + "2": {Value: "5001"},
	}, map[int]int{1: 6, 2: 6, 5001: 161})
	assert.Equal(t, 2, AttachLagMembership(oids, byIface, slog.Default()))
	assert.Equal(t, "Port-channel1", *gi1.Lag.Name)
	assert.Equal(t, "Port-channel1", *gi2.Lag.Name)
}

// Channelized lanes are members in their own right. Their names parse as
// children of the un-channelized port, which the walk also carries, so a
// placement decided on the name would point every lane's membership at an
// interface that is not in the aggregate at all.
func TestAttachLagMembership_ChannelizedLanesKeepTheirOwnMembership(t *testing.T) {
	dev := &diode.Device{Name: strPtr("cx8360")}
	port := lagIface("1/1/11", "10gbase-x-sfpp", dev)
	// Typed as the mapper types them: the device reports ethernetCsmacd,
	// and a colon-named child no longer contradicts that.
	lane1 := lagIface("1/1/11:1", "10gbase-x-sfpp", dev)
	lane2 := lagIface("1/1/11:2", "10gbase-x-sfpp", dev)
	lag1 := lagIface("lag1", "lag", dev)
	byIface := map[*diode.Interface]int{port: 110, lane1: 111, lane2: 112, lag1: 900}
	oids := lagIfTypes(ObjectIDValueMap{
		oidDot3adAggPortAttachedAggID + "111": {Value: "900"},
		oidDot3adAggPortAttachedAggID + "112": {Value: "900"},
	}, map[int]int{110: 6, 111: 6, 112: 6, 900: 161})

	assert.Equal(t, 2, AttachLagMembership(oids, byIface, slog.Default()))
	require.NotNil(t, lane1.Lag)
	assert.Equal(t, "lag1", *lane1.Lag.Name)
	require.NotNil(t, lane2.Lag)
	assert.Equal(t, "lag1", *lane2.Lag.Name)
	assert.Nil(t, port.Lag, "the un-channelized port is not a member of anything")
}

// The interface that would carry the reference has to be one NetBox
// accepts it on. With no ifType in the walk the member is used as-is and
// its type comes from the policy default, which an operator can set to a
// virtual one — and NetBox rejects the whole interface, not just the
// relationship, when a LAG parent lands on a virtual type.
func TestAttachLagMembership_RefusesTargetNetBoxWouldReject(t *testing.T) {
	dev := &diode.Device{Name: strPtr("sw")}
	ae1 := lagIface("ae1", "lag", dev)
	byIface := map[*diode.Interface]int{ae1: 9}
	for _, typ := range []string{"virtual", "bridge", "lag"} {
		member := lagIface("xe-0/0/9", typ, dev)
		byIface[member] = 1
		oids := lagIfTypes(ObjectIDValueMap{
			oidDot3adAggPortAttachedAggID + "1": {Value: "9"},
		}, map[int]int{9: 161})

		assert.Equal(t, 0, AttachLagMembership(oids, byIface, slog.Default()), "type %s", typ)
		assert.Nil(t, member.Lag, "type %s must not receive a LAG parent", typ)
		delete(byIface, member)
	}
}

func TestAttachLagMembership_RefusesWhatItCannotResolve(t *testing.T) {
	dev := &diode.Device{Name: strPtr("sw")}
	phys := lagIface("xe-0/0/1", "10gbase-x-sfpp", dev)
	orphanUnit := lagIface("xe-0/0/7.0", "virtual", dev) // parent xe-0/0/7 not walked
	loop := lagIface("lo0", "virtual", dev)
	notLag := lagIface("irb", "virtual", dev)
	ae1 := lagIface("ae1", "lag", dev)
	byIface := map[*diode.Interface]int{phys: 1, orphanUnit: 2, loop: 3, notLag: 4, ae1: 9}
	oids := lagIfTypes(ObjectIDValueMap{
		oidDot3adAggPortAttachedAggID + "1":  {Value: "4"},  // aggregate is not typed lag
		oidDot3adAggPortAttachedAggID + "2":  {Value: "9"},  // logical member, parent missing
		oidDot3adAggPortAttachedAggID + "3":  {Value: "9"},  // logical member, no parent at all
		oidDot3adAggPortAttachedAggID + "9":  {Value: "9"},  // aggregate names itself
		oidDot3adAggPortAttachedAggID + "77": {Value: "9"},  // member not walked
		oidDot3adAggPortAttachedAggID + "4":  {Value: "42"}, // aggregate not walked
	}, map[int]int{1: 6, 2: 53, 3: 24, 4: 53, 9: 161})
	assert.Equal(t, 0, AttachLagMembership(oids, byIface, slog.Default()))
	for _, i := range []*diode.Interface{phys, orphanUnit, loop, notLag, ae1} {
		assert.Nil(t, i.Lag, "%s must stay untouched", *i.Name)
	}
}

func TestAttachLagMembership_ContradictoryUnitsLeaveLagUnset(t *testing.T) {
	dev := &diode.Device{Name: strPtr("sw")}
	phys := lagIface("xe-0/0/1", "10gbase-x-sfpp", dev)
	u0 := lagIface("xe-0/0/1.0", "virtual", dev)
	u1 := lagIface("xe-0/0/1.100", "virtual", dev)
	ae1 := lagIface("ae1", "lag", dev)
	ae2 := lagIface("ae2", "lag", dev)
	byIface := map[*diode.Interface]int{phys: 1, u0: 10, u1: 11, ae1: 20, ae2: 21}
	oids := lagIfTypes(ObjectIDValueMap{
		oidDot3adAggPortAttachedAggID + "10": {Value: "20"},
		oidDot3adAggPortAttachedAggID + "11": {Value: "21"},
	}, map[int]int{1: 6, 10: 53, 11: 53, 20: 161, 21: 161})
	assert.Equal(t, 0, AttachLagMembership(oids, byIface, slog.Default()))
	assert.Nil(t, phys.Lag, "two units naming different aggregates is a contradiction, not a choice")
}

func TestAttachLagMembership_AmbiguousParentNameSkipped(t *testing.T) {
	// A stack that repeats a port name per member: the unit's parent name
	// matches two interfaces, so the membership cannot be pinned safely.
	m1 := &diode.Device{Name: strPtr("stack-1")}
	m2 := &diode.Device{Name: strPtr("stack-2")}
	a := lagIface("me0", "1000base-t", m1)
	b := lagIface("me0", "1000base-t", m2)
	unit := lagIface("me0.0", "virtual", m1)
	ae := lagIface("ae0", "lag", m1)
	byIface := map[*diode.Interface]int{a: 1, b: 2, unit: 3, ae: 9}
	oids := lagIfTypes(ObjectIDValueMap{oidDot3adAggPortAttachedAggID + "3": {Value: "9"}},
		map[int]int{1: 6, 2: 6, 3: 53, 9: 161})
	assert.Equal(t, 0, AttachLagMembership(oids, byIface, slog.Default()))
	assert.Nil(t, a.Lag)
	assert.Nil(t, b.Lag)
}

func TestAttachLagMembership_NoRowsIsNoOp(t *testing.T) {
	byIface, ifaces := fixtureJunosLagMembers()
	assert.Equal(t, 0, AttachLagMembership(ObjectIDValueMap{".1.3.6.1.2.1.1.5.0": {Value: "x"}}, byIface, slog.Default()))
	for _, i := range ifaces {
		assert.Nil(t, i.Lag)
	}
}

// The aggregator columns share the ifIndex keyspace with ifTable. They are
// post-pass rows and must never be grouped with the interface row of the
// same index: doing so would hand the group to the no-op mapper and the
// member port itself would vanish from the inventory.
//
// Without the post-pass exclusion the outcome depends on Go map iteration
// order (whichever parent OID is tried first wins the group), so the check
// is repeated: one loss in any run is a failure.
func TestLagMembershipRows_DoNotDisplaceInterfaceRows(t *testing.T) {
	for run := 0; run < 25; run++ {
		lagMembershipRowsDoNotDisplaceInterfaceRows(t)
	}
}

func lagMembershipRowsDoNotDisplaceInterfaceRows(t *testing.T) {
	t.Helper()
	logger := slog.Default()
	cfg := newTestMappingConfig(t, logger)
	mapper := NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")

	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.1.2.0":                  {Value: ".1.3.6.1.4.1.2636.1.1.1.4.82.5", Type: ObjectIdentifier, IdentifierSize: 1},
		".1.3.6.1.2.1.1.5.0":                  {Value: "qfx", IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.2.541":            {Value: "xe-0/0/2.0", IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.3.541":            {Value: "53", IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.2.540":            {Value: "xe-0/0/2", IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.3.540":            {Value: "6", IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.2.538":            {Value: "ae23", IdentifierSize: 1},
		".1.3.6.1.2.1.2.2.1.3.538":            {Value: "161", IdentifierSize: 1},
		oidDot3adAggPortSelectedAggID + "541": {Value: "538", IdentifierSize: 1},
		oidDot3adAggPortAttachedAggID + "541": {Value: "538", IdentifierSize: 1},
	}
	ents := mapper.MapObjectIDsToEntity(oids)
	byIfIndex := mapper.InterfacesByIfIndex()

	names := map[string]bool{}
	for _, e := range ents {
		if i, ok := e.(*diode.Interface); ok && i.Name != nil {
			names[*i.Name] = true
		}
	}
	assert.True(t, names["xe-0/0/2.0"], "the member unit's interface row must survive the shared index")
	assert.True(t, names["xe-0/0/2"])
	assert.True(t, names["ae23"])

	ents = TranslateAsStack(ents, oids, byIfIndex, nil, "", false, logger)
	require.Equal(t, 1, AttachLagMembership(oids, byIfIndex, logger))
	for iface, idx := range byIfIndex {
		switch idx {
		case 540:
			require.NotNil(t, iface.Lag)
			assert.Equal(t, "ae23", *iface.Lag.Name)
		default:
			assert.Nil(t, iface.Lag, "ifIndex %d", idx)
		}
	}
	_ = ents
}

func TestLagMembershipWalkGating(t *testing.T) {
	load := func(o config.Options) *Config {
		t.Helper()
		data, err := os.ReadFile("../policy/mapping.yaml")
		require.NoError(t, err)
		var mc config.Mapping
		require.NoError(t, yaml.Unmarshal(data, &mc))
		cfg, err := NewConfig(mc.Entries, slog.Default(), stubManufacturers{}, stubDeviceLookup{}, &config.Defaults{}, o)
		require.NoError(t, err)
		return cfg
	}
	const selected = ".1.2.840.10006.300.43.1.2.1.1.12"
	const attached = ".1.2.840.10006.300.43.1.2.1.1.13"

	on := load(config.Options{}).GenericObjectIDs()
	_, ok := on[selected]
	assert.True(t, ok, "selected column walked by default")
	_, ok = on[attached]
	assert.True(t, ok, "attached column walked by default")

	off := load(config.Options{EmitLagMembership: boolPtr(false)}).GenericObjectIDs()
	_, ok = off[selected]
	assert.False(t, ok, "emit_lag_membership: false removes the walk")
	_, ok = off[attached]
	assert.False(t, ok)
}
