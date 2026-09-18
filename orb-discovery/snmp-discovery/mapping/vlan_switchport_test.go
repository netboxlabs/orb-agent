package mapping

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping/qbridge"
)

// bridgeVlan is one row of the static VLAN table in a test fixture.
type bridgeVlan struct {
	vid      int
	name     string
	egress   []int // bridge ports
	untagged []int // bridge ports
}

// bridgeFixture builds a Q-BRIDGE walk: a bridge-port to ifIndex map, the
// static VLAN table, per-port PVIDs, and the IF-MIB columns the classifier
// reads. Ports are named by bridge port number throughout, as the MIB does.
func bridgeFixture(basePorts map[int]int, vlans []bridgeVlan, pvids map[int]int, ifTypes map[int]int) ObjectIDValueMap {
	out := ObjectIDValueMap{}
	for port, ifIndex := range basePorts {
		out[oidDot1dBasePortIfIndex+strconv.Itoa(port)] = Value{Value: strconv.Itoa(ifIndex), Type: Integer}
	}
	for port, vid := range pvids {
		out[oidDot1qPvid+strconv.Itoa(port)] = Value{Value: strconv.Itoa(vid), Type: Integer}
	}
	for _, v := range vlans {
		vid := strconv.Itoa(v.vid)
		out[oidDot1qVlanStaticName+vid] = Value{Value: v.name, Type: OctetString}
		out[".1.3.6.1.2.1.17.7.1.4.3.1.5."+vid] = Value{Value: "1", Type: Integer}
		out[oidDot1qVlanStaticEgressPorts+vid] = Value{Value: portMask(v.egress...), Type: OctetString}
		out[oidDot1qVlanStaticUntaggedPorts+vid] = Value{Value: portMask(v.untagged...), Type: OctetString}
	}
	for ifIndex, ifType := range ifTypes {
		idx := strconv.Itoa(ifIndex)
		out[".1.3.6.1.2.1.2.2.1.3."+idx] = Value{Value: strconv.Itoa(ifType), Type: Integer}
		out[".1.3.6.1.2.1.2.2.1.7."+idx] = Value{Value: "1", Type: Integer}
	}
	return out
}

// junosRegistry registers interfaces by ifIndex under the names the device
// reports, physical ports and their logical units alike. Types follow what
// those devices publish through ifType, since placement is decided on the
// type and not on the name: a unit is propVirtual/l3ipvlan (virtual), an
// aggregate is ieee8023adLag (lag), and everything else is a port.
// typeOverrides names the interfaces that need something else.
func junosRegistry(
	t *testing.T,
	byIfIndex map[int]string,
	typeOverrides ...map[string]string,
) (*EntityRegistry, map[string]*diode.Interface) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	byName := map[string]*diode.Interface{}
	for ifIndex, name := range byIfIndex {
		ifType := "10gbase-x-sfpp"
		switch {
		// Tier 0 of ResolveInterfaceType, which is what the mapper puts on
		// these interfaces: ANY name that parses as a child is typed
		// virtual before ifType is looked at, colon-separated channelized
		// lanes and ONU ports included. Typing those physically here would
		// assert something no device does.
		case ExtractParentInterfaceName(name) != "":
			ifType = "virtual"
		case strings.HasPrefix(name, "ae"):
			ifType = "lag"
		}
		for _, o := range typeOverrides {
			if t2, ok := o[name]; ok {
				ifType = t2
			}
		}
		iface := &diode.Interface{Name: StringPtr(name), Type: StringPtr(ifType)}
		registry.entities[InterfaceEntityType][ObjectIDIndex(strconv.Itoa(ifIndex))] = iface
		registry.MarkInterfaceVerified(iface)
		byName[name] = iface
	}
	return registry, byName
}

func vidsOf(vlans []*diode.VLAN) []int {
	out := make([]int, 0, len(vlans))
	for _, v := range vlans {
		out = append(out, int(*v.Vid))
	}
	return out
}

// Pre-ELS Junos keys dot1dBasePortIfIndex by the logical unit, so the
// switchport configuration arrived on xe-0/0/17.0 while the port itself was
// left bare. NETCONF discovery of the same device puts it on the port.
func TestVlanMapper_PostMap_JunosUnit_ConfigLandsOnPhysicalPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		517: "xe-0/0/17",
		617: "xe-0/0/17.0",
	})
	oids := bridgeFixture(
		map[int]int{1: 617},
		[]bridgeVlan{
			{vid: 156, name: "VL156", egress: []int{1}},
			{vid: 178, name: "VL178", egress: []int{1}},
		},
		nil,
		map[int]int{517: 6, 617: 135},
	)

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(oids, registry, &config.Defaults{})

	port := ifaces["xe-0/0/17"]
	require.NotNil(t, port.Mode, "the physical switchport carries the configuration")
	assert.Equal(t, "tagged", *port.Mode)
	assert.Equal(t, []int{156, 178}, vidsOf(port.TaggedVlans))

	unit := ifaces["xe-0/0/17.0"]
	assert.Nil(t, unit.Mode, "the logical unit keeps no switchport configuration")
	assert.Empty(t, unit.TaggedVlans)
	assert.Nil(t, unit.UntaggedVlan)
}

// An aggregate is a switchport in NetBox, so ae8.0 resolves onto ae8 rather
// than being left on the unit: only the unit is unwanted, not the LAG.
func TestVlanMapper_PostMap_JunosUnit_ConfigLandsOnAggregate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		508: "ae8",
		608: "ae8.0",
	})
	oids := bridgeFixture(
		map[int]int{1: 608},
		[]bridgeVlan{{vid: 77, name: "VL77", egress: []int{1}}},
		nil,
		map[int]int{508: 161, 608: 135},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	require.NotNil(t, ifaces["ae8"].Mode)
	assert.Equal(t, "tagged", *ifaces["ae8"].Mode)
	assert.Equal(t, []int{77}, vidsOf(ifaces["ae8"].TaggedVlans))
	assert.Nil(t, ifaces["ae8.0"].Mode)
}

// The control: a device whose bridge ports are the ports themselves must be
// bit-for-bit unaffected by unit resolution.
func TestVlanMapper_PostMap_PhysicalBridgePort_Unchanged(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		519: "xe-0/0/19",
		520: "xe-0/0/20",
	})
	oids := bridgeFixture(
		map[int]int{1: 519, 2: 520},
		[]bridgeVlan{
			{vid: 30, name: "VL30", egress: []int{1, 2}, untagged: []int{2}},
		},
		map[int]int{2: 30},
		map[int]int{519: 6, 520: 6},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	require.NotNil(t, ifaces["xe-0/0/19"].Mode)
	assert.Equal(t, "tagged", *ifaces["xe-0/0/19"].Mode)
	assert.Equal(t, []int{30}, vidsOf(ifaces["xe-0/0/19"].TaggedVlans))

	access := ifaces["xe-0/0/20"]
	require.NotNil(t, access.Mode)
	assert.Equal(t, "access", *access.Mode)
	require.NotNil(t, access.UntaggedVlan)
	assert.Equal(t, int64(30), *access.UntaggedVlan.Vid)
}

// Flexible VLAN tagging puts several bridging units on one port. The port's
// switchport state is their combination, and it must not depend on which
// unit the walk yielded first.
func TestVlanMapper_PostMap_UnitsOfOnePortCombine(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for run := 0; run < 20; run++ {
		registry, ifaces := junosRegistry(t, map[int]string{
			524: "xe-0/0/24",
			628: "xe-0/0/24.0",
			646: "xe-0/0/24.1876",
		})
		oids := bridgeFixture(
			map[int]int{1: 628, 2: 646},
			[]bridgeVlan{
				{vid: 10, name: "VL10", egress: []int{1}, untagged: []int{1}},
				{vid: 1876, name: "VL1876", egress: []int{2}},
			},
			map[int]int{1: 10},
			map[int]int{524: 6, 628: 135, 646: 135},
		)

		NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

		port := ifaces["xe-0/0/24"]
		require.NotNil(t, port.Mode, "run %d", run)
		assert.Equal(t, "tagged", *port.Mode, "a port with any tagged unit is a trunk")
		assert.Equal(t, []int{1876}, vidsOf(port.TaggedVlans), "run %d", run)
		require.NotNil(t, port.UntaggedVlan, "run %d", run)
		assert.Equal(t, int64(10), *port.UntaggedVlan.Vid, "the access unit supplies the native VLAN")
		assert.Nil(t, ifaces["xe-0/0/24.0"].Mode)
		assert.Nil(t, ifaces["xe-0/0/24.1876"].Mode)
	}
}

// Two units claiming different untagged VLANs contradict each other: a port
// has one native VLAN. Keep what they agree on, drop what they don't.
func TestVlanMapper_PostMap_UnitsWithDifferentUntagged(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		531: "xe-0/0/31",
		631: "xe-0/0/31.0",
		632: "xe-0/0/31.100",
	})
	oids := bridgeFixture(
		map[int]int{1: 631, 2: 632},
		[]bridgeVlan{
			{vid: 10, name: "VL10", egress: []int{1}, untagged: []int{1}},
			{vid: 20, name: "VL20", egress: []int{2}, untagged: []int{2}},
		},
		map[int]int{1: 10, 2: 20},
		map[int]int{531: 6, 631: 135, 632: 135},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	port := ifaces["xe-0/0/31"]
	assert.Nil(t, port.Mode, "nothing the units agree on, so nothing is claimed")
	assert.Nil(t, port.UntaggedVlan, "neither unit's native VLAN is guessed at")
	assert.Empty(t, port.TaggedVlans)
	for _, unit := range []string{"xe-0/0/31.0", "xe-0/0/31.100"} {
		assert.Nil(t, ifaces[unit].Mode, "%s: the units resolved to the port, so neither keeps switchport state", unit)
		assert.Nil(t, ifaces[unit].UntaggedVlan, unit)
	}
}

// A unit whose port never reached the walk keeps its own configuration:
// the device reported that membership, and dropping it to tidy the model
// would lose discovered data.
func TestVlanMapper_PostMap_UnitWithoutWalkedPort_KeepsItsOwnConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{641: "xe-0/0/41.0"})
	oids := bridgeFixture(
		map[int]int{1: 641},
		[]bridgeVlan{{vid: 44, name: "VL44", egress: []int{1}}},
		nil,
		map[int]int{641: 135},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	unit := ifaces["xe-0/0/41.0"]
	require.NotNil(t, unit.Mode)
	assert.Equal(t, "tagged", *unit.Mode)
	assert.Equal(t, []int{44}, vidsOf(unit.TaggedVlans))
}

// Two stack members can publish the same port name, so the parent name
// alone does not identify one interface. Binding to either would be a
// guess; the unit keeps the configuration instead.
func TestVlanMapper_PostMap_AmbiguousPortName_KeepsUnit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	names := map[int]string{1: "me0", 2: "me0", 3: "me0.0"}
	ifaces := map[int]*diode.Interface{}
	for ifIndex, name := range names {
		iface := &diode.Interface{Name: StringPtr(name)}
		registry.entities[InterfaceEntityType][ObjectIDIndex(strconv.Itoa(ifIndex))] = iface
		registry.MarkInterfaceVerified(iface)
		ifaces[ifIndex] = iface
	}
	oids := bridgeFixture(
		map[int]int{1: 3},
		[]bridgeVlan{{vid: 99, name: "VL99", egress: []int{1}}},
		nil,
		map[int]int{1: 6, 2: 6, 3: 135},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	require.NotNil(t, ifaces[3].Mode, "the unit keeps what the device reported")
	assert.Equal(t, "tagged", *ifaces[3].Mode)
	assert.Nil(t, ifaces[1].Mode, "neither candidate port is picked")
	assert.Nil(t, ifaces[2].Mode)
}

// An excluded port is not in the payload, so a unit must not bind its
// configuration to it.
func TestVlanMapper_PostMap_ExcludedPort_KeepsUnit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		550: "xe-0/0/50",
		650: "xe-0/0/50.0",
	})
	registry.ExcludeInterface("xe-0/0/50")
	oids := bridgeFixture(
		map[int]int{1: 650},
		[]bridgeVlan{{vid: 55, name: "VL55", egress: []int{1}}},
		nil,
		map[int]int{550: 6, 650: 135},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	assert.Nil(t, ifaces["xe-0/0/50"].Mode, "an excluded interface never receives configuration")
	require.NotNil(t, ifaces["xe-0/0/50.0"].Mode)
}

// A channelized lane is a switchport in its own right: the Aruba CX shape,
// where 1/1/11:3 parses as a child of 1/1/11 and the parent IS in the walk.
// The device types the lane as ethernetCsmacd, which is what keeps the
// configuration where it belongs.
func TestVlanMapper_PostMap_ChannelizedLane_KeepsItsOwnConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		700: "1/1/11",
		701: "1/1/11:3",
	})
	oids := bridgeFixture(
		map[int]int{1: 701},
		[]bridgeVlan{{vid: 300, name: "VL300", egress: []int{1}}},
		nil,
		map[int]int{700: 6, 701: 6},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	lane := ifaces["1/1/11:3"]
	require.NotNil(t, lane.Mode, "the lane is the switchport")
	assert.Equal(t, "tagged", *lane.Mode)
	assert.Equal(t, []int{300}, vidsOf(lane.TaggedVlans))
	assert.Nil(t, ifaces["1/1/11"].Mode, "the un-channelized name is not the switchport here")
}

// The same shape with a different vendor and separator: BDCOM GPON ONU
// ports (GPON0/2:1) parse as children of the PON port and are typed
// other(1), so dozens of them must not collapse onto one interface.
func TestVlanMapper_PostMap_OnuPort_KeepsItsOwnConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		800: "GPON0/2",
		801: "GPON0/2:1",
		802: "GPON0/2:2",
	}, map[string]string{"GPON0/2": "other"})
	oids := bridgeFixture(
		map[int]int{1: 801, 2: 802},
		[]bridgeVlan{
			{vid: 401, name: "VL401", egress: []int{1}},
			{vid: 402, name: "VL402", egress: []int{2}},
		},
		nil,
		map[int]int{800: 1, 801: 1, 802: 1},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	assert.Equal(t, []int{401}, vidsOf(ifaces["GPON0/2:1"].TaggedVlans))
	assert.Equal(t, []int{402}, vidsOf(ifaces["GPON0/2:2"].TaggedVlans))
	assert.Nil(t, ifaces["GPON0/2"].Mode, "ONU ports never collapse onto their PON port")
}

// An interface the walk carries no ifType for is left where it is. The
// name says "child", but nothing the device reported says "logical", and
// moving a port's VLANs on that basis is how lanes and ONU ports get
// collapsed onto their parent. Driven at the placement layer: a bridge
// port whose ifIndex has no ifTable row is not classified in the first
// place, so the policy has nowhere else to show.
func TestVlanMapper_ApplyClassifications_ChildWithoutIfType_KeepsItsOwnConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		900: "xe-0/0/90",
		901: "xe-0/0/90.0",
	})
	NewVlanMapper(logger, config.Options{}).applyClassifications(registry, map[int]qbridge.Classification{
		901: {Mode: qbridge.ModeTrunk, Tagged: []int{500}},
	}, map[int]string{900: "6"}, func(vid int) *diode.VLAN {
		v := int64(vid)
		return &diode.VLAN{Vid: &v}
	})

	require.NotNil(t, ifaces["xe-0/0/90.0"].Mode, "an untyped child keeps what the device reported")
	assert.Equal(t, []int{500}, vidsOf(ifaces["xe-0/0/90.0"].TaggedVlans))
	assert.Nil(t, ifaces["xe-0/0/90"].Mode)
}

// A unit of a channelized lane is still a unit, and resolves onto the lane.
func TestVlanMapper_PostMap_UnitOfChannelizedLane_LandsOnTheLane(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		701: "et-0/0/0:0",
		702: "et-0/0/0:0.0",
	})
	oids := bridgeFixture(
		map[int]int{1: 702},
		[]bridgeVlan{{vid: 301, name: "VL301", egress: []int{1}}},
		nil,
		map[int]int{701: 6, 702: 135},
	)

	NewVlanMapper(logger, config.Options{}).PostMap(oids, registry, &config.Defaults{})

	require.NotNil(t, ifaces["et-0/0/0:0"].Mode)
	assert.Equal(t, []int{301}, vidsOf(ifaces["et-0/0/0:0"].TaggedVlans))
	assert.Nil(t, ifaces["et-0/0/0:0.0"].Mode)
}

// tagged-all states its wildcard in the mode, with no tagged VLANs to
// carry it. A native-VLAN disagreement between units must not take the
// mode down with it. Driven at the placement layer: building a genuine
// 1..4094 membership through the fixture would say nothing more about
// the branch under test.
func TestVlanMapper_ApplyClassifications_UntaggedConflictKeepsTaggedAll(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		560: "xe-0/0/60",
		660: "xe-0/0/60.0",
		661: "xe-0/0/60.100",
	})
	native10, native20 := 10, 20
	vm := NewVlanMapper(logger, config.Options{})
	vm.applyClassifications(registry, map[int]qbridge.Classification{
		660: {Mode: qbridge.ModeTrunkAll, Tagged: []int{}, Untagged: &native10},
		661: {Mode: qbridge.ModeAccess, Tagged: []int{}, Untagged: &native20},
	}, map[int]string{660: "53", 661: "53"}, func(vid int) *diode.VLAN {
		v := int64(vid)
		return &diode.VLAN{Vid: &v}
	})

	port := ifaces["xe-0/0/60"]
	require.NotNil(t, port.Mode, "a trunk carrying everything is still a trunk")
	assert.Equal(t, "tagged-all", *port.Mode)
	assert.Nil(t, port.UntaggedVlan, "the contested native VLAN is still dropped")
	assert.Nil(t, ifaces["xe-0/0/60.0"].Mode)
	assert.Nil(t, ifaces["xe-0/0/60.100"].Mode)
}

// A wildcard trunk subsumes any list another unit reported. Emitting
// tagged-all beside an explicit subset contradicts the classifier, which
// states the wildcard in the mode and leaves the tagged set empty.
func TestVlanMapper_ApplyClassifications_TrunkAllDropsExplicitTagged(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		580: "xe-0/0/80",
		680: "xe-0/0/80.0",
		681: "xe-0/0/80.100",
	})
	native := 10
	NewVlanMapper(logger, config.Options{}).applyClassifications(registry, map[int]qbridge.Classification{
		680: {Mode: qbridge.ModeTrunkAll, Tagged: []int{}, Untagged: &native},
		681: {Mode: qbridge.ModeTrunk, Tagged: []int{20, 30}},
	}, map[int]string{680: "53", 681: "53"}, func(vid int) *diode.VLAN {
		v := int64(vid)
		return &diode.VLAN{Vid: &v}
	})

	port := ifaces["xe-0/0/80"]
	require.NotNil(t, port.Mode)
	assert.Equal(t, "tagged-all", *port.Mode)
	assert.Empty(t, port.TaggedVlans, "the wildcard already covers every VLAN a unit listed")
	require.NotNil(t, port.UntaggedVlan, "a trunk carrying everything still has a native VLAN")
	assert.Equal(t, int64(10), *port.UntaggedVlan.Vid)
}

// The same contradiction with nothing else to say leaves the port alone:
// access with no VLAN would be worse than no classification.
func TestVlanMapper_ApplyClassifications_UntaggedConflictAloneLeavesPortUnset(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		561: "xe-0/0/61",
		662: "xe-0/0/61.0",
		663: "xe-0/0/61.100",
	})
	a, b := 10, 20
	NewVlanMapper(logger, config.Options{}).applyClassifications(registry, map[int]qbridge.Classification{
		662: {Mode: qbridge.ModeAccess, Tagged: []int{}, Untagged: &a},
		663: {Mode: qbridge.ModeAccess, Tagged: []int{}, Untagged: &b},
	}, map[int]string{662: "53", 663: "53"}, func(vid int) *diode.VLAN {
		v := int64(vid)
		return &diode.VLAN{Vid: &v}
	})

	assert.Nil(t, ifaces["xe-0/0/61"].Mode)
	assert.Nil(t, ifaces["xe-0/0/61"].UntaggedVlan)
}

// Classify never leaves the native VLAN in the tagged set. Merging units
// must not reintroduce it: one unit reporting VLAN 10 untagged and another
// reporting it tagged describes one port whose native VLAN is 10, not a
// port that carries 10 both ways.
func TestVlanMapper_ApplyClassifications_NativeVlanNotAlsoTagged(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry, ifaces := junosRegistry(t, map[int]string{
		570: "xe-0/0/70",
		670: "xe-0/0/70.0",
		671: "xe-0/0/70.100",
	})
	native := 10
	NewVlanMapper(logger, config.Options{}).applyClassifications(registry, map[int]qbridge.Classification{
		670: {Mode: qbridge.ModeAccess, Tagged: []int{}, Untagged: &native},
		671: {Mode: qbridge.ModeTrunk, Tagged: []int{10, 20}, Untagged: nil},
	}, map[int]string{670: "53", 671: "53"}, func(vid int) *diode.VLAN {
		v := int64(vid)
		return &diode.VLAN{Vid: &v}
	})

	port := ifaces["xe-0/0/70"]
	require.NotNil(t, port.Mode)
	assert.Equal(t, "tagged", *port.Mode)
	require.NotNil(t, port.UntaggedVlan)
	assert.Equal(t, int64(10), *port.UntaggedVlan.Vid)
	assert.Equal(t, []int{20}, vidsOf(port.TaggedVlans), "the native VLAN is not also a tagged VLAN")
}
