package mapping

import (
	"bytes"
	"io"
	"log/slog"
	"strconv"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

const dellSysObjectID = "1.3.6.1.4.1.674.10895.3000"

// dellEmptyStaticFixture is the shape some Dell switches publish: dot1qPvid 1
// on every port, a static row for every VLAN with both port lists empty, and
// the membership only in the current table.
//
// Ports 1 to 5 are bridge ports 1 to 5 on ifIndex 101 to 105:
//   - 1 is an access port in VLAN 1;
//   - 2 is an access port in VLAN 10;
//   - 3 is a trunk tagged in 10 and 20, with no untagged VLAN;
//   - 4 is a trunk untagged in 30 and tagged in 20;
//   - 5 is in no VLAN, as a LAG member is.
func dellEmptyStaticFixture() ObjectIDValueMap {
	empty := string(make([]byte, 16))
	all := ObjectIDValueMap{oidSysObjectIDScalar: {Value: dellSysObjectID}}
	for bp := 1; bp <= 5; bp++ {
		port, ifx := strconv.Itoa(bp), strconv.Itoa(100+bp)
		all[oidDot1dBasePortIfIndex+port] = Value{Value: ifx}
		all[oidDot1qPvid+port] = Value{Value: "1"}
		all[oidIfAdminStatus+ifx] = Value{Value: "1"}
		all[oidIfType+ifx] = Value{Value: "6"}
	}
	for _, vid := range []string{"1", "10", "20", "30"} {
		all[oidDot1qVlanStaticName+vid] = Value{Value: "vlan" + vid}
		all[oidDot1qVlanStaticEgressPorts+vid] = Value{Value: empty}
		all[oidDot1qVlanStaticUntaggedPorts+vid] = Value{Value: empty}
	}
	for vid, masks := range map[string][2]string{
		"1":  {portMask(1), portMask(1)},
		"10": {portMask(2, 3), portMask(2)},
		"20": {portMask(3, 4), empty},
		"30": {portMask(4), portMask(4)},
	} {
		all[oidDot1qVlanCurrentEgressPorts+"0."+vid] = Value{Value: masks[0]}
		all[oidDot1qVlanCurrentUntaggedPorts+"0."+vid] = Value{Value: masks[1]}
	}
	return all
}

func dellTestInterfaces(registry *EntityRegistry) map[int]*diode.Interface {
	return interfacesFor(registry, map[int]string{101: "gi1", 102: "gi2", 103: "gi3", 104: "gi4", 105: "gi5"})
}

func untaggedVid(iface *diode.Interface) *int64 {
	if iface.UntaggedVlan == nil {
		return nil
	}
	return iface.UntaggedVlan.Vid
}

// Read as operational, the current table leaves the PVID of 1 standing on
// every port the static table does not withdraw it from, and there is no such
// port: trunks gain VLAN 1 untagged and ports in no VLAN become access ports
// in it. Read as configuration, it describes every port as the device does.
func TestVlanMapper_PostMap_DellCurrentTableStandsInForEmptyStaticLists(t *testing.T) {
	registry := NewEntityRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ifaces := dellTestInterfaces(registry)

	NewVlanMapper(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Options{}).
		PostMap(dellEmptyStaticFixture(), registry, &config.Defaults{})

	for _, tc := range []struct {
		ifIndex  int
		mode     *string
		untagged *int64
		tagged   []int
	}{
		{101, StringPtr("access"), int64Ptr(1), nil},
		{102, StringPtr("access"), int64Ptr(10), nil},
		{103, StringPtr("tagged"), nil, []int{10, 20}},
		{104, StringPtr("tagged"), int64Ptr(30), []int{20}},
		{105, nil, nil, nil},
	} {
		iface := ifaces[tc.ifIndex]
		name := *iface.Name
		assert.Equal(t, tc.mode, iface.Mode, "%s mode", name)
		assert.Equal(t, tc.untagged, untaggedVid(iface), "%s untagged VLAN", name)
		assert.ElementsMatch(t, tc.tagged, taggedVids(iface), "%s tagged VLANs", name)
	}
}

// The masks that stand in carry no current-table provenance, since that is
// what lets the static rules withdraw the PVID. A VLAN with no static row is
// one the device learned rather than configured, and keeps it; a static row
// the current table puts no port in stays as it was.
func TestVlanMapper_BuildGenericRows_DellStandInIsConfiguration(t *testing.T) {
	all := dellEmptyStaticFixture()
	all[oidDot1qVlanCurrentEgressPorts+"0.4000"] = Value{Value: portMask(4)}
	all[oidDot1qVlanCurrentUntaggedPorts+"0.4000"] = Value{Value: string(make([]byte, 16))}
	all[oidDot1qVlanStaticEgressPorts+"40"] = Value{Value: string(make([]byte, 16))}
	all[oidDot1qVlanStaticUntaggedPorts+"40"] = Value{Value: string(make([]byte, 16))}

	rows := NewVlanMapper(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Options{}).buildGenericRows(all)

	assert.Equal(t, portMask(2, 3), string(rows.VlanEgressPorts[10]))
	assert.Equal(t, portMask(2), string(rows.VlanUntaggedPorts[10]))
	for _, vid := range []int{1, 10, 20, 30, 40} {
		assert.NotContains(t, rows.VlanEgressFromCurrent, vid, "VLAN %d egress", vid)
		assert.NotContains(t, rows.VlanUntaggedFromCurrent, vid, "VLAN %d untagged", vid)
	}
	assert.Contains(t, rows.VlanEgressFromCurrent, 4000)
	assert.Contains(t, rows.VlanUntaggedFromCurrent, 4000)
	assert.Equal(t, string(make([]byte, 16)), string(rows.VlanEgressPorts[40]))
	assert.Contains(t, rows.VlanUntaggedPorts, 40)
}

// A current table answering one column cannot stand in. Without an untagged
// row the PVID of 1 would stand in for it and come back on every port, and
// without an egress row a trunk would read as access in its native VLAN. The
// device is left as it was rather than described wrongly.
func TestVlanMapper_PostMap_DellStandInNeedsBothCurrentColumns(t *testing.T) {
	for _, missing := range []string{oidDot1qVlanCurrentEgressPorts, oidDot1qVlanCurrentUntaggedPorts} {
		all := dellEmptyStaticFixture()
		for _, vid := range []string{"1", "10", "20", "30"} {
			delete(all, missing+"0."+vid)
		}
		registry := NewEntityRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
		ifaces := dellTestInterfaces(registry)

		NewVlanMapper(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Options{}).
			PostMap(all, registry, &config.Defaults{})

		for _, iface := range ifaces {
			assert.Nil(t, iface.Mode, "%s without %s: mode", *iface.Name, missing)
			assert.Nil(t, untaggedVid(iface), "%s without %s: untagged VLAN", *iface.Name, missing)
			assert.Empty(t, taggedVids(iface), "%s without %s: tagged VLANs", *iface.Name, missing)
		}

		rows := NewVlanMapper(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Options{}).buildGenericRows(all)
		assert.Equal(t, string(make([]byte, 16)), string(rows.VlanEgressPorts[1]), "without %s: VLAN 1 egress", missing)
		assert.Equal(t, string(make([]byte, 16)), string(rows.VlanUntaggedPorts[1]), "without %s: VLAN 1 untagged", missing)
	}
}

// Either static list is a static row: a VLAN publishing only one of them is
// configured as much as one publishing both.
func TestVlanMapper_BuildGenericRows_DellStandInForEitherStaticList(t *testing.T) {
	for _, staticPrefix := range []string{oidDot1qVlanStaticEgressPorts, oidDot1qVlanStaticUntaggedPorts} {
		all := dellEmptyStaticFixture()
		all[staticPrefix+"50"] = Value{Value: string(make([]byte, 16))}
		all[oidDot1qVlanCurrentEgressPorts+"0.50"] = Value{Value: portMask(5)}
		all[oidDot1qVlanCurrentUntaggedPorts+"0.50"] = Value{Value: portMask(5)}

		rows := NewVlanMapper(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Options{}).buildGenericRows(all)

		assert.Equal(t, portMask(5), string(rows.VlanEgressPorts[50]), staticPrefix)
		assert.Equal(t, portMask(5), string(rows.VlanUntaggedPorts[50]), staticPrefix)
		assert.NotContains(t, rows.VlanEgressFromCurrent, 50, staticPrefix)
		assert.NotContains(t, rows.VlanUntaggedFromCurrent, 50, staticPrefix)
	}
}

// Only on a Dell device, and only where every static list is empty: a device
// whose static table names a port is describing its configuration there, and
// the static table keeps winning everywhere on it.
func TestVlanMapper_BuildGenericRows_DellStandInIsGated(t *testing.T) {
	empty := string(make([]byte, 16))
	for _, tc := range []struct {
		what   string
		modify func(ObjectIDValueMap)
	}{
		{"another vendor", func(all ObjectIDValueMap) {
			all[oidSysObjectIDScalar] = Value{Value: "1.3.6.1.4.1.8072.3.2.10"}
		}},
		{"no sysObjectID", func(all ObjectIDValueMap) {
			delete(all, oidSysObjectIDScalar)
		}},
		{"a static egress list names a port", func(all ObjectIDValueMap) {
			all[oidDot1qVlanStaticEgressPorts+"30"] = Value{Value: portMask(4)}
		}},
		{"a static untagged list names a port", func(all ObjectIDValueMap) {
			all[oidDot1qVlanStaticUntaggedPorts+"30"] = Value{Value: portMask(4)}
		}},
	} {
		all := dellEmptyStaticFixture()
		tc.modify(all)

		rows := NewVlanMapper(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Options{}).buildGenericRows(all)

		assert.Equal(t, empty, string(rows.VlanEgressPorts[10]), "%s: VLAN 10 egress", tc.what)
		assert.Equal(t, empty, string(rows.VlanUntaggedPorts[10]), "%s: VLAN 10 untagged", tc.what)
	}
}

// Logged once per crawl at debug, so a device the rule applies to can be told
// from one it does not.
func TestVlanMapper_PostMap_DellStandInIsLogged(t *testing.T) {
	const msg = "the current table stands in"
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	registry := NewEntityRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	dellTestInterfaces(registry)
	NewVlanMapper(logger, config.Options{}).PostMap(dellEmptyStaticFixture(), registry, &config.Defaults{})
	assert.Equal(t, 1, bytes.Count(buf.Bytes(), []byte(msg)), buf.String())
	assert.Contains(t, buf.String(), "vlans=4")

	buf.Reset()
	all := dellEmptyStaticFixture()
	delete(all, oidSysObjectIDScalar)
	registry = NewEntityRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	dellTestInterfaces(registry)
	NewVlanMapper(logger, config.Options{}).PostMap(all, registry, &config.Defaults{})
	assert.NotContains(t, buf.String(), msg)
}
