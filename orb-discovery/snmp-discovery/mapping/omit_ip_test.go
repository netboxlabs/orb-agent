package mapping_test

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

// routedPort returns a device whose routed port carries its primary address.
// The mapper classified the port as an access port in VLAN 1, as it does on
// some platforms; the default run never sends those fields, since the port
// only travels nested in its address.
func routedPort() (*diode.Device, *diode.IPAddress, []diode.Entity) {
	device := &diode.Device{Name: diode.String("sw1"), Site: &diode.Site{Name: diode.String("lab")}}
	lag := &diode.Interface{Name: diode.String("Port-channel1"), Type: diode.String("lag"), Device: device}
	port := &diode.Interface{
		Name:              diode.String("Gi1/0/1"),
		Device:            device,
		Type:              diode.String("1000base-t"),
		Description:       diode.String("uplink"),
		Speed:             diode.Int64(1000000),
		Mtu:               diode.Int64(1500),
		Enabled:           diode.Bool(true),
		PrimaryMacAddress: &diode.MACAddress{MacAddress: diode.String("00:00:5E:00:53:01")},
		Mode:              diode.String("access"),
		UntaggedVlan:      &diode.VLAN{Vid: diode.Int64(1), Name: diode.String("default")},
		TaggedVlans:       []*diode.VLAN{{Vid: diode.Int64(10), Name: diode.String("users")}},
		Lag:               lag,
		Tags:              []*diode.Tag{{Name: diode.String("discovered")}},
		Metadata:          diode.Metadata{"run_id": "run-1"},
	}
	addr := &diode.IPAddress{Address: diode.String("192.0.2.1/31"), AssignedObject: port}
	device.PrimaryIp4 = addr
	return device, addr, []diode.Entity{device, lag, addr}
}

func interfaceNamed(t *testing.T, entities []diode.Entity, name string) *diode.Interface {
	t.Helper()
	for _, e := range entities {
		if iface, ok := e.(*diode.Interface); ok && iface.GetName() == name {
			return iface
		}
	}
	require.Failf(t, "interface not sent", "%s", name)
	return nil
}

// The interface goes out exactly as the default nests it in its address, so
// turning the option off writes nothing new to the interface.
func TestOmitIPAddresses_SendsTheInterfaceAsTheDefaultNestsIt(t *testing.T) {
	device, addr, entities := routedPort()
	device.PrimaryIp4 = nil
	mapping.PruneNestedRefs(entities, device, nil)
	want := addr.AssignedObject.(*diode.Interface)
	want.Metadata = diode.Metadata{"run_id": "run-1"}

	device, _, entities = routedPort()
	got := interfaceNamed(t, mapping.OmitIPAddresses(entities, device), "Gi1/0/1")

	assert.Equal(t, want, got)
	assert.Nil(t, got.Mode)
	assert.Nil(t, got.UntaggedVlan)
	assert.Empty(t, got.TaggedVlans)
	assert.Nil(t, got.Lag)
	assert.Empty(t, got.Tags)
}

// The primary IP goes from the device and from the stub the interface names.
func TestOmitIPAddresses_ClearsThePrimaryIP(t *testing.T) {
	device, _, entities := routedPort()
	device.PrimaryIp6 = &diode.IPAddress{Address: diode.String("2001:db8::1/64")}

	got := mapping.OmitIPAddresses(entities, device)

	assert.Nil(t, device.PrimaryIp4)
	assert.Nil(t, device.PrimaryIp6)
	port := interfaceNamed(t, got, "Gi1/0/1")
	require.NotNil(t, port.Device)
	assert.Nil(t, port.Device.PrimaryIp4)
	assert.Nil(t, port.Device.PrimaryIp6)
}

func TestOmitIPAddresses(t *testing.T) {
	device := &diode.Device{Name: diode.String("sw1")}
	gi1 := &diode.Interface{Name: diode.String("Gi1"), Device: device}
	vlan10 := &diode.Interface{Name: diode.String("Vlan10"), Device: device}
	a1 := &diode.IPAddress{Address: diode.String("192.0.2.1/24"), AssignedObject: vlan10}
	a2 := &diode.IPAddress{Address: diode.String("2001:db8::1/64"), AssignedObject: vlan10}
	a3 := &diode.IPAddress{Address: diode.String("198.51.100.1/24"), AssignedObject: gi1}
	unassigned := &diode.IPAddress{Address: diode.String("203.0.113.1/24")}
	prefix := &diode.Prefix{Prefix: diode.String("192.0.2.0/24")}

	got := mapping.OmitIPAddresses([]diode.Entity{device, gi1, a1, a2, a3, unassigned, prefix}, device)

	// Each address gives way to its interface, once, in its place; an interface
	// already sent is not repeated, and an unassigned address leaves nothing.
	require.Len(t, got, 4)
	assert.Same(t, device, got[0])
	assert.Same(t, gi1, got[1])
	assert.Equal(t, "Vlan10", got[2].(*diode.Interface).GetName())
	assert.Same(t, prefix, got[3])
}

// Two interfaces sharing a name on one device stay two entities.
func TestOmitIPAddresses_SameNameOnTwoIfIndexes(t *testing.T) {
	device := &diode.Device{Name: diode.String("sw1")}
	first := &diode.Interface{Name: diode.String("mgmt"), Device: device, Type: diode.String("1000base-t")}
	second := &diode.Interface{Name: diode.String("mgmt"), Device: device, Type: diode.String("virtual")}
	a1 := &diode.IPAddress{Address: diode.String("192.0.2.1/24"), AssignedObject: first}
	a2 := &diode.IPAddress{Address: diode.String("198.51.100.1/24"), AssignedObject: second}

	got := mapping.OmitIPAddresses([]diode.Entity{device, a1, a2}, device)

	require.Len(t, got, 3)
	assert.Equal(t, "1000base-t", got[1].(*diode.Interface).GetType())
	assert.Equal(t, "virtual", got[2].(*diode.Interface).GetType())
}

// A device the run only reaches through an interface loses its primary IP too.
func TestOmitIPAddresses_DeviceReachedThroughAnInterface(t *testing.T) {
	member := &diode.Device{Name: diode.String("sw1-2")}
	gi2 := &diode.Interface{Name: diode.String("Gi2/0/1"), Device: member}
	addr := &diode.IPAddress{Address: diode.String("192.0.2.2/24"), AssignedObject: gi2}
	member.PrimaryIp4 = addr

	got := mapping.OmitIPAddresses([]diode.Entity{addr}, nil)

	require.Len(t, got, 1)
	assert.Equal(t, "Gi2/0/1", got[0].(*diode.Interface).GetName())
	assert.Nil(t, member.PrimaryIp4)
}

// A device sent on its own loses its primary IP even with no interface in the
// run to reach it through.
func TestOmitIPAddresses_DeviceEntityOnItsOwn(t *testing.T) {
	device := &diode.Device{Name: diode.String("sw1")}
	device.PrimaryIp4 = &diode.IPAddress{Address: diode.String("192.0.2.1/24")}
	device.PrimaryIp6 = &diode.IPAddress{Address: diode.String("2001:db8::1/64")}

	assert.Equal(t, []diode.Entity{device}, mapping.OmitIPAddresses([]diode.Entity{device}, device))
	assert.Nil(t, device.PrimaryIp4)
	assert.Nil(t, device.PrimaryIp6)
}

// A stack member's unit keeps the parent on its own member, as it does when
// it travels nested in its address, even though the master has a port of the
// same name.
func TestOmitIPAddresses_UnitKeepsItsMembersParent(t *testing.T) {
	master := &diode.Device{Name: diode.String("sw"), Site: &diode.Site{Name: diode.String("lab")}}
	member := &diode.Device{Name: diode.String("sw-2"), Site: master.Site, VcPosition: diode.Int64(2)}
	onMaster := &diode.Interface{Name: diode.String("em0"), Type: diode.String("1000base-t"), Device: master}
	onMember := &diode.Interface{Name: diode.String("em0"), Type: diode.String("10gbase-x-sfpp"), Device: member}
	unit := &diode.Interface{
		Name: diode.String("em0.0"), Type: diode.String("virtual"), Device: member,
		// Taken before stack routing, so it still names the master's port.
		Parent: &diode.Interface{Name: onMaster.Name, Type: onMaster.Type, Device: master},
	}
	addr := &diode.IPAddress{Address: diode.String("192.0.2.1/24"), AssignedObject: unit}

	got := mapping.OmitIPAddresses([]diode.Entity{master, member, onMaster, onMember, addr}, master)

	sent := interfaceNamed(t, got[4:], "em0.0")
	require.NotNil(t, sent.Parent)
	require.NotNil(t, sent.Parent.Device)
	assert.Equal(t, "sw-2", *sent.Parent.Device.Name)
	assert.Equal(t, "10gbase-x-sfpp", sent.Parent.GetType())
}

// A device reached only through an interface sent on its own loses its primary
// IP too.
func TestOmitIPAddresses_DeviceReachedThroughASentInterface(t *testing.T) {
	member := &diode.Device{Name: diode.String("sw1-2")}
	member.PrimaryIp4 = &diode.IPAddress{Address: diode.String("192.0.2.2/24")}
	gi2 := &diode.Interface{Name: diode.String("Gi2/0/1"), Device: member}

	mapping.OmitIPAddresses([]diode.Entity{gi2}, nil)

	assert.Nil(t, member.PrimaryIp4)
}

// An interface whose device the run does not send as an entity is stubbed onto
// the target's device, as PruneNestedRefs does.
func TestOmitIPAddresses_FallsBackToTheTargetDevice(t *testing.T) {
	device := &diode.Device{Name: diode.String("sw1")}
	gi1 := &diode.Interface{Name: diode.String("Gi1"), Device: &diode.Device{}}
	addr := &diode.IPAddress{Address: diode.String("192.0.2.1/24"), AssignedObject: gi1}

	sent := interfaceNamed(t, mapping.OmitIPAddresses([]diode.Entity{addr}, device), "Gi1")

	require.NotNil(t, sent.Device)
	assert.Equal(t, "sw1", *sent.Device.Name)
}
