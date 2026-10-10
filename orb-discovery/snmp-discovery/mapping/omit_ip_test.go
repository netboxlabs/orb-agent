package mapping_test

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

func TestOmitIPAddresses(t *testing.T) {
	device := &diode.Device{Name: diode.String("sw1")}
	gi1 := &diode.Interface{Name: diode.String("Gi1"), Device: device}
	vlan10 := &diode.Interface{Name: diode.String("Vlan10"), Device: device}
	a1 := &diode.IPAddress{Address: diode.String("192.0.2.1/24"), AssignedObject: vlan10}
	a2 := &diode.IPAddress{Address: diode.String("2001:db8::1/64"), AssignedObject: vlan10}
	a3 := &diode.IPAddress{Address: diode.String("198.51.100.1/24"), AssignedObject: gi1}
	unassigned := &diode.IPAddress{Address: diode.String("203.0.113.1/24")}
	device.PrimaryIp4 = a1
	device.PrimaryIp6 = a2
	prefix := &diode.Prefix{Prefix: diode.String("192.0.2.0/24")}

	got := mapping.OmitIPAddresses([]diode.Entity{device, gi1, a1, a2, a3, unassigned, prefix})

	// Each address gives way to its interface, once, in its place; an interface
	// already sent is not repeated, and an unassigned address leaves nothing.
	assert.Equal(t, []diode.Entity{device, gi1, vlan10, prefix}, got)
	assert.Nil(t, device.PrimaryIp4)
	assert.Nil(t, device.PrimaryIp6)
}

// A device the run only reaches through an interface loses its primary IP too.
func TestOmitIPAddresses_DeviceReachedThroughAnInterface(t *testing.T) {
	member := &diode.Device{Name: diode.String("sw1-2")}
	gi2 := &diode.Interface{Name: diode.String("Gi2/0/1"), Device: member}
	addr := &diode.IPAddress{Address: diode.String("192.0.2.2/24"), AssignedObject: gi2}
	member.PrimaryIp4 = addr

	assert.Equal(t, []diode.Entity{gi2}, mapping.OmitIPAddresses([]diode.Entity{addr}))
	assert.Nil(t, member.PrimaryIp4)
}

// A device sent on its own loses its primary IP even with no interface in the
// run to reach it through.
func TestOmitIPAddresses_DeviceEntityOnItsOwn(t *testing.T) {
	device := &diode.Device{Name: diode.String("sw1")}
	device.PrimaryIp4 = &diode.IPAddress{Address: diode.String("192.0.2.1/24")}
	device.PrimaryIp6 = &diode.IPAddress{Address: diode.String("2001:db8::1/64")}

	assert.Equal(t, []diode.Entity{device}, mapping.OmitIPAddresses([]diode.Entity{device}))
	assert.Nil(t, device.PrimaryIp4)
	assert.Nil(t, device.PrimaryIp6)
}
