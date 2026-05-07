package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
)

func strPtr(s string) *string { return &s }

func TestNewIPMatchStub_Nil(t *testing.T) {
	assert.Nil(t, newIPMatchStub(nil))
}

func TestNewIPMatchStub_KeepsAddressAndVrfDropsRest(t *testing.T) {
	addr := "192.0.2.1/24"
	vrf := &diode.VRF{Name: strPtr("mgmt")}
	rich := &diode.IPAddress{
		Address:        &addr,
		Vrf:            vrf,
		AssignedObject: &diode.Interface{Name: strPtr("eth0")},
		Description:    strPtr("uplink"),
		Status:         strPtr("active"),
	}

	stub := newIPMatchStub(rich)

	assert.NotNil(t, stub)
	assert.NotSame(t, rich, stub, "must return a new pointer, not the input")
	assert.Equal(t, &addr, stub.Address)
	assert.Same(t, vrf, stub.Vrf, "Vrf is pointer-shared (already minimal)")
	assert.Nil(t, stub.AssignedObject, "AssignedObject must be cleared for cycle safety")
	assert.Nil(t, stub.Description)
	assert.Nil(t, stub.Status)
}

func TestNewMACMatchStub_Nil(t *testing.T) {
	assert.Nil(t, newMACMatchStub(nil))
}

func TestNewMACMatchStub_KeepsMacAddressOnly(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"
	rich := &diode.MACAddress{
		MacAddress:     &mac,
		AssignedObject: &diode.Interface{Name: strPtr("eth0")},
		Description:    strPtr("primary"),
	}

	stub := newMACMatchStub(rich)

	assert.NotNil(t, stub)
	assert.NotSame(t, rich, stub)
	assert.Equal(t, &mac, stub.MacAddress)
	assert.Nil(t, stub.AssignedObject)
	assert.Nil(t, stub.Description)
}

func TestNewDeviceStub_Nil(t *testing.T) {
	assert.Nil(t, newDeviceStub(nil))
}

func TestNewDeviceStub_KeepsMatcherAndRequiredFieldsDropsRest(t *testing.T) {
	site := &diode.Site{Name: strPtr("dc1")}
	tenant := &diode.Tenant{Name: strPtr("acme")}
	role := &diode.DeviceRole{Name: strPtr("access-switch")}
	deviceType := &diode.DeviceType{Model: strPtr("Catalyst 9300")}
	v4 := "192.0.2.10/24"
	v6 := "2001:db8::1/64"
	rich := &diode.Device{
		Name:        strPtr("sw1"),
		Site:        site,
		Tenant:      tenant,
		PrimaryIp4:  &diode.IPAddress{Address: &v4, AssignedObject: &diode.Interface{Name: strPtr("eth0")}},
		PrimaryIp6:  &diode.IPAddress{Address: &v6},
		Role:        role,
		DeviceType:  deviceType,
		Platform:    &diode.Platform{Name: strPtr("ios-xe")},
		Serial:      strPtr("FCW1234X5YZ"),
		AssetTag:    strPtr("ASSET-001"),
		Status:      strPtr("active"),
		Description: strPtr("ignore me"),
	}

	stub := newDeviceStub(rich)

	assert.NotNil(t, stub)
	assert.NotSame(t, rich, stub)
	assert.Equal(t, strPtr("sw1"), stub.Name)
	assert.Same(t, site, stub.Site)
	assert.Same(t, tenant, stub.Tenant)

	// DeviceType and Role are pointer-shared so the diode-netbox-plugin
	// can satisfy NetBox's create-time validation if a nested stub
	// resolves before the rich top-level Device has been upserted.
	assert.Same(t, role, stub.Role)
	assert.Same(t, deviceType, stub.DeviceType)

	// PrimaryIp4 stubbed (no AssignedObject) — cycle break.
	assert.NotNil(t, stub.PrimaryIp4)
	assert.NotSame(t, rich.PrimaryIp4, stub.PrimaryIp4)
	assert.Equal(t, &v4, stub.PrimaryIp4.Address)
	assert.Nil(t, stub.PrimaryIp4.AssignedObject)

	assert.NotNil(t, stub.PrimaryIp6)
	assert.Equal(t, &v6, stub.PrimaryIp6.Address)

	// All non-matcher / non-required fields cleared.
	assert.Nil(t, stub.Platform)
	assert.Nil(t, stub.Serial)
	assert.Nil(t, stub.AssetTag)
	assert.Nil(t, stub.Status)
	assert.Nil(t, stub.Description)
}

func TestNewDeviceStub_NilPrimaryIPs(t *testing.T) {
	rich := &diode.Device{Name: strPtr("sw1"), Site: &diode.Site{Name: strPtr("dc1")}}
	stub := newDeviceStub(rich)
	assert.NotNil(t, stub)
	assert.Nil(t, stub.PrimaryIp4)
	assert.Nil(t, stub.PrimaryIp6)
}

func TestNewInterfaceStub_Nil(t *testing.T) {
	assert.Nil(t, newInterfaceStub(nil, nil))
}

func TestNewInterfaceStub_KeepsNameDeviceMACTypeDropsRest(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"
	ifType := strPtr("1000base-t")
	deviceStub := &diode.Device{Name: strPtr("sw1")}
	rich := &diode.Interface{
		Name:              strPtr("Gi1/0/1"),
		Device:            &diode.Device{Name: strPtr("sw1"), Serial: strPtr("FCW123")},
		PrimaryMacAddress: &diode.MACAddress{MacAddress: &mac, Description: strPtr("primary")},
		Type:              ifType,
		Mtu:               int64Ptr(1500),
		Description:       strPtr("uplink"),
		Parent:            &diode.Interface{Name: strPtr("Po1")},
		Bridge:            &diode.Interface{Name: strPtr("br0")},
		Lag:               &diode.Interface{Name: strPtr("Po1")},
	}

	stub := newInterfaceStub(rich, deviceStub)

	assert.NotNil(t, stub)
	assert.NotSame(t, rich, stub)
	assert.Equal(t, strPtr("Gi1/0/1"), stub.Name)
	assert.Same(t, deviceStub, stub.Device, "must use the supplied device stub, not rich.Device")

	// Type pointer-shared so NetBox create-validation succeeds when the
	// stub is the only wire representation of an interface (see
	// newInterfaceStub doc-comment).
	assert.Same(t, ifType, stub.Type)

	assert.NotNil(t, stub.PrimaryMacAddress)
	assert.NotSame(t, rich.PrimaryMacAddress, stub.PrimaryMacAddress)
	assert.Equal(t, &mac, stub.PrimaryMacAddress.MacAddress)
	assert.Nil(t, stub.PrimaryMacAddress.Description)

	// Other fields cleared.
	assert.Nil(t, stub.Mtu)
	assert.Nil(t, stub.Description)
	assert.Nil(t, stub.Parent)
	assert.Nil(t, stub.Bridge)
	assert.Nil(t, stub.Lag)
}

func TestCurrentDeviceFrom_FindsFirstDevice(t *testing.T) {
	d := &diode.Device{Name: strPtr("sw1")}
	iface := &diode.Interface{Name: strPtr("eth0")}
	assert.Same(t, d, CurrentDeviceFrom([]diode.Entity{iface, d}))
}

func TestCurrentDeviceFrom_NoDeviceReturnsNil(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("eth0")}
	assert.Nil(t, CurrentDeviceFrom([]diode.Entity{iface}))
}

func TestCurrentDeviceFrom_EmptyReturnsNil(t *testing.T) {
	assert.Nil(t, CurrentDeviceFrom(nil))
}

func TestPruneNestedRefs_RewritesAllNestedDeviceRefs(t *testing.T) {
	v4 := "192.0.2.10/24"
	site := &diode.Site{Name: strPtr("dc1")}
	currentDevice := &diode.Device{
		Name:       strPtr("sw1"),
		Site:       site,
		PrimaryIp4: &diode.IPAddress{Address: &v4},
		Serial:     strPtr("FCW123"),
		Status:     strPtr("active"),
	}

	parent := &diode.Interface{Name: strPtr("Po1"), Device: currentDevice}
	bridge := &diode.Interface{Name: strPtr("br0"), Device: currentDevice}
	lag := &diode.Interface{Name: strPtr("Po1"), Device: currentDevice}

	iface := &diode.Interface{
		Name:   strPtr("Gi1/0/1"),
		Device: currentDevice,
		Parent: parent,
		Bridge: bridge,
		Lag:    lag,
	}

	ipIface := &diode.Interface{Name: strPtr("Gi1/0/2"), Device: currentDevice}
	addr := "10.0.0.1/24"
	ip := &diode.IPAddress{Address: &addr, AssignedObject: ipIface}

	macIface := &diode.Interface{Name: strPtr("Gi1/0/3"), Device: currentDevice}
	mac := "aa:bb:cc:dd:ee:ff"
	macEntity := &diode.MACAddress{MacAddress: &mac, AssignedObject: macIface}

	module := &diode.Module{Device: currentDevice}

	entities := []diode.Entity{currentDevice, iface, parent, bridge, lag, ip, macEntity, module}

	PruneNestedRefs(entities, currentDevice)

	// Top-level Device unchanged — still rich.
	assert.Equal(t, strPtr("FCW123"), currentDevice.Serial)
	assert.Equal(t, strPtr("active"), currentDevice.Status)

	// Top-level Interfaces: Device replaced with stub (not currentDevice).
	assert.NotSame(t, currentDevice, iface.Device)
	assert.Equal(t, strPtr("sw1"), iface.Device.Name)
	assert.Nil(t, iface.Device.Serial, "stub must not carry rich fields")

	// Same stub pointer should be reused across entities visited in this sweep.
	assert.Same(t, iface.Device, parent.Device)
	assert.Same(t, iface.Device, bridge.Device)
	assert.Same(t, iface.Device, lag.Device)
	assert.Same(t, iface.Device, module.Device)

	// Parent/Bridge/Lag on the top-level Interface are stub copies, not
	// the original top-level pointers.
	assert.NotSame(t, parent, iface.Parent)
	assert.NotSame(t, bridge, iface.Bridge)
	assert.NotSame(t, lag, iface.Lag)
	assert.Equal(t, strPtr("Po1"), iface.Parent.Name)
	assert.Same(t, iface.Device, iface.Parent.Device)

	// IPAddress.AssignedObject replaced with a stub.
	assignedIface, ok := ip.AssignedObject.(*diode.Interface)
	assert.True(t, ok)
	assert.NotSame(t, ipIface, assignedIface)
	assert.Equal(t, strPtr("Gi1/0/2"), assignedIface.Name)
	assert.Same(t, iface.Device, assignedIface.Device)

	// MACAddress.AssignedObject replaced with a stub.
	assignedMacIface, ok := macEntity.AssignedObject.(*diode.Interface)
	assert.True(t, ok)
	assert.NotSame(t, macIface, assignedMacIface)
	assert.Same(t, iface.Device, assignedMacIface.Device)
}

func TestPruneNestedRefs_NilCurrentDeviceIsNoOp(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("eth0")}
	entities := []diode.Entity{iface}
	PruneNestedRefs(entities, nil)
	assert.Nil(t, iface.Device)
}

func TestPruneNestedRefs_EmptySliceIsNoOp(t *testing.T) {
	dev := &diode.Device{Name: strPtr("sw1")}
	PruneNestedRefs(nil, dev)
	assert.Equal(t, strPtr("sw1"), dev.Name)
}
