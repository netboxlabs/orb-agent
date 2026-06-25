package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Primary IPs are stripped from the default stub. The diode
	// reconciler can only resolve the circular primary-IP reference
	// within a single change set, and each emitted entity becomes its
	// own change set; carrying a matcher-only primary IP here would
	// make every nested device stub try to SET device.primary_ip4 and
	// fail on first ingest. Only the cycle-closer IPAddress entity's
	// nested device may carry it (see newDeviceStubKeepingPrimary).
	assert.Nil(t, stub.PrimaryIp4)
	assert.Nil(t, stub.PrimaryIp6)

	// AssetTag propagates — it is populated via
	// PolicyConfig.Defaults.AssetTag and the stub must carry it so
	// matcher precedence stays consistent between rich and stub.
	require.NotNil(t, stub.AssetTag)
	assert.Equal(t, "ASSET-001", *stub.AssetTag)

	// All non-matcher / non-required fields cleared.
	assert.Nil(t, stub.Platform)
	assert.Nil(t, stub.Serial)
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

func TestNewDeviceStubKeepingPrimary_ReattachesV4AsMatcherOnlyStub(t *testing.T) {
	v4 := "192.0.2.10/24"
	owner := &diode.Device{
		Name:       strPtr("sw1"),
		Site:       &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{Model: strPtr("Catalyst 9300")},
		Role:       &diode.DeviceRole{Name: strPtr("access")},
		PrimaryIp4: &diode.IPAddress{
			Address:        &v4,
			AssignedObject: &diode.Interface{Name: strPtr("Vlan1")},
		},
	}

	stub := newDeviceStubKeepingPrimary(owner, false, owner.PrimaryIp4)

	require.NotNil(t, stub)
	// Inherits the default stub's matcher / required fields.
	assert.Equal(t, strPtr("sw1"), stub.Name)
	assert.Same(t, owner.Site, stub.Site)
	assert.Same(t, owner.Role, stub.Role)
	assert.Same(t, owner.DeviceType, stub.DeviceType)
	// Re-attaches the primary as a matcher-only stub: address kept,
	// AssignedObject cleared so it carries no cycle.
	require.NotNil(t, stub.PrimaryIp4)
	assert.NotSame(t, owner.PrimaryIp4, stub.PrimaryIp4)
	assert.Equal(t, &v4, stub.PrimaryIp4.Address)
	assert.Nil(t, stub.PrimaryIp4.AssignedObject)
	assert.Nil(t, stub.PrimaryIp6)
}

func TestNewDeviceStubKeepingPrimary_ReattachesV6Only(t *testing.T) {
	v6 := "2001:db8::1/64"
	owner := &diode.Device{
		Name:       strPtr("sw1"),
		PrimaryIp6: &diode.IPAddress{Address: &v6, AssignedObject: &diode.Interface{Name: strPtr("Vlan1")}},
	}
	stub := newDeviceStubKeepingPrimary(owner, true, owner.PrimaryIp6)
	require.NotNil(t, stub)
	assert.Nil(t, stub.PrimaryIp4)
	require.NotNil(t, stub.PrimaryIp6)
	assert.Equal(t, &v6, stub.PrimaryIp6.Address)
	assert.Nil(t, stub.PrimaryIp6.AssignedObject)
}

func TestNewDeviceStubKeepingPrimary_NilOwnerReturnsNil(t *testing.T) {
	assert.Nil(t, newDeviceStubKeepingPrimary(nil, false, nil))
}

func TestNewDeviceStub_PreservesSourceMatchDropsRunID(t *testing.T) {
	rich := &diode.Device{
		Name: strPtr("sw1"),
		Metadata: diode.Metadata{
			"source_match": diode.Metadata{"netbox_id": 42},
			"run_id":       "run-abc",
		},
	}

	stub := newDeviceStub(rich)

	// source_match is the diode-netbox-plugin's PK-based match path —
	// MUST flow to the stub or rich and stub diverge.
	assert.NotNil(t, stub.Metadata)
	sm, ok := stub.Metadata["source_match"].(diode.Metadata)
	assert.True(t, ok, "source_match must be a nested Metadata map on the stub")
	assert.Equal(t, 42, sm["netbox_id"])

	// Annotation metadata (run_id) is intentionally NOT on the stub —
	// stubs are matcher-only and must not carry per-run annotation.
	_, hasRunID := stub.Metadata["run_id"]
	assert.False(t, hasRunID, "stub must not carry run_id annotation")
}

func TestNewDeviceStub_NoMetadataWhenSourceMatchAbsent(t *testing.T) {
	rich := &diode.Device{
		Name:     strPtr("sw1"),
		Metadata: diode.Metadata{"run_id": "run-abc"}, // only annotation
	}
	stub := newDeviceStub(rich)
	// run_id is annotation, not a matcher — stub stays metadata-free.
	assert.Nil(t, stub.Metadata)
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

	PruneNestedRefs(entities, currentDevice, nil)

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
	PruneNestedRefs(entities, nil, nil)
	assert.Nil(t, iface.Device)
}

func TestPruneNestedRefs_EmptySliceIsNoOp(t *testing.T) {
	dev := &diode.Device{Name: strPtr("sw1")}
	PruneNestedRefs(nil, dev, nil)
	assert.Equal(t, strPtr("sw1"), dev.Name)
}

// TestPruneNestedRefs_PrimaryHitsKeepsPrimaryOnlyOnCycleCloser verifies
// the surgical primary-IP behavior: the diode reconciler can only
// resolve the circular primary-IP reference within a single change set,
// and the only entity that can validly do so is the top-level
// ipam.ipaddress entity for the primary IP (the cycle-closer) — it
// performs the IP->interface assignment AND sets device.primary_ip4 in
// the same change set. So the nested device stub on that one IPAddress
// keeps a matcher-only primary IP; every other nested device stub
// (other interfaces, modules, module bays, MAC, non-primary IPs) is
// stripped.
func TestPruneNestedRefs_PrimaryHitsKeepsPrimaryOnlyOnCycleCloser(t *testing.T) {
	v4 := "10.0.0.1/24"
	site := &diode.Site{Name: strPtr("dc1")}
	dtype := &diode.DeviceType{Model: strPtr("C9300")}
	role := &diode.DeviceRole{Name: strPtr("access")}
	rich := &diode.Device{
		Name:       strPtr("sw1"),
		Serial:     strPtr("FCW123"),
		Site:       site,
		DeviceType: dtype,
		Role:       role,
		PrimaryIp4: &diode.IPAddress{Address: &v4},
	}

	ifType := strPtr("1000base-t")
	mgmtMac := "aa:bb:cc:dd:ee:00"
	// Cycle-closer interface: the one the primary IP is assigned to.
	closerIface := &diode.Interface{
		Name:              strPtr("Vlan1"),
		Device:            rich,
		Type:              ifType,
		PrimaryMacAddress: &diode.MACAddress{MacAddress: &mgmtMac},
	}
	primaryIP := &diode.IPAddress{Address: &v4, AssignedObject: closerIface}

	// A non-primary IP on a different interface.
	otherIface := &diode.Interface{Name: strPtr("Gi1/0/2"), Device: rich, Type: ifType}
	otherAddr := "192.0.2.9/32"
	otherIP := &diode.IPAddress{Address: &otherAddr, AssignedObject: otherIface}

	// A MAC entity assigned to yet another interface.
	macIface := &diode.Interface{Name: strPtr("Gi1/0/3"), Device: rich, Type: ifType}
	macStr := "aa:bb:cc:dd:ee:ff"
	macEntity := &diode.MACAddress{MacAddress: &macStr, AssignedObject: macIface}

	// A module bay + interface module (chassis path).
	bay := &diode.ModuleBay{Device: rich, Name: strPtr("Slot 1")}
	module := &diode.Module{Device: rich}
	modIface := &diode.Interface{Name: strPtr("Gi1/0/4"), Device: rich, Type: ifType, Module: module}

	entities := []diode.Entity{rich, closerIface, otherIface, macIface, modIface, bay, module, primaryIP, otherIP, macEntity}

	primaryHits := map[*diode.IPAddress]bool{primaryIP: true}
	PruneNestedRefs(entities, rich, primaryHits)

	// Cycle-closer: nested device keeps matcher-only primary_ip4 and the
	// interface keeps its rich Type.
	closerStub, ok := primaryIP.AssignedObject.(*diode.Interface)
	require.True(t, ok)
	require.NotNil(t, closerStub.Type, "cycle-closer interface keeps its Type")
	require.NotNil(t, closerStub.Device)
	require.NotNil(t, closerStub.Device.PrimaryIp4, "cycle-closer nested device keeps primary_ip4")
	assert.Equal(t, v4, *closerStub.Device.PrimaryIp4.Address)
	assert.Nil(t, closerStub.Device.PrimaryIp4.AssignedObject, "primary_ip4 is matcher-only")
	// And the closer's nested device stub is NOT the shared cached stub.
	assert.NotSame(t, closerStub.Device, otherIface.Device)

	// Non-primary IP's nested device: stripped.
	otherStub, ok := otherIP.AssignedObject.(*diode.Interface)
	require.True(t, ok)
	require.NotNil(t, otherStub.Device)
	assert.Nil(t, otherStub.Device.PrimaryIp4, "non-primary IP nested device must be stripped")

	// Top-level non-primary interface's own Device stub: stripped.
	require.NotNil(t, otherIface.Device)
	assert.Nil(t, otherIface.Device.PrimaryIp4, "non-primary interface device stub stripped")

	// MAC's nested device: stripped.
	macStub, ok := macEntity.AssignedObject.(*diode.Interface)
	require.True(t, ok)
	require.NotNil(t, macStub.Device)
	assert.Nil(t, macStub.Device.PrimaryIp4, "MAC nested device must be stripped")

	// Module + ModuleBay device stubs: stripped.
	require.NotNil(t, bay.Device)
	assert.Nil(t, bay.Device.PrimaryIp4, "module bay device stub stripped")
	require.NotNil(t, module.Device)
	assert.Nil(t, module.Device.PrimaryIp4, "module device stub stripped")

	// Top-level rich Device stays rich (its own primary_ip4 untouched).
	require.NotNil(t, rich.PrimaryIp4)
	assert.Equal(t, v4, *rich.PrimaryIp4.Address)
}

// TestPruneNestedRefs_DualStackKeepsOnlyMatchingFamilyPerCycleCloser confirms
// that on a dual-stack device each cycle-closer keeps ONLY its own family's
// primary. The v4 IPAddress entity's change set assigns only the v4 address, so
// its nested device stub must carry primary_ip4 but NOT primary_ip6 (and vice
// versa) — otherwise it would try to set the other family's primary before that
// address is assigned to the device.
func TestPruneNestedRefs_DualStackKeepsOnlyMatchingFamilyPerCycleCloser(t *testing.T) {
	v4 := "10.0.0.1/24"
	v6 := "2001:db8::1/64"
	ifType := strPtr("1000base-t")
	rich := &diode.Device{
		Name:       strPtr("sw1"),
		Serial:     strPtr("FCW123"),
		Site:       &diode.Site{Name: strPtr("dc1")},
		DeviceType: &diode.DeviceType{Model: strPtr("C9300")},
		Role:       &diode.DeviceRole{Name: strPtr("access")},
		PrimaryIp4: &diode.IPAddress{Address: &v4},
		PrimaryIp6: &diode.IPAddress{Address: &v6},
	}
	// v4 and v6 primaries on DIFFERENT interfaces (separate change sets).
	v4Iface := &diode.Interface{Name: strPtr("Vlan1"), Device: rich, Type: ifType}
	v4IP := &diode.IPAddress{Address: &v4, AssignedObject: v4Iface}
	v6Iface := &diode.Interface{Name: strPtr("Vlan2"), Device: rich, Type: ifType}
	v6IP := &diode.IPAddress{Address: &v6, AssignedObject: v6Iface}

	entities := []diode.Entity{rich, v4Iface, v6Iface, v4IP, v6IP}
	PruneNestedRefs(entities, rich, map[*diode.IPAddress]bool{v4IP: true, v6IP: true})

	v4Stub := v4IP.AssignedObject.(*diode.Interface)
	require.NotNil(t, v4Stub.Device.PrimaryIp4, "v4 cycle-closer keeps primary_ip4")
	assert.Nil(t, v4Stub.Device.PrimaryIp6, "v4 cycle-closer must NOT carry primary_ip6")

	v6Stub := v6IP.AssignedObject.(*diode.Interface)
	require.NotNil(t, v6Stub.Device.PrimaryIp6, "v6 cycle-closer keeps primary_ip6")
	assert.Nil(t, v6Stub.Device.PrimaryIp4, "v6 cycle-closer must NOT carry primary_ip4")
}

// TestPruneNestedRefs_NilPrimaryHitsStripsEverything confirms that
// without a primaryHits set (the common no-cycle-closer case), every
// nested device stub has its primary IP stripped — including the IP
// whose address happens to equal the device's primary.
func TestPruneNestedRefs_NilPrimaryHitsStripsEverything(t *testing.T) {
	v4 := "10.0.0.1/24"
	rich := &diode.Device{
		Name:       strPtr("sw1"),
		PrimaryIp4: &diode.IPAddress{Address: &v4},
	}
	iface := &diode.Interface{Name: strPtr("Vlan1"), Device: rich, Type: strPtr("virtual")}
	ip := &diode.IPAddress{Address: &v4, AssignedObject: iface}
	entities := []diode.Entity{rich, iface, ip}

	PruneNestedRefs(entities, rich, nil)

	stub, ok := ip.AssignedObject.(*diode.Interface)
	require.True(t, ok)
	require.NotNil(t, stub.Device)
	assert.Nil(t, stub.Device.PrimaryIp4,
		"nil primaryHits: every nested device stub must be stripped")
}

// TestPruneNestedRefs_PrimaryHitsStackMemberFallsBackToMaster covers the
// stack edge: the cycle-closer's owner interface may belong to a stack
// member whose own PrimaryIp4 is nil, while the master/currentDevice
// carries it. newDeviceStubKeepingPrimary copies the primary from the
// device that actually carries it: it prefers the resolved owner and
// falls back to currentDevice when the owner's primary is nil. This
// member-vs-master case should be confirmed against a real stacked-
// switch capture.
func TestPruneNestedRefs_PrimaryHitsStackMemberFallsBackToMaster(t *testing.T) {
	v4 := "10.0.0.1/24"
	master := &diode.Device{
		Name:       strPtr("stack"),
		PrimaryIp4: &diode.IPAddress{Address: &v4},
	}
	// Member carries no primary IP of its own.
	member := &diode.Device{Name: strPtr("stack-2")}

	// The primary IP's interface is owned by the member.
	memberIface := &diode.Interface{Name: strPtr("Gi2/0/1"), Device: member, Type: strPtr("1000base-t")}
	primaryIP := &diode.IPAddress{Address: &v4, AssignedObject: memberIface}

	entities := []diode.Entity{master, member, memberIface, primaryIP}
	primaryHits := map[*diode.IPAddress]bool{primaryIP: true}

	// currentDevice is the master (the device carrying the primary).
	PruneNestedRefs(entities, master, primaryHits)

	stub, ok := primaryIP.AssignedObject.(*diode.Interface)
	require.True(t, ok)
	// Owner resolves to the member by name.
	assert.Equal(t, "stack-2", *stub.Device.Name, "owner stub must resolve to the member")
	// But the member's own primary is nil, so the fallback copies the
	// master/currentDevice primary onto the cycle-closer stub.
	require.NotNil(t, stub.Device.PrimaryIp4,
		"member-owner with nil primary must fall back to currentDevice's primary")
	assert.Equal(t, v4, *stub.Device.PrimaryIp4.Address)
	assert.Nil(t, stub.Device.PrimaryIp4.AssignedObject, "primary_ip4 stays matcher-only")
}

func TestPruneNestedRefs_StubsModuleBayAndInterfaceModule(t *testing.T) {
	rich := &diode.Device{
		Name:   strPtr("sw1"),
		Serial: strPtr("FCW123"),
		Status: strPtr("active"),
		DeviceType: &diode.DeviceType{
			Model:        strPtr("C9404R"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	bay := &diode.ModuleBay{
		Device: rich,
		Name:   strPtr("Slot 2"),
	}
	transceiverBay := &diode.ModuleBay{
		Device:   rich,
		Name:     strPtr("TenGigabitEthernet1/0/1"),
		Position: strPtr("1"),
	}
	transceiver := &diode.Module{
		Device:    rich,
		ModuleBay: transceiverBay,
		Serial:    strPtr("FNS24010TR1"),
		ModuleType: &diode.ModuleType{
			Model:        strPtr("SFP-10G-LR"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
		Description: strPtr("SFP-10GBase-LR transceiver"),
	}
	iface := &diode.Interface{
		Name:   strPtr("TenGigabitEthernet1/0/1"),
		Device: rich,
		Module: transceiver,
	}
	entities := []diode.Entity{rich, bay, transceiverBay, transceiver, iface}

	PruneNestedRefs(entities, rich, nil)

	// ModuleBay.Device must be stubbed.
	require.NotNil(t, bay.Device)
	assert.Equal(t, "sw1", *bay.Device.Name)
	assert.Nil(t, bay.Device.Serial, "ModuleBay.Device serial stripped on stub")
	assert.Nil(t, bay.Device.Status, "ModuleBay.Device status stripped on stub")

	// Interface.Module reduced to a matcher-only ref: Device stub + Serial
	// + ModuleBay matcher (name+position+device stub). Mirrors
	// device-discovery's _module_match_stub so the Diode reconciler
	// resolves the ref to the existing top-level Module instead of
	// trying to create one and failing the "module_bay/module_type
	// required" validation. ModuleType / Description / Status etc. stay
	// dropped so the wire payload stays bounded.
	require.NotNil(t, iface.Module)
	assert.Equal(t, "FNS24010TR1", strDerefSafe(iface.Module.Serial))
	assert.Nil(t, iface.Module.ModuleType,
		"Interface.Module stub must not carry ModuleType (drops large nested manufacturer)")
	assert.Nil(t, iface.Module.Description,
		"Interface.Module stub must not carry Description")

	require.NotNil(t, iface.Module.Device, "Interface.Module.Device must be a chassis stub")
	assert.Equal(t, "sw1", strDerefSafe(iface.Module.Device.Name))
	assert.Nil(t, iface.Module.Device.Status, "Interface.Module.Device must be a stub (no Status)")

	require.NotNil(t, iface.Module.ModuleBay,
		"Interface.Module.ModuleBay matcher must be preserved so the reconciler can resolve via the (device, bay) match path")
	assert.Equal(t, "TenGigabitEthernet1/0/1", strDerefSafe(iface.Module.ModuleBay.Name))
	assert.Equal(t, "1", strDerefSafe(iface.Module.ModuleBay.Position))
	require.NotNil(t, iface.Module.ModuleBay.Device, "ModuleBay matcher must carry a chassis device stub")
	assert.Equal(t, "sw1", strDerefSafe(iface.Module.ModuleBay.Device.Name))
	assert.Nil(t, iface.Module.ModuleBay.Device.Status,
		"ModuleBay matcher's Device must itself be a stub (no rich Status)")
}

// TestPruneNestedRefs_InterfaceModuleSurvivesWhenSerialNilButBayPresent —
// vendors that omit transceiver Serial in ENTITY-MIB (some Aruba and
// low-end OEMs) still populate the physical bay. When Serial is nil
// but ModuleBay is set, the pruner must preserve the stub so the
// reconciler can resolve the Module via the (Device, ModuleBay) match
// path. Mirrors device-discovery's `_module_match_stub` which
// unconditionally copies bay matcher fields when present.
func TestPruneNestedRefs_InterfaceModuleSurvivesWhenSerialNilButBayPresent(t *testing.T) {
	rich := &diode.Device{
		Name:   strPtr("sw1"),
		Site:   &diode.Site{Name: strPtr("dc1")},
		Serial: strPtr("FCW123"),
		Status: strPtr("active"),
		DeviceType: &diode.DeviceType{
			Model:        strPtr("C9404R"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	bay := &diode.ModuleBay{
		Device:   rich,
		Name:     strPtr("TenGigabitEthernet1/0/1"),
		Position: strPtr("1"),
	}
	transceiver := &diode.Module{
		Device:    rich,
		ModuleBay: bay,
		// Serial intentionally nil — vendor omitted entPhysicalSerialNum.
		ModuleType: &diode.ModuleType{
			Model:        strPtr("SFP-10G-LR"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	iface := &diode.Interface{
		Name:   strPtr("TenGigabitEthernet1/0/1"),
		Device: rich,
		Module: transceiver,
	}
	PruneNestedRefs([]diode.Entity{rich, bay, transceiver, iface}, rich, nil)

	require.NotNil(t, iface.Module,
		"Interface.Module must NOT be cleared when bay matcher is available even without serial")
	require.NotNil(t, iface.Module.ModuleBay, "bay matcher must be preserved")
	assert.Equal(t, "TenGigabitEthernet1/0/1", strDerefSafe(iface.Module.ModuleBay.Name))
	assert.Equal(t, "1", strDerefSafe(iface.Module.ModuleBay.Position))
	assert.Nil(t, iface.Module.Serial, "serial stays nil — matcher uses Device + Bay")
	assert.Nil(t, iface.Module.ModuleType, "ModuleType still dropped per Python parity")
	require.NotNil(t, iface.Module.Device, "Interface.Module.Device must be a chassis stub")
	assert.Equal(t, "sw1", strDerefSafe(iface.Module.Device.Name))
	assert.Nil(t, iface.Module.Device.Status, "Module.Device must be stubbed (no rich Status)")
	require.NotNil(t, iface.Module.ModuleBay.Device,
		"bay matcher must carry chassis Device stub so reconciler can resolve via (Device, Bay)")
	assert.Equal(t, "sw1", strDerefSafe(iface.Module.ModuleBay.Device.Name))
	assert.Nil(t, iface.Module.ModuleBay.Device.Status)
}

// TestPruneNestedRefs_InterfaceModuleStubDegradesToSerialOnly — when
// Serial is present but ModuleBay is nil, the stub must still emit so
// the reconciler can resolve via the (Device, Serial) match path. No
// regression on the common Cisco/Juniper transceiver path.
func TestPruneNestedRefs_InterfaceModuleStubDegradesToSerialOnly(t *testing.T) {
	rich := &diode.Device{
		Name:   strPtr("sw1"),
		Site:   &diode.Site{Name: strPtr("dc1")},
		Serial: strPtr("FCW123"),
	}
	transceiver := &diode.Module{
		Device:    rich,
		Serial:    strPtr("FNS00000001"),
		ModuleBay: nil, // intentionally nil
		ModuleType: &diode.ModuleType{
			Model:        strPtr("SFP-1G-T"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	iface := &diode.Interface{
		Name:   strPtr("Gi1/0/1"),
		Device: rich,
		Module: transceiver,
	}
	PruneNestedRefs([]diode.Entity{rich, transceiver, iface}, rich, nil)

	require.NotNil(t, iface.Module, "must not be cleared when serial is present")
	assert.Equal(t, "FNS00000001", strDerefSafe(iface.Module.Serial))
	assert.Nil(t, iface.Module.ModuleBay, "no bay was set on input, stays nil")
	assert.Nil(t, iface.Module.ModuleType, "ModuleType still dropped per Python parity")
	require.NotNil(t, iface.Module.Device)
	assert.Equal(t, "sw1", strDerefSafe(iface.Module.Device.Name))
}

// TestPruneNestedRefs_InterfaceModuleClearedWhenSerialAndBayBothMissing —
// the only legitimate clear path. Without Serial AND without
// ModuleBay, no matcher field can resolve the ref. Shipping such a
// stub would force the reconciler into creation mode and fail
// validation ("module_bay required, module_type required") because
// the stub also strips ModuleType.
func TestPruneNestedRefs_InterfaceModuleClearedWhenSerialAndBayBothMissing(t *testing.T) {
	rich := &diode.Device{
		Name:   strPtr("sw1"),
		Site:   &diode.Site{Name: strPtr("dc1")},
		Serial: strPtr("FCW123"),
	}
	transceiver := &diode.Module{
		Device: rich,
		// Serial nil, ModuleBay nil — unresolvable.
		ModuleType: &diode.ModuleType{
			Model:        strPtr("UNKNOWN"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	iface := &diode.Interface{
		Name:   strPtr("Gi1/0/1"),
		Device: rich,
		Module: transceiver,
	}
	PruneNestedRefs([]diode.Entity{rich, transceiver, iface}, rich, nil)

	assert.Nil(t, iface.Module,
		"must clear when neither Serial nor Bay can resolve the ref")
}

// TestPruneNestedRefs_InterfaceModuleSerialNilCleared — an
// Interface.Module reduced to {Device, Serial: nil, ModuleBay: nil}
// carries no identifier and is useless for matching. Rather than ship
// an ambiguous stub, the pruner must clear the ref entirely so the
// top-level Module entity remains the only wire representation.
func TestPruneNestedRefs_InterfaceModuleSerialNilCleared(t *testing.T) {
	rich := &diode.Device{
		Name:   strPtr("sw1"),
		Site:   &diode.Site{Name: strPtr("dc1")},
		Serial: strPtr("FCW123"),
	}
	// Transceiver Module without a Serial — common for vendors that omit
	// optic serial on entPhysicalSerialNum.
	transceiver := &diode.Module{
		Device: rich,
		ModuleType: &diode.ModuleType{
			Model:        strPtr("SFP-10G-LR"),
			Manufacturer: &diode.Manufacturer{Name: strPtr("Cisco")},
		},
	}
	iface := &diode.Interface{
		Name:   strPtr("Gi1/0/1"),
		Device: rich,
		Module: transceiver,
	}
	entities := []diode.Entity{rich, transceiver, iface}

	PruneNestedRefs(entities, rich, nil)

	assert.Nil(t, iface.Module,
		"Interface.Module must be cleared when its Serial is nil — an identifier-less stub would be ambiguous")
}

// TestPruneNestedRefs_InterfaceModuleEmptyStringSerialCleared — same
// behaviour for a pointer-to-empty-string Serial: still no identifier,
// so still clear the ref.
func TestPruneNestedRefs_InterfaceModuleEmptyStringSerialCleared(t *testing.T) {
	rich := &diode.Device{
		Name: strPtr("sw1"),
		Site: &diode.Site{Name: strPtr("dc1")},
	}
	empty := ""
	transceiver := &diode.Module{
		Device: rich,
		Serial: &empty,
	}
	iface := &diode.Interface{
		Name:   strPtr("Gi1/0/1"),
		Device: rich,
		Module: transceiver,
	}
	PruneNestedRefs([]diode.Entity{rich, transceiver, iface}, rich, nil)

	assert.Nil(t, iface.Module,
		"Interface.Module must be cleared when Serial points at the empty string")
}

// strDerefSafe — tiny test helper for safe *string deref.
func strDerefSafe(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
