package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceStub_DropsConfigKeepsMatchers(t *testing.T) {
	rich := &diode.Device{
		Name:       strptr("r1"),
		Site:       &diode.Site{Name: strptr("lab")},
		Tenant:     &diode.Tenant{Name: strptr("acme")},
		DeviceType: &diode.DeviceType{Model: strptr("X"), Manufacturer: &diode.Manufacturer{Name: strptr("Nokia")}},
		Role:       &diode.DeviceRole{Name: strptr("router")},
		AssetTag:   strptr("ASSET-1"),
		Status:     strptr("active"),
		Comments:   strptr("noisy comment"),
		Config:     &diode.DeviceConfig{Running: []byte("HUGE-CONFIG-BLOB")},
		PrimaryIp4: &diode.IPAddress{Address: strptr("10.0.0.1/32"), AssignedObject: &diode.Interface{Name: strptr("lo0")}},
		Metadata:   diode.Metadata{"source_match": diode.Metadata{"netbox_id": 7}, "run_id": "abc"},
	}
	s := newDeviceStub(rich)
	// Matchers preserved.
	assert.Equal(t, "r1", *s.Name)
	assert.Equal(t, "lab", *s.Site.Name)
	assert.Equal(t, "acme", *s.Tenant.Name)
	require.NotNil(t, s.DeviceType)
	require.NotNil(t, s.Role)
	assert.Equal(t, "ASSET-1", *s.AssetTag)
	// Heavy / non-matcher fields dropped.
	assert.Nil(t, s.Config, "stub must NOT carry the captured config")
	assert.Nil(t, s.Status)
	assert.Nil(t, s.Comments)
	// PrimaryIp4/6 stripped entirely (diode reconciler bug #545): a matcher-only
	// device.primary_ip4 is a circular ref the plugin tries to SET and fails on
	// first ingest, rolling back interfaces/modules. Only the cycle-closer
	// IPAddress entity's nested stub may carry it (newDeviceStubWithPrimary).
	assert.Nil(t, s.PrimaryIp4, "default stub must strip primary IPs (cycle-closer only)")
	assert.Nil(t, s.PrimaryIp6, "default stub must strip primary IPs (cycle-closer only)")
	// source_match kept; run_id annotation dropped.
	require.NotNil(t, s.Metadata)
	_, hasSM := s.Metadata["source_match"]
	assert.True(t, hasSM)
	_, hasRun := s.Metadata["run_id"]
	assert.False(t, hasRun)
}

// TestNewDeviceStubWithPrimary_ReattachesMatcherOnly verifies the non-cached
// sibling re-attaches the owner's set primary as an address-only matcher stub
// (AssignedObject nil) — the matcher-only shape used by the cycle-closer.
func TestNewDeviceStubWithPrimary_ReattachesMatcherOnly(t *testing.T) {
	// v4 owner: PrimaryIp4 re-attached as a matcher, PrimaryIp6 stays nil.
	ownerV4 := &diode.Device{
		Name:       strptr("r1"),
		DeviceType: &diode.DeviceType{Model: strptr("X"), Manufacturer: &diode.Manufacturer{Name: strptr("Nokia")}},
		Role:       &diode.DeviceRole{Name: strptr("router")},
		PrimaryIp4: &diode.IPAddress{Address: strptr("10.0.0.1/32"), Vrf: &diode.VRF{Name: strptr("blue")}, AssignedObject: &diode.Interface{Name: strptr("lo0")}},
	}
	s := newDeviceStubWithPrimary(ownerV4)
	require.NotNil(t, s.PrimaryIp4)
	assert.Equal(t, "10.0.0.1/32", *s.PrimaryIp4.Address)
	require.NotNil(t, s.PrimaryIp4.Vrf)
	assert.Equal(t, "blue", *s.PrimaryIp4.Vrf.Name)
	assert.Nil(t, s.PrimaryIp4.AssignedObject, "matcher-only: AssignedObject cleared (execution comes from the top-level IPAddress)")
	assert.Nil(t, s.PrimaryIp6)
	// Other matcher fields still present (it builds on newDeviceStub).
	assert.Equal(t, "r1", *s.Name)
	assert.Nil(t, s.Config)

	// v6 owner: PrimaryIp6 re-attached, PrimaryIp4 stays nil.
	ownerV6 := &diode.Device{
		Name:       strptr("r1"),
		DeviceType: &diode.DeviceType{Model: strptr("X"), Manufacturer: &diode.Manufacturer{Name: strptr("Nokia")}},
		Role:       &diode.DeviceRole{Name: strptr("router")},
		PrimaryIp6: &diode.IPAddress{Address: strptr("2001:db8::1/64"), AssignedObject: &diode.Interface{Name: strptr("lo0")}},
	}
	s6 := newDeviceStubWithPrimary(ownerV6)
	require.NotNil(t, s6.PrimaryIp6)
	assert.Equal(t, "2001:db8::1/64", *s6.PrimaryIp6.Address)
	assert.Nil(t, s6.PrimaryIp6.AssignedObject)
	assert.Nil(t, s6.PrimaryIp4)
}

func TestPruneNestedRefs_DropsConfigFromNestedDeviceRefs(t *testing.T) {
	dev := &diode.Device{
		Name:       strptr("r1"),
		DeviceType: &diode.DeviceType{Model: strptr("X"), Manufacturer: &diode.Manufacturer{Name: strptr("Nokia")}},
		Role:       &diode.DeviceRole{Name: strptr("router")},
		Config:     &diode.DeviceConfig{Running: []byte("HUGE-CONFIG-BLOB")},
	}
	eth := &diode.Interface{Name: strptr("Ethernet1"), Device: dev, Type: strptr("10gbase-x-sfpp")}
	ip := &diode.IPAddress{Address: strptr("10.0.0.1/31"), AssignedObject: &diode.Interface{Name: strptr("Ethernet1"), Device: dev}}
	bay := &diode.ModuleBay{Device: dev, Name: strptr("bay1")}
	mod := &diode.Module{Device: dev, ModuleBay: bay}
	entities := []diode.Entity{dev, eth, ip, bay, mod}

	PruneNestedRefs(entities, dev, nil)

	// Top-level Device stays rich (keeps config).
	require.NotNil(t, dev.Config)
	// Every nested Device reference is now a stub WITHOUT config.
	require.NotNil(t, eth.Device)
	assert.NotSame(t, dev, eth.Device, "interface.Device must be a stub, not the rich Device")
	assert.Nil(t, eth.Device.Config, "nested interface.Device must not carry config")
	assert.Equal(t, "r1", *eth.Device.Name)

	ipIface, _ := ip.AssignedObject.(*diode.Interface)
	require.NotNil(t, ipIface)
	require.NotNil(t, ipIface.Device)
	assert.Nil(t, ipIface.Device.Config, "IP→interface→device stub must not carry config")
	// The IP's assigned interface stub re-resolves Type from the rich top-level Ethernet1.
	require.NotNil(t, ipIface.Type)
	assert.Equal(t, "10gbase-x-sfpp", *ipIface.Type)

	assert.Nil(t, bay.Device.Config, "module bay device stub must not carry config")
	assert.Nil(t, mod.Device.Config, "module device stub must not carry config")
}

// TestPruneNestedRefs_CycleCloserKeepsPrimaryIP verifies the surgical fix for
// diode reconciler bug #545: the ONLY nested device stub allowed to carry
// primary_ip4/6 is the one on the exact IPAddress entity identified (by pointer
// identity) as the cycle-closer. Every other nested device stub — on other
// interfaces, modules, module bays, and non-primary IP entities — has its
// primary IP stripped.
func TestPruneNestedRefs_CycleCloserKeepsPrimaryIP(t *testing.T) {
	dev := &diode.Device{
		Name:       strptr("r1"),
		DeviceType: &diode.DeviceType{Model: strptr("X"), Manufacturer: &diode.Manufacturer{Name: strptr("Nokia")}},
		Role:       &diode.DeviceRole{Name: strptr("router")},
		// The rich top-level Device keeps its rich primary (set by detachForPrimaryIP).
		PrimaryIp4: &diode.IPAddress{Address: strptr("10.7.7.7/32")},
	}
	eth := &diode.Interface{Name: strptr("Loopback0"), Device: dev, Type: strptr("virtual")}
	other := &diode.Interface{Name: strptr("Ethernet2"), Device: dev, Type: strptr("10gbase-x-sfpp")}
	// primaryIP is the cycle-closer: the top-level ipam.ipaddress for the primary.
	primaryIP := &diode.IPAddress{Address: strptr("10.7.7.7/32"), AssignedObject: &diode.Interface{Name: strptr("Loopback0"), Device: dev}}
	nonPrimaryIP := &diode.IPAddress{Address: strptr("10.9.9.9/31"), AssignedObject: &diode.Interface{Name: strptr("Ethernet2"), Device: dev}}
	bay := &diode.ModuleBay{Device: dev, Name: strptr("bay1")}
	mod := &diode.Module{Device: dev, ModuleBay: bay}
	entities := []diode.Entity{dev, eth, other, primaryIP, nonPrimaryIP, bay, mod}

	PruneNestedRefs(entities, dev, primaryIP)

	// Cycle-closer: its nested device stub KEEPS primary_ip4 as a matcher-only stub.
	pIface, _ := primaryIP.AssignedObject.(*diode.Interface)
	require.NotNil(t, pIface)
	require.NotNil(t, pIface.Device)
	require.NotNil(t, pIface.Device.PrimaryIp4, "cycle-closer nested device stub must keep primary_ip4")
	assert.Equal(t, "10.7.7.7/32", *pIface.Device.PrimaryIp4.Address)
	assert.Nil(t, pIface.Device.PrimaryIp4.AssignedObject, "matcher-only on the nested stub")
	// The cycle-closer interface stub keeps its rich Type (re-resolved from Loopback0).
	require.NotNil(t, pIface.Type, "cycle-closer interface stub must keep its Type for create validation")
	assert.Equal(t, "virtual", *pIface.Type)

	// Non-primary IP: nested device stub is STRIPPED.
	npIface, _ := nonPrimaryIP.AssignedObject.(*diode.Interface)
	require.NotNil(t, npIface)
	require.NotNil(t, npIface.Device)
	assert.Nil(t, npIface.Device.PrimaryIp4, "non-primary IP's nested device stub must strip primary_ip4")

	// All other nested device refs stripped.
	assert.Nil(t, eth.Device.PrimaryIp4, "interface nested device stub must strip primary_ip4")
	assert.Nil(t, other.Device.PrimaryIp4)
	assert.Nil(t, bay.Device.PrimaryIp4, "module bay nested device stub must strip primary_ip4")
	assert.Nil(t, mod.Device.PrimaryIp4, "module nested device stub must strip primary_ip4")
}

// TestPruneNestedRefs_NilPrimaryStripsEverything verifies that with no
// cycle-closer (primaryIP == nil) every nested device stub is stripped — there
// is nothing to re-attach.
func TestPruneNestedRefs_NilPrimaryStripsEverything(t *testing.T) {
	dev := &diode.Device{
		Name:       strptr("r1"),
		DeviceType: &diode.DeviceType{Model: strptr("X"), Manufacturer: &diode.Manufacturer{Name: strptr("Nokia")}},
		Role:       &diode.DeviceRole{Name: strptr("router")},
		PrimaryIp4: &diode.IPAddress{Address: strptr("10.7.7.7/32")},
	}
	eth := &diode.Interface{Name: strptr("Loopback0"), Device: dev, Type: strptr("virtual")}
	ip := &diode.IPAddress{Address: strptr("10.7.7.7/32"), AssignedObject: &diode.Interface{Name: strptr("Loopback0"), Device: dev}}
	entities := []diode.Entity{dev, eth, ip}

	PruneNestedRefs(entities, dev, nil)

	ipIface, _ := ip.AssignedObject.(*diode.Interface)
	require.NotNil(t, ipIface)
	require.NotNil(t, ipIface.Device)
	assert.Nil(t, ipIface.Device.PrimaryIp4, "no cycle-closer: every nested device stub stripped")
	assert.Nil(t, eth.Device.PrimaryIp4)
}

func TestCurrentDeviceFrom(t *testing.T) {
	d := &diode.Device{Name: strptr("r1")}
	assert.Same(t, d, CurrentDeviceFrom([]diode.Entity{&diode.Interface{}, d}))
	assert.Nil(t, CurrentDeviceFrom([]diode.Entity{&diode.Interface{}}))
}
