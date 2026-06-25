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
	// PrimaryIp4 reduced to a matcher (AssignedObject cleared → cycle break).
	require.NotNil(t, s.PrimaryIp4)
	assert.Equal(t, "10.0.0.1/32", *s.PrimaryIp4.Address)
	assert.Nil(t, s.PrimaryIp4.AssignedObject)
	// source_match kept; run_id annotation dropped.
	require.NotNil(t, s.Metadata)
	_, hasSM := s.Metadata["source_match"]
	assert.True(t, hasSM)
	_, hasRun := s.Metadata["run_id"]
	assert.False(t, hasRun)
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

	PruneNestedRefs(entities, dev)

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

func TestCurrentDeviceFrom(t *testing.T) {
	d := &diode.Device{Name: strptr("r1")}
	assert.Same(t, d, CurrentDeviceFrom([]diode.Entity{&diode.Interface{}, d}))
	assert.Nil(t, CurrentDeviceFrom([]diode.Entity{&diode.Interface{}}))
}
