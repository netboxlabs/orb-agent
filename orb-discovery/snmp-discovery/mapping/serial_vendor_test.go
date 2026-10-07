package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

const (
	oidJnxBoxSerialNo   = ".1.3.6.1.4.1.2636.3.1.3.0"
	oidMtxrSerialNumber = ".1.3.6.1.4.1.14988.1.1.7.3.0"
	testJuniperSerial   = "TA3714470210"
	testMikrotikSerial  = "6C7D0E1F2A3B"
	testEntitySerialQFX = "WH3719450123"
)

// A Junos switch that implements no entPhysicalTable at all: the standard
// serial column answers noSuchObject, so the walk holds only the system
// group and the enterprise scalar.
func fixtureJunosNoEntityMIB() ObjectIDValueMap {
	return ObjectIDValueMap{
		".1.3.6.1.2.1.1.2.0": {Value: ".1.3.6.1.4.1.2636.1.1.1.2.92", Type: ObjectIdentifier},
		".1.3.6.1.2.1.1.5.0": {Value: "ex4550-core"},
		oidJnxBoxSerialNo:    {Value: testJuniperSerial},
	}
}

// RouterOS publishes an entPhysicalTable whose chassis row carries no
// serial, while the two USB host controllers under it report strings in
// the serial column. Neither of those is the device's serial.
func fixtureRouterOSComponentSerialsOnly() ObjectIDValueMap {
	return ObjectIDValueMap{
		".1.3.6.1.2.1.1.2.0": {Value: ".1.3.6.1.4.1.14988.1", Type: ObjectIdentifier},
		".1.3.6.1.2.1.1.5.0": {Value: "ccr1016-edge"},
		// chassis(3) at the root, empty serial
		".1.3.6.1.2.1.47.1.1.1.1.4.65536":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.65536":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.11.65536": {Value: ""},
		// contained components with serial-column strings
		".1.3.6.1.2.1.47.1.1.1.1.4.262145":  {Value: "65536"},
		".1.3.6.1.2.1.47.1.1.1.1.5.262145":  {Value: "9"},
		".1.3.6.1.2.1.47.1.1.1.1.11.262145": {Value: "tilegx-ehci.0"},
		".1.3.6.1.2.1.47.1.1.1.1.4.262146":  {Value: "65536"},
		".1.3.6.1.2.1.47.1.1.1.1.5.262146":  {Value: "9"},
		".1.3.6.1.2.1.47.1.1.1.1.11.262146": {Value: "tilegx-ohci.0"},
		oidMtxrSerialNumber:                 {Value: testMikrotikSerial},
	}
}

func TestVendorSerial_ReadsJuniperScalar(t *testing.T) {
	s, src := vendorSerial(fixtureJunosNoEntityMIB())
	assert.Equal(t, testJuniperSerial, s)
	assert.Equal(t, "JUNIPER-MIB jnxBoxSerialNo", src)
}

func TestVendorSerial_ReadsMikrotikScalar(t *testing.T) {
	s, src := vendorSerial(fixtureRouterOSComponentSerialsOnly())
	assert.Equal(t, testMikrotikSerial, s)
	assert.Equal(t, "MIKROTIK-MIB mtxrSerialNumber", src)
}

func TestVendorSerial_TrimsPaddingAndIgnoresEmpty(t *testing.T) {
	s, _ := vendorSerial(ObjectIDValueMap{oidJnxBoxSerialNo: {Value: " " + testJuniperSerial + "\x00\x00"}})
	assert.Equal(t, testJuniperSerial, s, "agent padding must not reach NetBox")

	s, src := vendorSerial(ObjectIDValueMap{oidMtxrSerialNumber: {Value: "\x00"}})
	assert.Empty(t, s, "a NUL-only scalar is no serial")
	assert.Empty(t, src)

	s, src = vendorSerial(ObjectIDValueMap{".1.3.6.1.2.1.1.5.0": {Value: "plain"}})
	assert.Empty(t, s, "no source in the walk")
	assert.Empty(t, src)
}

func TestTranslateAsStack_JunosWithoutEntityMIB_TakesJnxBoxSerialNo(t *testing.T) {
	master := &diode.Device{Name: strPtr("ex4550-core")}
	iface := &diode.Interface{Name: strPtr("xe-0/0/0"), Device: master}
	out := TranslateAsStack([]diode.Entity{master, iface}, fixtureJunosNoEntityMIB(), nil, nil, "", ModelNotPinned, slog.Default())

	assert.Len(t, out, 2, "shape unchanged: no virtual chassis invented")
	require.NotNil(t, master.Serial)
	assert.Equal(t, testJuniperSerial, *master.Serial)
}

func TestTranslateAsStack_RouterOSEmptyChassisSerial_TakesMtxrSerialNumber(t *testing.T) {
	master := &diode.Device{Name: strPtr("ccr1016-edge")}
	out := TranslateAsStack([]diode.Entity{master}, fixtureRouterOSComponentSerialsOnly(), nil, nil, "", ModelNotPinned, slog.Default())

	assert.Len(t, out, 1)
	require.NotNil(t, master.Serial)
	assert.Equal(t, testMikrotikSerial, *master.Serial)
	assert.NotContains(t, []string{"tilegx-ehci.0", "tilegx-ohci.0"}, *master.Serial,
		"a contained component's serial-column string is never the device serial")
}

func TestTranslateAsStack_EntityMIBChassisSerialKeepsPriorityOverVendorScalar(t *testing.T) {
	// A QFX that answers both: the standard chassis row is the device's
	// own statement of its serial and the enterprise scalar must not
	// displace it, whatever it says.
	oids := fixtureJunosNoEntityMIB()
	oids[".1.3.6.1.2.1.47.1.1.1.1.4.1"] = Value{Value: "0"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.5.1"] = Value{Value: "3"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.11.1"] = Value{Value: testEntitySerialQFX}
	oids[oidJnxBoxSerialNo] = Value{Value: "SOMETHING-ELSE"}

	master := &diode.Device{Name: strPtr("qfx5100")}
	TranslateAsStack([]diode.Entity{master}, oids, nil, nil, "", ModelNotPinned, slog.Default())

	require.NotNil(t, master.Serial)
	assert.Equal(t, testEntitySerialQFX, *master.Serial)
}

func TestTranslateAsStack_VirtualChassisIgnoresVendorScalar(t *testing.T) {
	// On a Virtual Chassis jnxBoxSerialNo reports the routing engine's
	// chassis; the master serial stays pinned to the lowest member row.
	oids := fixtureJunosNoEntityMIB()
	for i, serial := range []string{"MEMBER0SER", "MEMBER1SER"} {
		idx := string(rune('1' + i))
		oids[".1.3.6.1.2.1.47.1.1.1.1.4."+idx] = Value{Value: "0"}
		oids[".1.3.6.1.2.1.47.1.1.1.1.5."+idx] = Value{Value: "3"}
		oids[".1.3.6.1.2.1.47.1.1.1.1.6."+idx] = Value{Value: idx}
		oids[".1.3.6.1.2.1.47.1.1.1.1.11."+idx] = Value{Value: serial}
	}
	oids[oidJnxBoxSerialNo] = Value{Value: "MEMBER1SER"}

	master := &diode.Device{Name: strPtr("vc")}
	out := TranslateAsStack([]diode.Entity{master}, oids, nil, nil, "", ModelNotPinned, slog.Default())

	assert.Greater(t, len(out), 1, "a two-member stack is still emitted as one")
	require.NotNil(t, master.Serial)
	assert.Equal(t, "MEMBER0SER", *master.Serial)
}

func TestTranslateAsStack_NoSerialAnywhereLeavesNil(t *testing.T) {
	oids := fixtureJunosNoEntityMIB()
	oids[oidJnxBoxSerialNo] = Value{Value: ""}
	master := &diode.Device{Name: strPtr("ex4550-core")}
	TranslateAsStack([]diode.Entity{master}, oids, nil, nil, "", ModelNotPinned, slog.Default())
	assert.Nil(t, master.Serial, "nothing is invented when no source answers")
}

// The scalars are enterprise objects: each must sit in exactly its own
// vendor's walk set and never in the generic one, or every non-Juniper
// target would be asked for a Juniper object on each poll.
func TestVendorSerialScalars_WalkedOnlyUnderTheirVendorGate(t *testing.T) {
	cfg := newTestMappingConfig(t, slog.Default())

	generic := cfg.GenericObjectIDs()
	juniper := cfg.VendorObjectIDs("juniper")
	mikrotik := cfg.VendorObjectIDs("mikrotik")

	const jnx = ".1.3.6.1.4.1.2636.3.1.3"
	const mtxr = ".1.3.6.1.4.1.14988.1.1.7.3"

	_, ok := juniper[jnx]
	assert.True(t, ok, "jnxBoxSerialNo in the juniper walk set")
	_, ok = mikrotik[mtxr]
	assert.True(t, ok, "mtxrSerialNumber in the mikrotik walk set")

	for _, oid := range []string{jnx, mtxr} {
		_, ok = generic[oid]
		assert.False(t, ok, "%s must not be in the generic walk set", oid)
	}
	_, ok = juniper[mtxr]
	assert.False(t, ok, "mtxrSerialNumber must not be walked on Juniper")
	_, ok = mikrotik[jnx]
	assert.False(t, ok, "jnxBoxSerialNo must not be walked on MikroTik")
}

// Through the real mapping.yaml and the runner's call order: the scalar
// rides along as a post-pass-only column (no row entity of its own) and
// lands on the device the mapper built.
func TestVendorSerialFallback_ThroughFullMapperPipeline(t *testing.T) {
	logger := slog.Default()
	for _, tc := range []struct {
		name string
		oids ObjectIDValueMap
		want string
	}{
		{"juniper without entPhysicalTable", fixtureJunosNoEntityMIB(), testJuniperSerial},
		{"routeros with component serials only", fixtureRouterOSComponentSerialsOnly(), testMikrotikSerial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oids := ObjectIDValueMap{}
			for k, v := range tc.oids {
				v.IdentifierSize = 1
				oids[k] = v
			}
			cfg := newTestMappingConfig(t, logger)
			mapper := NewObjectIDMapper(cfg, logger, &config.Defaults{}, "10.0.0.1")
			ents := mapper.MapObjectIDsToEntity(oids)
			ents = TranslateAsStack(ents, oids, mapper.InterfacesByIfIndex(), nil, "", ModelNotPinned, logger)

			dev := CurrentDeviceFrom(ents)
			require.NotNil(t, dev, "the mapper still emits the device")
			require.NotNil(t, dev.Serial)
			assert.Equal(t, tc.want, *dev.Serial)
		})
	}
}
