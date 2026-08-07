package mapping

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyDeviceNameEmission(t *testing.T) {
	logger := slog.Default()
	const host = "10.0.0.1"

	sourceMatch := func() diode.Metadata {
		return diode.Metadata{"source_match": diode.Metadata{"netbox_id": 123}}
	}
	ents := func(dev *diode.Device) []diode.Entity { return []diode.Entity{dev} }

	t.Run("emit enabled leaves name untouched", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), Serial: StringPtr("FCW123")}
		ApplyDeviceNameEmission(ents(dev), dev, true, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + source_match clears name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), Metadata: sourceMatch()}
		ApplyDeviceNameEmission(ents(dev), dev, false, host, logger)
		assert.Nil(t, dev.Name)
	})

	t.Run("disabled + asset_tag clears name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), AssetTag: StringPtr("ASSET-1")}
		ApplyDeviceNameEmission(ents(dev), dev, false, host, logger)
		assert.Nil(t, dev.Name)
	})

	t.Run("disabled + serial only keeps name (serial is not a stub-carried matcher)", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), Serial: StringPtr("FCW123")}
		ApplyDeviceNameEmission(ents(dev), dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + no matcher keeps name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1")}
		ApplyDeviceNameEmission(ents(dev), dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + blank asset_tag keeps name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), AssetTag: StringPtr("  ")}
		ApplyDeviceNameEmission(ents(dev), dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + nil name is a no-op", func(t *testing.T) {
		dev := &diode.Device{Metadata: sourceMatch()}
		ApplyDeviceNameEmission(ents(dev), dev, false, host, logger)
		assert.Nil(t, dev.Name)
	})

	t.Run("disabled + virtual-chassis member untouched", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1-2"), VcPosition: int64Ptr(2), Metadata: sourceMatch()}
		ApplyDeviceNameEmission(ents(dev), dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1-2", *dev.Name)
	})

	t.Run("nil device does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ApplyDeviceNameEmission(nil, nil, false, host, logger)
		})
	})

	t.Run("nil logger, no matcher, does not panic (WARN branch)", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1")}
		assert.NotPanics(t, func() {
			ApplyDeviceNameEmission(ents(dev), dev, false, host, nil)
		})
		require.NotNil(t, dev.Name)
	})

	t.Run("nil logger, matcher present, clears name (Debug branch)", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), Metadata: sourceMatch()}
		assert.NotPanics(t, func() {
			ApplyDeviceNameEmission(ents(dev), dev, false, host, nil)
		})
		assert.Nil(t, dev.Name)
	})
}

// TestApplyDeviceNameEmission_VirtualChassis proves the master's name is
// suppressed across every representation on a stack — the rich master AND
// the shared VirtualChassis.Master matcher ref carried by the top-level VC
// entity and by every member — while member names and the VC name are
// preserved and the ref stays matchable via source_match.
func TestApplyDeviceNameEmission_VirtualChassis(t *testing.T) {
	logger := slog.Default()
	const host = "10.0.0.1"

	newRef := func() *diode.Device {
		return &diode.Device{Name: StringPtr("stack-sysname"), Metadata: diode.Metadata{"source_match": diode.Metadata{"netbox_id": 7}}}
	}
	master := &diode.Device{Name: StringPtr("stack-sysname"), Metadata: diode.Metadata{"source_match": diode.Metadata{"netbox_id": 7}}}
	// Real emission shares ONE masterRef across the VC entity and every
	// member; here we give the VC entity and the member DISTINCT refs so
	// each clearing branch (VirtualChassis and Device.VirtualChassis) is
	// exercised independently — a shared ref would let one branch mask the
	// other. Both mirror buildMasterRef: a matcher ref that pointer-copies
	// the name into its own field and carries source_match.
	vcRef := newRef()
	memberRef := newRef()
	vcName := "stack"
	member2 := &diode.Device{
		Name:           StringPtr("stack-2"),
		VcPosition:     int64Ptr(2),
		VirtualChassis: &diode.VirtualChassis{Name: &vcName, Master: memberRef},
	}
	vc := &diode.VirtualChassis{Name: &vcName, Master: vcRef}

	entities := []diode.Entity{master, vc, member2}
	ApplyDeviceNameEmission(entities, master, false, host, logger)

	assert.Nil(t, master.Name, "master rich device name suppressed")
	assert.Nil(t, vcRef.Name, "VC-entity master ref name suppressed")
	assert.Nil(t, memberRef.Name, "member master ref name suppressed")
	require.NotNil(t, member2.Name, "member name preserved")
	assert.Equal(t, "stack-2", *member2.Name)
	require.NotNil(t, vc.Name, "VC name preserved")
	assert.Equal(t, "stack", *vc.Name)
	_, vcOK := vcRef.Metadata["source_match"]
	assert.True(t, vcOK, "master ref stays matchable via source_match")
}

// TestApplyDeviceNameEmission_StubsStayMatchable pins the guard<->stub
// coupling: after the name is suppressed, PruneNestedRefs must leave every
// nested device stub carrying a surviving matcher (source_match or
// asset_tag) and no name. Guards against a future newDeviceStub change
// silently orphaning stubs.
func TestApplyDeviceNameEmission_StubsStayMatchable(t *testing.T) {
	logger := slog.Default()
	const host = "10.0.0.1"

	build := func(withSourceMatch bool) []diode.Entity {
		dev := &diode.Device{Name: StringPtr("sw1")}
		if withSourceMatch {
			dev.Metadata = diode.Metadata{"source_match": diode.Metadata{"netbox_id": 5}}
		} else {
			dev.AssetTag = StringPtr("ASSET-9")
		}
		iface := &diode.Interface{Name: StringPtr("Gi0/1"), Device: dev}
		// A primary IP, so the device's PrimaryIp4 snapshot is covered too. That
		// snapshot is a shallow copy taken during mapping, before suppression
		// runs, so it is the one derived copy that can re-supply the hostname.
		addr := "10.0.0.1/24"
		dev.PrimaryIp4 = detachForPrimaryIP(&diode.IPAddress{
			Address:        &addr,
			AssignedObject: &diode.Interface{Name: StringPtr("Vlan10"), Device: dev},
		}, dev)
		// Both families, so the assertion loop below is not silently v4-only.
		addr6 := "2001:db8::1/64"
		dev.PrimaryIp6 = detachForPrimaryIP6(&diode.IPAddress{
			Address:        &addr6,
			AssignedObject: &diode.Interface{Name: StringPtr("Vlan10"), Device: dev},
		}, dev)
		return []diode.Entity{dev, iface}
	}

	assertStubMatchable := func(t *testing.T, entities []diode.Entity) {
		t.Helper()
		dev := CurrentDeviceFrom(entities)
		ApplyDeviceNameEmission(entities, dev, false, host, logger)
		require.Nil(t, dev.Name, "top-level device name suppressed")
		PruneNestedRefs(entities, dev, nil)
		assertStub := func(stub *diode.Device, where string) {
			assert.Nil(t, stub.Name, where+": nested device stub must not carry a name once suppressed")
			_, hasSM := stub.Metadata["source_match"]
			hasTag := stub.AssetTag != nil && strings.TrimSpace(*stub.AssetTag) != ""
			assert.True(t, hasSM || hasTag, where+": nested device stub must keep a surviving matcher (source_match or asset_tag)")
		}
		for _, e := range entities {
			iface, ok := e.(*diode.Interface)
			if !ok || iface == nil || iface.Device == nil {
				continue
			}
			assertStub(iface.Device, "interface.device")
		}
		// The primary-IP snapshots are nested refs too, and are NOT reachable
		// from the loop above: the IP-assigned interface is deliberately absent
		// from the top-level entity slice.
		for where, ip := range map[string]*diode.IPAddress{
			"primary_ip4": dev.PrimaryIp4,
			"primary_ip6": dev.PrimaryIp6,
		} {
			if ip == nil {
				continue
			}
			if iface, ok := ip.AssignedObject.(*diode.Interface); ok && iface != nil && iface.Device != nil {
				assertStub(iface.Device, where)
			}
		}
	}

	t.Run("source_match device", func(t *testing.T) { assertStubMatchable(t, build(true)) })
	t.Run("asset_tag device", func(t *testing.T) { assertStubMatchable(t, build(false)) })
}

// TestApplyDeviceNameEmission_WarnLogged asserts the guard emits a WARN
// record (not just retains the name) when suppression is requested but no
// qualifying matcher is present.
func TestApplyDeviceNameEmission_WarnLogged(t *testing.T) {
	const host = "10.0.0.1"
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dev := &diode.Device{Name: StringPtr("sw1")} // no matcher
	ApplyDeviceNameEmission([]diode.Entity{dev}, dev, false, host, logger)

	out := buf.String()
	assert.Contains(t, out, "level=WARN")
	assert.Contains(t, out, "emit_device_name disabled but device has no alternative matcher")
	require.NotNil(t, dev.Name)
}
