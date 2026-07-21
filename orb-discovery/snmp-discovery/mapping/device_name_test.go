package mapping

import (
	"log/slog"
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

	t.Run("emit enabled leaves name untouched", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), Serial: StringPtr("FCW123")}
		ApplyDeviceNameEmission(dev, true, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + source_match clears name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), Metadata: sourceMatch()}
		ApplyDeviceNameEmission(dev, false, host, logger)
		assert.Nil(t, dev.Name)
	})

	t.Run("disabled + asset_tag clears name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), AssetTag: StringPtr("ASSET-1")}
		ApplyDeviceNameEmission(dev, false, host, logger)
		assert.Nil(t, dev.Name)
	})

	t.Run("disabled + serial only keeps name (serial is not a stub-carried matcher)", func(t *testing.T) {
		// Serial deliberately does NOT qualify: newDeviceStub omits Serial,
		// so clearing the name would orphan the nested device stubs.
		dev := &diode.Device{Name: StringPtr("sw1"), Serial: StringPtr("FCW123")}
		ApplyDeviceNameEmission(dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + no matcher keeps name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1")}
		ApplyDeviceNameEmission(dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + blank asset_tag keeps name", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), AssetTag: StringPtr("  ")}
		ApplyDeviceNameEmission(dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1", *dev.Name)
	})

	t.Run("disabled + nil name is a no-op", func(t *testing.T) {
		dev := &diode.Device{Metadata: sourceMatch()}
		ApplyDeviceNameEmission(dev, false, host, logger)
		assert.Nil(t, dev.Name)
	})

	t.Run("disabled + virtual-chassis member untouched", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1-2"), VcPosition: int64Ptr(2), Metadata: sourceMatch()}
		ApplyDeviceNameEmission(dev, false, host, logger)
		require.NotNil(t, dev.Name)
		assert.Equal(t, "sw1-2", *dev.Name)
	})

	t.Run("nil device does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ApplyDeviceNameEmission(nil, false, host, logger)
		})
	})

	t.Run("nil logger, no matcher, does not panic (WARN branch)", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1")}
		assert.NotPanics(t, func() {
			ApplyDeviceNameEmission(dev, false, host, nil)
		})
		require.NotNil(t, dev.Name) // no matcher -> kept, and no panic on the nil-logger WARN path
	})

	t.Run("nil logger, matcher present, clears name (Debug branch)", func(t *testing.T) {
		dev := &diode.Device{Name: StringPtr("sw1"), Metadata: sourceMatch()}
		assert.NotPanics(t, func() {
			ApplyDeviceNameEmission(dev, false, host, nil)
		})
		assert.Nil(t, dev.Name) // cleared, and no panic on the nil-logger Debug path
	})
}
