package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// rackDevice translates a one-leaf snapshot with defaults and returns the device.
func rackDevice(t *testing.T, defaults *config.Defaults) *diode.Device {
	t.Helper()
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	dev, _ := translateDevice(base, map[string]any{"/system/state/hostname": "leaf1"}, defaults, "")
	return dev
}

func TestTranslateDeviceRack(t *testing.T) {
	t.Run("the rack carries the device's site and location", func(t *testing.T) {
		dev := rackDevice(t, &config.Defaults{Site: "DC1", Location: "Hall 1", Rack: "R12"})
		require.NotNil(t, dev.Rack)
		require.Equal(t, "R12", *dev.Rack.Name)
		require.NotNil(t, dev.Site)
		require.Same(t, dev.Site, dev.Rack.Site)
		require.NotNil(t, dev.Location)
		require.Same(t, dev.Location, dev.Rack.Location)
	})

	t.Run("without a location the rack carries the site only", func(t *testing.T) {
		dev := rackDevice(t, &config.Defaults{Site: "DC1", Rack: "R12"})
		require.NotNil(t, dev.Rack)
		require.Same(t, dev.Site, dev.Rack.Site)
		require.Nil(t, dev.Rack.Location)
	})

	t.Run("the rack name is trimmed", func(t *testing.T) {
		dev := rackDevice(t, &config.Defaults{Site: "DC1", Rack: " R12 "})
		require.NotNil(t, dev.Rack)
		require.Equal(t, "R12", *dev.Rack.Name)
	})

	t.Run("a blank rack is unset", func(t *testing.T) {
		dev := rackDevice(t, &config.Defaults{Site: "DC1", Rack: "  "})
		require.Nil(t, dev.Rack)
	})

	t.Run("position and face are set, face lower-cased", func(t *testing.T) {
		pos := 40.5
		defaults := &config.Defaults{Site: "DC1", Rack: "R12", Position: &pos, Face: " FRONT "}
		dev := rackDevice(t, defaults)
		require.NotNil(t, dev.Position)
		require.InDelta(t, 40.5, *dev.Position, 0)
		require.NotNil(t, dev.Face)
		require.Equal(t, "front", *dev.Face)

		*dev.Position = 1
		require.InDelta(t, 40.5, pos, 0, "the emitted position must not alias the policy config")
	})

	t.Run("a rack alone sets no position or face", func(t *testing.T) {
		dev := rackDevice(t, &config.Defaults{Site: "DC1", Rack: "R12"})
		require.Nil(t, dev.Position)
		require.Nil(t, dev.Face)
	})

	t.Run("position and face without a rack are not emitted", func(t *testing.T) {
		pos := 40.0
		dev := rackDevice(t, &config.Defaults{Site: "DC1", Position: &pos, Face: "rear"})
		require.Nil(t, dev.Rack)
		require.Nil(t, dev.Position)
		require.Nil(t, dev.Face)
	})

	t.Run("nothing is set when unset", func(t *testing.T) {
		dev := rackDevice(t, &config.Defaults{Site: "DC1", Location: "Hall 1"})
		require.Nil(t, dev.Rack)
		require.Nil(t, dev.Position)
		require.Nil(t, dev.Face)
	})
}

// Placement rides on the top-level Device only. A nested reference is a
// matcher stub, and name and site already precede rack, position and face in
// Diode's device matchers.
func TestNestedDeviceRefsCarryNoRackPlacement(t *testing.T) {
	pos := 40.0
	dev := &diode.Device{
		Name:       strptr("leaf1"),
		Site:       &diode.Site{Name: strptr("DC1")},
		DeviceType: &diode.DeviceType{Model: strptr("X"), Manufacturer: &diode.Manufacturer{Name: strptr("Acme")}},
		Role:       &diode.DeviceRole{Name: strptr("leaf")},
		Rack:       &diode.Rack{Name: strptr("R12")},
		Position:   &pos,
		Face:       strptr("front"),
	}
	stub := newDeviceStub(dev)
	require.Nil(t, stub.Rack)
	require.Nil(t, stub.Position)
	require.Nil(t, stub.Face)

	eth := &diode.Interface{Name: strptr("Ethernet1"), Device: dev, Type: strptr("other")}
	PruneNestedRefs([]diode.Entity{dev, eth}, dev, nil)
	require.NotNil(t, dev.Rack, "the top-level device keeps its placement")
	require.NotNil(t, eth.Device)
	require.Nil(t, eth.Device.Rack)
	require.Nil(t, eth.Device.Position)
	require.Nil(t, eth.Device.Face)
}
