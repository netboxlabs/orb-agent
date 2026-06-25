package mapping

import (
	"math"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

func TestListKeyAndLeaf(t *testing.T) {
	key, leaf, ok := listKeyAndLeaf(
		"/interfaces/interface[name=Ethernet1]/state/mtu",
		"/interfaces/interface")
	require.True(t, ok)
	require.Equal(t, "Ethernet1", key)
	require.Equal(t, "state/mtu", leaf)
}

func TestListKeyAndLeafNonMatch(t *testing.T) {
	_, _, ok := listKeyAndLeaf("/system/state/hostname", "/interfaces/interface")
	require.False(t, ok)
}

func TestListKeyAndLeafSlashInName(t *testing.T) {
	// Key value contains a slash (e.g. "Ethernet1/1"); split must happen on ']'
	// not on '/', so the full key and the correct leaf are recovered.
	key, leaf, ok := listKeyAndLeaf(
		"/interfaces/interface[name=Ethernet1/1]/state/mtu",
		"/interfaces/interface")
	require.True(t, ok)
	require.Equal(t, "Ethernet1/1", key)
	require.Equal(t, "state/mtu", leaf)
}

func TestTranslateDeviceAndInterfaces(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	snap := map[string]any{
		"/system/state/hostname":                                     "spine1",
		"/system/state/software-version":                             "4.30.1F",
		"/interfaces/interface[name=Ethernet1]/config/description":   "uplink",
		"/interfaces/interface[name=Ethernet1]/state/admin-status":   "UP",
		"/interfaces/interface[name=Ethernet1]/state/mtu":            9214,
		"/interfaces/interface[name=Management1]/state/admin-status": "UP",
	}
	defaults := &config.Defaults{Site: "lab", Role: "spine", Interface: config.InterfaceDefaults{Type: "other"}}

	entities := Translate(base, snap, defaults, "")

	var dev *diode.Device
	ifaceNames := map[string]bool{}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			dev = v
		case *diode.Interface:
			ifaceNames[*v.Name] = true
		}
	}
	require.NotNil(t, dev)
	require.Equal(t, "spine1", *dev.Name)
	require.True(t, ifaceNames["Ethernet1"])
	require.True(t, ifaceNames["Management1"])
}

func TestTranslateAppliesRichDefaults(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	snap := map[string]any{
		"/system/state/hostname":                                   "spine1",
		"/interfaces/interface[name=Ethernet1]/state/admin-status": "UP",
	}
	defaults := &config.Defaults{
		Site: "lab", Role: "spine", Location: "rack-1",
		Tags:      []string{"managed"},
		Device:    config.DeviceDefaults{Comments: "auto-discovered", Tags: []string{"gnmi"}},
		Interface: config.InterfaceDefaults{Type: "other", Description: "discovered", Tags: []string{"if-tag"}},
	}
	entities := Translate(base, snap, defaults, "")
	dev := entities[0].(*diode.Device)
	require.Equal(t, "auto-discovered", *dev.Comments)
	require.NotNil(t, dev.Location)
	require.Equal(t, "rack-1", *dev.Location.Name)
	require.Same(t, dev.Site, dev.Location.Site) // location scoped to the device's site
	devTags := map[string]bool{}
	for _, tg := range dev.Tags {
		devTags[*tg.Name] = true
	}
	require.True(t, devTags["managed"] && devTags["gnmi"])

	var eth *diode.Interface
	for _, e := range entities {
		if i, ok := e.(*diode.Interface); ok && *i.Name == "Ethernet1" {
			eth = i
		}
	}
	require.NotNil(t, eth)
	require.Equal(t, "discovered", *eth.Description) // default applied (no leaf description present)
	// Interface tags = global defaults.tags + interface-level tags (defaults.tags
	// applies to all entities, like the Device path above).
	ifTags := map[string]bool{}
	for _, tg := range eth.Tags {
		ifTags[*tg.Name] = true
	}
	require.Len(t, eth.Tags, 2)
	require.True(t, ifTags["managed"] && ifTags["if-tag"])
}

// TestToInt64PtrUintTypes verifies that uint variants (as produced by the gNMI
// UintVal decoder for OpenConfig mtu) are correctly converted rather than
// silently dropped to nil.
func TestToInt64PtrUintTypes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int64
	}{
		{"uint", uint(9000), 9000},
		{"uint8", uint8(255), 255},
		{"uint16", uint16(1500), 1500},
		{"uint32", uint32(65535), 65535},
		{"uint64", uint64(9000), 9000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toInt64Ptr(tc.in)
			require.NotNil(t, got, "toInt64Ptr returned nil for %T(%v)", tc.in, tc.in)
			require.Equal(t, tc.want, *got)
		})
	}
}

// TestToInt64PtrFloatGuard verifies that finite in-range floats convert but
// NaN/Inf/out-of-int64-range floats return nil (an out-of-range float -> int64
// is implementation-defined in Go, so a hostile MTU must not slip through).
func TestToInt64PtrFloatGuard(t *testing.T) {
	require.Equal(t, int64(9000), *toInt64Ptr(float64(9000)))
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 1e300, -1e300} {
		require.Nil(t, toInt64Ptr(bad), "toInt64Ptr(%v) must be nil", bad)
	}
	// uint/uint64 > MaxInt64 would wrap to a negative int64 — must return nil.
	require.Nil(t, toInt64Ptr(uint64(math.MaxInt64)+1))
	require.Nil(t, toInt64Ptr(uint(math.MaxInt64)+1))
	require.Equal(t, int64(math.MaxInt64), *toInt64Ptr(uint64(math.MaxInt64)))
}

// TestTranslateUint64Mtu verifies that a uint64 mtu value from gNMI (the type
// returned by decodeTypedValue for UintVal) is propagated to the Interface.Mtu
// field instead of being silently dropped.
func TestTranslateUint64Mtu(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/state/mtu": uint64(9000),
	}
	entities := Translate(base, snap, nil, "")
	var eth *diode.Interface
	for _, e := range entities {
		if i, ok := e.(*diode.Interface); ok && *i.Name == "Ethernet1" {
			eth = i
		}
	}
	require.NotNil(t, eth)
	require.NotNil(t, eth.Mtu, "mtu must not be nil for uint64 gNMI value")
	require.Equal(t, int64(9000), *eth.Mtu)
}

func TestTranslateDeviceSerialAndVersion(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	// Base snapshot: hostname + software version + a CHASSIS component carrying
	// the device's own serial.
	chassisSnap := func() map[string]any {
		return map[string]any{
			"/system/state/hostname":                               "spine1",
			"/system/state/software-version":                       "4.30.1F",
			"/components/component[name=Chassis1]/state/type":      "CHASSIS",
			"/components/component[name=Chassis1]/state/serial-no": "JPE-CHASSIS-1",
		}
	}

	t.Run("platform default + version", func(t *testing.T) {
		entities := Translate(base, chassisSnap(),
			&config.Defaults{Device: config.DeviceDefaults{Platform: "Arista EOS"}}, "")
		dev := entities[0].(*diode.Device)
		require.NotNil(t, dev.Serial)
		require.Equal(t, "JPE-CHASSIS-1", *dev.Serial)
		require.NotNil(t, dev.Platform)
		require.Equal(t, "Arista EOS 4.30.1F", *dev.Platform.Name)
		// No manufacturer default, no chassis mfg-name, no vendor — the resolved
		// device manufacturer is "Unknown" and Platform carries it.
		require.NotNil(t, dev.Platform.Manufacturer)
		require.Equal(t, "Unknown", *dev.Platform.Manufacturer.Name)

		// The CHASSIS component must NOT surface as a Module/ModuleBay.
		for _, e := range entities {
			switch v := e.(type) {
			case *diode.Module:
				require.NotEqual(t, "Chassis1", *v.ModuleBay.Name)
			case *diode.ModuleBay:
				require.NotEqual(t, "Chassis1", *v.Name)
			}
		}
	})

	t.Run("platform + manufacturer default attached to Platform", func(t *testing.T) {
		entities := Translate(base, chassisSnap(),
			&config.Defaults{Device: config.DeviceDefaults{Platform: "Arista EOS", Manufacturer: "Arista"}}, "")
		dev := entities[0].(*diode.Device)
		require.NotNil(t, dev.Platform)
		require.Equal(t, "Arista EOS 4.30.1F", *dev.Platform.Name)
		require.NotNil(t, dev.Platform.Manufacturer)
		require.Equal(t, "Arista", *dev.Platform.Manufacturer.Name)
		// DeviceType must reference the same manufacturer name.
		require.NotNil(t, dev.DeviceType)
		require.Equal(t, "Arista", *dev.DeviceType.Manufacturer.Name)
	})

	t.Run("version only (no platform default)", func(t *testing.T) {
		entities := Translate(base, chassisSnap(), &config.Defaults{}, "")
		dev := entities[0].(*diode.Device)
		require.NotNil(t, dev.Platform)
		require.Equal(t, "4.30.1F", *dev.Platform.Name)
		require.NotNil(t, dev.Serial)
		require.Equal(t, "JPE-CHASSIS-1", *dev.Serial)
	})

	t.Run("platform default only (no version leaf) preserves prior behavior", func(t *testing.T) {
		snap := map[string]any{"/system/state/hostname": "spine1"}
		entities := Translate(base, snap,
			&config.Defaults{Device: config.DeviceDefaults{Platform: "Arista EOS"}}, "")
		dev := entities[0].(*diode.Device)
		require.NotNil(t, dev.Platform)
		require.Equal(t, "Arista EOS", *dev.Platform.Name)
		require.Nil(t, dev.Serial)
	})

	t.Run("neither platform default nor version", func(t *testing.T) {
		snap := map[string]any{"/system/state/hostname": "spine1"}
		entities := Translate(base, snap, &config.Defaults{}, "")
		dev := entities[0].(*diode.Device)
		require.Nil(t, dev.Platform)
		require.Nil(t, dev.Serial)
	})
}

// ifaceByName extracts the named Interface entity from a translation result, or
// nil if it was not emitted.
func ifaceByName(entities []diode.Entity, name string) *diode.Interface {
	for _, e := range entities {
		if i, ok := e.(*diode.Interface); ok && *i.Name == name {
			return i
		}
	}
	return nil
}

// TestTranslateInterfaceTypeFromOpenConfig verifies the OpenConfig state/type ->
// NetBox type map (lag/virtual), and that ethernetCsmacd (no media in the OC
// type) falls through to the policy default, or "other" with no default.
func TestTranslateInterfaceTypeFromOpenConfig(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	snap := map[string]any{
		"/interfaces/interface[name=Port-Channel1]/state/type": "iana-if-type:ieee8023adLag",
		"/interfaces/interface[name=Loopback0]/state/type":     "iana-if-type:softwareLoopback",
		"/interfaces/interface[name=Ethernet1]/state/type":     "iana-if-type:ethernetCsmacd",
	}

	t.Run("lag and virtual from OC type; ethernet falls to default", func(t *testing.T) {
		entities := Translate(base, snap,
			&config.Defaults{Interface: config.InterfaceDefaults{Type: "1000base-t"}}, "")
		require.Equal(t, "lag", *ifaceByName(entities, "Port-Channel1").Type)
		require.Equal(t, "virtual", *ifaceByName(entities, "Loopback0").Type)
		// ethernetCsmacd is intentionally not in the OC map -> policy default.
		require.Equal(t, "1000base-t", *ifaceByName(entities, "Ethernet1").Type)
	})

	t.Run("ethernet with no default -> other", func(t *testing.T) {
		// nil defaults -> default type "other"; lag/virtual still resolve from OC.
		entities := Translate(base, snap, nil, "")
		require.Equal(t, "lag", *ifaceByName(entities, "Port-Channel1").Type)
		require.Equal(t, "virtual", *ifaceByName(entities, "Loopback0").Type)
		require.Equal(t, "other", *ifaceByName(entities, "Ethernet1").Type)
	})
}

// TestTranslateInterfacePatterns verifies user interface_patterns (name regex ->
// NetBox type) win over both the OC-type map and the policy default.
func TestTranslateInterfacePatterns(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/state/type": "iana-if-type:ethernetCsmacd",
		// Port-Channel1 reports an OC lag type, but a user pattern must win.
		"/interfaces/interface[name=Port-Channel1]/state/type": "iana-if-type:ieee8023adLag",
	}
	defaults := &config.Defaults{
		Interface: config.InterfaceDefaults{Type: "other"},
		InterfacePatterns: []config.InterfacePattern{
			{Match: "^Ethernet", Type: "10gbase-x-sfpp"},
			{Match: "^Port-Channel", Type: "lag-override"},
		},
	}
	entities := Translate(base, snap, defaults, "")
	// Pattern beats the (absent) OC-type entry and the default.
	require.Equal(t, "10gbase-x-sfpp", *ifaceByName(entities, "Ethernet1").Type)
	// Pattern beats the OC-type map even when both could apply.
	require.Equal(t, "lag-override", *ifaceByName(entities, "Port-Channel1").Type)
}

// TestTranslateInterfaceExclude verifies interface_exclude_patterns drop the
// interface entirely (no Interface entity) while non-matching interfaces remain.
func TestTranslateInterfaceExclude(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	snap := map[string]any{
		"/interfaces/interface[name=Management1]/state/admin-status": "UP",
		"/interfaces/interface[name=Ethernet1]/state/admin-status":   "UP",
	}
	defaults := &config.Defaults{
		Interface:                config.InterfaceDefaults{Type: "other"},
		InterfaceExcludePatterns: []string{"^Management"},
	}
	entities := Translate(base, snap, defaults, "")
	require.Nil(t, ifaceByName(entities, "Management1"), "excluded interface must not be emitted")
	require.NotNil(t, ifaceByName(entities, "Ethernet1"))
}

func TestTranslateComponents(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	snap := map[string]any{
		"/system/state/hostname":                                "spine1",
		"/components/component[name=Linecard1]/state/type":      "LINECARD",
		"/components/component[name=Linecard1]/state/serial-no": "JPE123",
		"/components/component[name=Linecard1]/state/part-no":   "DCS-7500",
		"/components/component[name=PowerSupply1]/state/type":   "POWER_SUPPLY",
	}
	entities := Translate(base, snap, &config.Defaults{Device: config.DeviceDefaults{Manufacturer: "Arista"}}, "")
	var modules []*diode.Module
	var bays []*diode.ModuleBay
	bayIdx, modIdx := -1, -1
	for i, e := range entities {
		switch v := e.(type) {
		case *diode.Module:
			modules = append(modules, v)
			modIdx = i
		case *diode.ModuleBay:
			bays = append(bays, v)
			if bayIdx == -1 {
				bayIdx = i
			}
		}
	}
	// Only inventory-bearing components (LINECARD) are emitted; PSU is classified
	// but dropped in the MVP. Each emits a standalone ModuleBay AND a Module.
	require.Len(t, modules, 1)
	require.Len(t, bays, 1)
	require.Less(t, bayIdx, modIdx, "ModuleBay must be emitted before its Module")
	require.Equal(t, "JPE123", *modules[0].Serial)
	require.Equal(t, "DCS-7500", *modules[0].ModuleType.Model)
	require.Equal(t, "Arista", *modules[0].ModuleType.Manufacturer.Name)
	require.Equal(t, "Linecard1", *bays[0].Name)
}

// TestComponentTypeIdentityref verifies that the JSON_IETF-serialized identityref
// form of /components/component/state/type (module-prefixed, e.g.
// "openconfig-platform-types:CHASSIS") is normalized identically to the bare form
// ("CHASSIS"). Without prefix-stripping, exact upper-case equality fails and the
// chassis serial/manufacturer/model are silently lost AND every Module/ModuleBay
// is silently dropped. This test FAILS against the pre-fix exact-equality code.
func TestComponentTypeIdentityref(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	// Same topology as the bare-form tests, but with prefixed identityref types.
	snap := map[string]any{
		"/system/state/hostname":                                "spine1",
		"/components/component[name=Chassis1]/state/type":       "openconfig-platform-types:CHASSIS",
		"/components/component[name=Chassis1]/state/serial-no":  "JPE-CHASSIS-1",
		"/components/component[name=Chassis1]/state/part-no":    "DCS-7050",
		"/components/component[name=Chassis1]/state/mfg-name":   "Arista",
		"/components/component[name=Linecard1]/state/type":      "openconfig-platform-types:LINECARD",
		"/components/component[name=Linecard1]/state/serial-no": "JPE123",
		"/components/component[name=Linecard1]/state/part-no":   "DCS-LC",
		"/components/component[name=Xcvr1]/state/type":          "openconfig-platform-types:TRANSCEIVER",
		"/components/component[name=Xcvr1]/state/mfg-name":      "Finisar",
		"/components/component[name=Xcvr1]/state/part-no":       "FTLX",
	}
	entities := Translate(base, snap, &config.Defaults{}, "")

	dev := entities[0].(*diode.Device)
	require.NotNil(t, dev.Serial)
	require.Equal(t, "JPE-CHASSIS-1", *dev.Serial, "chassis serial must resolve from prefixed type")
	require.NotNil(t, dev.DeviceType)
	require.Equal(t, "Arista", *dev.DeviceType.Manufacturer.Name, "chassis mfg-name must resolve from prefixed type")
	require.Equal(t, "DCS-7050", *dev.DeviceType.Model, "chassis part-no must resolve from prefixed type")

	// Modules/ModuleBays must still be emitted for the prefixed LINECARD/TRANSCEIVER,
	// and the CHASSIS must NOT surface as a Module/ModuleBay.
	mods := map[string]*diode.Module{}
	bays := map[string]bool{}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Module:
			mods[*v.ModuleBay.Name] = v
		case *diode.ModuleBay:
			bays[*v.Name] = true
		}
	}
	require.Contains(t, mods, "Linecard1", "LINECARD must emit a Module from prefixed type")
	require.Contains(t, mods, "Xcvr1", "TRANSCEIVER must emit a Module from prefixed type")
	require.True(t, bays["Linecard1"] && bays["Xcvr1"])
	require.NotContains(t, mods, "Chassis1", "CHASSIS must not surface as a Module")
	require.False(t, bays["Chassis1"], "CHASSIS must not surface as a ModuleBay")
	// The transceiver carries its own mfg-name; the chassis manufacturer is Arista.
	require.Equal(t, "Finisar", *mods["Xcvr1"].ModuleType.Manufacturer.Name)
	require.Equal(t, "Arista", *mods["Linecard1"].ModuleType.Manufacturer.Name)
}

// TestTranslateDiscoversManufacturer exercises the manufacturer/model discovery
// precedence: policy default > chassis mfg-name (or part-no) > Capabilities
// vendor > "Unknown"; and per-component module manufacturer.
func TestTranslateDiscoversManufacturer(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")

	devOf := func(entities []diode.Entity) *diode.Device { return entities[0].(*diode.Device) }

	t.Run("chassis mfg-name discovered (no default)", func(t *testing.T) {
		snap := map[string]any{
			"/system/state/hostname":                              "spine1",
			"/system/state/software-version":                      "4.30.1F",
			"/components/component[name=Chassis1]/state/type":     "CHASSIS",
			"/components/component[name=Chassis1]/state/mfg-name": "Arista",
		}
		dev := devOf(Translate(base, snap,
			&config.Defaults{Device: config.DeviceDefaults{Platform: "Arista EOS"}}, ""))
		require.NotNil(t, dev.DeviceType)
		require.Equal(t, "Arista", *dev.DeviceType.Manufacturer.Name)
		require.NotNil(t, dev.Platform)
		require.NotNil(t, dev.Platform.Manufacturer)
		require.Equal(t, "Arista", *dev.Platform.Manufacturer.Name)
	})

	t.Run("capabilities vendor fallback (no mfg-name, no default)", func(t *testing.T) {
		snap := map[string]any{"/system/state/hostname": "r1"}
		dev := devOf(Translate(base, snap, &config.Defaults{}, "Nokia"))
		require.Equal(t, "Nokia", *dev.DeviceType.Manufacturer.Name)
	})

	t.Run("policy default overrides discovered", func(t *testing.T) {
		snap := map[string]any{
			"/system/state/hostname":                              "spine1",
			"/components/component[name=Chassis1]/state/type":     "CHASSIS",
			"/components/component[name=Chassis1]/state/mfg-name": "Arista",
		}
		dev := devOf(Translate(base, snap,
			&config.Defaults{Device: config.DeviceDefaults{Manufacturer: "OverrideCorp"}}, "Nokia"))
		require.Equal(t, "OverrideCorp", *dev.DeviceType.Manufacturer.Name)
	})

	t.Run("nothing discovered -> Unknown", func(t *testing.T) {
		snap := map[string]any{"/system/state/hostname": "r1"}
		dev := devOf(Translate(base, snap, &config.Defaults{}, ""))
		require.Equal(t, "Unknown", *dev.DeviceType.Manufacturer.Name)
		require.Equal(t, "Unknown", *dev.DeviceType.Model)
	})

	t.Run("chassis part-no -> DeviceType.Model (no model default)", func(t *testing.T) {
		snap := map[string]any{
			"/system/state/hostname":                             "spine1",
			"/components/component[name=Chassis1]/state/type":    "CHASSIS",
			"/components/component[name=Chassis1]/state/part-no": "DCS-7050",
		}
		dev := devOf(Translate(base, snap, &config.Defaults{}, ""))
		require.Equal(t, "DCS-7050", *dev.DeviceType.Model)
	})

	t.Run("model default overrides chassis part-no", func(t *testing.T) {
		snap := map[string]any{
			"/system/state/hostname":                             "spine1",
			"/components/component[name=Chassis1]/state/type":    "CHASSIS",
			"/components/component[name=Chassis1]/state/part-no": "DCS-7050",
		}
		dev := devOf(Translate(base, snap,
			&config.Defaults{Device: config.DeviceDefaults{Model: "ModelDefault"}}, ""))
		require.Equal(t, "ModelDefault", *dev.DeviceType.Model)
	})

	t.Run("per-component module manufacturer from its own mfg-name", func(t *testing.T) {
		// Chassis is Arista; a transceiver reports its own mfg-name "Finisar".
		snap := map[string]any{
			"/system/state/hostname":                              "spine1",
			"/components/component[name=Chassis1]/state/type":     "CHASSIS",
			"/components/component[name=Chassis1]/state/mfg-name": "Arista",
			"/components/component[name=Xcvr1]/state/type":        "TRANSCEIVER",
			"/components/component[name=Xcvr1]/state/mfg-name":    "Finisar",
			"/components/component[name=Xcvr1]/state/part-no":     "FTLX",
			"/components/component[name=Linecard1]/state/type":    "LINECARD",
		}
		entities := Translate(base, snap, &config.Defaults{}, "")
		mods := map[string]*diode.Module{}
		for _, e := range entities {
			if m, ok := e.(*diode.Module); ok {
				mods[*m.ModuleBay.Name] = m
			}
		}
		require.Contains(t, mods, "Xcvr1")
		require.Equal(t, "Finisar", *mods["Xcvr1"].ModuleType.Manufacturer.Name)
		// The linecard has no own mfg-name -> falls back to the device manufacturer.
		require.Contains(t, mods, "Linecard1")
		require.Equal(t, "Arista", *mods["Linecard1"].ModuleType.Manufacturer.Name)
	})
}

func TestTranslateInterfacesEnrichment(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	snap := map[string]any{
		// Ethernet1: 10G, real MAC, member of Port-Channel1
		"/interfaces/interface[name=Ethernet1]/state/type":                  "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet1]/ethernet/state/port-speed":   "openconfig-if-ethernet:SPEED_10GB",
		"/interfaces/interface[name=Ethernet1]/ethernet/state/mac-address":  "00:1c:73:00:00:01",
		"/interfaces/interface[name=Ethernet1]/ethernet/state/aggregate-id": "Port-Channel1",
		// Ethernet2: all-zero MAC -> skipped; 1G -> 1000base-t
		"/interfaces/interface[name=Ethernet2]/state/type":                 "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet2]/ethernet/state/port-speed":  "openconfig-if-ethernet:SPEED_1GB",
		"/interfaces/interface[name=Ethernet2]/ethernet/state/mac-address": "00:00:00:00:00:00",
		// Port-Channel1: OC lag type
		"/interfaces/interface[name=Port-Channel1]/state/type": "iana-if-type:ieee8023adLag",
	}
	ents := translateInterfaces(base, snap, dev, nil)
	byName := map[string]*diode.Interface{}
	for _, e := range ents {
		if i, ok := e.(*diode.Interface); ok {
			byName[*i.Name] = i
		}
	}

	e1 := byName["Ethernet1"]
	require.NotNil(t, e1)
	require.NotNil(t, e1.Speed)
	require.Equal(t, int64(10000000), *e1.Speed)
	require.NotNil(t, e1.PrimaryMacAddress)
	require.Equal(t, "00:1C:73:00:00:01", *e1.PrimaryMacAddress.MacAddress) // uppercased
	require.NotNil(t, e1.Lag)
	require.Equal(t, "Port-Channel1", *e1.Lag.Name)
	require.Nil(t, e1.Lag.Type)                  // matcher-only stub
	require.Equal(t, "10gbase-x-sfpp", *e1.Type) // speed-based (name has no media hint)

	e2 := byName["Ethernet2"]
	require.Nil(t, e2.PrimaryMacAddress) // all-zero MAC skipped
	require.Equal(t, "1000base-t", *e2.Type)

	po := byName["Port-Channel1"]
	require.Equal(t, "lag", *po.Type) // OC state/type
	require.Nil(t, po.Lag)            // the LAG itself has no aggregate-id
}

func TestTranslateInterfaceDuplex(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/state/type":                            "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet1]/ethernet/state/negotiated-duplex-mode": "FULL",
		"/interfaces/interface[name=Ethernet2]/state/type":                            "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet2]/ethernet/state/negotiated-duplex-mode": "HALF",
		"/interfaces/interface[name=Ethernet3]/state/type":                            "iana-if-type:ethernetCsmacd",
	}
	ents := translateInterfaces(base, snap, dev, nil)
	byName := map[string]*diode.Interface{}
	for _, e := range ents {
		if i, ok := e.(*diode.Interface); ok {
			byName[*i.Name] = i
		}
	}
	require.NotNil(t, byName["Ethernet1"].Duplex)
	require.Equal(t, "full", *byName["Ethernet1"].Duplex)
	require.Equal(t, "half", *byName["Ethernet2"].Duplex)
	require.Nil(t, byName["Ethernet3"].Duplex)
}

func TestTranslateVlanNamesAndInventory(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	snap := map[string]any{
		"/system/state/hostname": "r1",
		// switchport references vid 10
		"/interfaces/interface[name=Ethernet1]/state/type":                                  "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/interface-mode": "ACCESS",
		"/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/access-vlan":    float64(10),
		// NI defines vid 10 (real name) and vid 99 (unreferenced)
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/name":   "users",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/status": "ACTIVE",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=99]/state/name":   "mgmt",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=99]/state/status": "SUSPENDED",
	}
	defaults := &config.Defaults{Site: "lab", Vlan: config.VlanDefaults{Group: "lab-vlans"}}
	ents := Translate(base, snap, defaults, "")
	vlans := map[int64]*diode.VLAN{}
	for _, e := range ents {
		if v, ok := e.(*diode.VLAN); ok {
			vlans[*v.Vid] = v
		}
	}
	require.Equal(t, "users", *vlans[10].Name) // real name from NI subtree
	require.Equal(t, "active", *vlans[10].Status)
	require.NotNil(t, vlans[99]) // defined-but-unreferenced still emitted
	require.Equal(t, "mgmt", *vlans[99].Name)
	require.Equal(t, "reserved", *vlans[99].Status)      // SUSPENDED -> reserved
	require.Equal(t, "lab-vlans", *vlans[10].Group.Name) // group default applied
}

// A self-referential aggregate-id (agg == own name) must not produce a self-LAG.
func TestTranslateInterfacesSelfLagGuard(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/state/type":                  "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet1]/ethernet/state/aggregate-id": "Ethernet1",
	}
	ents := translateInterfaces(base, snap, dev, nil)
	require.Len(t, ents, 1)
	require.Nil(t, ents[0].(*diode.Interface).Lag)
}

func TestTranslateVrfBinding(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	snap := map[string]any{
		"/system/state/hostname":                           "r1",
		"/interfaces/interface[name=Ethernet2]/state/type": "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet2]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length": float64(31),
		"/interfaces/interface[name=Ethernet1]/state/type":                                                     "iana-if-type:ethernetCsmacd",
		"/network-instances/network-instance[name=blue]/state/type":                                            "openconfig-network-instance-types:L3VRF",
		"/network-instances/network-instance[name=blue]/state/route-distinguisher":                             "65000:1",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/interface":    "Ethernet2",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/subinterface": float64(0),
		"/network-instances/network-instance[name=default]/state/type":                                         "openconfig-network-instance-types:DEFAULT_INSTANCE",
		"/network-instances/network-instance[name=default]/interfaces/interface[id=Ethernet1]/state/interface": "Ethernet1",
	}
	ents := Translate(base, snap, &config.Defaults{Site: "lab"}, "")

	var vrf *diode.VRF
	ifaces := map[string]*diode.Interface{}
	var ip *diode.IPAddress
	for _, e := range ents {
		switch v := e.(type) {
		case *diode.VRF:
			vrf = v
		case *diode.Interface:
			ifaces[*v.Name] = v
		case *diode.IPAddress:
			ip = v
		}
	}
	require.NotNil(t, vrf)
	require.Equal(t, "blue", *vrf.Name)
	require.NotNil(t, ifaces["Ethernet2"].Vrf)
	require.Equal(t, "blue", *ifaces["Ethernet2"].Vrf.Name)
	require.Same(t, vrf, ifaces["Ethernet2"].Vrf)
	require.Nil(t, ifaces["Ethernet1"].Vrf)
	require.NotNil(t, ip)
	require.NotNil(t, ip.Vrf)
	require.Equal(t, "blue", *ip.Vrf.Name)
}

func TestTranslateEmitsPrefixes(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	snap := map[string]any{
		"/system/state/hostname":                           "r1",
		"/interfaces/interface[name=Ethernet2]/state/type": "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet2]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length": float64(31),
		"/network-instances/network-instance[name=blue]/state/type":                                                                         "openconfig-network-instance-types:L3VRF",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/interface":                                 "Ethernet2",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/subinterface":                              float64(0),
	}
	ents := Translate(base, snap, &config.Defaults{Site: "lab", Prefix: config.PrefixDefaults{Role: "mgmt"}}, "")
	var pfx *diode.Prefix
	for _, e := range ents {
		if p, ok := e.(*diode.Prefix); ok {
			pfx = p
		}
	}
	require.NotNil(t, pfx)
	require.Equal(t, "10.0.0.0/31", *pfx.Prefix)
	require.Equal(t, "lab", *pfx.Scope.(*diode.Site).Name)
	require.Equal(t, "mgmt", *pfx.Role.Name)
	require.NotNil(t, pfx.Vrf)
	require.Equal(t, "blue", *pfx.Vrf.Name) // VRF inherited from the IP (bound before the prefix pass)
}
