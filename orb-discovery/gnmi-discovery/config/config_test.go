package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMergeDefaults(t *testing.T) {
	t.Run("nil override returns policy defaults and result is not aliased to source", func(t *testing.T) {
		policy := &Defaults{
			Site: "NYC",
			Tags: []string{"a", "b"},
			Device: DeviceDefaults{
				Tags: []string{"d1"},
			},
			Interface: InterfaceDefaults{
				Tags: []string{"i1"},
			},
		}
		result := MergeDefaults(policy, nil)
		require.Equal(t, policy.Site, result.Site)
		require.Equal(t, policy.Tags, result.Tags)

		// Mutating result must not affect the original policy defaults.
		result.Tags = append(result.Tags, "injected")
		require.NotContains(t, policy.Tags, "injected", "result.Tags must not alias policy.Tags")

		result.Device.Tags = append(result.Device.Tags, "injected")
		require.NotContains(t, policy.Device.Tags, "injected", "result.Device.Tags must not alias policy.Device.Tags")

		result.Interface.Tags = append(result.Interface.Tags, "injected")
		require.NotContains(t, policy.Interface.Tags, "injected", "result.Interface.Tags must not alias policy.Interface.Tags")
	})

	t.Run("nil policyDefaults with non-nil override does not panic", func(t *testing.T) {
		override := &Defaults{Site: "LA", Role: "Leaf"}
		result := MergeDefaults(nil, override)
		require.NotNil(t, result)
		require.Equal(t, "LA", result.Site)
	})

	t.Run("override sets scalar fields; unset fields fall back to policy", func(t *testing.T) {
		policy := &Defaults{
			Site:     "NYC",
			Role:     "Spine",
			Location: "DC-1",
			Device: DeviceDefaults{
				Manufacturer: "Arista",
				Model:        "7050CX3",
				Platform:     "EOS",
				Comments:     "old comment",
			},
			Interface: InterfaceDefaults{
				Type:        "1000base-t",
				Description: "uplink",
			},
		}
		override := &Defaults{
			Site: "LA",
			Role: "Leaf",
			Device: DeviceDefaults{
				Model:    "7280R3",
				Comments: "new comment",
			},
			Interface: InterfaceDefaults{
				Description: "downlink",
			},
		}
		result := MergeDefaults(policy, override)

		// Override wins.
		require.Equal(t, "LA", result.Site)
		require.Equal(t, "Leaf", result.Role)
		require.Equal(t, "7280R3", result.Device.Model)
		require.Equal(t, "new comment", result.Device.Comments)
		require.Equal(t, "downlink", result.Interface.Description)

		// Policy fallbacks.
		require.Equal(t, "DC-1", result.Location)
		require.Equal(t, "Arista", result.Device.Manufacturer)
		require.Equal(t, "EOS", result.Device.Platform)
		require.Equal(t, "1000base-t", result.Interface.Type)
	})

	t.Run("override sets tags; they win and are not aliased to the override", func(t *testing.T) {
		policy := &Defaults{
			Tags:      []string{"policy-tag"},
			Device:    DeviceDefaults{Tags: []string{"policy-device-tag"}},
			Interface: InterfaceDefaults{Tags: []string{"policy-iface-tag"}},
		}
		override := &Defaults{
			Tags:      []string{"override-tag"},
			Device:    DeviceDefaults{Tags: []string{"override-device-tag"}},
			Interface: InterfaceDefaults{Tags: []string{"override-iface-tag"}},
		}
		result := MergeDefaults(policy, override)

		require.Equal(t, []string{"override-tag"}, result.Tags)
		require.Equal(t, []string{"override-device-tag"}, result.Device.Tags)
		require.Equal(t, []string{"override-iface-tag"}, result.Interface.Tags)

		// Appending to the result must not affect the override source.
		result.Tags = append(result.Tags, "extra")
		require.NotContains(t, override.Tags, "extra", "result.Tags must not alias override.Tags")

		result.Device.Tags = append(result.Device.Tags, "extra")
		require.NotContains(t, override.Device.Tags, "extra", "result.Device.Tags must not alias override.Device.Tags")

		result.Interface.Tags = append(result.Interface.Tags, "extra")
		require.NotContains(t, override.Interface.Tags, "extra", "result.Interface.Tags must not alias override.Interface.Tags")
	})

	t.Run("both nil returns empty Defaults", func(t *testing.T) {
		result := MergeDefaults(nil, nil)
		require.NotNil(t, result)
		require.Equal(t, &Defaults{}, result)
	})

	t.Run("nil policy with non-nil override clones all slice fields", func(t *testing.T) {
		override := &Defaults{
			Site:                     "SF",
			Tags:                     []string{"ov-tag"},
			Device:                   DeviceDefaults{Tags: []string{"ov-dev-tag"}},
			Interface:                InterfaceDefaults{Tags: []string{"ov-iface-tag"}},
			InterfacePatterns:        []InterfacePattern{{Match: "eth.*", Type: "1000base-t"}},
			InterfaceExcludePatterns: []string{"lo.*"},
		}
		result := MergeDefaults(nil, override)
		require.Equal(t, "SF", result.Site)
		require.Equal(t, []string{"ov-tag"}, result.Tags)
		require.Equal(t, []string{"ov-dev-tag"}, result.Device.Tags)
		require.Equal(t, []string{"ov-iface-tag"}, result.Interface.Tags)
		require.Equal(t, override.InterfacePatterns, result.InterfacePatterns)
		require.Equal(t, override.InterfaceExcludePatterns, result.InterfaceExcludePatterns)

		// Mutating result slices must not affect the override source.
		result.Tags = append(result.Tags, "extra")
		require.NotContains(t, override.Tags, "extra", "result.Tags must not alias override.Tags")
		result.InterfacePatterns = append(result.InterfacePatterns, InterfacePattern{Match: "x", Type: "y"})
		require.Len(t, override.InterfacePatterns, 1, "result.InterfacePatterns must not alias override.InterfacePatterns")
		result.InterfaceExcludePatterns = append(result.InterfaceExcludePatterns, "extra")
		require.NotContains(t, override.InterfaceExcludePatterns, "extra", "result.InterfaceExcludePatterns must not alias override.InterfaceExcludePatterns")
	})

	t.Run("override sets Location, Manufacturer, Platform, Interface.Type when non-empty", func(t *testing.T) {
		policy := &Defaults{
			Location: "DC-1",
			Device: DeviceDefaults{
				Manufacturer: "Cisco",
				Platform:     "IOS-XR",
			},
			Interface: InterfaceDefaults{
				Type: "old-type",
			},
		}
		override := &Defaults{
			Location: "DC-2",
			Device: DeviceDefaults{
				Manufacturer: "Arista",
				Platform:     "EOS",
			},
			Interface: InterfaceDefaults{
				Type: "1000base-t",
			},
		}
		result := MergeDefaults(policy, override)
		require.Equal(t, "DC-2", result.Location)
		require.Equal(t, "Arista", result.Device.Manufacturer)
		require.Equal(t, "EOS", result.Device.Platform)
		require.Equal(t, "1000base-t", result.Interface.Type)
	})

	t.Run("override sets InterfacePatterns and InterfaceExcludePatterns when non-empty", func(t *testing.T) {
		policy := &Defaults{
			InterfacePatterns:        []InterfacePattern{{Match: "eth.*", Type: "1000base-t"}},
			InterfaceExcludePatterns: []string{"lo.*"},
		}
		override := &Defaults{
			InterfacePatterns:        []InterfacePattern{{Match: "xe.*", Type: "10gbase-x-xfp"}},
			InterfaceExcludePatterns: []string{"mgmt.*"},
		}
		result := MergeDefaults(policy, override)
		require.Equal(t, override.InterfacePatterns, result.InterfacePatterns)
		require.Equal(t, override.InterfaceExcludePatterns, result.InterfaceExcludePatterns)

		// Mutating result slices must not affect the override source.
		result.InterfacePatterns = append(result.InterfacePatterns, InterfacePattern{Match: "x", Type: "y"})
		require.Len(t, override.InterfacePatterns, 1, "result.InterfacePatterns must not alias override.InterfacePatterns")
		result.InterfaceExcludePatterns = append(result.InterfaceExcludePatterns, "extra")
		require.NotContains(t, override.InterfaceExcludePatterns, "extra", "result.InterfaceExcludePatterns must not alias override.InterfaceExcludePatterns")
	})

	t.Run("empty override fields preserve all policy values", func(t *testing.T) {
		policy := &Defaults{
			Site:     "NYC",
			Location: "DC-1",
			Role:     "Spine",
			Tags:     []string{"p-tag"},
			Device: DeviceDefaults{
				Manufacturer: "Arista",
				Model:        "7050CX3",
				Platform:     "EOS",
				Comments:     "comment",
				Tags:         []string{"p-dev-tag"},
			},
			Interface: InterfaceDefaults{
				Type:        "1000base-t",
				Description: "uplink",
				Tags:        []string{"p-iface-tag"},
			},
			InterfacePatterns:        []InterfacePattern{{Match: "eth.*", Type: "1000base-t"}},
			InterfaceExcludePatterns: []string{"lo.*"},
		}
		override := &Defaults{} // all zero-values: nothing should be overridden
		result := MergeDefaults(policy, override)
		require.Equal(t, "NYC", result.Site)
		require.Equal(t, "DC-1", result.Location)
		require.Equal(t, "Spine", result.Role)
		require.Equal(t, []string{"p-tag"}, result.Tags)
		require.Equal(t, "Arista", result.Device.Manufacturer)
		require.Equal(t, "7050CX3", result.Device.Model)
		require.Equal(t, "EOS", result.Device.Platform)
		require.Equal(t, "comment", result.Device.Comments)
		require.Equal(t, []string{"p-dev-tag"}, result.Device.Tags)
		require.Equal(t, "1000base-t", result.Interface.Type)
		require.Equal(t, "uplink", result.Interface.Description)
		require.Equal(t, []string{"p-iface-tag"}, result.Interface.Tags)
		require.Equal(t, policy.InterfacePatterns, result.InterfacePatterns)
		require.Equal(t, policy.InterfaceExcludePatterns, result.InterfaceExcludePatterns)
	})
}

func TestMergeDefaultsVlan(t *testing.T) {
	policy := &Defaults{Site: "NYC", Vlan: VlanDefaults{Group: "g1", Tenant: "t1", Role: "r1", Tags: []string{"a"}, Description: "d1"}}
	// nil override -> clone preserves vlan
	got := MergeDefaults(policy, nil)
	require.Equal(t, "g1", got.Vlan.Group)
	require.Equal(t, "t1", got.Vlan.Tenant)
	// override wins on non-empty fields, preserves the rest
	override := &Defaults{Vlan: VlanDefaults{Group: "g2", Role: "r2"}}
	got = MergeDefaults(policy, override)
	require.Equal(t, "g2", got.Vlan.Group)       // overridden
	require.Equal(t, "r2", got.Vlan.Role)        // overridden
	require.Equal(t, "t1", got.Vlan.Tenant)      // preserved
	require.Equal(t, "d1", got.Vlan.Description) // preserved

	// no-alias contract: mutating the merged Vlan.Tags must not touch the source
	// (mirrors the existing Device.Tags/Interface.Tags non-alias assertions).
	src := &Defaults{Vlan: VlanDefaults{Tags: []string{"x"}}}
	m := MergeDefaults(src, nil)
	if len(m.Vlan.Tags) > 0 {
		m.Vlan.Tags[0] = "MUT"
	}
	require.Equal(t, "x", src.Vlan.Tags[0])
}

func TestMergeDefaultsPrefix(t *testing.T) {
	policy := &Defaults{Site: "NYC", Prefix: PrefixDefaults{Role: "r1", Tenant: "t1", Tags: []string{"a"}, Description: "d1"}}
	got := MergeDefaults(policy, nil)
	require.Equal(t, "r1", got.Prefix.Role)
	require.Equal(t, "t1", got.Prefix.Tenant)
	override := &Defaults{Prefix: PrefixDefaults{Role: "r2"}}
	got = MergeDefaults(policy, override)
	require.Equal(t, "r2", got.Prefix.Role)        // overridden
	require.Equal(t, "t1", got.Prefix.Tenant)      // preserved
	require.Equal(t, "d1", got.Prefix.Description) // preserved

	// no-alias: mutating merged Prefix.Tags must not touch the source
	src := &Defaults{Prefix: PrefixDefaults{Tags: []string{"x"}}}
	m := MergeDefaults(src, nil)
	if len(m.Prefix.Tags) > 0 {
		m.Prefix.Tags[0] = "MUT"
	}
	require.Equal(t, "x", src.Prefix.Tags[0])
}

func TestUnmarshalPolicy(t *testing.T) {
	data := []byte(`
policies:
  gnmi_fabric:
    config:
      debounce_ms: 2000
      mode: auto
      sample_interval_ms: 300000
      get_interval_ms: 900000
      defaults:
        site: New York NY
        role: Router
    scope:
      targets:
        - host: 10.0.0.11:6030
          username: ${GNMI_USER}
          password: ${GNMI_PASS}
          tls:
            skip_verify: true
          profile: arista_eos
        - host: 10.0.0.21:57400
          username: admin
          password: pw
          mode: on_change
`)
	var p Policies
	require.NoError(t, yaml.Unmarshal(data, &p))
	pol := p.Policies["gnmi_fabric"]
	require.Equal(t, 2000, pol.Config.DebounceMs)
	require.Equal(t, "auto", pol.Config.Mode)
	require.Len(t, pol.Scope.Targets, 2)
	require.Equal(t, "10.0.0.11:6030", pol.Scope.Targets[0].Host)
	require.True(t, pol.Scope.Targets[0].TLS.SkipVerify)
	require.Equal(t, "arista_eos", pol.Scope.Targets[0].Profile)
	require.Equal(t, "on_change", pol.Scope.Targets[1].Mode)
}

func TestResolvedOrigin(t *testing.T) {
	require.Equal(t, "openconfig", Target{}.ResolvedOrigin(), "unset origin defaults to openconfig")
	empty := ""
	require.Equal(t, "", Target{Origin: &empty}.ResolvedOrigin(), "explicit empty stays origin-less")
	oc := "oc"
	require.Equal(t, "oc", Target{Origin: &oc}.ResolvedOrigin())
}
