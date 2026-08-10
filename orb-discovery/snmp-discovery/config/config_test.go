package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"
)

func TestMergeDefaults(t *testing.T) {
	t.Run("Nil override returns policy defaults", func(t *testing.T) {
		policyDefaults := &Defaults{
			Site:     "Default Site",
			Role:     "switch",
			Location: "Default Location",
			Tags:     []string{"default"},
		}

		result := MergeDefaults(policyDefaults, nil)
		assert.Equal(t, policyDefaults, result)
	})

	t.Run("Override top-level fields", func(t *testing.T) {
		policyDefaults := &Defaults{
			Site:     "Default Site",
			Role:     "switch",
			Location: "Default Location",
			Tags:     []string{"default"},
		}

		overrideDefaults := &Defaults{
			Site: "Override Site",
			Role: "router",
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, "Override Site", result.Site)
		assert.Equal(t, "router", result.Role)
		assert.Equal(t, "Default Location", result.Location) // Not overridden
		assert.Equal(t, []string{"default"}, result.Tags)    // Not overridden
	})

	t.Run("Override tags replaces entire array", func(t *testing.T) {
		policyDefaults := &Defaults{
			Tags: []string{"default", "policy"},
		}

		overrideDefaults := &Defaults{
			Tags: []string{"override", "target"},
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, []string{"override", "target"}, result.Tags)
	})

	t.Run("Override nested Device fields", func(t *testing.T) {
		policyDefaults := &Defaults{
			Device: DeviceDefaults{
				Description: "Policy Device",
				Tags:        []string{"policy"},
				Comments:    "Policy Comments",
			},
		}

		overrideDefaults := &Defaults{
			Device: DeviceDefaults{
				Description: "Override Device",
				Tags:        []string{"override"},
			},
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, "Override Device", result.Device.Description)
		assert.Equal(t, []string{"override"}, result.Device.Tags)
		assert.Equal(t, "Policy Comments", result.Device.Comments) // Not overridden
	})

	t.Run("Override nested Interface fields", func(t *testing.T) {
		policyDefaults := &Defaults{
			Interface: InterfaceDefaults{
				Type:        "other",
				Description: "Policy Interface",
				Tags:        []string{"policy"},
			},
		}

		overrideDefaults := &Defaults{
			Interface: InterfaceDefaults{
				Type: "1000base-t",
				Tags: []string{"override"},
			},
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, "1000base-t", result.Interface.Type)
		assert.Equal(t, []string{"override"}, result.Interface.Tags)
		assert.Equal(t, "Policy Interface", result.Interface.Description) // Not overridden
	})

	t.Run("Override nested IPAddress fields", func(t *testing.T) {
		policyDefaults := &Defaults{
			IPAddress: IPAddressDefaults{
				Role:        "anycast",
				Tenant:      "default-tenant",
				Vrf:         VrfParameters{Name: "default-vrf"},
				Description: "Policy IP",
				Tags:        []string{"policy"},
				Comments:    "Policy Comments",
			},
		}

		overrideDefaults := &Defaults{
			IPAddress: IPAddressDefaults{
				Role:   "loopback",
				Tenant: "override-tenant",
				Tags:   []string{"override"},
			},
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, "loopback", result.IPAddress.Role)
		assert.Equal(t, "override-tenant", result.IPAddress.Tenant)
		assert.Equal(t, []string{"override"}, result.IPAddress.Tags)
		assert.Equal(t, "default-vrf", result.IPAddress.Vrf.Name)     // Not overridden
		assert.Equal(t, "Policy IP", result.IPAddress.Description)    // Not overridden
		assert.Equal(t, "Policy Comments", result.IPAddress.Comments) // Not overridden
	})

	t.Run("Override IPAddress VRF field-by-field", func(t *testing.T) {
		// Per-target override should be able to refine a single VrfParameters
		// field (e.g. rd) without having to restate the rest of the policy's
		// VRF config. Matches the Device/VLAN/Interface override pattern.
		policyDefaults := &Defaults{
			IPAddress: IPAddressDefaults{
				Vrf: VrfParameters{
					Name:        "prod",
					Rd:          "65000:100",
					Description: "Prod VRF",
					Comments:    "policy comments",
					Tags:        []string{"policy"},
				},
			},
		}

		t.Run("override only Rd", func(t *testing.T) {
			overrideDefaults := &Defaults{
				IPAddress: IPAddressDefaults{
					Vrf: VrfParameters{Rd: "65000:200"},
				},
			}
			result := MergeDefaults(policyDefaults, overrideDefaults)
			assert.Equal(t, "prod", result.IPAddress.Vrf.Name)
			assert.Equal(t, "65000:200", result.IPAddress.Vrf.Rd) // override won
			assert.Equal(t, "Prod VRF", result.IPAddress.Vrf.Description)
			assert.Equal(t, "policy comments", result.IPAddress.Vrf.Comments)
			assert.Equal(t, []string{"policy"}, result.IPAddress.Vrf.Tags)
		})

		t.Run("override only Name", func(t *testing.T) {
			overrideDefaults := &Defaults{
				IPAddress: IPAddressDefaults{
					Vrf: VrfParameters{Name: "edge-vrf"},
				},
			}
			result := MergeDefaults(policyDefaults, overrideDefaults)
			assert.Equal(t, "edge-vrf", result.IPAddress.Vrf.Name) // override won
			assert.Equal(t, "65000:100", result.IPAddress.Vrf.Rd)  // inherited
			assert.Equal(t, "Prod VRF", result.IPAddress.Vrf.Description)
		})

		t.Run("override all VRF fields", func(t *testing.T) {
			overrideDefaults := &Defaults{
				IPAddress: IPAddressDefaults{
					Vrf: VrfParameters{
						Name:        "edge-vrf",
						Rd:          "65000:200",
						Description: "Edge VRF",
						Comments:    "override comments",
						Tags:        []string{"override"},
					},
				},
			}
			result := MergeDefaults(policyDefaults, overrideDefaults)
			assert.Equal(t, "edge-vrf", result.IPAddress.Vrf.Name)
			assert.Equal(t, "65000:200", result.IPAddress.Vrf.Rd)
			assert.Equal(t, "Edge VRF", result.IPAddress.Vrf.Description)
			assert.Equal(t, "override comments", result.IPAddress.Vrf.Comments)
			assert.Equal(t, []string{"override"}, result.IPAddress.Vrf.Tags)
		})

		t.Run("empty override leaves VRF untouched", func(t *testing.T) {
			overrideDefaults := &Defaults{}
			result := MergeDefaults(policyDefaults, overrideDefaults)
			assert.Equal(t, "prod", result.IPAddress.Vrf.Name)
			assert.Equal(t, "65000:100", result.IPAddress.Vrf.Rd)
			assert.Equal(t, "Prod VRF", result.IPAddress.Vrf.Description)
			assert.Equal(t, "policy comments", result.IPAddress.Vrf.Comments)
			assert.Equal(t, []string{"policy"}, result.IPAddress.Vrf.Tags)
		})
	})

	t.Run("Override InterfacePatterns replaces entire array", func(t *testing.T) {
		policyDefaults := &Defaults{
			InterfacePatterns: []InterfacePattern{
				{Match: "^Eth", Type: "1000base-t"},
			},
		}

		overrideDefaults := &Defaults{
			InterfacePatterns: []InterfacePattern{
				{Match: "^GigabitEthernet", Type: "10gbase-x-sfpp"},
				{Match: "^TenGigabitEthernet", Type: "25gbase-x-sfp28"},
			},
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Len(t, result.InterfacePatterns, 2)
		assert.Equal(t, "^GigabitEthernet", result.InterfacePatterns[0].Match)
		assert.Equal(t, "10gbase-x-sfpp", result.InterfacePatterns[0].Type)
		assert.Equal(t, "^TenGigabitEthernet", result.InterfacePatterns[1].Match)
		assert.Equal(t, "25gbase-x-sfp28", result.InterfacePatterns[1].Type)
	})

	t.Run("Complex merge with multiple levels", func(t *testing.T) {
		policyDefaults := &Defaults{
			Site:     "Default Site",
			Role:     "switch",
			Location: "Default Location",
			Tags:     []string{"default", "policy"},
			Device: DeviceDefaults{
				Description: "Policy Device",
				Tags:        []string{"policy-device"},
			},
			Interface: InterfaceDefaults{
				Type:        "other",
				Description: "Policy Interface",
			},
			IPAddress: IPAddressDefaults{
				Role:   "anycast",
				Tenant: "default-tenant",
			},
			InterfacePatterns: []InterfacePattern{
				{Match: "^Eth", Type: "1000base-t"},
			},
		}

		overrideDefaults := &Defaults{
			Site: "Override Site",
			Role: "router",
			Device: DeviceDefaults{
				Description: "Override Device",
			},
			IPAddress: IPAddressDefaults{
				Tenant: "override-tenant",
			},
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)

		// Check overridden fields
		assert.Equal(t, "Override Site", result.Site)
		assert.Equal(t, "router", result.Role)
		assert.Equal(t, "Override Device", result.Device.Description)
		assert.Equal(t, "override-tenant", result.IPAddress.Tenant)

		// Check non-overridden fields retain policy defaults
		assert.Equal(t, "Default Location", result.Location)
		assert.Equal(t, []string{"default", "policy"}, result.Tags)
		assert.Equal(t, []string{"policy-device"}, result.Device.Tags)
		assert.Equal(t, "other", result.Interface.Type)
		assert.Equal(t, "Policy Interface", result.Interface.Description)
		assert.Equal(t, "anycast", result.IPAddress.Role)
		assert.Len(t, result.InterfacePatterns, 1)
	})

	t.Run("Empty string fields in override should not override policy defaults", func(t *testing.T) {
		policyDefaults := &Defaults{
			Site:     "Default Site",
			Role:     "switch",
			Location: "Default Location",
		}

		overrideDefaults := &Defaults{
			Site: "",       // Empty string should not override
			Role: "router", // Non-empty should override
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, "Default Site", result.Site) // Should retain policy default
		assert.Equal(t, "router", result.Role)       // Should be overridden
		assert.Equal(t, "Default Location", result.Location)
	})

	t.Run("Empty array in override should not override policy defaults", func(t *testing.T) {
		policyDefaults := &Defaults{
			Tags: []string{"default", "policy"},
			InterfacePatterns: []InterfacePattern{
				{Match: "^Eth", Type: "1000base-t"},
			},
		}

		overrideDefaults := &Defaults{
			Tags:              []string{},           // Empty array should not override
			InterfacePatterns: []InterfacePattern{}, // Empty array should not override
		}

		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, []string{"default", "policy"}, result.Tags)
		assert.Len(t, result.InterfacePatterns, 1)
	})

	t.Run("Override InterfaceExcludePatterns replaces global list", func(t *testing.T) {
		policyDefaults := &Defaults{
			InterfaceExcludePatterns: []string{"^eth.*"},
		}
		overrideDefaults := &Defaults{
			InterfaceExcludePatterns: []string{"^tap.*", "^veth.*"},
		}
		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, []string{"^tap.*", "^veth.*"}, result.InterfaceExcludePatterns)
	})

	t.Run("Empty override does not replace InterfaceExcludePatterns", func(t *testing.T) {
		policyDefaults := &Defaults{
			InterfaceExcludePatterns: []string{"^eth.*"},
		}
		overrideDefaults := &Defaults{
			Site: "Override Site",
		}
		result := MergeDefaults(policyDefaults, overrideDefaults)
		assert.Equal(t, []string{"^eth.*"}, result.InterfaceExcludePatterns)
	})
}

func TestPolicyOptions_Defaults(t *testing.T) {
	yamlBody := []byte(`
schedule: "0 */6 * * *"
defaults: {}
timeout: 300
snmp_timeout: 5
options:
  create_unknown_vlans: true
`)
	var pc PolicyConfig
	if err := yaml.Unmarshal(yamlBody, &pc); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if pc.Options.CreateUnknownVlans == nil || !*pc.Options.CreateUnknownVlans {
		t.Error("CreateUnknownVlans: got nil or false, want *true")
	}
}

func TestPolicyOptions_Omitted(t *testing.T) {
	yamlBody := []byte(`
schedule: "0 */6 * * *"
defaults: {}
timeout: 300
`)
	var pc PolicyConfig
	if err := yaml.Unmarshal(yamlBody, &pc); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if pc.Options.CreateUnknownVlans != nil {
		t.Errorf("CreateUnknownVlans: got %v, want nil (omitted)", pc.Options.CreateUnknownVlans)
	}
}

func TestMergeDefaults_DeviceModelManufacturerPlatform(t *testing.T) {
	policy := &Defaults{
		Device: DeviceDefaults{
			Description: "policy-desc",
		},
	}
	override := &Defaults{
		Device: DeviceDefaults{
			Model:        "C9300-48P",
			Manufacturer: "Cisco Systems",
			Platform:     "IOS-XE 17.09.04a",
		},
	}
	merged := MergeDefaults(policy, override)
	assert.Equal(t, "C9300-48P", merged.Device.Model)
	assert.Equal(t, "Cisco Systems", merged.Device.Manufacturer)
	assert.Equal(t, "IOS-XE 17.09.04a", merged.Device.Platform)
	assert.Equal(t, "policy-desc", merged.Device.Description, "description must survive the override")
}

func TestMergeDefaults_DeviceOverrideFieldLevel(t *testing.T) {
	policy := &Defaults{
		Device: DeviceDefaults{
			Model:        "policy-model",
			Manufacturer: "policy-mfr",
			Platform:     "policy-plat",
		},
	}
	override := &Defaults{
		Device: DeviceDefaults{
			Model: "override-model",
		},
	}
	merged := MergeDefaults(policy, override)
	assert.Equal(t, "override-model", merged.Device.Model, "Model is overridden")
	assert.Equal(t, "policy-mfr", merged.Device.Manufacturer, "Manufacturer preserved (override was empty)")
	assert.Equal(t, "policy-plat", merged.Device.Platform, "Platform preserved (override was empty)")
}

func TestMergeDefaults_PolicyDeviceModelManufacturerPlatformSurviveNilOverride(t *testing.T) {
	policy := &Defaults{
		Device: DeviceDefaults{
			Model:        "policy-model",
			Manufacturer: "policy-mfr",
			Platform:     "policy-plat",
		},
	}
	merged := MergeDefaults(policy, nil)
	assert.Equal(t, "policy-model", merged.Device.Model)
	assert.Equal(t, "policy-mfr", merged.Device.Manufacturer)
	assert.Equal(t, "policy-plat", merged.Device.Platform)
}

func TestTargetNetboxID_parsed(t *testing.T) {
	input := `
host: "192.168.1.1"
netbox_id: 42
`
	var target Target
	err := yaml.Unmarshal([]byte(input), &target)
	require.NoError(t, err)
	require.NotNil(t, target.NetboxID)
	assert.Equal(t, 42, *target.NetboxID)
}

func TestTargetNetboxID_optional(t *testing.T) {
	input := `host: "10.0.0.1"`
	var target Target
	err := yaml.Unmarshal([]byte(input), &target)
	require.NoError(t, err)
	assert.Nil(t, target.NetboxID)
}

func TestAuthentication_ContextName_ParsesFromScopeAndTarget(t *testing.T) {
	input := `
targets:
  - host: "10.3.2.20"
    authentication:
      protocol_version: "3"
      username: "umsnmp"
      auth_protocol: "SHA"
      auth_passphrase: "secret"
      priv_protocol: "AES"
      priv_passphrase: "secret"
      context_name: "mfpdirect"
authentication:
  protocol_version: "3"
  username: "policyuser"
  context_name: "policycontext"
`
	var scope Scope
	err := yaml.Unmarshal([]byte(input), &scope)
	require.NoError(t, err)

	assert.Equal(t, "policycontext", scope.Authentication.ContextName)
	require.Len(t, scope.Targets, 1)
	require.NotNil(t, scope.Targets[0].Authentication)
	assert.Equal(t, "mfpdirect", scope.Targets[0].Authentication.ContextName)
}

func TestAuthentication_ContextName_Optional(t *testing.T) {
	input := `protocol_version: "3"`
	var auth Authentication
	err := yaml.Unmarshal([]byte(input), &auth)
	require.NoError(t, err)
	assert.Empty(t, auth.ContextName)
}

func TestMappingEntry_IndexKind(t *testing.T) {
	yamlBody := []byte(`
entries:
  - oid: ".1.3.6.1.2.1.4.34.1"
    entity: "ipAddress"
    field: "_id"
    index_kind: "inet_address"
`)
	var m Mapping
	require.NoError(t, yaml.Unmarshal(yamlBody, &m))
	require.Len(t, m.Entries, 1)
	assert.Equal(t, "inet_address", m.Entries[0].IndexKind)
}

func TestMappingEntry_IndexKind_DefaultEmpty(t *testing.T) {
	yamlBody := []byte(`
entries:
  - oid: ".1.3.6.1.2.1.4.20.1"
    entity: "ipAddress"
    field: "_id"
    identifier_size: 4
`)
	var m Mapping
	require.NoError(t, yaml.Unmarshal(yamlBody, &m))
	require.Len(t, m.Entries, 1)
	assert.Equal(t, "", m.Entries[0].IndexKind)
}

func TestMergeDefaults_VLAN(t *testing.T) {
	policy := &Defaults{
		VLAN: VLANDefaults{
			Description: "policy desc",
			Tags:        []string{"policy-tag"},
			Group:       "policy-group",
			Tenant:      "policy-tenant",
			Status:      "active",
		},
	}
	override := &Defaults{
		VLAN: VLANDefaults{
			Description: "override desc",
			Tags:        []string{"override-tag"},
			Tenant:      "override-tenant",
		},
	}
	merged := MergeDefaults(policy, override)

	assert.Equal(t, "override desc", merged.VLAN.Description)
	assert.Equal(t, []string{"override-tag"}, merged.VLAN.Tags)
	assert.Equal(t, "policy-group", merged.VLAN.Group, "Group should be preserved from policy")
	assert.Equal(t, "override-tenant", merged.VLAN.Tenant)
	assert.Equal(t, "active", merged.VLAN.Status, "Status should be preserved from policy")
}

func TestMappingEntry_VendorField(t *testing.T) {
	yamlBody := []byte(`
oid: ".1.3.6.1.4.1.9.9.68.1.2.2.1"
entity: "interface_vlan"
vendor: "cisco"
`)
	var m MappingEntry
	if err := yaml.Unmarshal(yamlBody, &m); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if m.Vendor != "cisco" {
		t.Errorf("Vendor: got %q, want %q", m.Vendor, "cisco")
	}
}

func TestMappingEntry_VendorOmitted(t *testing.T) {
	yamlBody := []byte(`
oid: ".1.3.6.1.2.1.2.2.1"
entity: "interface"
`)
	var m MappingEntry
	if err := yaml.Unmarshal(yamlBody, &m); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if m.Vendor != "" {
		t.Errorf("Vendor: got %q, want empty (generic)", m.Vendor)
	}
}

func TestDefaults_AssetTag_ParsesFromYAML(t *testing.T) {
	yamlContent := []byte(`
defaults:
  site: dc1
  asset_tag: "ASSET-007"
`)
	var parsed struct {
		Defaults Defaults `yaml:"defaults"`
	}
	require.NoError(t, yaml.Unmarshal(yamlContent, &parsed))
	assert.Equal(t, "ASSET-007", parsed.Defaults.AssetTag)
}

func TestDefaults_AssetTag_ParsesOIDReference(t *testing.T) {
	yamlContent := []byte(`
defaults:
  asset_tag: ".1.3.6.1.2.1.1.4.0"
`)
	var parsed struct {
		Defaults Defaults `yaml:"defaults"`
	}
	require.NoError(t, yaml.Unmarshal(yamlContent, &parsed))
	assert.Equal(t, ".1.3.6.1.2.1.1.4.0", parsed.Defaults.AssetTag)
}

func TestMergeDefaults_AssetTag_OverrideWins(t *testing.T) {
	policy := &Defaults{AssetTag: "POLICY-TAG"}
	override := &Defaults{AssetTag: "OVERRIDE-TAG"}
	merged := MergeDefaults(policy, override)
	assert.Equal(t, "OVERRIDE-TAG", merged.AssetTag)
}

func TestMergeDefaults_AssetTag_EmptyOverrideKeepsPolicy(t *testing.T) {
	policy := &Defaults{AssetTag: "POLICY-TAG"}
	override := &Defaults{AssetTag: ""}
	merged := MergeDefaults(policy, override)
	assert.Equal(t, "POLICY-TAG", merged.AssetTag)
}

func TestMergeDefaults_AssetTag_NoOverride(t *testing.T) {
	policy := &Defaults{AssetTag: "POLICY-TAG"}
	merged := MergeDefaults(policy, nil)
	assert.Equal(t, "POLICY-TAG", merged.AssetTag)
}

func TestMergeDefaults_PerAfVrf_FieldLevelNoBleed(t *testing.T) {
	policy := &Defaults{IPAddress: IPAddressDefaults{
		Vrf:     VrfParameters{Name: "any", Rd: "65000:1"},
		VrfIpv4: VrfParameters{Name: "four", Description: "v4 desc"},
	}}
	override := &Defaults{IPAddress: IPAddressDefaults{
		VrfIpv4: VrfParameters{Rd: "65000:44"},
		VrfIpv6: VrfParameters{Name: "six"},
	}}
	merged := MergeDefaults(policy, override)

	// Field-level refinement: override rd lands without clearing the
	// policy-level name/description of the SAME knob.
	assert.Equal(t, "four", merged.IPAddress.VrfIpv4.Name)
	assert.Equal(t, "65000:44", merged.IPAddress.VrfIpv4.Rd)
	assert.Equal(t, "v4 desc", merged.IPAddress.VrfIpv4.Description)
	// New knob introduced by override only.
	assert.Equal(t, "six", merged.IPAddress.VrfIpv6.Name)
	// No bleed between knobs: the AF-agnostic vrf is untouched.
	assert.Equal(t, "any", merged.IPAddress.Vrf.Name)
	assert.Equal(t, "65000:1", merged.IPAddress.Vrf.Rd)
}

func TestMergeDefaults_PrefixBlock(t *testing.T) {
	policy := &Defaults{Prefix: PrefixDefaults{
		Description: "policy-desc",
		Role:        "policy-role",
		ScopeSite:   "policy-site",
		Vrf:         VrfParameters{Name: "policy-vrf", Rd: "65000:1"},
	}}
	override := &Defaults{Prefix: PrefixDefaults{
		Tenant:        "override-tenant",
		ScopeLocation: "override-loc",
		Comments:      "override-comments",
		Tags:          []string{"o"},
		Vrf:           VrfParameters{Rd: "65000:9"},
		VrfIpv6:       VrfParameters{Name: "six"},
	}}
	merged := MergeDefaults(policy, override)
	assert.Equal(t, "policy-desc", merged.Prefix.Description)
	assert.Equal(t, "policy-role", merged.Prefix.Role)
	assert.Equal(t, "policy-site", merged.Prefix.ScopeSite)
	assert.Equal(t, "override-tenant", merged.Prefix.Tenant)
	assert.Equal(t, "override-loc", merged.Prefix.ScopeLocation)
	assert.Equal(t, "override-comments", merged.Prefix.Comments)
	assert.Equal(t, []string{"o"}, merged.Prefix.Tags)
	// Field-level vrf refinement: rd overridden, name preserved.
	assert.Equal(t, "policy-vrf", merged.Prefix.Vrf.Name)
	assert.Equal(t, "65000:9", merged.Prefix.Vrf.Rd)
	assert.Equal(t, "six", merged.Prefix.VrfIpv6.Name)
}

func TestIPAddressDefaults_PerAfVrf_YAMLPolymorphic(t *testing.T) {
	raw := []byte(`
defaults:
  ip_address:
    vrf: anycast
    vrf_ipv4: { name: four, rd: "65000:4" }
    vrf_ipv6: six
`)
	var pc PolicyConfig
	require.NoError(t, yaml.Unmarshal(raw, &pc))
	assert.Equal(t, "anycast", pc.Defaults.IPAddress.Vrf.Name)
	assert.Equal(t, "four", pc.Defaults.IPAddress.VrfIpv4.Name)
	assert.Equal(t, "65000:4", pc.Defaults.IPAddress.VrfIpv4.Rd)
	assert.Equal(t, "six", pc.Defaults.IPAddress.VrfIpv6.Name)
	assert.Equal(t, "", pc.Defaults.IPAddress.VrfIpv6.Rd)
}

func TestPolicyOptions_DiscoverModulesDefaultsToOff(t *testing.T) {
	raw := []byte(`
options:
  create_unknown_vlans: true
`)
	var pc PolicyConfig
	require.NoError(t, yaml.Unmarshal(raw, &pc))
	assert.Equal(t, DiscoverModulesOff, pc.Options.ModuleDiscoveryMode(),
		"DiscoverModules should default to off when omitted")
}

func TestPolicyOptions_DiscoverModulesParsed(t *testing.T) {
	// YAML wire format stays as literal strings (that's what we test);
	// expected outputs use the package constants so the test fails
	// loudly if a constant value ever drifts.
	cases := []struct {
		in  string
		out string
	}{
		{"off", DiscoverModulesOff},
		{"linecards", DiscoverModulesLinecards},
		{"full", DiscoverModulesFull},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			raw := []byte("options:\n  discover_modules: " + c.in + "\n")
			var pc PolicyConfig
			require.NoError(t, yaml.Unmarshal(raw, &pc))
			assert.Equal(t, c.out, pc.Options.ModuleDiscoveryMode())
		})
	}
}

func TestAssetTagDiscoveryEnabled(t *testing.T) {
	var nilOpts *Options
	assert.False(t, nilOpts.AssetTagDiscoveryEnabled(), "nil Options must be off")
	assert.False(t, (&Options{}).AssetTagDiscoveryEnabled(), "unset must default off")

	off := false
	assert.False(t, (&Options{DiscoverAssetTags: &off}).AssetTagDiscoveryEnabled())

	on := true
	assert.True(t, (&Options{DiscoverAssetTags: &on}).AssetTagDiscoveryEnabled())
}

// TestVrfParameters_UnmarshalYAML locks in the dual-shape contract:
// defaults.ip_address.vrf accepts either a scalar string (interpreted as
// VRF Name; Rd left empty so NetBox can match an existing VRF whose rd
// column is null) OR a map with name / rd / description / comments /
// tags (the rich form, matching device-discovery's VrfParameters).
func TestVrfParameters_UnmarshalYAML(t *testing.T) {
	t.Run("scalar string populates Name only", func(t *testing.T) {
		raw := []byte("defaults:\n  ip_address:\n    vrf: production\n")
		var pc PolicyConfig
		require.NoError(t, yaml.Unmarshal(raw, &pc))
		assert.Equal(t, "production", pc.Defaults.IPAddress.Vrf.Name)
		assert.Empty(t, pc.Defaults.IPAddress.Vrf.Rd,
			"scalar form MUST leave Rd empty (no rd=name fallback)")
		assert.Empty(t, pc.Defaults.IPAddress.Vrf.Description)
		assert.Empty(t, pc.Defaults.IPAddress.Vrf.Comments)
		assert.Empty(t, pc.Defaults.IPAddress.Vrf.Tags)
	})

	t.Run("map form populates all fields", func(t *testing.T) {
		raw := []byte(`defaults:
  ip_address:
    vrf:
      name: production
      rd: "65000:100"
      description: Prod VRF
      comments: Imported from SNMP
      tags: [auto, vrf]
`)
		var pc PolicyConfig
		require.NoError(t, yaml.Unmarshal(raw, &pc))
		assert.Equal(t, "production", pc.Defaults.IPAddress.Vrf.Name)
		assert.Equal(t, "65000:100", pc.Defaults.IPAddress.Vrf.Rd)
		assert.Equal(t, "Prod VRF", pc.Defaults.IPAddress.Vrf.Description)
		assert.Equal(t, "Imported from SNMP", pc.Defaults.IPAddress.Vrf.Comments)
		assert.Equal(t, []string{"auto", "vrf"}, pc.Defaults.IPAddress.Vrf.Tags)
	})

	t.Run("map form with only name + rd", func(t *testing.T) {
		raw := []byte("defaults:\n  ip_address:\n    vrf:\n      name: production\n      rd: \"65000:100\"\n")
		var pc PolicyConfig
		require.NoError(t, yaml.Unmarshal(raw, &pc))
		assert.Equal(t, "production", pc.Defaults.IPAddress.Vrf.Name)
		assert.Equal(t, "65000:100", pc.Defaults.IPAddress.Vrf.Rd)
	})

	t.Run("absent vrf leaves zero value", func(t *testing.T) {
		raw := []byte("defaults:\n  ip_address:\n    role: anycast\n")
		var pc PolicyConfig
		require.NoError(t, yaml.Unmarshal(raw, &pc))
		assert.Empty(t, pc.Defaults.IPAddress.Vrf.Name)
	})

	t.Run("invalid node kind returns error", func(t *testing.T) {
		raw := []byte("defaults:\n  ip_address:\n    vrf: [unexpected, sequence]\n")
		var pc PolicyConfig
		err := yaml.Unmarshal(raw, &pc)
		require.Error(t, err)
	})

	t.Run("explicit null decodes to zero value", func(t *testing.T) {
		// Decode-safety contract: `vrf: null` / `vrf: ~` MUST NOT
		// produce a VRF named "null". Whether the resulting zero value
		// actually clears an inherited VRF at MergeDefaults time is a
		// separate concern — MergeDefaults follows the same
		// non-empty-wins pattern as every other override field, so
		// `vrf: null` and an absent `vrf` key are indistinguishable
		// during merge. This test only asserts the decode boundary.
		for _, raw := range [][]byte{
			[]byte("defaults:\n  ip_address:\n    vrf: null\n"),
			[]byte("defaults:\n  ip_address:\n    vrf: ~\n"),
		} {
			var pc PolicyConfig
			require.NoError(t, yaml.Unmarshal(raw, &pc))
			assert.Empty(t, pc.Defaults.IPAddress.Vrf.Name,
				"vrf: null / vrf: ~ MUST decode to zero value, not Name=\"null\"")
			assert.Empty(t, pc.Defaults.IPAddress.Vrf.Rd)
		}
	})

	t.Run("re-decode into populated receiver clears stale fields", func(t *testing.T) {
		// If the same VrfParameters value is re-used across decodes
		// (e.g. tests, layered configs), the scalar form must NOT
		// leave stale Rd / Description / Comments / Tags behind. Drive
		// the receiver through the full ScalarNode path by unmarshaling
		// a wrapper map and pulling out the resolved Vrf field.
		v := VrfParameters{
			Name:        "stale",
			Rd:          "65000:999",
			Description: "stale-desc",
			Comments:    "stale-comments",
			Tags:        []string{"stale"},
		}
		wrapper := struct {
			Vrf VrfParameters `yaml:"vrf"`
		}{Vrf: v}
		require.NoError(t, yaml.Unmarshal([]byte("vrf: production\n"), &wrapper))
		assert.Equal(t, "production", wrapper.Vrf.Name)
		assert.Empty(t, wrapper.Vrf.Rd, "stale Rd must be cleared by scalar re-decode")
		assert.Empty(t, wrapper.Vrf.Description)
		assert.Empty(t, wrapper.Vrf.Comments)
		assert.Empty(t, wrapper.Vrf.Tags)
	})
}

func TestOptions_InterfaceNameSourceMode(t *testing.T) {
	auto := "auto"
	ifname := "ifname"
	ifdescr := "ifdescr"
	bogus := "wat"

	var nilOpts *Options
	assert.Equal(t, InterfaceNameSourceAuto, nilOpts.InterfaceNameSourceMode(), "nil receiver defaults to auto")
	assert.Equal(t, InterfaceNameSourceAuto, (&Options{}).InterfaceNameSourceMode(), "unset field defaults to auto")
	assert.Equal(t, "auto", (&Options{InterfaceNameSource: &auto}).InterfaceNameSourceMode())
	assert.Equal(t, "ifname", (&Options{InterfaceNameSource: &ifname}).InterfaceNameSourceMode())
	assert.Equal(t, "ifdescr", (&Options{InterfaceNameSource: &ifdescr}).InterfaceNameSourceMode())
	// Accessor returns the raw value verbatim; normalization of unknowns
	// happens at policy parse (Manager.applyDefaults), not here.
	assert.Equal(t, "wat", (&Options{InterfaceNameSource: &bogus}).InterfaceNameSourceMode())
}

func TestTenantParameters_UnmarshalScalar(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("tenant: acme\n"), &d)
	require.NoError(t, err)
	assert.Equal(t, "acme", d.Tenant.Name)
	assert.Empty(t, d.Tenant.Group)
}

func TestTenantParameters_UnmarshalMapping(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte(
		"tenant:\n  name: acme\n  group: customers\n  description: main tenant\n  comments: managed\n  tags: [a, b]\n"), &d)
	require.NoError(t, err)
	assert.Equal(t, "acme", d.Tenant.Name)
	assert.Equal(t, "customers", d.Tenant.Group)
	assert.Equal(t, "main tenant", d.Tenant.Description)
	assert.Equal(t, "managed", d.Tenant.Comments)
	assert.Equal(t, []string{"a", "b"}, d.Tenant.Tags)
}

func TestTenantParameters_UnmarshalNullAndReceiverReset(t *testing.T) {
	// Mirrors the VrfParameters reset semantics: re-decoding into the same
	// struct must not leak fields from a previous mapping-form pass, and a
	// YAML null leaves the zero value.
	var tp TenantParameters
	require.NoError(t, yaml.Unmarshal([]byte("name: acme\ngroup: customers\n"), &tp))
	require.NoError(t, yaml.Unmarshal([]byte("plainname"), &tp))
	assert.Equal(t, "plainname", tp.Name)
	assert.Empty(t, tp.Group, "scalar re-decode must reset Group")

	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("tenant: null\n"), &d))
	assert.Empty(t, d.Tenant.Name)
}

func TestTenantParameters_UnmarshalBadKind(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("tenant:\n  - a\n  - b\n"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant: expected string or mapping")
}

func TestMergeDefaults_TenantFieldWise(t *testing.T) {
	policy := &Defaults{Tenant: TenantParameters{Name: "acme", Group: "customers"}}

	merged := MergeDefaults(policy, &Defaults{})
	assert.Equal(t, "acme", merged.Tenant.Name, "empty override keeps policy tenant")
	assert.Equal(t, "customers", merged.Tenant.Group)

	// Field-wise like mergeVrfParameters: a name-only override must KEEP
	// the policy group (device-discovery deep-merges overrides the same way).
	merged = MergeDefaults(policy, &Defaults{Tenant: TenantParameters{Name: "other"}})
	assert.Equal(t, "other", merged.Tenant.Name)
	assert.Equal(t, "customers", merged.Tenant.Group)

	// Group-only override refines group while keeping the policy name.
	merged = MergeDefaults(policy, &Defaults{Tenant: TenantParameters{Group: "internal"}})
	assert.Equal(t, "acme", merged.Tenant.Name)
	assert.Equal(t, "internal", merged.Tenant.Group)
}

func TestDeviceNameEmissionEnabled(t *testing.T) {
	var nilOpts *Options
	assert.True(t, nilOpts.DeviceNameEmissionEnabled(), "nil Options must default to emitting")
	assert.True(t, (&Options{}).DeviceNameEmissionEnabled(), "unset must default to emitting")

	on := true
	assert.True(t, (&Options{EmitDeviceName: &on}).DeviceNameEmissionEnabled())

	off := false
	assert.False(t, (&Options{EmitDeviceName: &off}).DeviceNameEmissionEnabled())
}
