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
				Vrf:         "default-vrf",
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
		assert.Equal(t, "default-vrf", result.IPAddress.Vrf)          // Not overridden
		assert.Equal(t, "Policy IP", result.IPAddress.Description)    // Not overridden
		assert.Equal(t, "Policy Comments", result.IPAddress.Comments) // Not overridden
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
