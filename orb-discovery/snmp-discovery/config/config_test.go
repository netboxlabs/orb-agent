package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
}
