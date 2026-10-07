package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func parseDefaults(t *testing.T, doc string) (Defaults, error) {
	t.Helper()
	var pc PolicyConfig
	err := yaml.Unmarshal([]byte("defaults:\n"+doc), &pc)
	return pc.Defaults, err
}

func TestVrfParameters_Tenant(t *testing.T) {
	d, err := parseDefaults(t, "  ip_address:\n    vrf:\n      name: example-vrf\n      tenant: acme\n"+
		"  prefix:\n    vrf_ipv6:\n      name: example-vrf\n      tenant:\n        name: acme\n        group: customers\n")
	require.NoError(t, err)
	assert.Equal(t, TenantParameters{Name: "acme"}, d.IPAddress.Vrf.Tenant)
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.Prefix.VrfIpv6.Tenant)
}

func TestVrfParameters_UnknownKeys(t *testing.T) {
	for _, tc := range []struct{ name, doc, err string }{
		{name: "vrf", doc: "  ip_address:\n    vrf:\n      name: v\n      tennant: acme\n", err: `vrf has no "tennant" key`},
		{name: "vrf tenant", doc: "  prefix:\n    vrf:\n      name: v\n      tenant:\n        name: acme\n        grup: g\n", err: `vrf.tenant has no "grup" key`},
		{name: "merged", doc: "  ip_address:\n    vrf:\n      <<: {name: v, tennant: acme}\n", err: `vrf has no "tennant" key`},
		{name: "aliased tenant", doc: "  tenant: &t {name: acme, grup: g}\n  ip_address:\n    vrf:\n      name: v\n      tenant: *t\n", err: `vrf.tenant has no "grup" key`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDefaults(t, tc.doc)
			assert.EqualError(t, err, tc.err)
		})
	}

	d, err := parseDefaults(t, "  tenant:\n    name: acme\n    grup: g\n")
	require.NoError(t, err, "defaults.tenant stays lenient")
	assert.Equal(t, "acme", d.Tenant.Name)
}

func TestVrfParameters_IsZeroCountsTenant(t *testing.T) {
	assert.False(t, VrfParameters{Tenant: TenantParameters{Name: "acme"}}.IsZero())
	assert.False(t, VrfParameters{Tenant: TenantParameters{Group: "customers"}}.IsZero())
	assert.True(t, VrfParameters{}.IsZero())
}

func TestMergeDefaults_VrfTenantFieldWise(t *testing.T) {
	policy := &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Name: "example-vrf", Tenant: TenantParameters{Name: "acme", Group: "customers"},
	}}}
	merged := MergeDefaults(policy, &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Tenant: TenantParameters{Group: "partners"},
	}}})
	assert.Equal(t, VrfParameters{
		Name: "example-vrf", Tenant: TenantParameters{Name: "acme", Group: "partners"},
	}, merged.IPAddress.Vrf)
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, policy.IPAddress.Vrf.Tenant, "policy untouched")
}

func TestMergeDefaults_RenamedTenantEverywhere(t *testing.T) {
	acme := TenantParameters{Name: "acme", Group: "customers", Description: "d"}
	globex := TenantParameters{Name: "globex"}
	policy := &Defaults{
		Tenant:    acme,
		IPAddress: IPAddressDefaults{Tenant: acme, Vrf: VrfParameters{Name: "v", Tenant: acme}},
		Prefix:    PrefixDefaults{Tenant: acme},
		VLAN:      VLANDefaults{Tenant: acme},
	}
	merged := MergeDefaults(policy, &Defaults{
		Tenant:    globex,
		IPAddress: IPAddressDefaults{Tenant: globex, Vrf: VrfParameters{Tenant: globex}},
		Prefix:    PrefixDefaults{Tenant: globex},
		VLAN:      VLANDefaults{Tenant: globex},
	})
	for _, tenant := range []TenantParameters{
		merged.Tenant, merged.IPAddress.Tenant, merged.IPAddress.Vrf.Tenant, merged.Prefix.Tenant, merged.VLAN.Tenant,
	} {
		assert.Equal(t, globex, tenant)
	}
	assert.NoError(t, merged.ValidateVrfTenants(), "an override renaming the tenant everywhere is consistent")
}

func TestMergeDefaults_VrfRenameComparesTrimmed(t *testing.T) {
	policy := &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{Name: "v", Rd: "65000:1"}}}
	merged := MergeDefaults(policy, &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{Name: "v "}}})
	assert.Equal(t, "65000:1", merged.IPAddress.Vrf.Rd, "a padded name is the same VRF")
}

func TestMergeDefaults_VrfTenantRenamed(t *testing.T) {
	policy := &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Name: "example-vrf", Rd: "65000:1",
		Tenant: TenantParameters{Name: "acme", Group: "customers", Description: "d"},
	}}}
	merged := MergeDefaults(policy, &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Tenant: TenantParameters{Name: "globex"},
	}}})
	assert.Equal(t, VrfParameters{Name: "example-vrf", Tenant: TenantParameters{Name: "globex"}}, merged.IPAddress.Vrf,
		"another tenant makes another VRF: it keeps the name and takes neither the rd nor the tenant's group")

	nameless := &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{Rd: "65000:1"}}}
	merged = MergeDefaults(nameless, &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{Name: "example-vrf"}}})
	assert.Equal(t, VrfParameters{Name: "example-vrf", Rd: "65000:1"}, merged.IPAddress.Vrf,
		"a nameless policy VRF is refined, not replaced")

	groupOnly := &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Name: "example-vrf", Tenant: TenantParameters{Group: "customers"},
	}}}
	merged = MergeDefaults(groupOnly, &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Tenant: TenantParameters{Name: "acme"},
	}}})
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, merged.IPAddress.Vrf.Tenant,
		"a nameless policy VRF tenant is refined, not replaced")
}

func TestIPAddressPrefixAndVlanTenant_MappingForm(t *testing.T) {
	d, err := parseDefaults(t, "  ip_address:\n    tenant:\n      name: acme\n      group: customers\n  prefix:\n    tenant: globex\n"+
		"  vlan:\n    tenant:\n      name: acme\n      group: customers\n")
	require.NoError(t, err)
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.IPAddress.Tenant)
	assert.Equal(t, TenantParameters{Name: "globex"}, d.Prefix.Tenant)
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.VLAN.Tenant)

	merged := MergeDefaults(&d, &Defaults{
		IPAddress: IPAddressDefaults{Tenant: TenantParameters{Group: "partners"}},
		Prefix:    PrefixDefaults{Tenant: TenantParameters{Name: "initech"}},
	})
	assert.Equal(t, TenantParameters{Name: "acme", Group: "partners"}, merged.IPAddress.Tenant)
	assert.Equal(t, TenantParameters{Name: "initech"}, merged.Prefix.Tenant)
}

func TestDefaults_ValidateVrfTenants(t *testing.T) {
	acme := TenantParameters{Name: "acme", Group: "customers", Description: "d"}
	other := TenantParameters{Name: "acme", Group: "customers", Description: "x"}
	for _, tc := range []struct {
		name string
		d    Defaults
		err  string
	}{
		{name: "none"},
		{name: "consistent", d: Defaults{
			Tenant:    acme,
			IPAddress: IPAddressDefaults{Tenant: acme, Vrf: VrfParameters{Name: "v", Tenant: acme}},
			Prefix:    PrefixDefaults{Tenant: acme, Vrf: VrfParameters{Name: "v", Tenant: acme}},
		}},
		{
			name: "ip tenant", d: Defaults{IPAddress: IPAddressDefaults{Tenant: acme, VrfIpv4: VrfParameters{Name: "v", Tenant: other}}},
			err: "defaults.ip_address.tenant and defaults.ip_address.vrf_ipv4.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "device tenant", d: Defaults{Tenant: acme, IPAddress: IPAddressDefaults{VrfIpv6: VrfParameters{Name: "v", Tenant: other}}},
			err: "defaults.tenant and defaults.ip_address.vrf_ipv6.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "prefix tenant", d: Defaults{Prefix: PrefixDefaults{Tenant: acme, Vrf: VrfParameters{Name: "v", Tenant: other}}},
			err: "defaults.prefix.tenant and defaults.prefix.vrf.tenant name the same NetBox tenant but write it differently",
		},
		{name: "group written two ways", d: Defaults{IPAddress: IPAddressDefaults{
			Tenant: TenantParameters{Name: "globex", Group: "Customers"}, Vrf: VrfParameters{Name: "v", Tenant: acme},
		}}, err: "defaults.ip_address.tenant and defaults.ip_address.vrf.tenant name the same NetBox tenant group in two ways"},
		{name: "blank tenant name", d: Defaults{IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: " ", Group: "customers"}}}},
		{
			name: "prefix vrf against device tenant", d: Defaults{Tenant: acme, Prefix: PrefixDefaults{Vrf: VrfParameters{Name: "v", Tenant: other}}},
			err: "defaults.tenant and defaults.prefix.vrf.tenant name the same NetBox tenant but write it differently",
		},
		{name: "vrf against vrf", d: Defaults{
			IPAddress: IPAddressDefaults{Vrf: VrfParameters{Name: "v", Tenant: acme}},
			Prefix:    PrefixDefaults{Vrf: VrfParameters{Name: "v", Tenant: other}},
		}, err: "defaults.ip_address.vrf.tenant and defaults.prefix.vrf.tenant name the same NetBox tenant but write it differently"},
		{name: "vlan tenant", d: Defaults{
			VLAN:      VLANDefaults{Tenant: TenantParameters{Name: "Acme"}},
			IPAddress: IPAddressDefaults{Vrf: VrfParameters{Name: "v", Tenant: acme}},
		}, err: "defaults.ip_address.vrf.tenant and defaults.vlan.tenant name the same NetBox tenant but write it differently"},
		{name: "pairs without a vrf tenant", d: Defaults{Tenant: acme, IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "Acme"}}}},
		{
			name: "vrf tenant without a name", d: Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{Name: "v", Tenant: TenantParameters{Group: "customers"}}}},
			err: "defaults.ip_address.vrf.tenant has no name",
		},
		{
			name: "vrf knob with a tenant and no name", d: Defaults{Prefix: PrefixDefaults{VrfIpv4: VrfParameters{Tenant: acme}}},
			err: "defaults.prefix.vrf_ipv4 sets a tenant but no VRF name",
		},
		{name: "grouped vlan tenant", d: Defaults{VLAN: VLANDefaults{Tenant: acme}, IPAddress: IPAddressDefaults{Vrf: VrfParameters{Name: "v", Tenant: acme}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.ValidateVrfTenants()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestMergeDefaults_SameTenantInAnotherGroup(t *testing.T) {
	policy := &Defaults{Tenant: TenantParameters{Name: "acme", Group: "customers", Description: "d"}}
	merged := MergeDefaults(policy, &Defaults{Tenant: TenantParameters{Name: "acme", Group: "partners"}})
	assert.Equal(t, TenantParameters{Name: "acme", Group: "partners"}, merged.Tenant, "another group is another tenant")
}

func TestMergeDefaults_VrfRefinedByAnAddedRdOrTenantGroup(t *testing.T) {
	policy := &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Name: "v", Description: "d", Tenant: TenantParameters{Name: "acme", Description: "t"},
	}}}
	merged := MergeDefaults(policy, &Defaults{IPAddress: IPAddressDefaults{Vrf: VrfParameters{
		Rd: "65000:1", Tenant: TenantParameters{Group: "customers"},
	}}})
	assert.Equal(t, VrfParameters{
		Name: "v", Rd: "65000:1", Description: "d",
		Tenant: TenantParameters{Name: "acme", Group: "customers", Description: "t"},
	}, merged.IPAddress.Vrf, "fields the policy left unset refine it")
}

func TestDefaults_ValidateVrfTenants_TenantMaps(t *testing.T) {
	acme := TenantParameters{Name: "acme", Group: "customers", Description: "d"}
	other := TenantParameters{Name: "acme", Group: "customers", Description: "x"}
	for _, tc := range []struct {
		name string
		d    Defaults
		err  string
	}{
		{name: "device against a bare address tenant, as before", d: Defaults{Tenant: acme, IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "acme"}}}},
		{
			name: "device against an address tenant map", d: Defaults{Tenant: acme, IPAddress: IPAddressDefaults{Tenant: other}},
			err: "defaults.tenant and defaults.ip_address.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "prefix against vlan", d: Defaults{Prefix: PrefixDefaults{Tenant: TenantParameters{Name: "acme", Comments: "c"}}, VLAN: VLANDefaults{Tenant: TenantParameters{Name: "acme", Comments: "k"}}},
			err: "defaults.prefix.tenant and defaults.vlan.tenant name the same NetBox tenant but write it differently",
		},
		{name: "two device-level maps only", d: Defaults{Tenant: acme}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.ValidateVrfTenants()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}
