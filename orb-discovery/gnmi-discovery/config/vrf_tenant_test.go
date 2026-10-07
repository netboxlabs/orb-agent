package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func parseDefaults(t *testing.T, doc string) (Defaults, error) {
	t.Helper()
	var d Defaults
	err := yaml.Unmarshal([]byte(doc), &d)
	return d, err
}

func TestTenantParameters_Forms(t *testing.T) {
	d, err := parseDefaults(t, "vrf:\n  tenant:\n    name: acme\n    group: customers\nip_address:\n  tenant: acme\nprefix:\n  tenant:\n    name: globex\n"+
		"vlan:\n  tenant:\n    name: acme\n    group: customers\n")
	require.NoError(t, err)
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.Vrf.Tenant)
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.Vlan.Tenant)
	assert.Equal(t, TenantParameters{Name: "acme"}, d.IPAddress.Tenant)
	assert.Equal(t, TenantParameters{Name: "globex"}, d.Prefix.Tenant)

	d, err = parseDefaults(t, "vrf:\n  tenant: null\n")
	require.NoError(t, err)
	assert.Equal(t, TenantParameters{}, d.Vrf.Tenant)
}

func TestTenantParameters_UnknownKeys(t *testing.T) {
	for _, doc := range []string{
		"vrf:\n  tenant:\n    name: acme\n    grup: customers\n",
		"ip_address:\n  tenant:\n    <<: {name: acme, grup: customers}\n",
		"base: &t {name: acme, grup: customers}\nprefix:\n  tenant: *t\n",
	} {
		_, err := parseDefaults(t, doc)
		assert.EqualError(t, err, `tenant has no "grup" key`, doc)
	}
	_, err := parseDefaults(t, "vrf:\n  tenant: [acme]\n")
	assert.ErrorContains(t, err, "tenant: expected string or mapping")
}

func TestMergeDefaults_TenantRefinedOrReplaced(t *testing.T) {
	acme := TenantParameters{Name: "acme", Group: "customers", Description: "d"}
	policy := &Defaults{Vrf: VRFDefaults{Tenant: acme}, IPAddress: IPAddressDefaults{Tenant: acme}, Prefix: PrefixDefaults{Tenant: acme}}

	merged := MergeDefaults(policy, &Defaults{
		Vrf:       VRFDefaults{Tenant: TenantParameters{Name: "globex"}},
		IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "acme", Description: "x"}},
		Prefix:    PrefixDefaults{Tenant: TenantParameters{Group: "partners"}},
	})
	assert.Equal(t, TenantParameters{Name: "globex"}, merged.Vrf.Tenant, "another tenant takes nothing from the policy's")
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers", Description: "x"}, merged.IPAddress.Tenant, "the same tenant is refined")
	assert.Equal(t, TenantParameters{Name: "acme", Group: "partners"}, merged.Prefix.Tenant,
		"another group is another tenant: it keeps the name but takes nothing else")
	assert.Equal(t, acme, policy.Vrf.Tenant, "policy untouched")

	merged = MergeDefaults(&Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Group: "customers"}}},
		&Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Name: "acme"}}})
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, merged.Vrf.Tenant, "a nameless policy tenant is refined")

	merged = MergeDefaults(policy, &Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Name: "acme "}}})
	assert.Equal(t, "customers", merged.Vrf.Tenant.Group, "names compare trimmed, as Diode does")
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
			Vrf: VRFDefaults{Tenant: acme}, IPAddress: IPAddressDefaults{Tenant: acme}, Prefix: PrefixDefaults{Tenant: acme},
		}},
		{
			name: "ip tenant", d: Defaults{Vrf: VRFDefaults{Tenant: acme}, IPAddress: IPAddressDefaults{Tenant: other}},
			err: "defaults.vrf.tenant and defaults.ip_address.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "prefix tenant", d: Defaults{Vrf: VRFDefaults{Tenant: acme}, Prefix: PrefixDefaults{Tenant: TenantParameters{Name: "Acme"}}},
			err: "defaults.vrf.tenant and defaults.prefix.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "vlan tenant", d: Defaults{Vrf: VRFDefaults{Tenant: acme}, Vlan: VlanDefaults{Tenant: TenantParameters{Name: "acme"}}},
			err: "defaults.vrf.tenant and defaults.vlan.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "group written two ways", d: Defaults{Vrf: VRFDefaults{Tenant: acme}, IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "globex", Group: "Customers"}}},
			err: "defaults.vrf.tenant and defaults.ip_address.tenant name the same NetBox tenant group in two ways",
		},
		{name: "bare names", d: Defaults{IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "acme"}}, Prefix: PrefixDefaults{Tenant: TenantParameters{Name: "Acme"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.ValidateTenants()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestMergeDefaults_TenantRefinesCommentsAndTags(t *testing.T) {
	acme := TenantParameters{Name: "acme", Group: "customers", Description: "d"}
	merged := MergeDefaults(&Defaults{Vlan: VlanDefaults{Tenant: acme}},
		&Defaults{Vlan: VlanDefaults{Tenant: TenantParameters{Name: "acme", Comments: "c", Tags: []string{"t"}}}})
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers", Description: "d", Comments: "c", Tags: []string{"t"}}, merged.Vlan.Tenant)
}

func TestMergeDefaults_TenantTagsDoNotAlias(t *testing.T) {
	policy := &Defaults{
		Vrf:       VRFDefaults{Tenant: TenantParameters{Name: "acme", Tags: []string{"p"}}},
		IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "initech"}},
	}
	override := &Defaults{IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "globex", Tags: []string{"o"}}}}
	for _, merged := range []*Defaults{MergeDefaults(policy, nil), MergeDefaults(nil, override), MergeDefaults(policy, override)} {
		if len(merged.Vrf.Tenant.Tags) > 0 {
			merged.Vrf.Tenant.Tags[0] = "changed"
		}
		if len(merged.IPAddress.Tenant.Tags) > 0 {
			merged.IPAddress.Tenant.Tags[0] = "changed"
		}
	}
	assert.Equal(t, []string{"p"}, policy.Vrf.Tenant.Tags)
	assert.Equal(t, []string{"o"}, override.IPAddress.Tenant.Tags)
}

func TestDefaults_ValidateVrfTenantsRules(t *testing.T) {
	rich := TenantParameters{Name: "acme", Group: "customers", Description: "d"}
	for _, tc := range []struct {
		name string
		d    Defaults
		err  string
	}{
		{name: "bare names stay as they were", d: Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Name: "Acme"}}, IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "acme"}}}},
		{
			name: "address against prefix", d: Defaults{IPAddress: IPAddressDefaults{Tenant: rich}, Prefix: PrefixDefaults{Tenant: TenantParameters{Name: "acme", Group: "customers", Description: "x"}}},
			err: "defaults.ip_address.tenant and defaults.prefix.tenant name the same NetBox tenant but write it differently",
		},
		{name: "grouped vlan tenant", d: Defaults{Vrf: VRFDefaults{Tenant: rich}, Vlan: VlanDefaults{Tenant: rich}}},
		{
			name: "described but ungrouped", d: Defaults{IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "acme", Description: "d"}}, Prefix: PrefixDefaults{Tenant: TenantParameters{Name: "acme", Description: "x"}}},
			err: "defaults.ip_address.tenant and defaults.prefix.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "a tenant map without a name", d: Defaults{Prefix: PrefixDefaults{Tenant: TenantParameters{Group: "customers"}}},
			err: "defaults.prefix.tenant has no name",
		},
		{
			name: "a blank name", d: Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Name: " "}}},
			err: "defaults.vrf.tenant has no name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.ValidateTenants()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}
