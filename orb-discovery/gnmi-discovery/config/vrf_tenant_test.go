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
	d, err := parseDefaults(t, "vrf:\n  tenant:\n    name: acme\n    group: customers\nip_address:\n  tenant: acme\nprefix:\n  tenant:\n    name: globex\n")
	require.NoError(t, err)
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.Vrf.Tenant)
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
	assert.Equal(t, TenantParameters{Name: "acme", Group: "partners", Description: "d"}, merged.Prefix.Tenant, "a nameless override refines")
	assert.Equal(t, acme, policy.Vrf.Tenant, "policy untouched")

	merged = MergeDefaults(&Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Group: "customers"}}},
		&Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Name: "acme"}}})
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, merged.Vrf.Tenant, "a nameless policy tenant is refined")

	merged = MergeDefaults(policy, &Defaults{Vrf: VRFDefaults{Tenant: TenantParameters{Name: "acme "}}})
	assert.Equal(t, "customers", merged.Vrf.Tenant.Group, "names compare trimmed, as Diode does")
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Acme Corp": "acme-corp",
		"Acme.Corp": "acmecorp",
		" _Acme_ ":  "acme",
		"Café":      "cafe",
		"a\vb":      "a-b",
		"日本":        "",
	} {
		assert.Equal(t, want, slug(in), in)
	}
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
			name: "vlan tenant", d: Defaults{Vrf: VRFDefaults{Tenant: acme}, Vlan: VlanDefaults{Tenant: "acme"}},
			err: "defaults.vrf.tenant and defaults.vlan.tenant name the same NetBox tenant but write it differently",
		},
		{
			name: "group written two ways", d: Defaults{Vrf: VRFDefaults{Tenant: acme}, IPAddress: IPAddressDefaults{Tenant: TenantParameters{Name: "globex", Group: "Customers"}}},
			err: "defaults.vrf.tenant and defaults.ip_address.tenant name the same NetBox tenant group in two ways",
		},
		{name: "pairs without the vrf tenant", d: Defaults{IPAddress: IPAddressDefaults{Tenant: acme}, Prefix: PrefixDefaults{Tenant: other}}},
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
