package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

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

func TestTenantParameters_UnmarshalMappingMissingName(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("tenant:\n  group: customers\n  tags: [a]\n"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant: mapping requires name")
}

func TestVrfParameters_UnmarshalScalar(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("vrf: production\n"), &d))
	assert.Equal(t, VrfParameters{Name: "production"}, d.Vrf)
}

func TestVrfParameters_UnmarshalMapping(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte(
		"vrf:\n  name: production\n  rd: \"65000:100\"\n  description: d\n  comments: c\n  tags: [a, b]\n"+
			"  tenant:\n    name: acme\n    group: customers\n"), &d))
	assert.Equal(t, VrfParameters{
		Name:        "production",
		Rd:          "65000:100",
		Tenant:      TenantParameters{Name: "acme", Group: "customers"},
		Description: "d",
		Comments:    "c",
		Tags:        []string{"a", "b"},
	}, d.Vrf)
}

func TestVrfParameters_UnmarshalTenantScalar(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("vrf:\n  name: production\n  tenant: acme\n"), &d))
	assert.Equal(t, TenantParameters{Name: "acme"}, d.Vrf.Tenant)
}

func TestVrfParameters_UnmarshalAnchoredTenant(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte(
		"tenant: &owner\n  name: acme\n  group: customers\nvrf:\n  name: production\n  tenant: *owner\n"), &d))
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.Tenant)
	assert.Equal(t, d.Tenant, d.Vrf.Tenant)
}

func TestVrfParameters_UnmarshalNullAndReceiverReset(t *testing.T) {
	var v VrfParameters
	require.NoError(t, yaml.Unmarshal([]byte("name: production\nrd: \"65000:100\"\ntenant: acme\n"), &v))
	require.NoError(t, yaml.Unmarshal([]byte("plainname"), &v))
	assert.Equal(t, VrfParameters{Name: "plainname"}, v, "scalar re-decode must reset the other fields")

	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("vrf: null\n"), &d))
	assert.Equal(t, VrfParameters{}, d.Vrf)
}

func TestVrfParameters_UnmarshalBadKind(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  - a\n  - b\n"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vrf: expected string or mapping")
}

func TestVrfParameters_UnmarshalMappingMissingName(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  rd: \"65000:100\"\n  tenant: acme\n"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vrf: mapping requires name")
}

func TestVrfParameters_UnmarshalTenantMissingName(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  name: production\n  tenant:\n    group: customers\n"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant: mapping requires name")
}

func TestDefaults_Validate(t *testing.T) {
	for _, tc := range []struct {
		name             string
		vrfRd, defaultRd string
		err              string
	}{
		{name: "neither"},
		{name: "vrf rd only", vrfRd: "65000:1"},
		{name: "defaults rd only", defaultRd: "65000:1"},
		{name: "equal", vrfRd: "65000:1", defaultRd: "65000:1"},
		{
			name: "conflict", vrfRd: "65000:1", defaultRd: "65000:2",
			err: `defaults.rd "65000:2" conflicts with defaults.vrf.rd "65000:1"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Defaults{Vrf: VrfParameters{Name: "MyVRF", Rd: tc.vrfRd}, Rd: tc.defaultRd}.Validate()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}
