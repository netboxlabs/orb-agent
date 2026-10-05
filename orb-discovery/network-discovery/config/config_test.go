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
