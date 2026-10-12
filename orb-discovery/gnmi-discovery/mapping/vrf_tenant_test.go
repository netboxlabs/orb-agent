package mapping

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

func TestDiodeTenant(t *testing.T) {
	assert.Nil(t, diodeTenant(config.TenantParameters{}))
	assert.Nil(t, diodeTenant(config.TenantParameters{Group: "customers"}), "a tenant needs a name")

	tenant := diodeTenant(config.TenantParameters{Name: "acme", Group: "customers", Description: "d", Comments: "c", Tags: []string{"a", "b"}})
	require.NotNil(t, tenant)
	assert.Equal(t, "acme", tenant.GetName())
	require.NotNil(t, tenant.Group)
	assert.Equal(t, "customers", tenant.Group.GetName())
	assert.Equal(t, "d", *tenant.Description)
	assert.Equal(t, "c", *tenant.Comments)
	require.Len(t, tenant.Tags, 2)
	assert.Equal(t, "b", *tenant.Tags[1].Name)

	plain := diodeTenant(config.TenantParameters{Name: "acme"})
	assert.Nil(t, plain.Group)
	assert.Nil(t, plain.Description)
	assert.Nil(t, plain.Comments)
	assert.Empty(t, plain.Tags)
}
