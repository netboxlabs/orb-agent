package policy

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func TestIPAddressEntity_TenantDefaultApplied(t *testing.T) {
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: config.PolicyConfig{
			Defaults: config.Defaults{
				Tenant: config.TenantParameters{
					Name:        "acme",
					Group:       "customers",
					Description: "d",
					Comments:    "c",
					Tags:        []string{"a", "b"},
				},
			},
		},
	}

	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), "192.0.2.10/24", "192.0.2.10", "p")

	require.NotNil(t, ip.Tenant)
	require.NotNil(t, ip.Tenant.Name)
	assert.Equal(t, "acme", *ip.Tenant.Name)
	require.NotNil(t, ip.Tenant.Group)
	require.NotNil(t, ip.Tenant.Group.Name)
	assert.Equal(t, "customers", *ip.Tenant.Group.Name)
	require.NotNil(t, ip.Tenant.Description)
	assert.Equal(t, "d", *ip.Tenant.Description)
	require.NotNil(t, ip.Tenant.Comments)
	assert.Equal(t, "c", *ip.Tenant.Comments)
	require.Len(t, ip.Tenant.Tags, 2)
	assert.Equal(t, "a", *ip.Tenant.Tags[0].Name)
	assert.Equal(t, "b", *ip.Tenant.Tags[1].Name)
}

func TestIPAddressEntity_TenantDefaultNameOnly(t *testing.T) {
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: config.PolicyConfig{
			Defaults: config.Defaults{
				Tenant: config.TenantParameters{Name: "acme"},
			},
		},
	}

	ip, _ := r.ipAddressEntity(scannedHost("host.example.net"), "192.0.2.10/24", "192.0.2.10", "p")
	require.NotNil(t, ip.Tenant)
	require.NotNil(t, ip.Tenant.Name)
	assert.Equal(t, "acme", *ip.Tenant.Name)
	assert.Nil(t, ip.Tenant.Group)
}
