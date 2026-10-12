package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

var vrfOwner = config.TenantParameters{Name: "acme", Group: "customers"}

func TestIPAddressMapper_applyDefaults_VrfTenant(t *testing.T) {
	m := newTestIPAddressMapper()
	entity := &diode.IPAddress{Address: strPtr("192.0.2.10/24")}
	m.applyDefaults(entity, &config.Defaults{IPAddress: config.IPAddressDefaults{
		Tenant: config.TenantParameters{Name: "ip-tenant", Group: "ip-group"},
		Vrf:    config.VrfParameters{Name: "example-vrf", Tenant: vrfOwner},
	}})

	require.NotNil(t, entity.Vrf)
	require.NotNil(t, entity.Vrf.Tenant)
	assert.Equal(t, "acme", entity.Vrf.Tenant.GetName())
	require.NotNil(t, entity.Vrf.Tenant.Group)
	assert.Equal(t, "customers", entity.Vrf.Tenant.Group.GetName())
	require.NotNil(t, entity.Tenant)
	assert.Equal(t, "ip-tenant", entity.Tenant.GetName())
	require.NotNil(t, entity.Tenant.Group, "ip_address.tenant takes the map form")
	assert.Equal(t, "ip-group", entity.Tenant.Group.GetName())
}

func TestIPAddressMapper_applyDefaults_VrfDoesNotInheritTenant(t *testing.T) {
	m := newTestIPAddressMapper()
	entity := &diode.IPAddress{Address: strPtr("192.0.2.10/24")}
	m.applyDefaults(entity, &config.Defaults{
		Tenant:    vrfOwner,
		IPAddress: config.IPAddressDefaults{Tenant: vrfOwner, Vrf: config.VrfParameters{Name: "example-vrf"}},
	})

	require.NotNil(t, entity.Vrf)
	assert.Nil(t, entity.Vrf.Tenant)
}

func TestPrefixDefaults_VrfTenantAndPrefixTenant(t *testing.T) {
	d := &config.Defaults{Prefix: config.PrefixDefaults{
		Tenant:  config.TenantParameters{Name: "prefix-tenant", Group: "prefix-group"},
		VrfIpv6: config.VrfParameters{Name: "example-vrf", Tenant: vrfOwner},
	}}
	vrf, _ := prefixDefaultsVrf(&d.Prefix, "ipv6")
	require.NotNil(t, vrf)
	require.NotNil(t, vrf.Tenant)
	assert.Equal(t, "acme", vrf.Tenant.GetName())
	assert.Equal(t, "customers", vrf.Tenant.Group.GetName())

	plain, _ := prefixDefaultsVrf(&config.PrefixDefaults{Vrf: config.VrfParameters{Name: "example-vrf"}}, "ipv4")
	require.NotNil(t, plain)
	assert.Nil(t, plain.Tenant)

	prefix := &diode.Prefix{}
	applyPrefixDefaults(prefix, d, nil)
	require.NotNil(t, prefix.Tenant)
	assert.Equal(t, "prefix-tenant", prefix.Tenant.GetName())
	require.NotNil(t, prefix.Tenant.Group)
	assert.Equal(t, "prefix-group", prefix.Tenant.Group.GetName())
}

func TestVrfKey_Tenant(t *testing.T) {
	vrf := func(rd string, tenant *diode.Tenant) *diode.VRF {
		v := &diode.VRF{Name: strPtr("example-vrf"), Tenant: tenant}
		if rd != "" {
			v.Rd = strPtr(rd)
		}
		return v
	}
	owned := &diode.Tenant{Name: strPtr("acme")}
	grouped := &diode.Tenant{Name: strPtr("acme"), Group: &diode.TenantGroup{Name: strPtr("customers")}}
	described := &diode.Tenant{Name: strPtr("acme"), Description: strPtr("d")}

	keys := map[string]bool{vrfKey(vrf("", nil)): true, vrfKey(vrf("", owned)): true, vrfKey(vrf("", grouped)): true}
	assert.Len(t, keys, 3, "without an rd the tenant and its group are identity")
	assert.Equal(t, vrfKey(vrf("", owned)), vrfKey(vrf("", described)), "other tenant fields are not")
	assert.Equal(t, vrfKey(vrf("65000:1", nil)), vrfKey(vrf("65000:1", grouped)), "an rd alone is identity")
}
