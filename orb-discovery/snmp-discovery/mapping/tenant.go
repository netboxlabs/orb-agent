package mapping

import (
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// diodeTenant builds a Diode tenant from a tenant default, or nil when it
// names none. Values are copied, so the entity never aliases the config.
func diodeTenant(p config.TenantParameters) *diode.Tenant {
	if p.Name == "" {
		return nil
	}
	tenant := &diode.Tenant{Name: diode.String(p.Name)}
	if p.Group != "" {
		tenant.Group = &diode.TenantGroup{Name: diode.String(p.Group)}
	}
	if p.Description != "" {
		tenant.Description = diode.String(p.Description)
	}
	if p.Comments != "" {
		tenant.Comments = diode.String(p.Comments)
	}
	for _, tag := range p.Tags {
		tenant.Tags = append(tenant.Tags, &diode.Tag{Name: diode.String(tag)})
	}
	return tenant
}

// diodeVrf builds a Diode VRF from VRF defaults that name one. The tenant is
// the VRF's own; it is never taken from another tenant default.
func diodeVrf(p config.VrfParameters) *diode.VRF {
	vrf := &diode.VRF{Name: diode.String(p.Name), Tenant: diodeTenant(p.Tenant)}
	if p.Rd != "" {
		vrf.Rd = diode.String(p.Rd)
	}
	if p.Description != "" {
		vrf.Description = diode.String(p.Description)
	}
	if p.Comments != "" {
		vrf.Comments = diode.String(p.Comments)
	}
	for _, tag := range p.Tags {
		vrf.Tags = append(vrf.Tags, &diode.Tag{Name: diode.String(tag)})
	}
	return vrf
}
