package policy

import (
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// diodeTenant builds a Diode tenant stub from policy defaults.
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
	for i := range p.Tags {
		tenant.Tags = append(tenant.Tags, &diode.Tag{Name: diode.String(p.Tags[i])})
	}
	return tenant
}
