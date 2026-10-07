package mapping

import (
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// diodeTenant builds a Diode tenant from a tenant default, or nil when it
// names none.
func diodeTenant(p config.TenantParameters) *diode.Tenant {
	if p.Name == "" {
		return nil
	}
	tenant := &diode.Tenant{Name: strptr(p.Name)}
	if p.Group != "" {
		tenant.Group = &diode.TenantGroup{Name: strptr(p.Group)}
	}
	if p.Description != "" {
		tenant.Description = strptr(p.Description)
	}
	if p.Comments != "" {
		tenant.Comments = strptr(p.Comments)
	}
	for _, tag := range p.Tags {
		tenant.Tags = append(tenant.Tags, &diode.Tag{Name: strptr(tag)})
	}
	return tenant
}
