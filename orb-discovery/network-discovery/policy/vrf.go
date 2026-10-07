package policy

import (
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// diodeVrf builds a Diode VRF stub from policy defaults. defaults.rd applies
// when the VRF carries no rd of its own; the VRF's tenant is its own and is
// never taken from defaults.tenant.
func diodeVrf(d config.Defaults) *diode.VRF {
	if d.Vrf.Name == "" {
		return nil
	}
	vrf := &diode.VRF{
		Name:   diode.String(d.Vrf.Name),
		Tenant: diodeTenant(d.Vrf.Tenant),
	}
	rd := strings.TrimSpace(d.Vrf.Rd)
	if rd == "" {
		rd = strings.TrimSpace(d.Rd)
	}
	if rd != "" {
		vrf.Rd = diode.String(rd)
	}
	if d.Vrf.Description != "" {
		vrf.Description = diode.String(d.Vrf.Description)
	}
	if d.Vrf.Comments != "" {
		vrf.Comments = diode.String(d.Vrf.Comments)
	}
	for i := range d.Vrf.Tags {
		vrf.Tags = append(vrf.Tags, &diode.Tag{Name: diode.String(d.Vrf.Tags[i])})
	}
	return vrf
}
