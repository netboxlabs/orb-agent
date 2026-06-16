package mapping

import (
	"net"
	"sort"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/gnmi-discovery/config"
)

// vrfName returns a VRF's name, or "" for the global table.
func vrfName(v *diode.VRF) string {
	if v == nil || v.Name == nil {
		return ""
	}
	return *v.Name
}

// translatePrefixes derives a NetBox Prefix for the connected network of each
// discovered IPAddress in entities (net.ParseCIDR masks to the network), deduped by
// (cidr, vrf). Each prefix inherits the IP's discovered VRF (nil = global), the
// device Site as scope, and the policy defaults.prefix role/tenant/tags/description.
// Host-length networks (/32,/128) are emitted (parity with device-discovery). The
// Device.PrimaryIp matcher stub is nested in the Device, not a top-level entity, so
// it is not seen here.
func translatePrefixes(entities []diode.Entity, dev *diode.Device, defaults *config.Defaults) []diode.Entity {
	var site *diode.Site
	if dev != nil {
		site = dev.Site
	}
	var role *diode.Role
	var tenant *diode.Tenant
	var tags []*diode.Tag
	var desc string
	if defaults != nil {
		p := defaults.Prefix
		if p.Role != "" {
			role = &diode.Role{Name: strptr(p.Role)}
		}
		if p.Tenant != "" {
			tenant = &diode.Tenant{Name: strptr(p.Tenant)}
		}
		// Prefix tags = policy-level tags + prefix-level tags (defaults.tags applies
		// to all entities, mirroring the Device path).
		tags = toTags(append(append([]string{}, defaults.Tags...), p.Tags...))
		desc = p.Description
	}

	type key struct{ cidr, vrf string }
	prefixes := map[key]*diode.Prefix{}
	var order []key
	for _, e := range entities {
		ip, ok := e.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		_, ipnet, err := net.ParseCIDR(*ip.Address)
		if err != nil {
			continue
		}
		cidr := ipnet.String()
		k := key{cidr, vrfName(ip.Vrf)}
		if _, dup := prefixes[k]; dup {
			continue
		}
		pfx := &diode.Prefix{
			Prefix: strptr(cidr),
			Vrf:    ip.Vrf,
			Status: strptr("active"),
		}
		if site != nil {
			pfx.Scope = site
		}
		if role != nil {
			pfx.Role = role
		}
		if tenant != nil {
			pfx.Tenant = tenant
		}
		if len(tags) > 0 {
			pfx.Tags = tags
		}
		if desc != "" {
			pfx.Description = strptr(desc)
		}
		prefixes[k] = pfx
		order = append(order, k)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].cidr != order[j].cidr {
			return order[i].cidr < order[j].cidr
		}
		return order[i].vrf < order[j].vrf
	})
	out := make([]diode.Entity, 0, len(order))
	for _, k := range order {
		out = append(out, prefixes[k])
	}
	return out
}
