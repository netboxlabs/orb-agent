package mapping

import "github.com/netboxlabs/diode-sdk-go/diode"

// OmitIPAddresses drops every IPAddress entity, for emit_ip_addresses: false.
//
// An interface that carries an address is not sent on its own: it rides
// nested in the address. Each address therefore gives way to its interface,
// in its place and once, unless that interface is already sent. The primary
// IP of every device the run reaches, as an entity or through an interface,
// is cleared, since it would point at an address the run no longer sends.
func OmitIPAddresses(entities []diode.Entity) []diode.Entity {
	sent := map[*diode.Interface]bool{}
	for _, e := range entities {
		if iface, ok := e.(*diode.Interface); ok {
			sent[iface] = true
		}
	}
	out := make([]diode.Entity, 0, len(entities))
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.IPAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok && iface != nil && !sent[iface] {
				sent[iface] = true
				out = append(out, iface)
			}
			continue
		case *diode.Device:
			clearPrimaryIP(v)
		}
		out = append(out, e)
	}
	for iface := range sent {
		clearPrimaryIP(iface.Device)
	}
	return out
}

func clearPrimaryIP(d *diode.Device) {
	if d != nil {
		d.PrimaryIp4 = nil
		d.PrimaryIp6 = nil
	}
}
