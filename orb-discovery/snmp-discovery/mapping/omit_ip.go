package mapping

import "github.com/netboxlabs/diode-sdk-go/diode"

// OmitIPAddresses replaces PruneNestedRefs for emit_ip_addresses: false. It
// prunes the nested refs the same way and drops every IPAddress entity.
//
// An interface that carries an address is not sent on its own: it rides
// nested in the address, as the stub PruneNestedRefs builds for it. Each
// address therefore gives way to that stub, in its place and once per
// interface, unless the interface is already sent. The stub carries only what
// the default sends for the interface, so the option changes nothing else
// about it; it keeps the interface's run metadata, as top-level entities do.
//
// The primary IP of every device the run reaches, as an entity or through an
// interface, is cleared first, since it would point at an address the run no
// longer sends; no stub carries one either.
func OmitIPAddresses(entities []diode.Entity, currentDevice *diode.Device) []diode.Entity {
	sent := map[*diode.Interface]bool{}
	assigned := map[*diode.IPAddress]*diode.Interface{}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			clearPrimaryIP(v)
		case *diode.Interface:
			sent[v] = true
			clearPrimaryIP(v.Device)
		case *diode.IPAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok && iface != nil {
				assigned[v] = iface
				clearPrimaryIP(iface.Device)
			}
		}
	}

	PruneNestedRefs(entities, currentDevice, nil)

	out := make([]diode.Entity, 0, len(entities))
	for _, e := range entities {
		addr, ok := e.(*diode.IPAddress)
		if !ok {
			out = append(out, e)
			continue
		}
		iface := assigned[addr]
		stub, ok := addr.AssignedObject.(*diode.Interface)
		if iface == nil || sent[iface] || !ok || stub == nil {
			continue
		}
		sent[iface] = true
		stub.Metadata = iface.Metadata
		out = append(out, stub)
	}
	return out
}

func clearPrimaryIP(d *diode.Device) {
	if d != nil {
		d.PrimaryIp4 = nil
		d.PrimaryIp6 = nil
	}
}
