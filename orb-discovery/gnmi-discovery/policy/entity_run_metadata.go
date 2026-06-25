package policy

import "github.com/netboxlabs/diode-sdk-go/diode"

// annotateEntitiesWithRunID stamps run_id on every emitted entity's Diode
// metadata, plus the nested refs that are themselves emitted as NetBox objects:
// the shared *Device; an Interface's Lag, untagged/tagged VLANs, and VRF; and an
// IPAddress's assigned Interface and VRF. It covers all the entity types gNMI
// emits — Device, Interface, Module, ModuleBay, IPAddress, VLAN, VRF, Prefix.
// Existing metadata keys (e.g. source_match) are preserved — only run_id is set.
func annotateEntitiesWithRunID(entities []diode.Entity, runID string) {
	set := func(md *diode.Metadata) {
		if *md == nil {
			*md = diode.Metadata{}
		}
		(*md)["run_id"] = runID
	}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			if v != nil {
				set(&v.Metadata)
			}
		case *diode.Interface:
			if v != nil {
				set(&v.Metadata)
				if v.Device != nil {
					set(&v.Device.Metadata)
				}
				if v.Lag != nil {
					set(&v.Lag.Metadata)
					if v.Lag.Device != nil {
						set(&v.Lag.Device.Metadata)
					}
				}
				if v.UntaggedVlan != nil {
					set(&v.UntaggedVlan.Metadata)
				}
				for _, vl := range v.TaggedVlans {
					if vl != nil {
						set(&vl.Metadata)
					}
				}
				if v.Vrf != nil {
					set(&v.Vrf.Metadata)
				}
			}
		case *diode.Module:
			if v != nil {
				set(&v.Metadata)
				if v.Device != nil {
					set(&v.Device.Metadata)
				}
			}
		case *diode.ModuleBay:
			if v != nil {
				set(&v.Metadata)
				if v.Device != nil {
					set(&v.Device.Metadata)
				}
			}
		case *diode.IPAddress:
			if v != nil {
				set(&v.Metadata)
				if iface, ok := v.AssignedObject.(*diode.Interface); ok && iface != nil {
					set(&iface.Metadata)
					if iface.Device != nil {
						set(&iface.Device.Metadata)
					}
				}
				if v.Vrf != nil {
					set(&v.Vrf.Metadata)
				}
			}
		case *diode.VLAN:
			if v != nil {
				set(&v.Metadata)
			}
		case *diode.VRF:
			if v != nil {
				set(&v.Metadata)
			}
		case *diode.Prefix:
			if v != nil {
				set(&v.Metadata)
			}
		}
	}
}
