package policy

import (
	"unsafe"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// annotateDeviceWithSourceMatch sets source_match metadata on the *diode.Device
// reachable from the entity batch — either at the top level, via Interface.Device,
// or via IPAddress→Interface.Device. This covers the shapes produced by
// MapObjectIDsToEntity; deeper links (Interface.Parent/Bridge/Lag,
// IPAddress.NatInside) are not traversed.
func annotateDeviceWithSourceMatch(entities []diode.Entity, netboxID int) {
	seen := make(map[unsafe.Pointer]struct{})
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			setDeviceSourceMatch(v, netboxID, seen)
		case *diode.Interface:
			if v != nil {
				setDeviceSourceMatch(v.Device, netboxID, seen)
			}
		case *diode.IPAddress:
			if v != nil {
				if iface, ok := v.AssignedObject.(*diode.Interface); ok && iface != nil {
					setDeviceSourceMatch(iface.Device, netboxID, seen)
				}
			}
		}
	}
}

func setDeviceSourceMatch(d *diode.Device, netboxID int, seen map[unsafe.Pointer]struct{}) {
	if d == nil {
		return
	}
	p := unsafe.Pointer(d)
	if _, ok := seen[p]; ok {
		return
	}
	seen[p] = struct{}{}
	if d.Metadata == nil {
		d.Metadata = make(diode.Metadata)
	}
	d.Metadata["source_match"] = diode.Metadata{"netbox_id": netboxID}
}

// annotateEntitiesWithRunID sets per-entity Diode metadata key "run_id" on each entity
// in the batch and on nested Device, Interface, IPAddress, and VLAN references.
func annotateEntitiesWithRunID(entities []diode.Entity, runID string) {
	seen := make(map[unsafe.Pointer]struct{})
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			annotateDevice(v, runID, seen)
		case *diode.Interface:
			annotateInterface(v, runID, seen)
		case *diode.IPAddress:
			annotateIPAddress(v, runID, seen)
		case *diode.VLAN:
			annotateVLAN(v, runID, seen)
		}
	}
}

func mergeRunID(md *diode.Metadata, runID string) {
	if md == nil {
		return
	}
	if *md == nil {
		*md = make(diode.Metadata)
	}
	(*md)["run_id"] = runID
}

func annotateDevice(d *diode.Device, runID string, seen map[unsafe.Pointer]struct{}) {
	if d == nil {
		return
	}
	p := unsafe.Pointer(d)
	if _, ok := seen[p]; ok {
		return
	}
	seen[p] = struct{}{}
	mergeRunID(&d.Metadata, runID)
}

func annotateInterface(iface *diode.Interface, runID string, seen map[unsafe.Pointer]struct{}) {
	if iface == nil {
		return
	}
	p := unsafe.Pointer(iface)
	if _, ok := seen[p]; ok {
		return
	}
	seen[p] = struct{}{}
	mergeRunID(&iface.Metadata, runID)
	annotateDevice(iface.Device, runID, seen)
	annotateInterface(iface.Parent, runID, seen)
	annotateInterface(iface.Bridge, runID, seen)
	annotateInterface(iface.Lag, runID, seen)
	annotateVLAN(iface.UntaggedVlan, runID, seen)
	for _, v := range iface.TaggedVlans {
		annotateVLAN(v, runID, seen)
	}
}

func annotateIPAddress(ip *diode.IPAddress, runID string, seen map[unsafe.Pointer]struct{}) {
	if ip == nil {
		return
	}
	p := unsafe.Pointer(ip)
	if _, ok := seen[p]; ok {
		return
	}
	seen[p] = struct{}{}
	mergeRunID(&ip.Metadata, runID)
	if ip.AssignedObject != nil {
		switch a := ip.AssignedObject.(type) {
		case *diode.Interface:
			annotateInterface(a, runID, seen)
		case *diode.FHRPGroup:
			mergeRunID(&a.Metadata, runID)
		case *diode.VMInterface:
			mergeRunID(&a.Metadata, runID)
		}
	}
	if ip.NatInside != nil {
		annotateIPAddress(ip.NatInside, runID, seen)
	}
}

func annotateVLAN(vlan *diode.VLAN, runID string, seen map[unsafe.Pointer]struct{}) {
	if vlan == nil {
		return
	}
	p := unsafe.Pointer(vlan)
	if _, ok := seen[p]; ok {
		return
	}
	seen[p] = struct{}{}
	mergeRunID(&vlan.Metadata, runID)
}
