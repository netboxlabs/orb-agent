package policy

import (
	"unsafe"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// emittedStack reports whether this batch describes a multi-device stack,
// returning the master's serial for the caller's log line.
//
// A target's netbox_id names one NetBox device, but a stack member's
// management address is answered by the whole system: querying either
// address of an HA pair returns both chassis, and nothing in ENTITY-MIB,
// IF-MIB or IP-MIB ties an address to the chassis that owns it.
// Management addresses sit on an SVI, which is a logical interface of the
// pair rather than of a member, so entAliasMappingTable cannot resolve them
// either — across 30 stacks in the LibreNMS corpus, 48 of 52 addresses have
// no chassis at all, and no stack has two that resolve to different ones.
//
// So the pin cannot be checked against the member it was written for, and
// applying it to the master anyway asserts that the master is that device.
// When it is not, Diode is told the virtual chassis has a different master,
// and since dcim.virtualchassis matches on master, NetBox is asked to build
// a second chassis around it.
//
// TranslateAsStack emits the VirtualChassis and the member Devices together,
// so either is sufficient to recognise one.
//
// The serial is captured from the master whether or not a stack was
// recognised here, because the caller also withholds on a walk-derived
// signal this function cannot see. On that path there is no VirtualChassis
// to read the master's serial from, and it is the one field that identifies
// the affected device in the log.
func emittedStack(entities []diode.Entity) (string, bool) {
	found := false
	serial := ""
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.VirtualChassis:
			if v != nil {
				found = true
				if v.Master != nil && v.Master.Serial != nil && serial == "" {
					serial = *v.Master.Serial
				}
			}
		case *diode.Device:
			if v == nil {
				continue
			}
			if v.VcPosition != nil {
				found = true
				continue
			}
			// The master: no member position, and on a refused stack the
			// only Device emitted at all.
			if v.Serial != nil && serial == "" {
				serial = *v.Serial
			}
		}
	}
	return serial, found
}

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
			// Inline master ref inside a member's VirtualChassis.Master must
			// also carry source_match so Diode's unique_master matcher
			// resolves consistently with the rich master Device.
			if v.VirtualChassis != nil {
				setDeviceSourceMatch(v.VirtualChassis.Master, netboxID, seen)
			}
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
		case *diode.VirtualChassis:
			// Top-level VC carries the master ref that needs source_match
			// for unique_master matcher resolution.
			if v != nil {
				setDeviceSourceMatch(v.Master, netboxID, seen)
			}
		}
	}
}

func setDeviceSourceMatch(d *diode.Device, netboxID int, seen map[unsafe.Pointer]struct{}) {
	if d == nil {
		return
	}
	// Skip non-master members emitted by mapping.TranslateAsStack:
	// each carries VcPosition. Annotating them with master's
	// netbox_id would make Diode's source_match matcher collapse
	// every member onto the same NetBox device row.
	if d.VcPosition != nil {
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
		case *diode.VirtualChassis:
			annotateVirtualChassis(v, runID, seen)
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

func annotateVirtualChassis(vc *diode.VirtualChassis, runID string, seen map[unsafe.Pointer]struct{}) {
	if vc == nil {
		return
	}
	p := unsafe.Pointer(vc)
	if _, ok := seen[p]; ok {
		return
	}
	seen[p] = struct{}{}
	mergeRunID(&vc.Metadata, runID)
	// Stamp run_id on the inline Master Device stub so it lines up with
	// the run_id on the rich top-level Device that the stub matches —
	// keeps annotation consistent with how VLAN and Interface
	// annotation reach their nested Device refs. annotateDevice only
	// mutates d.Metadata (no recursion into Device's nested fields), so
	// no cycle risk through Master.VirtualChassis.
	if vc.Master != nil {
		annotateDevice(vc.Master, runID, seen)
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
