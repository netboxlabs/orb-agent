// Package mapping helpers that produce matcher-only stubs of diode
// entities. These are used to shrink nested references in the wire
// payload: only fields the diode-netbox-plugin needs to *match* the
// existing object are kept; full data still rides on the top-level
// entity.
package mapping

import "github.com/netboxlabs/diode-sdk-go/diode"

// newIPMatchStub returns an IPAddress carrying only the matcher fields
// (Address, Vrf). AssignedObject is intentionally nil — that is what
// breaks the IP→Interface→Device cycle when this stub is embedded in a
// Device stub's PrimaryIp4/PrimaryIp6.
func newIPMatchStub(ip *diode.IPAddress) *diode.IPAddress {
	if ip == nil {
		return nil
	}
	return &diode.IPAddress{
		Address: ip.Address,
		Vrf:     ip.Vrf,
	}
}

// newMACMatchStub returns a MACAddress carrying only MacAddress. Used
// inside Interface stubs to preserve the unique_primary_mac_address
// matcher precedence on dcim.interface.
func newMACMatchStub(mac *diode.MACAddress) *diode.MACAddress {
	if mac == nil {
		return nil
	}
	return &diode.MACAddress{
		MacAddress: mac.MacAddress,
	}
}

// newDeviceStub returns a Device populated with matcher-only fields
// plus the validation-required fields the diode-netbox-plugin checks
// when CREATING a dcim.device row from a nested reference. Site,
// Tenant, DeviceType, and Role are pointer-shared from the source —
// already minimal in snmp-discovery, no transitive bloat.
//
// PrimaryIp4/PrimaryIp6 are deliberately NOT carried here. The
// dcim.device.primary_ip4 reference is circular (the IP points at an
// interface that points at the device, while the device points back at
// the IP), and the diode reconciler can only resolve that cycle within
// a SINGLE change set. Each emitted entity becomes its own change set,
// so a nested device stub that tries to SET primary_ip4 fails on first
// ingest ("IP not assigned to this device") and rolls back the
// interfaces / modules emitted alongside it. The only entity that can
// validly close the cycle is the top-level ipam.ipaddress entity for
// the primary IP itself, which performs the IP->interface assignment
// and sets primary_ip4 in the same change set; PruneNestedRefs
// re-attaches a matcher-only primary onto that one stub via
// newDeviceStubKeepingPrimary. Every other nested device stub stays
// primary-IP-free.
//
// Why DeviceType and Role: when the reconciler processes an Interface
// (or other entity) whose nested Device reference does not yet match
// an existing NetBox device — i.e. on the first discovery cycle,
// before the rich top-level Device has been upserted — the plugin
// falls back to creating the device from the nested data. NetBox
// rejects creation if device_type or role are missing, even when the
// stub would have eventually matched the rich Device. Carrying these
// references on the stub eliminates the cold-start race observed
// during E2E.
//
// INVARIANT: the fields here must be a superset of (a) every
// dcim.device matcher field that snmp-discovery currently populates
// on the rich Device, and (b) every dcim.device field NetBox treats
// as required for create. As of this branch:
//
//   - AssetTag IS populated (via PolicyConfig.Defaults.AssetTag,
//     literal or OID reference, or from the chassis row's
//     entPhysicalAssetID when asset tag discovery is enabled). The stub
//     MUST carry it so rich and stub resolve via the same matcher
//     precedence path.
//
//   - PrimaryIp4 and PrimaryIp6 are NOT carried (see the function-doc
//     paragraph above). Stripping them off the default stub means the
//     stub resolves via a lower-precedence matcher than the rich
//     Device's primary_ip* path — that is acceptable because every stub
//     also carries asset_tag (when populated) and name+site+tenant, and
//     because setting primary_ip4 from a nested stub fails ingest
//     outright. Only the cycle-closer stub built by
//     newDeviceStubKeepingPrimary re-attaches a matcher-only primary.
//
//   - VcPosition and VirtualChassis ARE populated on non-master
//     member Devices when emitting a stack, but are intentionally
//     NOT carried on stubs. Matcher #8 (virtual_chassis plus
//     vc_position) sits behind higher-precedence matchers — asset_tag,
//     name+site+tenant, name+site, rack+position+face — that every
//     member Device already carries via the fields above. Copying the
//     rich VirtualChassis subtree onto every nested stub would just
//     bloat the wire payload.
//
//   - OobIp, Rack, Position, and Face remain not-populated.
//
// If a new mapper starts setting other matcher fields, or if NetBox
// adds new required fields for dcim.device, this stub must grow to
// match — otherwise the rich entity and the stub will resolve via
// different matcher precedence paths or fail validation on the first
// cycle.
//
// Metadata.source_match (e.g. netbox_id) is the diode-netbox-plugin's
// PK-based match path, so it must not diverge between rich and stub.
// Annotation metadata such as run_id is intentionally NOT copied —
// stubs are matcher-only.
func newDeviceStub(d *diode.Device) *diode.Device {
	if d == nil {
		return nil
	}
	stub := &diode.Device{
		Name:       d.Name,
		Site:       d.Site,
		Tenant:     d.Tenant,
		DeviceType: d.DeviceType,
		Role:       d.Role,
		AssetTag:   d.AssetTag,
	}
	if sm, ok := d.Metadata["source_match"]; ok {
		stub.Metadata = diode.Metadata{"source_match": sm}
	}
	return stub
}

// newDeviceStubKeepingPrimary returns a non-cached device stub for the
// cycle-closer: the top-level ipam.ipaddress entity that sets the
// device's primary IP within its own change set. It starts from the
// default (primary-IP-stripped) newDeviceStub and re-attaches whichever
// primary the owner carries as a matcher-only stub (AssignedObject
// cleared, so the re-attached IP itself carries no cycle).
//
// This stub MUST NEVER be inserted into PruneNestedRefs' stubCache: the
// cached stub is the primary-IP-free shape shared across every other
// nested reference, and overwriting it would leak the primary onto
// stubs that cannot validly set it.
func newDeviceStubKeepingPrimary(owner *diode.Device) *diode.Device {
	if owner == nil {
		return nil
	}
	stub := newDeviceStub(owner)
	if owner.PrimaryIp4 != nil {
		stub.PrimaryIp4 = newIPMatchStub(owner.PrimaryIp4)
	}
	if owner.PrimaryIp6 != nil {
		stub.PrimaryIp6 = newIPMatchStub(owner.PrimaryIp6)
	}
	return stub
}

// newInterfaceStub returns an Interface populated with matcher fields
// plus the validation-required `Type` field. Used wherever an
// Interface appears as a nested reference: Parent, Bridge, Lag,
// IPAddress.AssignedObject, MACAddress.AssignedObject. PrimaryMacAddress
// is preserved (via newMACMatchStub) so the stub keeps the
// unique_primary_mac_address matcher precedence and resolves to the
// same interface as the rich top-level entity.
//
// Why Type: snmp-discovery filters interfaces that are referenced as
// IPAddress.AssignedObject from top-level emission to avoid emitting
// them twice (mapping.go:716-718). For those interfaces, the nested
// stub is the *only* wire payload representing them. If first-time
// discovery needs to create the interface row, NetBox rejects creation
// without `type`. Pointer-sharing iface.Type costs negligible bytes
// and prevents the lossy first-discovery path.
func newInterfaceStub(iface *diode.Interface, deviceStub *diode.Device) *diode.Interface {
	if iface == nil {
		return nil
	}
	return &diode.Interface{
		Name:              iface.Name,
		Device:            deviceStub,
		Type:              iface.Type,
		PrimaryMacAddress: newMACMatchStub(iface.PrimaryMacAddress),
	}
}

// CurrentDeviceFrom returns the first *diode.Device in the slice, or
// nil. In normal operation the snmp-discovery mapper emits exactly one
// top-level Device per walk (the registry's CurrentDeviceIndex), so
// this is a cheap O(N) lookup and avoids threading the pointer through
// the runner separately.
func CurrentDeviceFrom(entities []diode.Entity) *diode.Device {
	for _, e := range entities {
		if d, ok := e.(*diode.Device); ok {
			return d
		}
	}
	return nil
}

// PruneNestedRefs walks entities once and replaces nested Device and
// Interface references with matcher-only stubs. Top-level rich Device
// entities are left unchanged — only nested references *to* them on
// other entities are rewritten.
//
// Multi-Device aware: each nested Device ref resolves to its OWN
// top-level Device by name (fallback: serial) before stubbing.
// Single-Device behavior is preserved as the degenerate case — the
// multi-device code IS the single-device code.
//
// Call from the runner AFTER annotateDeviceWithSourceMatch and
// annotateEntitiesWithRunID, BEFORE Ingest. Running before annotation
// would either (a) cause annotators to skip rich Devices because they
// would only see stubs, or (b) bloat every stub with run_id metadata,
// defeating the savings.
//
// primaryHits identifies the cycle-closer IPAddress entities (the
// top-level ipam.ipaddress entities that set a device's primary IP).
// For those entities only, the rebuilt nested device stub retains a
// matcher-only primary IP via newDeviceStubKeepingPrimary, because the
// reconciler can resolve the circular primary-IP reference only within
// that single change set. Every other nested device stub — on other
// interfaces, modules, module bays, MAC addresses, and non-primary IPs
// — is the default primary-IP-free stub. Pass nil to strip primary IPs
// everywhere.
//
// No-op if entities is empty.
func PruneNestedRefs(entities []diode.Entity, currentDevice *diode.Device, primaryHits map[*diode.IPAddress]bool) {
	if len(entities) == 0 {
		return
	}

	byName := map[string]*diode.Device{}
	bySerial := map[string]*diode.Device{}
	// Build a name -> top-level Interface index so nested Parent/
	// Bridge/Lag refs can re-resolve their owning Device via the
	// authoritative top-level Interface entry (which TranslateAsStack
	// has already routed to the correct member). Subinterface parent
	// resolution runs BEFORE TranslateAsStack and may leave nested
	// refs pointing at master; this index fixes it during pruning.
	// Top-level Interface index. Keyed by Name. Stores ALL matches to
	// support stacks where two member Devices both expose an iface
	// with the same name (e.g. per-member management ports like
	// `me0`/`mgmt0` on Junos VC and Cisco StackWise). When a nested
	// ref by-name lookup is ambiguous, stubForIface skips the
	// owner-rewrite rather than rebinding to a wrong member.
	ifaceByName := map[string][]*diode.Interface{}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			if v.Name != nil {
				byName[*v.Name] = v
			}
			if v.Serial != nil {
				bySerial[*v.Serial] = v
			}
		case *diode.Interface:
			if v.Name != nil {
				ifaceByName[*v.Name] = append(ifaceByName[*v.Name], v)
			}
		}
	}

	stubCache := map[*diode.Device]*diode.Device{}
	stubFor := func(ref *diode.Device) *diode.Device {
		if ref == nil {
			return nil
		}
		var owner *diode.Device
		if ref.Name != nil {
			owner = byName[*ref.Name]
		}
		if owner == nil && ref.Serial != nil {
			owner = bySerial[*ref.Serial]
		}
		if owner == nil {
			owner = currentDevice // legacy single-Device fallback
		}
		if owner == nil {
			// No known top-level Device and no currentDevice (e.g. the
			// mapper produced no Device entity for this walk). Leave the
			// existing ref in place rather than stubbing an anonymous
			// device — the annotators already set run_id on the ref and
			// we must not replace it with a bare stub.
			return ref
		}
		if cached, ok := stubCache[owner]; ok {
			return cached
		}
		s := newDeviceStub(owner)
		stubCache[owner] = s
		return s
	}

	// resolveIfaceOwner returns the owner Device for a nested Interface
	// ref, re-resolving by NAME against the top-level Interface index
	// (when one exists) so a stale Parent.Device (set by
	// ResolveSubinterfaceParents before TranslateAsStack) is corrected
	// to the current owner. Only rewrites the owner when the top-level
	// lookup is unambiguous: if multiple top-level interfaces share the
	// same name (cross-member duplicates like `me0`/`mgmt0` on Junos VC
	// / Cisco StackWise), the lookup cannot tell which member owns this
	// particular ref — keeping ref.Device preserves whatever upstream
	// routing produced (correct in the common case). Shared by
	// stubForIface and the cycle-closer rebuild so the two paths cannot
	// drift in how they resolve the owner.
	resolveIfaceOwner := func(ref *diode.Interface) *diode.Device {
		owner := ref.Device
		if ref.Name != nil {
			if tops, ok := ifaceByName[*ref.Name]; ok && len(tops) == 1 && tops[0].Device != nil {
				owner = tops[0].Device
			}
		}
		return owner
	}

	// stubForIface re-resolves a nested Interface ref before stubbing.
	stubForIface := func(ref *diode.Interface) *diode.Interface {
		if ref == nil {
			return nil
		}
		return newInterfaceStub(ref, stubFor(resolveIfaceOwner(ref)))
	}

	for _, entity := range entities {
		switch e := entity.(type) {
		case *diode.Device:
			// Top-level rich Devices stay rich.
			continue
		case *diode.Interface:
			e.Device = stubFor(e.Device)
			if e.Parent != nil {
				e.Parent = stubForIface(e.Parent)
			}
			if e.Bridge != nil {
				e.Bridge = stubForIface(e.Bridge)
			}
			if e.Lag != nil {
				e.Lag = stubForIface(e.Lag)
			}
			if e.Module != nil {
				// Reduce nested Interface.Module to a matcher-only ref:
				// chassis Device stub + Serial (if known) + ModuleBay
				// matcher (if known). The top-level Module entity
				// carries the full record (module_type, description,
				// status, etc.); this nested form lets the Diode
				// reconciler resolve the ref to that top-level row via
				// the (Device, ModuleBay) or (Device, Serial) match
				// paths without re-creating it.
				//
				// Shape mirrors device-discovery's _module_match_stub
				// (device-discovery/device_discovery/stubs.py
				// `_module_match_stub`): emit Device unconditionally,
				// then conditionally copy Serial and ModuleBay matcher
				// fields when present on the rich Module. Vendors that
				// omit transceiver serial in ENTITY-MIB (some Aruba
				// and low-end OEMs) still populate the bay, so the
				// (Device, ModuleBay) path alone must keep the ref
				// resolvable.
				//
				// Only when BOTH Serial AND ModuleBay are unusable do
				// we drop the ref entirely — at that point the stub
				// carries no identifier and the reconciler would fall
				// into creation mode and fail the
				// "module_bay required, module_type required"
				// validation (we also strip ModuleType).
				devStub := stubFor(e.Module.Device)
				stub := &diode.Module{Device: devStub}
				if e.Module.Serial != nil && *e.Module.Serial != "" {
					stub.Serial = e.Module.Serial
				}
				if e.Module.ModuleBay != nil {
					stub.ModuleBay = &diode.ModuleBay{
						Device:   devStub,
						Name:     e.Module.ModuleBay.Name,
						Position: e.Module.ModuleBay.Position,
					}
				}
				if stub.Serial == nil && stub.ModuleBay == nil {
					// Unresolvable: drop the ref so the reconciler
					// doesn't try to create a Module without the
					// required validation fields.
					e.Module = nil
				} else {
					e.Module = stub
				}
			}
		case *diode.IPAddress:
			if iface, ok := e.AssignedObject.(*diode.Interface); ok && iface != nil {
				if primaryHits != nil && primaryHits[e] {
					// Cycle-closer: this IPAddress entity sets a device's
					// primary IP within its own change set, so its nested
					// device stub MUST retain a matcher-only primary IP.
					// Resolve the owner exactly as the stripped path does
					// (resolveIfaceOwner respects the duplicate-name guard),
					// then build a NON-cached keeping-primary stub so the
					// shared primary-IP-free cache stays untouched. The
					// interface keeps its rich Type/MAC via newInterfaceStub.
					//
					// Stack edge: the resolved owner may be a stack member
					// whose own PrimaryIp4/6 is nil while the master /
					// currentDevice carries it. newDeviceStubKeepingPrimary
					// copies whatever primary the device it is built from
					// carries, so we build the identity stub from the owner
					// (member) but source the primary from the device that
					// actually carries it: prefer the owner, fall back to
					// currentDevice when the owner has none. This
					// member-vs-master case is handled by the fallback below
					// and should be confirmed against a real stacked-switch
					// capture.
					owner := resolveIfaceOwner(iface)
					if owner == nil {
						// Mirror the stripped path's currentDevice fallback
						// when the ref names no resolvable top-level Device.
						owner = currentDevice
					}
					primarySrc := owner
					if primarySrc == nil ||
						(primarySrc.PrimaryIp4 == nil && primarySrc.PrimaryIp6 == nil) {
						if currentDevice != nil &&
							(currentDevice.PrimaryIp4 != nil || currentDevice.PrimaryIp6 != nil) {
							primarySrc = currentDevice
						}
					}
					devStub := newDeviceStubKeepingPrimary(owner)
					// When the owner carried no primary, copy it from the
					// fallback source (the master) onto the owner's stub.
					if devStub != nil && primarySrc != owner && primarySrc != nil {
						devStub.PrimaryIp4 = newIPMatchStub(primarySrc.PrimaryIp4)
						devStub.PrimaryIp6 = newIPMatchStub(primarySrc.PrimaryIp6)
					}
					e.AssignedObject = newInterfaceStub(iface, devStub)
				} else {
					e.AssignedObject = stubForIface(iface)
				}
			}
		case *diode.MACAddress:
			if iface, ok := e.AssignedObject.(*diode.Interface); ok && iface != nil {
				e.AssignedObject = stubForIface(iface)
			}
		case *diode.Module:
			e.Device = stubFor(e.Device)
		case *diode.ModuleBay:
			e.Device = stubFor(e.Device)
		}
	}
}
