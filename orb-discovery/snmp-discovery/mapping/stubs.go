// Package mapping helpers that produce matcher-only stubs of diode
// entities. These are used to shrink nested references in the wire
// payload: only fields the diode-netbox-plugin needs to *match* the
// existing object are kept; full data still rides on the top-level
// entity.
package mapping

import (
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

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
// default (primary-IP-stripped) newDeviceStub and re-attaches ONLY the
// primary that corresponds to the IPAddress entity being pruned, as a
// matcher-only stub (AssignedObject cleared, so the re-attached IP itself
// carries no cycle): isV6 selects PrimaryIp6 vs PrimaryIp4 and primary is
// the device's primary for that family (nil leaves it stripped).
//
// Only the matching family is carried. On a dual-stack device the IPv4
// cycle-closer's change set assigns only the IPv4 address to the interface,
// so attaching primary_ip6 there would try to set the IPv6 primary before
// its address is assigned to the device — re-creating the first-ingest
// circular-primary failure (and vice versa for the IPv6 cycle-closer).
//
// This stub MUST NEVER be inserted into PruneNestedRefs' stubCache: the
// cached stub is the primary-IP-free shape shared across every other
// nested reference, and overwriting it would leak the primary onto
// stubs that cannot validly set it.
func newDeviceStubKeepingPrimary(owner *diode.Device, isV6 bool, primary *diode.IPAddress) *diode.Device {
	if owner == nil {
		return nil
	}
	stub := newDeviceStub(owner)
	if primary != nil {
		if isV6 {
			stub.PrimaryIp6 = newIPMatchStub(primary)
		} else {
			stub.PrimaryIp4 = newIPMatchStub(primary)
		}
	}
	return stub
}

// newInterfaceStub returns an Interface populated with the matcher
// fields plus the interface's plain attributes (type, description,
// speed, mtu, enabled). Used wherever an Interface appears as a nested
// reference: Parent, Bridge, Lag, IPAddress.AssignedObject,
// MACAddress.AssignedObject. PrimaryMacAddress is preserved (via
// newMACMatchStub) so the stub keeps the unique_primary_mac_address
// matcher precedence and resolves to the same interface as the rich
// top-level entity.
//
// Why the plain attributes: snmp-discovery filters interfaces that are
// referenced as IPAddress.AssignedObject from top-level emission to
// avoid emitting them twice. For those interfaces the nested stub is
// the *only* wire payload, so it must carry both `type` (NetBox
// rejects first-time interface creation without it) and the plain
// attributes the mapper computed, or they are silently lost. Pointer-
// sharing them costs negligible bytes. Structural refs (parent/bridge/
// lag) are intentionally dropped; they carry their own nested payloads.
//
// Tags is deliberately NOT carried. Nested IP-assigned interface refs have
// never carried it, so adding it here would start tagging interfaces that are
// untagged today — a product change, not a fix. Diode applies updates with
// PATCH semantics, so omitting the field never strips tags from an interface
// that already has them; only a first-time creation comes up untagged, which
// is the existing behaviour for every other IP-assigned interface.
func newInterfaceStub(iface *diode.Interface, deviceStub *diode.Device) *diode.Interface {
	if iface == nil {
		return nil
	}
	return &diode.Interface{
		Name:              iface.Name,
		Device:            deviceStub,
		Type:              iface.Type,
		Description:       iface.Description,
		Speed:             iface.Speed,
		Mtu:               iface.Mtu,
		Enabled:           iface.Enabled,
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
	// liveIfaceByAddr maps an address to the LIVE interface its top-level
	// IPAddress entity is assigned to. TranslateAsStack has already routed that
	// interface to its owning stack member, whereas a primary-IP snapshot froze
	// the owner back during mapping. The primary-IP interface is deliberately
	// excluded from top-level Interface emission (see getAssignedInterfaces), so
	// ifaceByName structurally cannot resolve it and the address is the only
	// exact key. Stores ALL matches so an address claimed by more than one
	// interface is treated as ambiguous and left alone, mirroring ifaceByName.
	liveIfaceByAddr := map[string][]*diode.Interface{}
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
		case *diode.IPAddress:
			if v.Address != nil {
				if i, ok := v.AssignedObject.(*diode.Interface); ok && i != nil {
					liveIfaceByAddr[*v.Address] = append(liveIfaceByAddr[*v.Address], i)
				}
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

	// prunePrimarySnapshot stubs the device ref buried in a top-level Device's
	// primary-IP snapshot. detachForPrimaryIP shallow-copies the Device during
	// mapping to break the Device -> IP -> Interface -> Device cycle, so without
	// this the snapshot keeps whatever the Device looked like BEFORE
	// TranslateAsStack, the annotators and name suppression ran: a stale
	// device_type, a hostname the operator asked to suppress, no source_match,
	// and the master as owner where the live interface belongs to a member.
	//
	// Cannot reintroduce the cycle: newDeviceStub carries no PrimaryIp4/6 and
	// newInterfaceStub carries no Parent/Bridge/Lag/Module, which is exactly what
	// detachForPrimaryIP clears by hand.
	prunePrimarySnapshot := func(ip *diode.IPAddress) {
		if ip == nil {
			return
		}
		iface, ok := ip.AssignedObject.(*diode.Interface)
		if !ok || iface == nil {
			return
		}
		// Resolve the owner from the live entity for this exact address when
		// there is exactly one: it reflects TranslateAsStack's member routing,
		// while the snapshot's own copy is frozen at the master.
		if ip.Address != nil {
			if live, ok := liveIfaceByAddr[*ip.Address]; ok && len(live) == 1 && live[0] != nil {
				iface = live[0]
			}
		}
		// Deliberately still routed through stubForIface rather than stubbing
		// live[0].Device directly. The point of this function is that the
		// snapshot and the live cycle-closer entity agree, and the live entity
		// goes through resolveIfaceOwner too; bypassing it here would let the
		// two diverge again whenever resolveIfaceOwner rewrites an owner.
		stubbed := stubForIface(iface)
		// stubFor has an escape hatch that returns the ref unchanged when no
		// owning Device can be resolved. Writing a still-rich device back here
		// would point the snapshot at a Device that carries this very primary
		// IP, and the SDK's proto conversion does not detect cycles.
		if stubbed != nil && stubbed.Device != nil &&
			(stubbed.Device.PrimaryIp4 != nil || stubbed.Device.PrimaryIp6 != nil) {
			return
		}
		ip.AssignedObject = stubbed
	}

	for _, entity := range entities {
		switch e := entity.(type) {
		case *diode.Device:
			// The Device itself stays rich, but its primary-IP snapshots hold
			// nested refs like any other entity and must be stubbed.
			prunePrimarySnapshot(e.PrimaryIp4)
			prunePrimarySnapshot(e.PrimaryIp6)
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
				// Reduce nested Interface.Module to a matcher-only ref: chassis
				// Device stub + ModuleBay matcher + ModuleType, plus Serial when
				// known. The top-level Module entity carries the full record
				// (description, status, etc.).
				//
				// ModuleBay is the load-bearing part: it is dcim.module's only
				// unique matcher besides asset_tag. Serial is carried for create
				// fidelity only — dcim.module has no serial matcher, so a
				// serial-only stub resolves nothing. Vendors that omit transceiver
				// serial in ENTITY-MIB (some Aruba and low-end OEMs) still populate
				// the bay, so the bay alone must keep the ref resolvable.
				//
				// ModuleType is retained even though it matches nothing. A ref only
				// resolves once the referenced ModuleBay row exists; until then
				// Diode falls back to CREATING the Module, and NetBox rejects a
				// Module without a module_type. Emitting module entities ahead of
				// interfaces does not prevent that: bulk-plan-apply batches plans
				// and applies them independently, so payload order is not
				// reconciliation order, and one failed plan takes its whole batch
				// down — including unrelated interfaces. Only the
				// (Manufacturer, Model) pair is copied, which is the complete
				// dcim.moduletype matcher, so the ref cannot grow as drivers
				// populate richer ModuleType fields.
				//
				// Mirrors device-discovery's _module_match_stub
				// (device-discovery/device_discovery/stubs.py).
				//
				// Only when BOTH Serial AND ModuleBay are unusable do we drop the
				// ref entirely: it then carries no identifier, and creating it
				// would fail anyway because NetBox requires module_bay.
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
				if mt := e.Module.ModuleType; mt != nil {
					stub.ModuleType = &diode.ModuleType{Model: mt.Model}
					if mt.Manufacturer != nil {
						stub.ModuleType.Manufacturer = &diode.Manufacturer{
							Name: mt.Manufacturer.Name,
						}
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
					// Only this IPAddress's OWN family may be set here: its
					// change set assigns just this address to the interface, so
					// attaching the other family's primary (dual-stack) would
					// try to set a primary whose address is not yet assigned.
					isV6 := e.Address != nil && strings.Contains(*e.Address, ":")
					owner := resolveIfaceOwner(iface)
					if owner == nil {
						// Mirror the stripped path's currentDevice fallback
						// when the ref names no resolvable top-level Device.
						owner = currentDevice
					}
					// Stack edge: the resolved owner may be a stack member
					// whose own primary is nil while the master / currentDevice
					// carries it. Source this family's primary from the device
					// that actually carries it — prefer the owner, fall back to
					// currentDevice. This member-vs-master case should be
					// confirmed against a real stacked-switch capture.
					var primary *diode.IPAddress
					switch {
					case isV6 && owner != nil && owner.PrimaryIp6 != nil:
						primary = owner.PrimaryIp6
					case !isV6 && owner != nil && owner.PrimaryIp4 != nil:
						primary = owner.PrimaryIp4
					case isV6 && currentDevice != nil && currentDevice.PrimaryIp6 != nil:
						primary = currentDevice.PrimaryIp6
					case !isV6 && currentDevice != nil && currentDevice.PrimaryIp4 != nil:
						primary = currentDevice.PrimaryIp4
					}
					e.AssignedObject = newInterfaceStub(iface, newDeviceStubKeepingPrimary(owner, isV6, primary))
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
