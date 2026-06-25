// Package mapping — stubs.go: matcher-only stubs for nested entity references.
//
// At the runner boundary (after annotation, before Ingest) every nested
// *diode.Device / *diode.Interface reference is replaced with a stub carrying
// only the fields the diode-netbox-plugin needs to MATCH the existing object,
// plus the few NetBox requires for create-time validation. The full record
// still rides on the single top-level entity.
//
// This is the gNMI port of snmp-discovery's stubs.go (PR #392) and
// device-discovery's stubs.py (PR #394). It matters most here because the
// top-level Device may carry a large `config.running` blob (options.capture_config):
// without pruning, that blob is duplicated onto the nested Device ref of every
// interface / IP / module, inflating the wire payload by megabytes. The stub
// deliberately omits Config (and all non-matcher fields), so the heavy config
// rides exactly once — mirroring device-discovery's `ClearField("config")` on
// nested device refs.
package mapping

import "github.com/netboxlabs/diode-sdk-go/diode"

// newIPMatchStub returns an IPAddress carrying only the matcher fields
// (Address, Vrf). AssignedObject is intentionally nil — that breaks the
// IP→Interface→Device cycle when embedded as a Device stub's PrimaryIp4/6.
func newIPMatchStub(ip *diode.IPAddress) *diode.IPAddress {
	if ip == nil {
		return nil
	}
	return &diode.IPAddress{Address: ip.Address, Vrf: ip.Vrf}
}

// newMACMatchStub returns a MACAddress carrying only MacAddress, preserving the
// unique_primary_mac_address matcher precedence on dcim.interface.
func newMACMatchStub(mac *diode.MACAddress) *diode.MACAddress {
	if mac == nil {
		return nil
	}
	return &diode.MACAddress{MacAddress: mac.MacAddress}
}

// newDeviceStub returns a Device with matcher-only fields plus the
// validation-required fields NetBox checks when CREATING a dcim.device from a
// nested reference (DeviceType, Role) — needed for the cold-start cycle before
// the rich top-level Device has been upserted.
//
// PrimaryIp4/6 are deliberately NOT carried (diode reconciler bug #545):
// dcim.device.primary_ip4 is a circular reference the diode-netbox-plugin can
// only resolve within a SINGLE change set, but each emitted entity is its own
// change set. A matcher-only primary IP on a nested device stub makes the plugin
// try to SET it — which fails ("IP not assigned to this device") on first ingest
// and rolls back the interfaces/modules in that change set. The ONLY entity that
// can validly set device.primary_ip4 in one change set is the top-level
// ipam.ipaddress for the primary IP (it does the IP→interface assignment AND, via
// its own nested device stub's primary_ip4, closes the cycle in the same change
// set). That single cycle-closer stub is built by newDeviceStubWithPrimary in
// PruneNestedRefs; every other nested device stub strips the primary IP here.
//
// INVARIANT: this must be a superset of every dcim.device matcher field
// gnmi-discovery populates on the rich Device (other than primary IPs, see
// above), plus NetBox's create-required fields. AssetTag is carried (Diode's
// highest-precedence dcim.device matcher; gnmi-discovery sets it from
// defaults.asset_tag). Config / Status / Platform / Comments / Location / Tags
// are NOT matchers and NOT required for create, so they are dropped — this is the
// whole point of the stub (Config is large). source_match metadata (netbox_id) is
// the plugin's PK match path, so it must not diverge between rich and stub; run_id
// annotation is matcher-irrelevant and intentionally omitted.
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

// newDeviceStubWithPrimary returns a newDeviceStub for owner that ALSO re-attaches
// the owner's set primary IP as a matcher-only stub — the sole exception to the
// primary-IP stripping in newDeviceStub. It is used ONLY for the cycle-closer:
// the nested device stub on the top-level ipam.ipaddress entity for the primary
// IP (see PruneNestedRefs). AssignPrimaryIP sets at most one family per call, so
// at most one of PrimaryIp4/PrimaryIp6 is re-attached.
//
// The re-attached primary is matcher-only (Address + Vrf, AssignedObject nil, via
// newIPMatchStub) BY DESIGN: the cycle is EXECUTED by the top-level IPAddress
// entity's own AssignedObject (which performs the IP→interface assignment), not by
// this nested stub — the stub only lets the plugin set device.primary_ip4 within
// that same change set. NEVER insert this stub into stubCache: it is intentionally
// per-cycle-closer and must not leak onto other nested device refs.
func newDeviceStubWithPrimary(owner *diode.Device) *diode.Device {
	s := newDeviceStub(owner)
	if s == nil {
		return nil
	}
	if owner.PrimaryIp4 != nil {
		s.PrimaryIp4 = newIPMatchStub(owner.PrimaryIp4)
	}
	if owner.PrimaryIp6 != nil {
		s.PrimaryIp6 = newIPMatchStub(owner.PrimaryIp6)
	}
	return s
}

// newInterfaceStub returns an Interface with matcher fields plus the
// validation-required Type. PrimaryMacAddress is preserved (matcher precedence).
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

// CurrentDeviceFrom returns the first *diode.Device in entities, or nil.
// gnmi-discovery emits exactly one top-level Device per cycle.
func CurrentDeviceFrom(entities []diode.Entity) *diode.Device {
	for _, e := range entities {
		if d, ok := e.(*diode.Device); ok {
			return d
		}
	}
	return nil
}

// PruneNestedRefs walks entities once and replaces nested Device and Interface
// references with matcher-only stubs. Top-level rich entities are untouched —
// only references TO them on other entities are rewritten.
//
// primaryIP is the cycle-closer: the LIVE *diode.IPAddress returned by
// AssignPrimaryIP (the top-level ipam.ipaddress for the device's primary IP), or
// nil when no primary was assigned. The nested device stub on THIS exact entity
// (matched by pointer identity, never by value) is built with
// newDeviceStubWithPrimary so it retains device.primary_ip4 — letting the plugin
// close the primary-IP cycle within that one entity's change set (diode reconciler
// bug #545). Every OTHER nested device stub strips the primary IP. When primaryIP
// is nil there is no cycle-closer and all stubs are stripped.
//
// Call from the runner AFTER run_id / source_match annotation, BEFORE Ingest:
// running earlier would either make the annotators traverse stubs (and skip the
// rich Device) or bloat every stub with run_id, defeating the savings.
//
// No-op on empty input.
func PruneNestedRefs(entities []diode.Entity, currentDevice *diode.Device, primaryIP *diode.IPAddress) {
	if len(entities) == 0 {
		return
	}

	byName := map[string]*diode.Device{}
	bySerial := map[string]*diode.Device{}
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

	// ownerFor resolves the top-level rich Device that a nested Device ref points
	// at: by name, then by serial, then the single-Device fallback. Shared by the
	// stripped path and the cycle-closer path so their resolution can't drift.
	ownerFor := func(ref *diode.Device) *diode.Device {
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
			owner = currentDevice // single-Device fallback
		}
		return owner
	}

	stubCache := map[*diode.Device]*diode.Device{}
	stubFor := func(ref *diode.Device) *diode.Device {
		if ref == nil {
			return nil
		}
		owner := ownerFor(ref)
		if owner == nil {
			return ref // no known top-level Device: leave the ref as-is
		}
		if cached, ok := stubCache[owner]; ok {
			return cached
		}
		s := newDeviceStub(owner)
		stubCache[owner] = s
		return s
	}

	// resolveIface re-resolves a nested Interface ref by name against the
	// top-level Interface index (when unambiguous) so the stub can carry the rich
	// interface's Type/MAC/owner — important because some nested refs (e.g. an
	// IPAddress.AssignedObject built in translateIPs) are minimal name+device
	// shells without Type. Mirrors the duplicate-name guard: an ambiguous name
	// (>1 top-level interface) falls back to the ref as-is.
	resolveIface := func(ref *diode.Interface) *diode.Interface {
		src := ref
		if ref.Name != nil {
			if tops, ok := ifaceByName[*ref.Name]; ok && len(tops) == 1 {
				src = tops[0]
			}
		}
		return src
	}

	// stubForIface builds the matcher-only interface stub using the STRIPPED
	// device stub (the common case). All references EXCEPT the cycle-closer use it.
	stubForIface := func(ref *diode.Interface) *diode.Interface {
		if ref == nil {
			return nil
		}
		src := resolveIface(ref)
		return newInterfaceStub(src, stubFor(src.Device))
	}

	// cycleCloserIface builds the matcher-only interface stub for the cycle-closer
	// IPAddress: the interface keeps its rich Type/MAC (newInterfaceStub of the
	// re-resolved rich interface — CRITICAL, without the rich Type the
	// IP→interface create can fail NetBox validation), but its nested device stub
	// is newDeviceStubWithPrimary so it carries primary_ip4 in this one change set.
	// The device stub is intentionally NOT cached (it must not leak onto other
	// nested refs).
	cycleCloserIface := func(ref *diode.Interface) *diode.Interface {
		if ref == nil {
			return nil
		}
		src := resolveIface(ref)
		owner := ownerFor(src.Device)
		if owner == nil {
			return stubForIface(ref) // no known top-level Device: fall back to stripped
		}
		return newInterfaceStub(src, newDeviceStubWithPrimary(owner))
	}

	for _, entity := range entities {
		switch e := entity.(type) {
		case *diode.Device:
			continue // top-level rich Devices stay rich
		case *diode.Interface:
			e.Device = stubFor(e.Device)
			if e.Parent != nil {
				e.Parent = stubForIface(e.Parent)
			}
			if e.Lag != nil {
				e.Lag = stubForIface(e.Lag)
			}
		case *diode.IPAddress:
			if iface, ok := e.AssignedObject.(*diode.Interface); ok && iface != nil {
				if primaryIP != nil && e == primaryIP {
					e.AssignedObject = cycleCloserIface(iface)
				} else {
					e.AssignedObject = stubForIface(iface)
				}
			}
		case *diode.Module:
			e.Device = stubFor(e.Device)
			if e.ModuleBay != nil {
				e.ModuleBay.Device = stubFor(e.ModuleBay.Device)
			}
		case *diode.ModuleBay:
			e.Device = stubFor(e.Device)
		}
	}
}
