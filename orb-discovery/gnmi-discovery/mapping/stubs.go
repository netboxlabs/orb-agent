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
// the rich top-level Device has been upserted. PrimaryIp4/6 go through
// newIPMatchStub so AssignedObject is cleared (cycle break).
//
// INVARIANT: this must be a superset of every dcim.device matcher field
// gnmi-discovery populates on the rich Device, plus NetBox's create-required
// fields. AssetTag is carried (Diode's highest-precedence dcim.device matcher;
// gnmi-discovery sets it from defaults.asset_tag). Config / Status / Platform /
// Comments / Location / Tags are NOT matchers and NOT required for create, so
// they are dropped — this is the whole point of the stub (Config is large).
// source_match metadata (netbox_id) is the plugin's PK match path, so it must
// not diverge between rich and stub; run_id annotation is matcher-irrelevant and
// intentionally omitted.
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
		PrimaryIp4: newIPMatchStub(d.PrimaryIp4),
		PrimaryIp6: newIPMatchStub(d.PrimaryIp6),
	}
	if sm, ok := d.Metadata["source_match"]; ok {
		stub.Metadata = diode.Metadata{"source_match": sm}
	}
	return stub
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
// Call from the runner AFTER run_id / source_match annotation, BEFORE Ingest:
// running earlier would either make the annotators traverse stubs (and skip the
// rich Device) or bloat every stub with run_id, defeating the savings.
//
// No-op on empty input.
func PruneNestedRefs(entities []diode.Entity, currentDevice *diode.Device) {
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
			owner = currentDevice // single-Device fallback
		}
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

	// stubForIface re-resolves a nested Interface ref by name against the
	// top-level Interface index (when unambiguous) so the stub carries the rich
	// interface's Type/MAC/owner — important because some nested refs (e.g. an
	// IPAddress.AssignedObject built in translateIPs) are minimal name+device
	// shells without Type.
	stubForIface := func(ref *diode.Interface) *diode.Interface {
		if ref == nil {
			return nil
		}
		src := ref
		if ref.Name != nil {
			if tops, ok := ifaceByName[*ref.Name]; ok && len(tops) == 1 {
				src = tops[0]
			}
		}
		return newInterfaceStub(src, stubFor(src.Device))
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
				e.AssignedObject = stubForIface(iface)
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
