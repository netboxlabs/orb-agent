// Copyright 2026 NetBox Labs, Inc.

// Package mapping — module_translate.go: Diode entity emission for
// module / module bay (+ ModuleType) entities. Public entry point is
// TranslateModulesWithAlias; TranslateModules is a thin wrapper for
// callers that don't carry alias data.
//
// Emission rules:
//   - "off" mode short-circuits before extraction (zero behaviour change).
//   - "linecards" mode emits chassis-slot modules + their bays only.
//     PSU / Fan are classified for labelling but never emitted as
//     module entities. Transceivers are skipped entirely.
//   - "full" mode adds transceiver sub-bays (device-rooted — see
//     sub-bay reconciler workaround at the emission site) and empty
//     bays, and populates the iface->Module attachment map.
package mapping

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/metrics"
)

// TranslateModules is a thin wrapper for callers without alias data —
// the iface attachment map will be empty.
func TranslateModules(
	oids ObjectIDValueMap,
	chassisInv *ChassisInventory,
	memberDevices map[int]*diode.Device,
	options *config.Options,
	defaults *config.Defaults,
	logger *slog.Logger,
) ([]diode.Entity, map[string]*diode.Module) {
	return TranslateModulesWithAlias(oids, chassisInv, memberDevices, options, defaults, logger, nil)
}

// TranslateModulesWithAlias is the full-fidelity entry point used by
// the runner. Returns (entities, ifaceModuleMap):
//   - entities: every ModuleBay + Module emitted, in extraction order.
//   - ifaceModuleMap: in "full" mode, {ifIndex -> *Module} (ifIndex as
//     decimal string) so the runner can attach Interface.Module on
//     physical ports by looking up each Interface's ifIndex. nil in
//     "linecards" mode. ifIndex keying (not ifName) is required: VC/stack
//     members can reuse the same canonical ifName locally and an
//     ifName-keyed map would collapse distinct transceivers.
//
// Returns (nil, nil) when:
//   - mode == "off"
//   - the ENTITY-MIB walk produced no modules and no bays at all
func TranslateModulesWithAlias(
	oids ObjectIDValueMap,
	chassisInv *ChassisInventory,
	memberDevices map[int]*diode.Device,
	options *config.Options,
	defaults *config.Defaults,
	logger *slog.Logger,
	aliasMap map[string]string,
) ([]diode.Entity, map[string]*diode.Module) {
	mode := options.ModuleDiscoveryMode()
	if mode == config.DiscoverModulesOff {
		return nil, nil
	}

	inv := extractModuleInventory(oids, logger)
	if len(inv.Modules) == 0 && len(inv.SubModules) == 0 && len(inv.EmptyBays) == 0 {
		return nil, nil
	}

	assignMemberID(&inv, chassisInv, oids, logger)

	var entities []diode.Entity
	emittedModules := make(map[string]*diode.Module, len(inv.Modules))
	// dcim.modulebay's matcher is name+device: two bays sharing a name on
	// one member would merge into one NetBox object, taking their modules
	// with them. Keyed by (MemberID, effective bay name) — MemberID is
	// only populated by assignMemberID above, which is why this guard
	// lives here and not in extractModuleInventory.
	seenTransceiverBays := make(map[transceiverBayKey]string, len(inv.Modules))

	for _, m := range inv.Modules {
		// PSU / Fan are classified for labelling only — never emitted as
		// module entities (mirrors device-discovery PR #419).
		if m.Type == ModuleTypePSU || m.Type == ModuleTypeFan {
			continue
		}
		// A transceiver is full-mode-only. Modular optics are already
		// excluded by the mode gate below because they live in SubModules;
		// a fixed-port optic is a top-level module and needs this.
		if m.Type == ModuleTypeTransceiver && mode != config.DiscoverModulesFull {
			continue
		}
		// assignMemberID stamps MemberID=-1 on entries whose chassis
		// ancestor isn't in the VC member set. Skip — already warn-logged.
		if m.MemberID < 0 {
			continue
		}
		// No capture in the corpus has shown two fixed-port transceivers
		// collide on the same member's bay name, but the merge this
		// guards against is silent and Diode never retracts a wrong
		// value, so refuse rather than risk it. Scoped to transceivers —
		// bay-name collisions among other module types are pre-existing
		// and out of scope here. Skip and warn rather than invent a
		// disambiguated name: a fabricated value would itself become a
		// permanent wrong value.
		if m.Type == ModuleTypeTransceiver {
			key := transceiverBayKey{member: m.MemberID, bay: effectiveBayName(m)}
			if _, dup := seenTransceiverBays[key]; dup {
				logger.Warn("module discovery: duplicate transceiver bay name dropped",
					"bay", key.bay, "ent", m.EntIndex, "member", m.MemberID, "model", m.Model,
					"reason", "dup_bay_name")
				continue
			}
			seenTransceiverBays[key] = m.EntIndex
		}
		device := memberDevices[m.MemberID]
		if device == nil {
			logger.Warn("module discovery: no device for member",
				"member", m.MemberID, "ent", m.EntIndex, "model", m.Model)
			continue
		}
		bay := emitModuleBay(device, m)
		entities = append(entities, bay)
		if c := metrics.GetModuleBaysEmitted(); c != nil {
			c.Add(context.Background(), 1, metric.WithAttributes(
				attribute.String("vendor", vendorFromDevice(device)),
			))
		}
		mod := emitModule(device, bay, m, defaults)
		entities = append(entities, mod)
		if c := metrics.GetModulesEmitted(); c != nil {
			c.Add(context.Background(), 1, metric.WithAttributes(
				attribute.String("vendor", vendorFromDevice(device)),
				attribute.String("type", string(m.Type)),
			))
		}
		emittedModules[m.EntIndex] = mod
	}

	if mode != config.DiscoverModulesFull {
		// Linecards mode stops here — no transceivers, no empty bays,
		// no iface attachment map.
		return entities, nil
	}

	// Full-mode-only: transceiver sub-bays + empty bays + iface routing.
	//
	// Walk EVERY key in inv.SubModules — not just those keyed by
	// top-level inv.Modules entries. Vendors like Juniper nest optics
	// two module-levels below the chassis (Chassis -> FPC -> PIC -> optic),
	// so the optic's parent class=9 (the PIC) is itself a sub-module
	// stored under inv.SubModules[FPC.EntIndex]. Iterating only top-
	// level parents silently dropped those optics. Each transceiver
	// already carries MemberID (stamped by assignMemberID), so device
	// routing remains correct regardless of nesting depth. The
	// emittedModules guard prevents the (theoretical) double-emit if
	// the same EntIndex is reachable via two parents.
	subKeys := make([]string, 0, len(inv.SubModules))
	for k := range inv.SubModules {
		subKeys = append(subKeys, k)
	}
	sort.Strings(subKeys)
	for _, parentIdx := range subKeys {
		for _, tr := range inv.SubModules[parentIdx] {
			if tr.Type != ModuleTypeTransceiver {
				continue
			}
			if tr.MemberID < 0 {
				continue
			}
			if _, dup := emittedModules[tr.EntIndex]; dup {
				continue
			}
			device := memberDevices[tr.MemberID]
			if device == nil {
				logger.Warn("module discovery: no device for transceiver member",
					"member", tr.MemberID, "ent", tr.EntIndex, "model", tr.Model)
				continue
			}
			// Sub-bay reconciler workaround (spec §Sub-bay emission
			// workaround): emit transceiver sub-bays DEVICE-ROOTED
			// (no Module=parent_linecard link). Linking the sub-bay to
			// its parent linecard makes the Diode reconciler re-plan
			// the parent inside the sub-bay's changeset and trip
			// dcim_module_module_bay_id_key on apply. Restore the link
			// when the upstream reconciler resolves nested parent-
			// module refs against committed sibling entities.
			subBay := emitModuleBay(device, tr)
			entities = append(entities, subBay)
			if c := metrics.GetModuleBaysEmitted(); c != nil {
				c.Add(context.Background(), 1, metric.WithAttributes(
					attribute.String("vendor", vendorFromDevice(device)),
				))
			}

			mod := emitModule(device, subBay, tr, defaults)
			entities = append(entities, mod)
			if c := metrics.GetModulesEmitted(); c != nil {
				c.Add(context.Background(), 1, metric.WithAttributes(
					attribute.String("vendor", vendorFromDevice(device)),
					attribute.String("type", string(tr.Type)),
				))
			}
			emittedModules[tr.EntIndex] = mod
		}
	}

	// Empty bays — class=5 rows with no module or port child and no
	// optic PID of their own (extractModuleInventory's harvest). Bare
	// ModuleBay only; no Module entity.
	for _, b := range inv.EmptyBays {
		if b.MemberID < 0 {
			continue
		}
		device := memberDevices[b.MemberID]
		if device == nil {
			logger.Warn("module discovery: no device for empty bay member",
				"member", b.MemberID, "ent", b.EntIndex, "bay", b.BayName)
			continue
		}
		entities = append(entities, emitModuleBay(device, b))
		if c := metrics.GetModuleBaysEmitted(); c != nil {
			c.Add(context.Background(), 1, metric.WithAttributes(
				attribute.String("vendor", vendorFromDevice(device)),
			))
		}
	}

	ifaceMap := buildIfaceModuleMap(inv, aliasMap, emittedModules)
	return entities, ifaceMap
}

// transceiverBayKey is the (member, effective bay name) dedup key used
// by the duplicate-bay-name guard in TranslateModulesWithAlias.
type transceiverBayKey struct {
	member int
	bay    string
}

// effectiveBayName returns the name a ModuleBay will actually carry —
// BayName, falling back to BayPosition, falling back to "Unknown". This
// is the same fallback chain emitModuleBay applies, factored out so the
// duplicate-bay-name guard compares the value Diode will actually see
// rather than the raw (possibly blank) ModuleEntry field.
func effectiveBayName(m ModuleEntry) string {
	if m.BayName != "" {
		return m.BayName
	}
	if m.BayPosition != "" {
		return m.BayPosition
	}
	return "Unknown"
}

// emitModuleBay constructs a ModuleBay entity for a top-level
// (chassis-slot) module. Always carries Device — the chassis device is
// the matching scope for both ModuleBay and Module per Diode docs.
func emitModuleBay(device *diode.Device, m ModuleEntry) *diode.ModuleBay {
	// Bay rows occasionally arrive without a name; effectiveBayName
	// falls back to position, then "Unknown", so we never ship an
	// empty-string required field (Diode rejects "").
	name := effectiveBayName(m)
	bay := &diode.ModuleBay{
		Device: device,
		Name:   &name,
	}
	if m.BayPosition != "" {
		pos := m.BayPosition
		bay.Position = &pos
	}
	return bay
}

// emitModule constructs a Module entity attached to its ModuleBay.
// Carries Device (NetBox matching scope) and a ModuleType built from
// the PID (Model) + the manufacturer resolved from the emitted Device.
// Manufacturer precedence: Device.DeviceType.Manufacturer.Name first
// (so the ModuleType label always matches what NetBox sees on the
// owning device), then the policy-level defaults, finally "Unknown".
// Sharing vendorFromDevice with the metrics path keeps the label and
// the emitted entity identical strings.
func emitModule(device *diode.Device, bay *diode.ModuleBay, m ModuleEntry, defaults *config.Defaults) *diode.Module {
	// Mirrors classifyModule's Model -> VendorType -> Unknown fallback so
	// the emitted ModuleType label matches the classification. Aruba CX
	// populates entPhysicalVendorType where Cisco populates ModelName;
	// using Model alone would emit "Unknown" for valid Aruba hardware.
	model := modelOrVendorType(m.Model, m.VendorType)
	mfgName := resolveModuleManufacturer(device, defaults)
	moduleType := &diode.ModuleType{
		Model: &model,
		Manufacturer: &diode.Manufacturer{
			Name: &mfgName,
		},
	}
	mod := &diode.Module{
		Device:     device,
		ModuleBay:  bay,
		ModuleType: moduleType,
	}
	if m.Serial != "" {
		serial := m.Serial
		mod.Serial = &serial
	}
	if m.Description != "" {
		desc := m.Description
		mod.Description = &desc
	}
	return mod
}

// vendorFromDevice resolves the per-device manufacturer name for metric
// attribution. Reads the already-set DeviceType.Manufacturer.Name on the
// emitted Device — that's the same value emitModule uses for the
// ModuleType, so the counter labels stay consistent with what NetBox sees.
// Falls back to "Unknown" on any nil/blank in the chain so a missing
// pointer never produces an empty-string attribute.
func vendorFromDevice(d *diode.Device) string {
	if d == nil || d.DeviceType == nil || d.DeviceType.Manufacturer == nil || d.DeviceType.Manufacturer.Name == nil {
		return "Unknown"
	}
	if name := strings.TrimSpace(*d.DeviceType.Manufacturer.Name); name != "" {
		return name
	}
	return "Unknown"
}

// modelOrVendorType prefers a non-blank trimmed model, falling back to
// the trimmed vendorType, and finally "Unknown". Parallels
// classifyModule so the emitted ModuleType.Model matches the type
// classification for vendors (e.g. Aruba CX) that populate
// entPhysicalVendorType instead of entPhysicalModelName.
func modelOrVendorType(model, vendorType string) string {
	if v := strings.TrimSpace(model); v != "" {
		return v
	}
	if v := strings.TrimSpace(vendorType); v != "" {
		return v
	}
	return "Unknown"
}

// vendorFromDefaults returns the policy-level device manufacturer or
// "Unknown" when unset. Diode rejects empty strings for required
// Manufacturer.Name.
func vendorFromDefaults(d *config.Defaults) string {
	if d == nil || d.Device.Manufacturer == "" {
		return "Unknown"
	}
	return d.Device.Manufacturer
}

// SpliceModulesAfterDevices inserts moduleEntities into entitiesForTarget
// immediately after the leading run of Device + VirtualChassis entries,
// preserving the Diode ingest ordering contract:
//
//	Device(s) -> ModuleBay + Module -> Interface -> IP -> MAC -> VLAN
//
// TranslateAsStack already partitioned entitiesForTarget into that
// bucket order, but Module entities land in their own bucket — naively
// appending them would leave them at the tail and break the runner's
// Interface.Module attachment (Interfaces would appear before the
// Modules they reference). Find the first non-Device/non-VC index and
// splice moduleEntities there.
//
// Returns entitiesForTarget unchanged when moduleEntities is empty.
func SpliceModulesAfterDevices(entitiesForTarget []diode.Entity, moduleEntities []diode.Entity) []diode.Entity {
	if len(moduleEntities) == 0 {
		return entitiesForTarget
	}
	splice := len(entitiesForTarget)
	for i, e := range entitiesForTarget {
		switch e.(type) {
		case *diode.Device, *diode.VirtualChassis:
			continue
		default:
			splice = i
		}
		if splice < len(entitiesForTarget) {
			break
		}
	}
	merged := make([]diode.Entity, 0, len(entitiesForTarget)+len(moduleEntities))
	merged = append(merged, entitiesForTarget[:splice]...)
	merged = append(merged, moduleEntities...)
	merged = append(merged, entitiesForTarget[splice:]...)
	return merged
}

// resolveModuleManufacturer picks the Manufacturer name to stamp on an
// emitted ModuleType. Precedence:
//  1. The emitted Device's DeviceType.Manufacturer.Name — keeps the
//     ModuleType label identical to the vendor attribute used by the
//     OTLP counters (vendorFromDevice).
//  2. The policy-level defaults.device.manufacturer — fallback for the
//     rare path where the device entity lacks a manufacturer.
//  3. "Unknown" — Diode rejects empty strings on this required field.
func resolveModuleManufacturer(device *diode.Device, defaults *config.Defaults) string {
	if v := vendorFromDevice(device); v != "Unknown" {
		return v
	}
	return vendorFromDefaults(defaults)
}
