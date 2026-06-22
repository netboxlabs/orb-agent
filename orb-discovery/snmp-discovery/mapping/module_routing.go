// Copyright 2026 NetBox Labs, Inc.

// Package mapping — module_routing.go: per-VC-member dispatch for the
// module / module bay inventory built by extractModuleInventory. Walks
// each module's containedIn chain until it hits a class=3 chassis, then
// maps that chassis EntPhysicalIndex to the owning ChassisInventory
// member id. Sits between extractModuleInventory and the translation
// step so the extractor stays chassis-topology-agnostic.
package mapping

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/metrics"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// assignMemberID stamps each ModuleEntry in inv with the logical member
// id that owns it.
//
//   - chassisInv == nil OR no members -> standalone target; every entry
//     lands on MemberID=0 so the translation step emits modules under
//     the master device.
//   - VC / stack target -> walk the entPhysicalContainedIn chain from
//     each module's EntIndex until reaching a chassis EntPhysicalIndex
//     present in chassisInv.Members. Stamp the corresponding member id.
//     Modules whose chain terminates at a chassis NOT in chassisInv get
//     the sentinel MemberID=-1 plus a warn log; the translation step
//     skips MemberID<0 entries.
//
// The cycle guard mirrors extractModuleInventory.walkParents — a `seen`
// set bounded by the chain length suffices since the containedIn
// relation is meant to be a DAG (malformed MIBs notwithstanding).
func assignMemberID(inv *ModuleInventory, chassisInv *ChassisInventory, oids ObjectIDValueMap, logger *slog.Logger) {
	if inv == nil {
		return
	}

	// Standalone fast path — nothing to walk.
	if chassisInv == nil || len(chassisInv.Members) == 0 {
		for i := range inv.Modules {
			inv.Modules[i].MemberID = 0
		}
		for parent, list := range inv.SubModules {
			for i := range list {
				list[i].MemberID = 0
			}
			inv.SubModules[parent] = list
		}
		for i := range inv.EmptyBays {
			inv.EmptyBays[i].MemberID = 0
		}
		return
	}

	entIdxToMemberID := make(map[string]int, len(chassisInv.Members))
	for _, m := range chassisInv.Members {
		entIdxToMemberID[m.EntPhysicalIndex] = m.ID
	}

	resolve := func(startEnt string) (int, bool) {
		// Walk containedIn until we hit a class=3 ent that lives in the
		// chassisInv member map. seen guards a malformed self-/mutual-
		// referential containedIn pair from looping forever.
		cur := strings.TrimSpace(oids[oidEntPhysicalContainedIn+startEnt].Value)
		seen := make(map[string]struct{})
		for cur != "" && cur != "0" {
			if _, dup := seen[cur]; dup {
				return 0, false
			}
			seen[cur] = struct{}{}
			class := strings.TrimSpace(oids[oidEntPhysicalClass+cur].Value)
			if class == entPhysicalClassChassis {
				id, ok := entIdxToMemberID[cur]
				return id, ok
			}
			cur = strings.TrimSpace(oids[oidEntPhysicalContainedIn+cur].Value)
		}
		return 0, false
	}

	stamp := func(e *ModuleEntry) {
		id, ok := resolve(e.EntIndex)
		if !ok {
			logger.Warn("module discovery: orphan module — chassis ancestor not in chassis inventory",
				"ent", e.EntIndex, "model", e.Model)
			e.MemberID = -1
			if c := metrics.GetModulesDropped(); c != nil {
				c.Add(context.Background(), 1, metric.WithAttributes(
					attribute.String("reason", "orphan_member"),
				))
			}
			return
		}
		e.MemberID = id
	}

	for i := range inv.Modules {
		stamp(&inv.Modules[i])
	}
	for parent, list := range inv.SubModules {
		for i := range list {
			stamp(&list[i])
		}
		inv.SubModules[parent] = list
	}
	for i := range inv.EmptyBays {
		stamp(&inv.EmptyBays[i])
	}
}

// buildIfaceModuleMap builds the {ifIndex -> *diode.Module} lookup the
// runner needs to set Interface.Module on each transceiver-owning port.
// Keying by ifIndex (decimal string) — not ifName — is required because
// VC/stack targets (Juniper VC, some Aruba stacks) reuse the same
// canonical ifName across members; an ifName-keyed map collapses
// distinct transceivers onto a single entry and the runner attaches the
// wrong member's module. ifIndex is globally unique in the SNMP walk
// space, so collision is impossible.
//
// Only transceivers under inv.SubModules participate — top-level modules
// (linecards, supervisors) aren't single-port entities and don't route
// to an ifIndex. For each transceiver:
//
//  1. aliasMap[EntIndex] gives the ifIndex (set up upstream by the
//     entAliasMappingTable walk).
//  2. emittedModules[EntIndex] is the *diode.Module the translator
//     already produced; this map points the ifIndex at it.
//
// Any step that misses simply skips the transceiver — partial coverage
// is normal (optic with no alias-table row, port-channel placeholder, etc.).
func buildIfaceModuleMap(
	inv ModuleInventory,
	aliasMap map[string]string,
	emittedModules map[string]*diode.Module,
) map[string]*diode.Module {
	out := make(map[string]*diode.Module)
	for _, list := range inv.SubModules {
		for _, e := range list {
			if e.Type != ModuleTypeTransceiver {
				continue
			}
			ifIdx, ok := aliasMap[e.EntIndex]
			if !ok {
				continue
			}
			mod, ok := emittedModules[e.EntIndex]
			if !ok {
				continue
			}
			out[ifIdx] = mod
		}
	}
	return out
}

// aliasCandidate carries the parsed (logical index, ifIndex) for one
// entAliasMappingTable row so AliasMapFromOIDs can apply the RFC 6933
// precedence rule (non-zero logical-index beats .0 wildcard).
type aliasCandidate struct {
	logicalIdx int
	ifIdx      int
}

// AliasMapFromOIDs parses entAliasMappingTable rows into a flat
// entPhysicalIndex -> ifIndex map (decimal strings). Mirrors the parse
// rules in chassis_routing.go:152-179 (drop malformed suffixes; drop
// non-ifEntry.ifIndex values).
//
// When multiple rows resolve to the same entPhysicalIndex, the
// precedence mirrors chassis_routing.go:188-220:
//
//  1. RFC 6933 defines non-zero entAliasLogicalIndexOrZero rows as the
//     per-logical-entity mapping carrying explicit context. They take
//     precedence over the .0 "default mapping in the absence of any
//     logical entity" row — regardless of which target ifIndex is
//     numerically smaller. Without this rule, devices that publish both
//     forms (multi-logical-entity contexts) resolve a transceiver to
//     the wrong interface.
//  2. Among non-zero rows, the lowest logical index wins — defensive
//     tiebreaker when several per-entity rows compete.
//  3. Final tiebreaker: lowest target ifIndex. Keeps resolution stable
//     across re-runs since Go map iteration is randomized.
func AliasMapFromOIDs(oids ObjectIDValueMap) map[string]string {
	candidates := make(map[string][]aliasCandidate)
	for oid, v := range oids {
		if !strings.HasPrefix(oid, oidEntAliasMappingIdent) {
			continue
		}
		suffix := strings.TrimPrefix(oid, oidEntAliasMappingIdent)
		parts := strings.SplitN(suffix, ".", 2)
		if len(parts) != 2 {
			continue
		}
		entIdx := parts[0]
		logicalIdx, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		// Normalize: strip leading dot (gosnmp's ObjectIdentifier
		// rendering varies) then require the value to point at
		// ifEntry.ifIndex — skip ifAlias / ifDescr targets.
		val := strings.TrimPrefix(strings.TrimSpace(v.Value), ".")
		if !strings.HasPrefix(val, oidIfEntryIfIndexNoDot) {
			continue
		}
		ifIdxStr := strings.TrimPrefix(val, oidIfEntryIfIndexNoDot)
		ifIdx, err := strconv.Atoi(ifIdxStr)
		if err != nil {
			continue
		}
		candidates[entIdx] = append(candidates[entIdx], aliasCandidate{
			logicalIdx: logicalIdx,
			ifIdx:      ifIdx,
		})
	}
	out := make(map[string]string, len(candidates))
	for entIdx, rows := range candidates {
		slices.SortFunc(rows, func(a, b aliasCandidate) int {
			aZero := 1
			if a.logicalIdx == 0 {
				aZero = 0
			}
			bZero := 1
			if b.logicalIdx == 0 {
				bZero = 0
			}
			if aZero != bZero {
				// Non-zero (aZero=1 / bZero=1) sorts FIRST.
				return bZero - aZero
			}
			if a.logicalIdx != b.logicalIdx {
				return a.logicalIdx - b.logicalIdx
			}
			return a.ifIdx - b.ifIdx
		})
		out[entIdx] = strconv.Itoa(rows[0].ifIdx)
	}
	return out
}

// MemberDevicesFromEntities groups the Devices in entities by member id
// for module dispatch. Master (VcPosition == nil) is keyed by the lowest
// member id in chassisInv.Members[0].ID — mirroring TranslateAsStack's
// memberByID convention (chassis.go:432). For standalone targets
// (chassisInv nil/empty) the master falls back to key 0. Non-master
// members are keyed by *VcPosition.
func MemberDevicesFromEntities(
	entities []diode.Entity,
	chassisInv *ChassisInventory,
) map[int]*diode.Device {
	out := make(map[int]*diode.Device)
	masterID := 0
	if chassisInv != nil && len(chassisInv.Members) > 0 {
		// Members are sorted ascending by ID upstream;
		// Members[0].ID is the master's logical member id.
		masterID = chassisInv.Members[0].ID
	}
	for _, e := range entities {
		dev, ok := e.(*diode.Device)
		if !ok || dev == nil {
			continue
		}
		if dev.VcPosition != nil {
			out[int(*dev.VcPosition)] = dev
			continue
		}
		// First master wins — defensive against duplicate emission.
		if _, exists := out[masterID]; !exists {
			out[masterID] = dev
		}
	}
	return out
}

// AttachIfaceModules sets Interface.Module on each transceiver-owning
// interface referenced by entities. It walks three referrer shapes:
//
//   - *diode.Interface directly in the slice (physical ports emitted as
//     top-level entities).
//   - *diode.IPAddress whose AssignedObject is a *diode.Interface (the
//     L3 routed-port case — MapObjectIDsToEntity filters such interfaces
//     out of the top-level slice via getAssignedInterfaces, so they
//     surface ONLY through this nested reference).
//   - *diode.MACAddress whose AssignedObject is a *diode.Interface
//     (mirrors the IP path; chassis.go:484 already walks this shape for
//     member-rerouting).
//
// For each found interface we look up its ifIndex in ifIndexByIface (the
// registry-derived pointer->ifIndex map) and use the decimal ifIndex to
// pick the module from ifaceModuleMap. Lookups that miss are skipped:
// partial coverage is normal (interfaces with no transceiver, ifIndexes
// absent from entAliasMappingTable, etc.).
//
// Idempotent: re-running won't change a value already set. Defensive
// against nil maps so the runner can call it unconditionally.
func AttachIfaceModules(
	entities []diode.Entity,
	ifaceModuleMap map[string]*diode.Module,
	ifIndexByIface map[*diode.Interface]int,
) {
	if len(ifaceModuleMap) == 0 || len(ifIndexByIface) == 0 {
		return
	}
	attach := func(iface *diode.Interface) {
		if iface == nil {
			return
		}
		idx, hasIdx := ifIndexByIface[iface]
		if !hasIdx {
			return
		}
		mod, hit := ifaceModuleMap[strconv.Itoa(idx)]
		if !hit {
			return
		}
		iface.Module = mod
	}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Interface:
			attach(v)
		case *diode.IPAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok {
				attach(iface)
			}
		case *diode.MACAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok {
				attach(iface)
			}
		}
	}
}
