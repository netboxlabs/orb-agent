// Package mapping — module.go: scaffold for chassis module / module
// bay discovery on modular Cisco IOS-XE chassis. ChassisModuleMapper
// is intentionally a no-op; it exists only to register the
// entPhysicalDescr + entPhysicalVendorType walk columns. The actual
// translation lives in TranslateModulesWithAlias in module_translate.go.
package mapping

import (
	"context"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/metrics"
)

// entPhysical column prefixes specific to module discovery (the rest
// — class, containedIn, parentRel, name, serial, model — live in
// chassis.go and are reused here).
const (
	oidEntPhysicalDescr      = ".1.3.6.1.2.1.47.1.1.1.1.2."
	oidEntPhysicalVendorType = ".1.3.6.1.2.1.47.1.1.1.1.3."

	entPhysicalClassModule    = "9"
	entPhysicalClassContainer = "5"
	entPhysicalClassPort      = "10"
)

// ChassisModuleMapper is a no-op orbToEntityMapper. See package file
// doc — data flows through the raw oids map into
// TranslateModulesWithAlias, not via this Map call.
type ChassisModuleMapper struct {
	logger *slog.Logger
}

// Map is intentionally a no-op — see type doc.
func (m *ChassisModuleMapper) Map(
	_ map[ObjectIDIndex]*ObjectIDValue,
	_ *Entry,
	_ *EntityRegistry,
	_ *config.Defaults,
) diode.Entity {
	return nil
}

// ModuleType is the vendor-neutral classification assigned by
// classifyModule. Drives both the linecards-mode filter (skip
// transceivers) and downstream Diode emission as Module.Type.
type ModuleType string

// Module-type tags returned by classifyModule.
const (
	ModuleTypeLinecard    ModuleType = "linecard"
	ModuleTypeSupervisor  ModuleType = "supervisor"
	ModuleTypeTransceiver ModuleType = "transceiver"
	ModuleTypePSU         ModuleType = "psu" // classified for labelling only; never emitted as a module entity
	ModuleTypeFan         ModuleType = "fan" // classified for labelling only; never emitted as a module entity
	ModuleTypeUnknown     ModuleType = "unknown"
)

// ModuleEntry is one entPhysical row after classification: a class=9
// module, or a class=5/class=10 row whose PID identifies it as a
// transceiver (see isOpticPID). BayEntIndex points at the class=5
// container that owns this module — the bay is emitted as a separate
// entity alongside the module installed in it.
type ModuleEntry struct {
	EntIndex     string     // own entPhysicalIndex
	BayEntIndex  string     // parent class=5 container entPhysicalIndex
	BayName      string     // entPhysicalName of the bay
	BayPosition  string     // entPhysicalParentRelPos of the BAY (chassis slot number — NOT the module's own parentRelPos, which is almost always "1")
	Name         string     // entPhysicalName
	Serial       string     // entPhysicalSerialNum
	Model        string     // entPhysicalModelName
	Description  string     // entPhysicalDescr
	VendorType   string     // entPhysicalVendorType
	Type         ModuleType // classifyModule output
	MemberID     int        // ChassisInventory.Members[].ID; 0 for standalone
	ParentEntIdx string     // for transceivers, class=9 module they sit under; "" for top-level
}

// ModuleInventory is the deduped, classified set for one target.
// Modules carries top-level (chassis-rooted) modules; SubModules maps
// each parent EntIndex → its transceiver children. EmptyBays carries
// class=5 rows with no class=9/class=10 child of their own but whose
// parent resolves to a chassis or container — Aruba CX-style empty
// slots; emitted only in `full` mode.
type ModuleInventory struct {
	Modules    []ModuleEntry
	SubModules map[string][]ModuleEntry
	EmptyBays  []ModuleEntry // bare bays — BayEntIndex == EntIndex; Serial/Model empty
}

func newModuleInventory() ModuleInventory {
	return ModuleInventory{
		SubModules: make(map[string][]ModuleEntry),
	}
}

// opticPIDPrefixes lists PID prefixes that identify a transceiver across
// vendors. An optic PID is sufficient on its own — a transceiver is a
// transceiver whether it sits under a linecard or directly in a fixed
// chassis port.
//
// These designators are MSA/SFF standardized, so the same set applies to every
// vendor and to every backend. Kept deliberately in step with
// device-discovery's _OPTIC_PREFIXES in custom_napalm/_modules.py: an optic
// recognised by one backend and not the other would make a device's inventory
// depend on how it happened to be discovered. QSFP-DD appears in that list but
// is omitted here because QSFP- already subsumes it; every other entry can
// match something QSFP-/SFP- cannot.
var opticPIDPrefixes = []string{
	"SFP-", "SFP+", "SFP28-", "SFP56-",
	"QSFP-", "QSFP+", "QSFP28", "QSFP56-",
	"QDD-", "OSFP-",
	"GLC-", "X2-", "CFP-", "CFP2-", "XENPAK-", "XFP-", "CVR-",
}

// isOpticPID reports whether a row's effective PID names a transceiver.
// Effective PID mirrors classifyModule: trimmed Model, falling back to
// trimmed VendorType.
func isOpticPID(model, vendorType string) bool {
	pid := strings.TrimSpace(model)
	if pid == "" {
		pid = strings.TrimSpace(vendorType)
	}
	return hasOpticPIDPrefix(strings.ToUpper(pid))
}

// hasOpticPIDPrefix reports whether an already upper-cased effective PID
// carries a known optic vendor prefix. Shared by isOpticPID and
// classifyModule (which already has its own upper-cased PID in hand) so
// the prefix list is only ever walked in one place.
func hasOpticPIDPrefix(upper string) bool {
	for _, p := range opticPIDPrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// isOpticSubEntity reports whether a class=9 row describes part of an optic
// rather than a module. One vendor publishes such a row per lane beneath
// each transceiver: no model, no serial, an effective PID that is blank or
// the placeholder "0.0", and a parent that is itself an optic. Emitting
// these yields one bare module per lane, all sharing the optic's bay.
func isOpticSubEntity(r row, byIdx map[string]row) bool {
	if strings.TrimSpace(r.Model) != "" || strings.TrimSpace(r.Serial) != "" {
		return false
	}
	if pid := strings.TrimSpace(r.VendorType); pid != "" && pid != "0.0" {
		return false
	}
	parent, ok := byIdx[r.ContainedIn]
	return ok && isOpticPID(parent.Model, parent.VendorType)
}

// opticDescrIfaceRe matches a transceiver row's descr where the vendor names
// the interface the optic serves. Anchored on purpose: the same platform
// publishes "Lane 0 for Xcvr for Ethernet1" beneath each optic, and an
// unanchored match would emit one bay per lane.
var opticDescrIfaceRe = regexp.MustCompile(`^Xcvr for (\S+)$`)

// servedInterface returns the interface an optic row names, or "" when the
// row names none. The result is a bay label: a row that identifies its port
// gives the most accurate name available for the bay the optic sits in.
//
// Absence is not evidence that the optic is uninstalled, and must not be read
// as such. Captures publish installed optics whose name is the literal token
// "port" and whose descr merely repeats the PID (see stackedPortOpticFixture),
// so a row naming no interface falls back to its containment-derived bay rather
// than being withheld. entPhysicalTable lists entities that are physically
// present, so withholding one because its label is unparseable would discard
// hardware that is there. Absence of a module parent likewise authorises
// nothing on its own.
// pid is the row's own effective PID (see effectivePID) — passed through to
// ifaceShaped so a candidate that is really the optic's own part number,
// not an interface, is rejected on both the descr-derived and the
// name-derived path.
func servedInterface(name, descr, pid string) string {
	if m := opticDescrIfaceRe.FindStringSubmatch(strings.TrimSpace(descr)); m != nil {
		if ifaceShaped(m[1], pid) {
			return m[1]
		}
	}
	if n := strings.TrimSpace(name); ifaceShaped(n, pid) {
		return n
	}
	return ""
}

// ifaceShaped reports whether a token can be an interface name. A digit is
// required: one platform names every optic row with the bare word "port",
// which would otherwise name every bay on the chassis identically.
//
// A token that names a transceiver rather than a port is rejected two ways. It
// cannot equal pid, the row's own effective PID. It also cannot begin with a
// transceiver designator: a vendor that omits the "Xcvr for <iface>" descr may
// publish a generic product label such as "SFP-10G-LR" in entPhysicalName while
// entPhysicalModelName carries the specific part number, so equality alone would
// let the label through and give every optic of that type the same bay name. No
// interface is named for a transceiver designator, so the prefix test is safe as
// well as necessary.
func ifaceShaped(tok, pid string) bool {
	if tok == "" || strings.ContainsAny(tok, " \t") {
		return false
	}
	if !strings.ContainsAny(tok, "0123456789") {
		return false
	}
	if pid != "" && strings.EqualFold(tok, pid) {
		return false
	}
	return !hasOpticPIDPrefix(strings.ToUpper(tok))
}

// effectivePID returns the row's own PID for the "is this token really the
// optic's part number" check in ifaceShaped: trimmed Model, falling back to
// trimmed VendorType. Deliberately distinct from isOpticPID/classifyModule's
// upper-cased copies of the same rule — this one stays case-preserving
// because ifaceShaped's caller compares case-insensitively itself.
func effectivePID(model, vendorType string) string {
	pid := strings.TrimSpace(model)
	if pid == "" {
		pid = strings.TrimSpace(vendorType)
	}
	return pid
}

// classifyModule picks a ModuleType from a row's PID and its location
// in the containment tree. hasModuleParent is true when an ancestor in
// the entPhysicalTable chain is itself class=9. Effective PID prefers
// trimmed Model and falls back to trimmed VendorType when Model is
// blank — Aruba CX populates VendorType where Cisco populates Model.
func classifyModule(model, vendorType string, hasModuleParent bool) ModuleType {
	pid := strings.TrimSpace(model)
	if pid == "" {
		pid = strings.TrimSpace(vendorType)
	}

	// PSU / Fan are vendor-neutral and parent-agnostic — they appear at
	// chassis level and under shelves alike. Match both bare-prefix
	// forms (PSU-, PWR-, FAN-) and model-prefixed Cisco forms where
	// the type token sits in the middle or as a suffix (C9404R-PWR-2KW-AC,
	// C9400-FAN, C9404R-FAN-2).
	upper := strings.ToUpper(pid)
	if isPSUPID(upper) {
		return ModuleTypePSU
	}
	if isFanPID(upper) {
		return ModuleTypeFan
	}

	// An optic PID identifies a transceiver wherever it sits. Requiring a
	// class=9 ancestor mistyped every optic on a fixed-port platform as a
	// linecard, and a wrong type persists: Diode ingest never retracts.
	// upper is already the effective PID computed above — reuse it
	// instead of calling isOpticPID, which would recompute it from model
	// and vendorType from scratch.
	if hasOpticPIDPrefix(upper) {
		return ModuleTypeTransceiver
	}
	if !hasModuleParent && isSupervisorPID(upper) {
		// Supervisor lives at chassis depth on dual-sup platforms.
		return ModuleTypeSupervisor
	}

	if pid == "" {
		return ModuleTypeUnknown
	}

	// Safe default — non-optic under a module parent OR no special
	// pattern at chassis level both land here.
	return ModuleTypeLinecard
}

// row is one indexed entPhysical row, keyed by EntIndex in the byIdx map
// that extractModuleInventory builds. Package-scoped (rather than local to
// that function) so isOpticSubEntity can also walk it.
type row struct {
	EntIndex    string
	ContainedIn string
	Class       string
	ParentRel   string
	Name        string
	Serial      string
	Model       string
	Descr       string
	VendorType  string
}

// extractModuleInventory scans oids for class=9 entPhysical rows, plus
// class=5/class=10 rows whose PID identifies a transceiver, and
// classifies each one. Drops orphans (broken containedIn chain) and
// unclassifiable rows (class=1/2). Walks the containedIn chain to
// determine the owning bay (class=5 ancestor) and whether the module
// sits under another class=9 module (transceiver candidate).
//
// Member dispatch (MemberID) is intentionally NOT populated here —
// that lives in assignMemberID so this extractor stays
// chassis-topology-agnostic.
func extractModuleInventory(oids ObjectIDValueMap, logger *slog.Logger) ModuleInventory {
	inv := newModuleInventory()

	// Index every entPhysical row by EntIndex so we can walk parents.
	byIdx := make(map[string]row)
	// trimSNMPString strips ENTITY-MIB-padded NULs and surrounding
	// whitespace. Applied to every string field at extraction so dedup
	// keys stay stable across runs and downstream Diode payloads are
	// clean (mirrors chassis.go's normalization). Class / ContainedIn /
	// ParentRel are also numeric-shaped strings that benefit from the
	// trim, so they go through it too.
	for s, v := range oids {
		switch {
		case strings.HasPrefix(s, oidEntPhysicalClass):
			idx := strings.TrimPrefix(s, oidEntPhysicalClass)
			r := byIdx[idx]
			r.EntIndex = idx
			r.Class = trimSNMPString(v.Value)
			byIdx[idx] = r
		case strings.HasPrefix(s, oidEntPhysicalContainedIn):
			idx := strings.TrimPrefix(s, oidEntPhysicalContainedIn)
			r := byIdx[idx]
			r.EntIndex = idx
			r.ContainedIn = trimSNMPString(v.Value)
			byIdx[idx] = r
		case strings.HasPrefix(s, oidEntPhysicalParentRel):
			idx := strings.TrimPrefix(s, oidEntPhysicalParentRel)
			r := byIdx[idx]
			r.EntIndex = idx
			r.ParentRel = trimSNMPString(v.Value)
			byIdx[idx] = r
		case strings.HasPrefix(s, oidEntPhysicalName):
			idx := strings.TrimPrefix(s, oidEntPhysicalName)
			r := byIdx[idx]
			r.EntIndex = idx
			r.Name = trimSNMPString(v.Value)
			byIdx[idx] = r
		case strings.HasPrefix(s, oidEntPhysicalSerialNum):
			idx := strings.TrimPrefix(s, oidEntPhysicalSerialNum)
			r := byIdx[idx]
			r.EntIndex = idx
			r.Serial = trimSNMPString(v.Value)
			byIdx[idx] = r
		case strings.HasPrefix(s, oidEntPhysicalModelName):
			idx := strings.TrimPrefix(s, oidEntPhysicalModelName)
			r := byIdx[idx]
			r.EntIndex = idx
			r.Model = trimSNMPString(v.Value)
			byIdx[idx] = r
		case strings.HasPrefix(s, oidEntPhysicalDescr):
			idx := strings.TrimPrefix(s, oidEntPhysicalDescr)
			r := byIdx[idx]
			r.EntIndex = idx
			r.Descr = trimSNMPString(v.Value)
			byIdx[idx] = r
		case strings.HasPrefix(s, oidEntPhysicalVendorType):
			idx := strings.TrimPrefix(s, oidEntPhysicalVendorType)
			r := byIdx[idx]
			r.EntIndex = idx
			r.VendorType = trimSNMPString(v.Value)
			byIdx[idx] = r
		}
	}

	// walkParents climbs the containedIn chain. Returns the nearest
	// class=5 bay EntIndex, the nearest class=9 module ancestor
	// EntIndex (both "" when absent), and whether a class=3 chassis was
	// reached (used by extractModuleInventory to synthesize a bay for
	// chassis-rooted modules on fixed-FRU switches). A `seen` set guards
	// against malformed-MIB cycles — without it a self-referential or
	// mutually referential containedIn pair would loop forever.
	walkParents := func(start row) (bayIdx string, parentModuleIdx string, reachedChassis bool, ok bool) {
		cur := start.ContainedIn
		seen := make(map[string]struct{})
		for cur != "" && cur != "0" {
			if _, dup := seen[cur]; dup {
				logger.Debug("module: containment cycle detected",
					"ent", start.EntIndex, "at", cur)
				return "", "", false, false
			}
			seen[cur] = struct{}{}
			parent, exists := byIdx[cur]
			if !exists {
				// Broken chain — orphan.
				return "", "", false, false
			}
			if bayIdx == "" && parent.Class == entPhysicalClassContainer {
				bayIdx = cur
			}
			if parentModuleIdx == "" && parent.Class == entPhysicalClassModule {
				parentModuleIdx = cur
			}
			if parent.Class == entPhysicalClassChassis {
				reachedChassis = true
			}
			cur = parent.ContainedIn
		}
		return bayIdx, parentModuleIdx, reachedChassis, true
	}

	// bayBelowModule reports whether the resolved bay sits beneath the given
	// module. walkParents takes the nearest container and the nearest module
	// independently, so a bay it returns may be the module's own slot rather
	// than a cage inside the module. That distinction decides whether the bay
	// already identifies a port. The same cycle guard as walkParents applies:
	// a malformed containedIn chain must not loop.
	bayBelowModule := func(bayIdx, moduleIdx string) bool {
		if bayIdx == "" || moduleIdx == "" {
			return false
		}
		seen := make(map[string]struct{})
		for cur := bayIdx; cur != "" && cur != "0"; {
			if cur == moduleIdx {
				return true
			}
			if _, dup := seen[cur]; dup {
				return false
			}
			seen[cur] = struct{}{}
			parent, exists := byIdx[cur]
			if !exists {
				return false
			}
			cur = parent.ContainedIn
		}
		return false
	}

	// Process module-bay-shaped rows in EntIndex-ascending order so dedup
	// "first occurrence wins" is deterministic. ENTITY-MIB indexes are
	// numeric — a lex sort would put "10" before "9" and pick the wrong
	// dedup winner, so compare as integers with a lex tiebreaker for
	// any non-numeric edge cases.
	//
	// Class 9 is the module class, but a transceiver is published as a
	// container or as a port depending on vendor. Widen to those two
	// classes for optic-PID rows only — a bare cage or a port row without
	// an optic PID is not a module bay.
	moduleIdxs := make([]string, 0, len(byIdx))
	for _, r := range byIdx {
		switch r.Class {
		case entPhysicalClassModule:
			if isOpticSubEntity(r, byIdx) {
				logger.Debug("module discovery: optic sub-entity skipped",
					"ent", r.EntIndex,
					"descr", r.Descr,
					"reason", "optic_sub_entity")
				continue
			}
		case entPhysicalClassContainer, entPhysicalClassPort:
			if !isOpticPID(r.Model, r.VendorType) {
				continue
			}
		default:
			continue
		}
		moduleIdxs = append(moduleIdxs, r.EntIndex)
	}
	sort.Slice(moduleIdxs, func(i, j int) bool {
		ai, errI := strconv.Atoi(moduleIdxs[i])
		aj, errJ := strconv.Atoi(moduleIdxs[j])
		if errI != nil || errJ != nil || ai == aj {
			return moduleIdxs[i] < moduleIdxs[j]
		}
		return ai < aj
	})
	seenSerial := make(map[string]struct{})

	// bayHasChild tracks bay-shaped rows that gained at least one
	// module child — used by the empty-bay harvest below. Usually keyed
	// by the class=5 container, but a chassis-rooted module with no
	// class=5 ancestor synthesizes its own EntIndex as the bay (see
	// synthesizedBay below), so a key here is not always a class=5 row.
	bayHasChild := make(map[string]bool)

	for _, idx := range moduleIdxs {
		r := byIdx[idx]
		bayIdx, parentModuleIdx, reachedChassis, chainOK := walkParents(r)
		if !chainOK {
			logger.Warn("module discovery: orphan module dropped",
				"ent", r.EntIndex,
				"model", r.Model,
				"reason", "orphan_containment")
			if c := metrics.GetModulesDropped(); c != nil {
				c.Add(context.Background(), 1, metric.WithAttributes(
					attribute.String("reason", "orphan_containment"),
				))
			}
			continue
		}
		// Fixed-FRU switches sometimes report modules directly under
		// chassis with no class=5 container — synthesize a bay so the
		// module is still emitted. Self-referential BayEntIndex is fine;
		// the downstream Diode emission only needs a stable identifier.
		synthesizedBay := false
		if bayIdx == "" {
			if !reachedChassis {
				// No class=5 AND no chassis — truly orphan.
				logger.Warn("module discovery: orphan module dropped",
					"ent", r.EntIndex,
					"model", r.Model,
					"reason", "orphan_containment")
				if c := metrics.GetModulesDropped(); c != nil {
					c.Add(context.Background(), 1, metric.WithAttributes(
						attribute.String("reason", "orphan_containment"),
					))
				}
				continue
			}
			bayIdx = r.EntIndex
			synthesizedBay = true
		}
		if r.Serial != "" {
			key := strings.ToLower(strings.TrimSpace(r.Serial))
			if _, dup := seenSerial[key]; dup {
				logger.Warn("module discovery: duplicate-serial module dropped",
					"ent", r.EntIndex,
					"serial", r.Serial,
					"model", r.Model,
					"reason", "dup_serial")
				if c := metrics.GetModulesDropped(); c != nil {
					c.Add(context.Background(), 1, metric.WithAttributes(
						attribute.String("reason", "dup_serial"),
					))
				}
				continue
			}
			seenSerial[key] = struct{}{}
		}
		bay := byIdx[bayIdx]
		// Position is the BAY's parentRelPos (chassis slot), not the
		// module's own (which is almost always "1" inside its bay).
		// When the bay was synthesized from the module itself, derive a
		// distinct name ("Slot <parentRel>") so NetBox doesn't display a
		// bay sharing the module's exact label; fall back to module Name
		// only if ParentRel is empty.
		bayName := bay.Name
		bayPos := bay.ParentRel
		if synthesizedBay {
			if r.ParentRel != "" {
				bayName = "Slot " + r.ParentRel
			} else {
				bayName = r.Name
			}
			bayPos = r.ParentRel
		}
		entry := ModuleEntry{
			EntIndex:     r.EntIndex,
			BayEntIndex:  bayIdx,
			BayName:      bayName,
			BayPosition:  bayPos,
			Name:         r.Name,
			Serial:       r.Serial,
			Model:        r.Model,
			Description:  r.Descr,
			VendorType:   r.VendorType,
			Type:         classifyModule(r.Model, r.VendorType, parentModuleIdx != ""),
			ParentEntIdx: parentModuleIdx,
		}
		// A fixed-port optic's bay is named for the interface the row
		// names. A modular optic keeps the derivation from its real cage,
		// which already identifies the port — but only when a real cage is
		// what it got.
		//
		// Two shapes have no cage. An optic under a linecard that sits in a
		// slot resolves to the linecard's own slot, so every optic on the
		// card would share that bay name, collide with the linecard's bay,
		// and lose all but the first to the duplicate-bay guard. An optic
		// under a chassis-rooted module has no container above it at all, so
		// the bay was synthesized from the optic's own row; bayBelowModule
		// answers true for it only because the optic is trivially beneath
		// its own parent, not because a cage exists, and the synthesized
		// name is the row's ParentRel, which some platforms report
		// non-positionally (-1) for every child. Name both for the interface.
		pid := effectivePID(r.Model, r.VendorType)
		if entry.Type == ModuleTypeTransceiver &&
			(parentModuleIdx == "" || synthesizedBay ||
				!bayBelowModule(bayIdx, parentModuleIdx)) {
			switch iface := servedInterface(r.Name, r.Descr, pid); {
			case iface != "":
				entry.BayName = iface
				entry.BayPosition = iface
			case parentModuleIdx != "" && !synthesizedBay:
				// Inside a module, no cage of its own, and the row names no
				// interface. The bay resolved here is the enclosing module's
				// own slot, so keeping its name would put this optic in that
				// module's bay and contest the module already installed there
				// — invisible to the duplicate-bay guard, which is scoped to
				// transceivers. Fall back to the optic's own index: stable
				// across polls and unique on the device, where the inherited
				// name is neither.
				//
				// Deliberately narrow. A fixed-port optic's container is its
				// own cage and names the port correctly, and a synthesized bay
				// is already derived from this row; neither is inherited from
				// anything, so both keep what they have.
				entry.BayName = r.EntIndex
				entry.BayPosition = r.EntIndex
			}
		}
		// A blank serial is not a reason to drop an optic. dcim.module is
		// matched on its module bay (unique_module_bay) and has no serial
		// matcher, NetBox leaves dcim.Module.serial blank-able and in no
		// constraint, and emitModule omits the field entirely when blank so
		// a repoll updates the same object rather than creating another.
		// See the ModuleBay note in stubs.go. Vendors that publish optics
		// without a serial are common rather than exceptional, so gating on
		// one would discard inventory that reconciles perfectly well.
		bayHasChild[bayIdx] = true
		if parentModuleIdx == "" {
			inv.Modules = append(inv.Modules, entry)
		} else {
			inv.SubModules[parentModuleIdx] = append(inv.SubModules[parentModuleIdx], entry)
		}
	}

	// Deterministic emission order for top-level modules.
	sort.Slice(inv.Modules, func(i, j int) bool {
		return inv.Modules[i].EntIndex < inv.Modules[j].EntIndex
	})

	// bayHasChild above only marks a module's own (nearest) class=5 bay.
	// A container whose children are themselves containers — never a
	// class=9/10 leaf directly — stays unmarked even when a module several
	// containers below it is fully populated, and the empty-bay harvest
	// below would then wrongly harvest it as empty. Propagate "has a
	// child" upward through every container ancestor so the harvest's
	// invariant holds: a container is an empty bay only if nothing
	// beneath it was emitted.
	//
	// Snapshot the already-marked keys first — ranging a map while adding
	// new keys to it is undefined for the keys added during the range.
	markedBays := make([]string, 0, len(bayHasChild))
	for idx := range bayHasChild {
		markedBays = append(markedBays, idx)
	}
	// Generous bound on how many container levels to climb — real
	// ENTITY-MIB trees are a handful of levels deep at most; this only
	// guards against a pathological/malformed capture.
	const maxContainmentWalkDepth = 64
	for _, idx := range markedBays {
		cur := byIdx[idx].ContainedIn
		seen := make(map[string]struct{})
		for depth := 0; cur != "" && cur != "0" && depth < maxContainmentWalkDepth; depth++ {
			if _, dup := seen[cur]; dup {
				logger.Debug("module: containment cycle detected during bay propagation",
					"from", idx, "at", cur)
				break
			}
			seen[cur] = struct{}{}
			parent, exists := byIdx[cur]
			if !exists || parent.Class != entPhysicalClassContainer {
				// Stop at the first non-container ancestor. A class=5 row
				// that directly hosts an emitted class=9 module is
				// already marked by the normal path above (that module's
				// bay IS this row); the only gap this closes is a
				// container whose children are all containers.
				break
			}
			if bayHasChild[cur] {
				// Already marked — its own ancestors were marked on an
				// earlier pass through this same loop, so stop rather
				// than re-walking ground already covered.
				break
			}
			bayHasChild[cur] = true
			cur = parent.ContainedIn
		}
	}

	// Empty-bay harvest. A class=5 row whose parent is a chassis or
	// another container and which has no class=9 child is an empty
	// slot — emitted as a bare bay in `full` mode (Aruba CX quirk).
	//
	// Port containers (class=5 whose only children are class=10 ports)
	// look like "no class=9 child" but they are not module bays — they
	// are slots for ports, not modules. Track which class=5 rows own
	// any class=10 child and skip them so we never surface a spurious
	// empty bay for a port container.
	containerHasPortChild := make(map[string]bool)
	for _, r := range byIdx {
		if r.Class == entPhysicalClassPort {
			parent, exists := byIdx[r.ContainedIn]
			if exists && parent.Class == entPhysicalClassContainer {
				containerHasPortChild[parent.EntIndex] = true
			}
		}
	}
	class5Idxs := make([]string, 0)
	for idx, r := range byIdx {
		if r.Class == entPhysicalClassContainer {
			class5Idxs = append(class5Idxs, idx)
		}
	}
	sort.Strings(class5Idxs)
	for _, idx := range class5Idxs {
		if bayHasChild[idx] {
			continue
		}
		if containerHasPortChild[idx] {
			continue
		}
		r := byIdx[idx]
		// An optic row is not an empty bay. It is inventory in its own
		// right, emitted as a module by the scan above; harvesting it as
		// well emits the same physical part twice, the second time with
		// its model and serial dropped and its bay named from the optic's
		// own position — which is identical on every port.
		if isOpticPID(r.Model, r.VendorType) {
			continue
		}
		parent, exists := byIdx[r.ContainedIn]
		if !exists {
			continue
		}
		// Only surface empties whose parent is a chassis or another
		// container/module — keeps leaf-shaped containers (e.g. ports
		// with no slot semantics) out of the bay list.
		if parent.Class != entPhysicalClassChassis &&
			parent.Class != entPhysicalClassContainer &&
			parent.Class != entPhysicalClassModule {
			continue
		}
		inv.EmptyBays = append(inv.EmptyBays, ModuleEntry{
			EntIndex:    r.EntIndex,
			BayEntIndex: r.EntIndex, // self — no module to anchor to
			BayName:     r.Name,
			BayPosition: r.ParentRel,
			Type:        ModuleTypeUnknown,
		})
	}
	return inv
}

// isPSUPID recognises power-supply PIDs on an already upper-cased PID.
// Covers bare prefixes (PSU-2KW-AC, PWR-C5-715WAC) and model-prefixed
// Cisco forms where the token sits in the middle (C9404R-PWR-2KW-AC).
func isPSUPID(upper string) bool {
	if strings.HasPrefix(upper, "PSU-") || strings.HasPrefix(upper, "PWR-") {
		return true
	}
	if strings.Contains(upper, "-PSU-") || strings.Contains(upper, "-PWR-") {
		return true
	}
	return false
}

// isFanPID recognises fan-tray PIDs on an already upper-cased PID.
// Tightened to require -FAN as a delimited token (suffix, or followed
// by a digit) so embedded substrings like C9400-FANTOM-LC do not match.
// Accepts: FAN-* prefix, FAN<digit> prefix, -FAN suffix, -FAN-<digit>.
func isFanPID(upper string) bool {
	if upper == "" {
		return false
	}
	if strings.HasPrefix(upper, "FAN-") {
		return true
	}
	if strings.HasSuffix(upper, "-FAN") {
		return true
	}
	// -FAN- followed by a digit (model-suffixed pattern: -FAN-2, -FAN-2KW)
	if idx := strings.Index(upper, "-FAN-"); idx >= 0 {
		rest := upper[idx+len("-FAN-"):]
		if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			return true
		}
	}
	// Bare FAN followed by a digit (FAN1, FAN2T)
	if strings.HasPrefix(upper, "FAN") && len(upper) > 3 && upper[3] >= '0' && upper[3] <= '9' {
		return true
	}
	return false
}

// isSupervisorPID recognises Cisco-style supervisor product IDs on an
// already upper-cased PID. Covers C9400-SUP-1 (dash-delimited), VS-SUP2T
// (digit-suffixed, no trailing dash) and SUPV variants.
func isSupervisorPID(upper string) bool {
	if strings.Contains(upper, "SUP-") || strings.Contains(upper, "-SUP-") || strings.Contains(upper, "SUPV") {
		return true
	}
	// SUP followed by a digit — VS-SUP2T-10G, SUP6T, SUP7, etc.
	for i := 0; i+3 < len(upper); i++ {
		if upper[i] == 'S' && upper[i+1] == 'U' && upper[i+2] == 'P' {
			c := upper[i+3]
			if c >= '0' && c <= '9' {
				return true
			}
		}
	}
	return false
}
