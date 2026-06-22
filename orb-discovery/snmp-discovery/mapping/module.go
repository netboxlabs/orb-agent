// Package mapping — module.go: scaffold for chassis module / module
// bay discovery on modular Cisco IOS-XE chassis. ChassisModuleMapper
// is intentionally a no-op; it exists only to register the
// entPhysicalDescr + entPhysicalVendorType walk columns. The actual
// translation lives in TranslateModulesWithAlias in module_translate.go.
package mapping

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/metrics"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

// ModuleEntry is one class=9 row from entPhysicalTable after
// classification. BayEntIndex points at the class=5 container that
// owns this module — the bay is emitted as a separate entity
// alongside the module installed in it.
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
// class=5 rows with no class=9 child but whose parent resolves to a
// chassis or container — Aruba CX-style empty slots; emitted only in
// `full` mode.
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

// Optic PID prefixes — pluggable transceivers across Cisco / generic
// vendors. Matched only when the row sits under a class=9 module
// parent; PID alone is insufficient (a chassis-level optic-shaped PID
// is treated as a linecard).
var opticPIDPrefixes = []string{"QSFP-", "SFP-", "X2-", "GLC-", "CFP-", "XENPAK-", "XFP-"}

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

	// Transceiver requires BOTH a module-class ancestor AND an optic
	// PID — depth alone catches non-optic sub-modules; PID alone
	// catches spare optics inventoried at chassis level.
	if hasModuleParent {
		for _, p := range opticPIDPrefixes {
			if strings.HasPrefix(upper, p) {
				return ModuleTypeTransceiver
			}
		}
	} else if isSupervisorPID(upper) {
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

// extractModuleInventory scans oids for class=9 entPhysical rows and
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

	// Process class=9 rows in EntIndex-ascending order so dedup
	// "first occurrence wins" is deterministic. ENTITY-MIB indexes are
	// numeric — a lex sort would put "10" before "9" and pick the wrong
	// dedup winner, so compare as integers with a lex tiebreaker for
	// any non-numeric edge cases.
	classNineIdxs := make([]string, 0, len(byIdx))
	for _, r := range byIdx {
		if r.Class == entPhysicalClassModule {
			classNineIdxs = append(classNineIdxs, r.EntIndex)
		}
	}
	sort.Slice(classNineIdxs, func(i, j int) bool {
		ai, errI := strconv.Atoi(classNineIdxs[i])
		aj, errJ := strconv.Atoi(classNineIdxs[j])
		if errI != nil || errJ != nil || ai == aj {
			return classNineIdxs[i] < classNineIdxs[j]
		}
		return ai < aj
	})
	seenSerial := make(map[string]struct{})

	// bayHasChild tracks class=5 rows that gained at least one class=9
	// child — used by the empty-bay harvest below.
	bayHasChild := make(map[string]bool)

	for _, idx := range classNineIdxs {
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
		bayHasChild[bayIdx] = true
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
