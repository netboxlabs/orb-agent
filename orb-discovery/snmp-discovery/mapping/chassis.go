// Package mapping — chassis.go: detection + translation of SNMP
// virtual-chassis / switch-stack topology into Diode VirtualChassis +
// member Device entities. Reads ENTITY-MIB entPhysicalTable + RFC 6933
// entAliasMappingTable. Vendor-neutral; relies on lowest-member-id
// master pinning for stability across stack-role failovers.
//
// Public entry point: TranslateAsStack.
package mapping

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// ChassisInventoryMapper is a no-op orbToEntityMapper. The
// chassis_inventory entity type exists solely so that ENTITY-MIB
// columns and entAliasMappingTable get walked into the runner's
// ObjectIDValueMap. The actual translation happens later in
// TranslateAsStack, which reads the raw oids map directly.
type ChassisInventoryMapper struct {
	logger *slog.Logger
}

// Map is intentionally a no-op — see type doc.
func (m *ChassisInventoryMapper) Map(
	_ map[ObjectIDIndex]*ObjectIDValue,
	_ *Entry,
	_ *EntityRegistry,
	_ *config.Defaults,
) diode.Entity {
	return nil
}

// ChassisMember is one row of ENTITY-MIB entPhysicalTable identified
// as a top-level chassis (class=3, containedIn=0). The ID is the
// derived logical member id (see assignMemberIDs); EntPhysicalIndex is
// the raw row index used for entAliasMappingTable chain walks.
// AssetTag is the trimmed entPhysicalAssetID value ("" when unset or not walked).
//
// DescendantIDs is derivation-only input for assignMemberIDs' descendant
// tier, in the same category as EntName and ParentRelPos (both exported,
// both read only by the id helpers). It holds the DISTINCT SORTED leading
// numbers found on this chassis's port descendants; nil means "no signal"
// and makes the tier decline. Populated only for multi-member sets — see
// collectDescendantIDs.
type ChassisMember struct {
	ID               int
	EntPhysicalIndex string
	Serial           string
	Model            string
	EntName          string
	ParentRelPos     int
	AssetTag         string
	DescendantIDs    []int
}

// ChassisInventory is the deduped, validated, member-id-sorted set of
// stack members for one target. Len(Members) >= 2 means stack.
type ChassisInventory struct {
	Members           []ChassisMember
	DroppedIDs        map[int]struct{}
	DroppedEntIndexes map[string]int // entPhysicalIndex -> dropped member id
}

// IsStack reports whether the inventory should trigger VC emission.
func (c ChassisInventory) IsStack() bool { return len(c.Members) >= 2 }

// entPhysical column prefixes — kept as constants so the extractor and
// future enrichers reference the same OIDs.
const (
	oidEntPhysicalContainedIn = ".1.3.6.1.2.1.47.1.1.1.1.4."
	oidEntPhysicalClass       = ".1.3.6.1.2.1.47.1.1.1.1.5."
	oidEntPhysicalParentRel   = ".1.3.6.1.2.1.47.1.1.1.1.6."
	oidEntPhysicalName        = ".1.3.6.1.2.1.47.1.1.1.1.7."
	oidEntPhysicalSerialNum   = ".1.3.6.1.2.1.47.1.1.1.1.11."
	oidEntPhysicalModelName   = ".1.3.6.1.2.1.47.1.1.1.1.13."
	oidEntPhysicalAssetID     = ".1.3.6.1.2.1.47.1.1.1.1.15."

	entPhysicalClassChassis = "3"
	entPhysicalClassStack   = "11"
)

// isStackContainerParent reports whether the entPhysicalIndex `idx`
// names a class=11 (stack) entity in the walked map. Cisco StackWise
// Virtual (and similar two-chassis pair architectures) nest the
// physical chassis(3) rows under a class=11 (stack) parent rather
// than placing them at the ENTITY-MIB root. Returning true allows
// extractInventory to treat the wrapped chassis rows as stack members.
func isStackContainerParent(oids ObjectIDValueMap, idx string) bool {
	if idx == "" || idx == "0" {
		return false
	}
	v, ok := oids[oidEntPhysicalClass+idx]
	if !ok {
		return false
	}
	return strings.TrimSpace(v.Value) == entPhysicalClassStack
}

// extractInventory scans oids for class=3 entPhysical rows with
// non-empty serial. A chassis row qualifies as a stack member when
// either:
//   - entPhysicalContainedIn == 0 (flat pattern — direct children of
//     the ENTITY-MIB root; used by Catalyst 9300/3850 stacks, Aruba
//     VSF, Juniper EX Virtual Chassis, etc.); or
//   - entPhysicalContainedIn points to a class=11 (stack) entity
//     (wrapped pattern — physical chassis are nested under a stack
//     container; used by Cisco StackWise Virtual on the 9400/9500/9600
//     series and similar pair architectures).
//
// Returns members sorted ascending by ID. Member ids are derived
// set-wide by assignMemberIDs (one scheme for all members:
// parentRelPos → entPhysicalName trailing int → port-descendant number
// → ordinal).
func extractInventory(oids ObjectIDValueMap, logger *slog.Logger) ChassisInventory {
	candidates := []string{}
	for oid, v := range oids {
		if !strings.HasPrefix(oid, oidEntPhysicalClass) {
			continue
		}
		if strings.TrimSpace(v.Value) != entPhysicalClassChassis {
			continue
		}
		idx := strings.TrimPrefix(oid, oidEntPhysicalClass)
		candidates = append(candidates, idx)
	}

	members := make([]ChassisMember, 0, len(candidates))
	for _, idx := range candidates {
		contained := trimSNMPString(oids[oidEntPhysicalContainedIn+idx].Value)
		if contained != "0" && !isStackContainerParent(oids, contained) {
			continue
		}
		serial := trimSNMPString(oids[oidEntPhysicalSerialNum+idx].Value)
		if serial == "" {
			logger.Warn("chassis row dropped: empty serial",
				"entPhysicalIndex", idx)
			continue
		}
		parentRel, _ := strconv.Atoi(trimSNMPString(oids[oidEntPhysicalParentRel+idx].Value))
		members = append(members, ChassisMember{
			EntPhysicalIndex: idx,
			Serial:           serial,
			Model:            trimSNMPString(oids[oidEntPhysicalModelName+idx].Value),
			EntName:          trimSNMPString(oids[oidEntPhysicalName+idx].Value),
			ParentRelPos:     parentRel,
			AssetTag:         trimSNMPString(oids[oidEntPhysicalAssetID+idx].Value),
		})
	}

	// Sort by entPhysicalIndex first so assignMemberIDs' set-wide
	// ordinal tier (used when neither the parentRelPos column nor
	// entPhysicalName is usable for the whole set) assigns
	// deterministic walk-order ids.
	slices.SortFunc(members, func(a, b ChassisMember) int {
		ai, _ := strconv.Atoi(a.EntPhysicalIndex)
		bi, _ := strconv.Atoi(b.EntPhysicalIndex)
		return ai - bi
	})
	collectDescendantIDs(members, oids, childIndexFromOIDs(oids))
	assignMemberIDs(members, logger)
	// Dedup pass 1: drop later-occurring duplicates of the same serial,
	// keep the lowest-id occurrence. Track dropped ids and their
	// entPhysicalIndexes for the routing warn-and-skip rule.
	dropped := map[int]struct{}{}
	droppedEnts := map[string]int{} // entPhysicalIndex -> dropped member id
	bySerial := map[string]int{}
	survivors := members[:0]
	for _, m := range members {
		if existing, ok := bySerial[m.Serial]; ok {
			// Keep the lower id, drop the higher id.
			keep, drop := existing, m.ID
			dropEnt := m.EntPhysicalIndex
			if m.ID < existing {
				keep, drop = m.ID, existing
				// Find the old survivor's entPhysicalIndex before rewriting.
				for i := range survivors {
					if survivors[i].Serial == m.Serial {
						dropEnt = survivors[i].EntPhysicalIndex
						survivors[i] = m
						break
					}
				}
			}
			bySerial[m.Serial] = keep
			if drop != keep {
				dropped[drop] = struct{}{}
				droppedEnts[dropEnt] = drop
			}
			logger.Warn("chassis row dropped: duplicate serial",
				"serial", m.Serial, "kept_id", keep, "dropped_id", drop)
			continue
		}
		bySerial[m.Serial] = m.ID
		survivors = append(survivors, m)
	}
	members = survivors

	// Dedup pass 2: same id with different serials -> drop all
	// occurrences of that id (ambiguous -> refuse to emit).
	byID := map[int][]ChassisMember{}
	for _, m := range members {
		byID[m.ID] = append(byID[m.ID], m)
	}
	survivors = members[:0]
	for _, group := range byID {
		if len(group) > 1 {
			id := group[0].ID
			dropped[id] = struct{}{}
			for _, row := range group {
				droppedEnts[row.EntPhysicalIndex] = id
			}
			logger.Warn("chassis row dropped: ambiguous duplicate member id",
				"id", id, "count", len(group))
			continue
		}
		survivors = append(survivors, group[0])
	}
	members = survivors

	return ChassisInventory{
		Members:           sortByID(members),
		DroppedIDs:        dropped,
		DroppedEntIndexes: droppedEnts,
	}
}

// ChassisInventoryFromOIDs returns the parsed ChassisInventory for the
// device described by oids. Thin exported wrapper around
// extractInventory so the runner can re-derive what TranslateAsStack
// computed internally.
func ChassisInventoryFromOIDs(oids ObjectIDValueMap, logger *slog.Logger) *ChassisInventory {
	inv := extractInventory(oids, logger)
	return &inv
}

// buildMasterRef returns a non-recursive matcher-only Device for use
// as VirtualChassis.Master on the top-level VC entity AND on each
// non-master member Device's VirtualChassis.Master.
//
// Carries the matcher fields the rich master Device carries below the
// primary-IP rungs — divergence breaks the Diode plugin's matcher
// precedence cascade (asset_tag -> primary_ip4 -> primary_ip6 -> oob_ip
// -> name+site+tenant -> name+site -> rack+position+face ->
// virtual_chassis+vc_position) and creates ghost VCs.
//
// MUST NOT carry VirtualChassis (non-recursion — dodges the plugin's
// "Unable to resolve circular reference in entities" error) or
// VcPosition (would only feed matcher #8 which is unreachable behind
// the higher-precedence matchers above).
//
// MUST NOT carry primary_ip4/6 either. dcim.device.primary_ip is a
// circular reference the reconciler resolves only within a SINGLE
// change set, and the master ref is never the entity that closes that
// cycle — only the top-level ipam.ipaddress entity for the primary IP
// does, in its own change set. A primary IP on the master ref would
// just make it try to SET primary_ip and fail on first ingest. So this
// ref relies on asset_tag and name+site+tenant matchers instead.
func buildMasterRef(master *diode.Device) *diode.Device {
	if master == nil {
		return nil
	}
	ref := &diode.Device{
		Name:       master.Name,
		Serial:     master.Serial,
		AssetTag:   master.AssetTag,
		Site:       master.Site,
		Tenant:     master.Tenant,
		Role:       master.Role,
		DeviceType: master.DeviceType,
	}
	if sm, ok := master.Metadata["source_match"]; ok {
		ref.Metadata = diode.Metadata{"source_match": sm}
	}
	return ref
}

// buildMemberDevice constructs a non-master member Device proto.
//
//   - Name = "{vcName}-{memberID}" (entPhysicalName like
//     "Switch 2" is intentionally not used: it would produce poor
//     NetBox names and collide across stacks in the same site).
//   - Serial = per-member entPhysicalSerialNum.
//   - AssetTag = nil here; the caller sets a per-row entPhysicalAssetID
//     value afterwards when asset tag discovery produced one for this
//     member. defaults.asset_tag is never copied to members —
//     Diode's highest-precedence matcher for dcim.device is unique on
//     asset_tag, so one operator-supplied tag applied to N members
//     would collapse them onto one NetBox row.
//   - VcPosition = member.ID; VirtualChassis = {Name: vcName, Master: masterRef}.
//   - DeviceType from member.Model when populated, else inherit master's.
//   - Site / Tenant / Role / Platform / Location inherited from master.
func buildMemberDevice(master *diode.Device, member ChassisMember, masterRef *diode.Device, vcName string) *diode.Device {
	name := fmt.Sprintf("%s-%d", vcName, member.ID)
	pos := int64(member.ID)
	dev := &diode.Device{
		Name:       &name,
		Serial:     &member.Serial,
		Site:       master.Site,
		Tenant:     master.Tenant,
		Role:       master.Role,
		Platform:   master.Platform,
		Location:   master.Location,
		VcPosition: &pos,
		VirtualChassis: &diode.VirtualChassis{
			Name:   &vcName,
			Master: masterRef,
		},
	}
	if member.Model != "" {
		// Always honor per-member entPhysicalModelName when present,
		// even if master.DeviceType is nil (sysObjectID lookup failed
		// upstream). Inherit master's Manufacturer when available; else
		// leave it nil and let NetBox / defaults take over.
		var mfg *diode.Manufacturer
		if master.DeviceType != nil {
			mfg = master.DeviceType.Manufacturer
		}
		dev.DeviceType = &diode.DeviceType{
			Model:        StringPtr(member.Model),
			Manufacturer: mfg,
		}
	} else {
		dev.DeviceType = master.DeviceType
	}
	return dev
}

func sortByID(members []ChassisMember) []ChassisMember {
	slices.SortFunc(members, func(a, b ChassisMember) int { return a.ID - b.ID })
	return members
}

// strDeref dereferences p or returns "" when nil.
func strDeref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// trimSNMPString removes every NUL byte (interior as well as padding) and
// trims surrounding whitespace from DisplayString-like SNMP values. It is the
// canonical sanitizer for any device-provided text bound for a NetBox/Diode
// field. Two reasons NUL handling matters: many vendor agents pad short
// strings with trailing NUL bytes — a NUL-padded "FOC1234\x00" would compare
// unequal to "FOC1234" from another agent, breaking dedup and stable matching
// across runs — and NetBox/PostgreSQL rejects a NUL anywhere in a text field,
// failing ingestion outright. strings.ReplaceAll returns the input unchanged
// (no allocation) when there is no NUL, so the common clean case is cheap.
func trimSNMPString(s string) string {
	return strings.Trim(strings.ReplaceAll(s, "\x00", ""), " \t\r\n")
}

var trailingIntRe = regexp.MustCompile(`(\d+)\s*$`)

// leadingMemberNumRe matches the leading slash-delimited number of an
// interface-style entPhysicalName ("2/1/1" -> 2, "1/1/1:1" -> 1). Anchored so
// vendor-decorated names that merely contain the pattern ("GigabitEthernet1/0/1",
// "RPM sensor for fan Tray-2/1/1") yield nothing rather than a slot number.
//
// Not trailingIntRe: that reads the END of a member's own name ("Switch 2").
var leadingMemberNumRe = regexp.MustCompile(`^(\d+)/`)

// prelState classifies the member set's entPhysicalParentRelPos values.
type prelState int

const (
	prelUsable    prelState = iota // all values > 0 and distinct: use as ids
	prelAmbiguous                  // all values > 0 but duplicated: device asserts two rows at one position
	prelAbsent                     // any value <= 0: unpopulated or zero-based numbering
)

// assignMemberIDs derives every member's logical id using ONE scheme for
// the whole set. Per-member tier fallback (the previous deriveMemberID)
// mixed schemes across siblings: a member with parentRelPos=0 fell to the
// name tier while the rest used the prel tier, and on devices that number
// entPhysicalParentRelPos zero-based the two schemes are offset by one —
// colliding ids sent valid members into the ambiguous-id dedup (#458).
//
// Tier precedence, first usable wins for ALL members:
//  1. parentRelPos when USABLE (every value > 0, distinct);
//  2. entPhysicalName trailing int — usable iff every member has one and
//     they are distinct (0 is allowed: FPC-style members are genuinely
//     zero-numbered);
//  3. the leading number on each member's PORT descendants, reached through
//     entPhysicalContainedIn, under descendantIDs' strict predicate. Resolves
//     stacks that report the same position AND the same name on every chassis
//     row while numbering their ports 1/1/x .. N/1/x. Port names are the
//     namespace entAliasMappingTable maps to ifName, so this id and an
//     ifName-derived id agree — on the vendors where that holds, which is why
//     the predicate refuses rather than assumes;
//  4. when parentRelPos is AMBIGUOUS (duplicate positive positions) or
//     names are AMBIGUOUS (full coverage, duplicate numbers) and neither
//     the other signal nor the descendant tier could rescue, keep the
//     colliding values so the caller's ambiguity dedup refuses those rows —
//     silently renumbering them would mis-attribute ifName-routed
//     interfaces;
//  5. ordinal 1..N in slice order (callers pass entPhysicalIndex-sorted
//     members, so this is walk order).
//
// Scheme selection runs over the pre-dedup member rows: a duplicate-serial
// junk row with an out-of-scheme prel/name can downgrade the tier for the
// whole set. Accepted for now — no real walk exhibiting it is known, and
// pass-1 serial dedup still bounds the damage.
//
// Any value <= 0 marks the WHOLE prel column untrustworthy (prelAbsent):
// duplicates inside a zero-containing set carry no position signal and do
// not trigger ambiguity refusal — the column is simply abandoned.
// Observability: a wrong-but-distinct assignment is silent downstream
// (vc_position, member device names, ifName routing all trust the ids),
// so every lossy or low-confidence set-wide rejection of a PRESENT signal
// is warn-logged; the high-confidence names-rescue path logs Info (only
// when prel carried any positive signal — an all-zero column is normal).
func assignMemberIDs(members []ChassisMember, logger *slog.Logger) {
	if len(members) == 0 {
		return
	}
	prel, state := parentRelIDs(members)
	if state == prelUsable {
		applyIDs(members, prel)
		return
	}
	names, nstate := nameIDs(members)
	if nstate == nameUsable {
		// High-confidence outcome: names carry explicit distinct numbers.
		// Info (not Warn) when prel had signal — a zero-based prel column
		// with numbered names is this code's normal, correct path, and a
		// permanent Warn on every poll would be noise.
		if hasPositivePrel(members) {
			logger.Info("member id: entPhysicalParentRelPos unusable set-wide, using entPhysicalName-derived ids",
				"reason", prelStateReason(state), "members", len(members))
		}
		applyIDs(members, names)
		return
	}
	// Tier 3: the device's own containment tree, ahead of both refusals and
	// the ordinal fallback. A device asserting one position twice has asserted
	// nonsense; one with both columns silent has asserted nothing. Containment
	// beats walk order in either case, and descendantIDs' predicate is what
	// makes trusting it safe.
	desc, dstate := descendantIDs(members)
	if dstate == descendantUsable {
		logger.Info("member id: using entPhysicalContainedIn descendant-derived ids",
			"reason", prelStateReason(state), "name_reason", nameStateReason(nstate),
			"ids", desc, "members", len(members))
		applyIDs(members, desc)
		return
	}
	if dstate == descendantConflict {
		// Warn only when this decline costs the device its stack: with
		// ambiguous prel or names the next stop is refusal. Otherwise the
		// ordinal fallback still emits a working stack, and a permanent Warn
		// on every poll of a healthy device whose ports are merely
		// slot-numbered ("1/1".."1/48" on every member) is noise.
		log := logger.Debug
		if state == prelAmbiguous || nstate == nameAmbiguous {
			log = logger.Warn
		}
		log("member id: descendant-derived ids rejected as contradictory",
			"sets", descendantSets(members), "members", len(members))
	}

	// From here every outcome is lossy or low-confidence: Warn. Colliding
	// ids are deliberately KEPT so the caller's ambiguity dedup refuses
	// those rows — silently renumbering them would mis-attribute
	// ifName-routed interfaces on any device whose ports are absent from
	// entAliasMappingTable (present-table devices route by containment and
	// use the id only as a map key — see chassisRouter.routeIfIndex).
	if state == prelAmbiguous {
		logger.Warn("member id: duplicate positive entPhysicalParentRelPos and no usable names; keeping colliding ids for ambiguity refusal",
			"members", len(members))
		applyIDs(members, prel)
		return
	}
	if nstate == nameAmbiguous {
		logger.Warn("member id: duplicate entPhysicalName numbers and no usable positions; keeping colliding ids for ambiguity refusal",
			"members", len(members))
		applyIDs(members, names)
		return
	}
	if partialNames(members) {
		logger.Warn("member id: entPhysicalName carries numbers on some members only; ignoring name signal set-wide",
			"members", len(members))
	}
	if hasPositivePrel(members) {
		logger.Warn("member id: no usable id signal; assigning ordinal member ids in walk order",
			"members", len(members))
	}
	ordinal := make([]int, len(members))
	for i := range ordinal {
		ordinal[i] = i + 1
	}
	applyIDs(members, ordinal)
}

// childIndexFromOIDs inverts entPhysicalContainedIn into parent -> children,
// so the descendant walk can descend where routeIfIndex ascends.
//
// Values go through trimSNMPString, matching how extractInventory reads the
// same column: a NUL-padded parent pointer must still key to its chassis, or
// the subtree reads as empty and the descendant tier silently declines.
func childIndexFromOIDs(oids ObjectIDValueMap) map[string][]string {
	out := make(map[string][]string, len(oids)/8)
	for oid, v := range oids {
		if !strings.HasPrefix(oid, oidEntPhysicalContainedIn) {
			continue
		}
		parent := trimSNMPString(v.Value)
		out[parent] = append(out[parent], strings.TrimPrefix(oid, oidEntPhysicalContainedIn))
	}
	return out
}

// collectDescendantIDs populates each member's DescendantIDs with the distinct
// sorted leading numbers on the port rows in its entPhysicalContainedIn
// subtree. Input to the descendant tier.
//
// Multi-member sets only: a lone member trivially satisfies the tier's
// predicate, so a subtree could renumber the one chassis of a
// partially-reporting stack, and every standalone switch would pay a DFS per
// poll for nothing.
//
// Two properties are easy to get wrong:
//
//   - The class filter gates COLLECTION, not traversal. The chain is
//     port(10) -> module(9) -> chassis(3), so filtering the walk itself
//     returns an empty set for every member.
//   - The walk stops at any other chassis or stack row, member or not.
//     Class-3 rows are excluded from the member set for a non-root parent or
//     a missing serial; descending through one would merge a rejected
//     sibling's ports in and veto an otherwise-clean device.
func collectDescendantIDs(members []ChassisMember, oids ObjectIDValueMap, childrenOf map[string][]string) {
	if len(members) < 2 {
		return
	}
	classOf := func(idx string) string {
		return trimSNMPString(oids[oidEntPhysicalClass+idx].Value)
	}
	for i := range members {
		found := map[int]struct{}{}
		seen := map[string]struct{}{members[i].EntPhysicalIndex: {}}
		queue := append([]string(nil), childrenOf[members[i].EntPhysicalIndex]...)
		for len(queue) > 0 {
			idx := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			if _, dup := seen[idx]; dup {
				continue
			}
			seen[idx] = struct{}{}
			switch classOf(idx) {
			case entPhysicalClassChassis, entPhysicalClassStack:
				// Another chassis's territory (or a nested stack) — do not
				// descend, do not collect.
				continue
			case entPhysicalClassPort:
				name := trimSNMPString(oids[oidEntPhysicalName+idx].Value)
				if m := leadingMemberNumRe.FindStringSubmatch(name); m != nil {
					if n, err := strconv.Atoi(m[1]); err == nil {
						found[n] = struct{}{}
					}
				}
			}
			queue = append(queue, childrenOf[idx]...)
		}
		if len(found) == 0 {
			continue // leave nil: no signal
		}
		nums := make([]int, 0, len(found))
		for n := range found {
			nums = append(nums, n)
		}
		slices.Sort(nums)
		members[i].DescendantIDs = nums
	}
}

func hasPositivePrel(members []ChassisMember) bool {
	for _, m := range members {
		if m.ParentRelPos > 0 {
			return true
		}
	}
	return false
}

func partialNames(members []ChassisMember) bool {
	n := 0
	for _, m := range members {
		if trailingIntRe.FindString(m.EntName) != "" {
			n++
		}
	}
	return n > 0 && n < len(members)
}

func prelStateReason(s prelState) string {
	if s == prelAmbiguous {
		return "duplicate positive positions"
	}
	return "contains zero or negative positions"
}

func nameStateReason(s nameState) string {
	if s == nameAmbiguous {
		return "duplicate name numbers"
	}
	return "name numbers missing on at least one member"
}

func applyIDs(members []ChassisMember, ids []int) {
	for i := range members {
		members[i].ID = ids[i]
	}
}

// parentRelIDs returns the members' parentRelPos values and their
// classification. The values are only meaningful for prelUsable (distinct
// ids) and prelAmbiguous (deliberately colliding ids for the caller's
// ambiguity dedup); prelAbsent returns nil.
func parentRelIDs(members []ChassisMember) ([]int, prelState) {
	ids := make([]int, len(members))
	seen := make(map[int]struct{}, len(members))
	state := prelUsable
	for i, m := range members {
		if m.ParentRelPos <= 0 {
			return nil, prelAbsent
		}
		if _, dup := seen[m.ParentRelPos]; dup {
			state = prelAmbiguous
		}
		seen[m.ParentRelPos] = struct{}{}
		ids[i] = m.ParentRelPos
	}
	return ids, state
}

// descendantState classifies the member set's descendant-derived numbers.
type descendantState int

const (
	descendantUsable   descendantState = iota // every member yields exactly one number, all distinct, all > 0
	descendantConflict                        // a member's ports disagree, or two members claim one number
	descendantAbsent                          // at least one member has no numbered port descendants
)

// descendantIDs returns member ids derived from the leading number on each
// chassis's port descendants. Mirrors parentRelIDs and nameIDs: pure over the
// member slice, meaningful only for descendantUsable.
//
// Strict on purpose — a wrong-but-distinct id is silent downstream. Any of
// these vetoes the whole set: a member with no numbered ports; a member whose
// ports carry more than one number; two members claiming one number; a number
// <= 0.
//
// The zero rule differs from nameIDs, which allows 0 because an FPC-style
// member really is zero-numbered. Here the leading field of a PORT name is a
// slot, and devices do name every port "0/N" under a chassis called "Unit 1",
// where 0 would set vc_position 0 and re-pin the master.
//
// Walk order need not match id order: extractInventory re-sorts by id, so an
// agent enumerating chassis rows in join order is numbered, not refused.
func descendantIDs(members []ChassisMember) ([]int, descendantState) {
	ids := make([]int, len(members))
	seen := make(map[int]struct{}, len(members))
	for i, m := range members {
		if len(m.DescendantIDs) == 0 {
			return nil, descendantAbsent
		}
		if len(m.DescendantIDs) > 1 {
			return nil, descendantConflict
		}
		id := m.DescendantIDs[0]
		if id <= 0 {
			return nil, descendantConflict
		}
		if _, dup := seen[id]; dup {
			return nil, descendantConflict
		}
		seen[id] = struct{}{}
		ids[i] = id
	}
	return ids, descendantUsable
}

// descendantSets renders the per-member descendant numbers for logging, so a
// conflict decline says WHICH members disagreed instead of only that one did.
func descendantSets(members []ChassisMember) string {
	var b strings.Builder
	for i, m := range members {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%s=%v", m.EntPhysicalIndex, m.DescendantIDs)
	}
	return b.String()
}

// nameState classifies the member set's entPhysicalName trailing-int values.
type nameState int

const (
	nameUsable    nameState = iota // every member has a trailing int, all distinct: use as ids
	nameAmbiguous                  // every member has a trailing int, but duplicated: device asserts one number twice
	nameAbsent                     // at least one member has no trailing int
)

// nameIDs returns trailing-integer ids parsed from entPhysicalName and
// their classification. Zero is a valid id here (FPC-style members are
// genuinely zero-numbered). The ids are meaningful for nameUsable
// (distinct) and nameAmbiguous (deliberately colliding, for the caller's
// ambiguity refusal); nameAbsent returns nil.
func nameIDs(members []ChassisMember) ([]int, nameState) {
	ids := make([]int, len(members))
	seen := make(map[int]struct{}, len(members))
	state := nameUsable
	for i, m := range members {
		match := trailingIntRe.FindString(m.EntName)
		if match == "" {
			return nil, nameAbsent
		}
		id, err := strconv.Atoi(strings.TrimSpace(match))
		if err != nil {
			return nil, nameAbsent
		}
		if _, dup := seen[id]; dup {
			state = nameAmbiguous
		}
		seen[id] = struct{}{}
		ids[i] = id
	}
	return ids, state
}

// resolveAssetTags maps member ID -> the entPhysicalAssetID value that
// is safe to emit for that chassis row. Returns nil when every member
// has an empty tag (fast-exit, no allocation). Filter order per row:
//
//  1. empty — silent skip;
//  2. vetAssetTag — rejects invalid UTF-8, control bytes, well-known
//     placeholders, and values exceeding assetTagMaxLen (warn-logged);
//  3. masterTag collision — members[0] (lowest ID, sorted ascending)
//     carrying the same tag as the operator-supplied defaults agrees
//     with the default and is dropped at Debug level; any other member
//     sharing masterTag is a genuine collision and is warn-logged;
//  4. duplicate across chassis rows — two or more rows sharing the same
//     tag after the earlier filters would create a NetBox uniqueness
//     violation; both are warn-logged and dropped.
//
// Dropping is required, not cosmetic: asset_tag is unique in NetBox
// and is the Diode plugin's highest-precedence device matcher, so a
// duplicate would collapse two devices onto one NetBox row.
// Callers pass inv.Members which is ID-sorted ascending; members[0]
// is always the master row.
func resolveAssetTags(members []ChassisMember, masterTag string, logger *slog.Logger) map[int]string {
	// Early exit: skip allocation when nothing was walked.
	hasTag := false
	for _, m := range members {
		if m.AssetTag != "" {
			hasTag = true
			break
		}
	}
	if !hasTag {
		return nil
	}

	counts := make(map[string]int, len(members))
	for _, m := range members {
		if m.AssetTag != "" {
			counts[m.AssetTag]++
		}
	}

	out := make(map[int]string, len(members))
	for i, m := range members {
		tag := m.AssetTag
		if tag == "" {
			continue
		}
		if reason, ok := vetAssetTag(tag); !ok {
			logger.Warn("asset tag skipped: "+reason,
				"member_id", m.ID, "entPhysicalIndex", m.EntPhysicalIndex)
			continue
		}
		if masterTag != "" && tag == masterTag {
			if i == 0 {
				// The device's own row agreeing with the operator's
				// configured default is healthy, not a collision.
				logger.Debug("asset tag agrees with defaults asset_tag",
					"member_id", m.ID)
			} else {
				logger.Warn("asset tag skipped: collides with defaults asset_tag",
					"asset_tag", tag, "member_id", m.ID)
			}
			continue
		}
		if counts[tag] > 1 {
			logger.Warn("asset tag skipped: duplicate across chassis rows",
				"asset_tag", tag, "member_id", m.ID)
			continue
		}
		out[m.ID] = tag
	}
	return out
}

// refusedMasterSerial returns the serial to put on the master when every
// chassis row was refused, or "" when there was nothing to refuse (a device
// with no chassis rows is simply not a stack, and must stay untouched).
//
// DroppedEntIndexes carries the refused rows' entPhysicalIndexes, so the
// serial is read back from oids: the inventory itself keeps no serial for a
// dropped row. Lowest index wins, matching the master-pinning convention.
func refusedMasterSerial(inv ChassisInventory, oids ObjectIDValueMap) string {
	if len(inv.DroppedEntIndexes) == 0 {
		return ""
	}
	idxs := make([]string, 0, len(inv.DroppedEntIndexes))
	for idx := range inv.DroppedEntIndexes {
		idxs = append(idxs, idx)
	}
	slices.SortFunc(idxs, func(a, b string) int {
		ai, _ := strconv.Atoi(a)
		bi, _ := strconv.Atoi(b)
		return ai - bi
	})
	for _, idx := range idxs {
		if s := trimSNMPString(oids[oidEntPhysicalSerialNum+idx].Value); s != "" {
			return s
		}
	}
	return ""
}

// TranslateAsStack inspects the raw oids map for ENTITY-MIB chassis
// inventory. Three outcomes:
//
//   - 0 chassis rows with non-empty serial -> entities returned
//     unchanged (no Serial assignment possible), EXCEPT when rows existed
//     and were all refused as ambiguous, in which case the master keeps a
//     serial but gets no VirtualChassis (see refusedMasterSerial).
//   - 1 chassis row -> set master.Serial on the existing Device,
//     return entities unchanged otherwise (standalone case).
//   - >= 2 chassis rows -> emit master + top-level VirtualChassis +
//     member Devices, re-point each Interface's Device ref to its
//     owning member, skip interfaces whose parsed member id was
//     dropped during validation.
//
// ifIndexByIface maps each Interface entity to its ifIndex (the
// registry knows; the proto doesn't carry it). May be nil — in that
// case alias-table routing is skipped and ifName parsing drives all
// routing decisions.
//
// claimAssetTag, when non-nil, is consulted once per tag at
// application time; returning false suppresses the tag (used by the
// runner to prevent the same wire tag appearing on devices from
// different targets of one policy — NetBox asset_tag is unique and
// the highest-precedence Diode matcher, so cross-target duplicates
// would merge two devices onto one record). nil means always allow.
//
// Must be called from the runner AFTER mapper.MapObjectIDsToEntity
// returns and BEFORE annotate*/Ingest. See runner.go.
func TranslateAsStack(
	entities []diode.Entity,
	oids ObjectIDValueMap,
	ifIndexByIface map[*diode.Interface]int,
	claimAssetTag func(tag string) bool,
	logger *slog.Logger,
) []diode.Entity {
	master := CurrentDeviceFrom(entities)
	if master == nil {
		return entities
	}

	// Register the operator-supplied defaults tag (if any) with the
	// claimer before any discovered-tag processing — including for
	// devices with no chassis rows at all. A defaults-owned value must
	// not be claimable as a DISCOVERED tag by another target of this
	// policy: cloned EEPROM data reporting the same string would emit
	// and merge onto this device's NetBox record via the asset_tag
	// matcher. The result is deliberately ignored — defaults always
	// stick to this device; the claimer warns on conflicting ownership.
	if dt := strDeref(master.AssetTag); dt != "" && claimAssetTag != nil {
		claimAssetTag(dt)
	}

	inv := extractInventory(oids, logger)
	if len(inv.Members) == 0 {
		// Two situations reach zero members: no chassis rows at all (not a
		// stack, leave it alone) and every row refused as ambiguous. Only
		// the member NUMBERING is ambiguous in the second case, so refuse
		// the structure but keep the serial, taken from the lowest
		// entPhysicalIndex — the one ordering that does not depend on the
		// disputed ids, so it is stable across polls of the same data.
		//
		// Not guaranteed to equal what a later RESOLVING poll picks: that
		// takes the lowest member id, which is the lowest index only when
		// ids ascend with it. Still better than no serial, and serial is
		// not a Diode matcher, so nothing re-keys.
		if s := refusedMasterSerial(inv, oids); s != "" && master.Serial == nil {
			master.Serial = &s
			logger.Warn("stack refused: emitting master serial only, no virtual chassis",
				"serial", s, "refused_ids", len(inv.DroppedIDs))
		}
		return entities
	}

	// Asset tags from entPhysicalAssetID (column walked only when
	// discover_asset_tags is on — absent data makes this a no-op).
	// strDeref(master.AssetTag) carries the operator-supplied defaults
	// value into the collision check.
	assetTags := resolveAssetTags(inv.Members, strDeref(master.AssetTag), logger)

	// Nil-safe wrapper: claimAssetTag == nil means always allow.
	claim := func(tag string) bool {
		return claimAssetTag == nil || claimAssetTag(tag)
	}

	// Standalone (1 chassis row): set Serial, return unchanged shape.
	if !inv.IsStack() {
		s := inv.Members[0].Serial
		master.Serial = &s
		if tag, ok := assetTags[inv.Members[0].ID]; ok && master.AssetTag == nil && claim(tag) {
			master.AssetTag = StringPtr(tag)
		}
		return entities
	}

	// Stack (>= 2 chassis rows): full emission.
	// 1. Set Serial on master from the lowest-id chassis row.
	lowest := inv.Members[0] // sorted ascending
	masterSerial := lowest.Serial
	master.Serial = &masterSerial
	// Master also gets its per-member Model in case the rich
	// DeviceMapper picked a top-level chassis model that diverges
	// (or didn't resolve a DeviceType at all — sysObjectID miss).
	//
	// Matches buildMemberDevice: every member's device_type comes from its own
	// chassis row, which is what makes a mixed-model stack right, and the
	// master is just the lowest-id chassis row. This does override
	// override_defaults.device.model, which the backend documents as
	// highest-priority — a real contract bug, but it applies equally to the
	// member Devices and cannot be fixed here (no access to config.Defaults),
	// and guarding only the master would split one stack across two types.
	if lowest.Model != "" {
		var mfg *diode.Manufacturer
		if master.DeviceType != nil {
			mfg = master.DeviceType.Manufacturer
		}
		master.DeviceType = &diode.DeviceType{
			Model:        StringPtr(lowest.Model),
			Manufacturer: mfg,
		}
	}

	// Must precede buildMasterRef so the matcher stub carries the same asset_tag as the rich master.
	if tag, ok := assetTags[lowest.ID]; ok && master.AssetTag == nil && claim(tag) {
		master.AssetTag = StringPtr(tag)
	}

	vcName := ""
	if master.Name != nil {
		vcName = *master.Name
	}

	// 2. Build masterRef AFTER any primary-IP assignment on the
	// rich master. snmp-discovery's primary-IP assignment runs
	// inside MapObjectIDsToEntity before we get here, so master
	// already carries PrimaryIp4/6 at this point.
	masterRef := buildMasterRef(master)

	// 3. Build per-member Device entities (skip the master row).
	memberByID := map[int]*diode.Device{lowest.ID: master}
	memberDevices := make([]*diode.Device, 0, len(inv.Members)-1)
	for _, m := range inv.Members[1:] {
		dev := buildMemberDevice(master, m, masterRef, vcName)
		if tag, ok := assetTags[m.ID]; ok && claim(tag) {
			dev.AssetTag = StringPtr(tag)
		}
		memberByID[m.ID] = dev
		memberDevices = append(memberDevices, dev)
	}

	// 4. Re-route Interface.Device for member-owned ports.
	//    Routing precedence: entAliasMappingTable -> ParseMemberID
	//    fallback. Dropped-id ports are skipped (excluded from output)
	//    along with their dependent IPs/MACs.
	router := newChassisRouter(inv, oids, logger)
	keptInterfaces := make(map[*diode.Interface]bool)
	skippedInterfaces := make(map[*diode.Interface]bool)

	// Route every Interface seen anywhere in the entity graph —
	// not just top-level ones. MapObjectIDsToEntity filters out
	// IP-assigned interfaces from top-level emission (mapping.go
	// ~line 716); without walking IP.AssignedObject + MAC.AssignedObject
	// here those interfaces would keep Device=master after rerouting.
	processIface := func(iface *diode.Interface) {
		if iface == nil || keptInterfaces[iface] || skippedInterfaces[iface] {
			return
		}
		owner := routeInterface(iface, ifIndexByIface, router, inv, memberByID, logger)
		if owner == -1 {
			skippedInterfaces[iface] = true
			return
		}
		if dev, ok := memberByID[owner]; ok {
			iface.Device = dev
		}
		keptInterfaces[iface] = true
	}
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Interface:
			processIface(v)
		case *diode.IPAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok {
				processIface(iface)
			}
		case *diode.MACAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok {
				processIface(iface)
			}
		}
	}

	// 5. Rebuild output partitioned by type so the deterministically
	//    sorted buckets stay deterministic even though `entities` came
	//    out of Go-map iteration upstream.
	//    Canonical order:
	//      master, VC, member_devices (sorted by VcPosition),
	//      interfaces (sorted by Name), IPs (sorted by Address),
	//      MACs (sorted by MacAddress), VLANs (sorted by Vid),
	//      then modules and any remaining entities, both in input
	//      order — these buckets are NOT actively sorted; their
	//      determinism depends on the caller passing a deterministic
	//      input slice.
	var (
		ifaces  []*diode.Interface
		ips     []*diode.IPAddress
		macs    []*diode.MACAddress
		vlans   []*diode.VLAN
		modules []*diode.Module
		others  []diode.Entity
	)
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			// Master handled separately; member Devices generated by
			// this function (never present in the input slice).
			continue
		case *diode.Interface:
			if keptInterfaces[v] {
				ifaces = append(ifaces, v)
			}
		case *diode.IPAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok {
				if skippedInterfaces[iface] {
					continue // orphan: drop IP whose interface was skipped
				}
			}
			ips = append(ips, v)
		case *diode.MACAddress:
			if iface, ok := v.AssignedObject.(*diode.Interface); ok {
				if skippedInterfaces[iface] {
					continue
				}
			}
			macs = append(macs, v)
		case *diode.VLAN:
			vlans = append(vlans, v)
		case *diode.Module:
			modules = append(modules, v)
		default:
			others = append(others, v)
		}
	}

	slices.SortFunc(ifaces, func(a, b *diode.Interface) int {
		return strings.Compare(strDeref(a.Name), strDeref(b.Name))
	})
	slices.SortFunc(ips, func(a, b *diode.IPAddress) int {
		return strings.Compare(strDeref(a.Address), strDeref(b.Address))
	})
	slices.SortFunc(macs, func(a, b *diode.MACAddress) int {
		return strings.Compare(strDeref(a.MacAddress), strDeref(b.MacAddress))
	})
	slices.SortFunc(vlans, func(a, b *diode.VLAN) int {
		ai := int64(0)
		bi := int64(0)
		if a.Vid != nil {
			ai = *a.Vid
		}
		if b.Vid != nil {
			bi = *b.Vid
		}
		return int(ai - bi)
	})

	out := make([]diode.Entity, 0,
		3+len(memberDevices)+len(ifaces)+len(ips)+len(macs)+len(vlans)+len(modules)+len(others))
	out = append(out, master)
	out = append(out, &diode.VirtualChassis{
		Name:   &vcName,
		Master: masterRef,
	})
	for _, d := range memberDevices {
		out = append(out, d)
	}
	for _, e := range ifaces {
		out = append(out, e)
	}
	for _, e := range ips {
		out = append(out, e)
	}
	for _, e := range macs {
		out = append(out, e)
	}
	for _, e := range vlans {
		out = append(out, e)
	}
	for _, e := range modules {
		out = append(out, e)
	}
	out = append(out, others...)
	return out
}

// routeInterface returns:
//   - the owning member id (>=0) when routing succeeded
//   - -1 when the resolved id was dropped during validation (caller skips)
//   - master.ID (lowest member id) when no signal yields a match —
//     route to master for LAGs, SVIs, loopbacks, mgmt ports.
//
// Precedence: entAliasMappingTable (when ifIndexByIface has an entry
// for this Interface) -> ParseMemberID(ifName) fallback.
func routeInterface(
	iface *diode.Interface,
	ifIndexByIface map[*diode.Interface]int,
	router *chassisRouter,
	inv ChassisInventory,
	memberByID map[int]*diode.Device,
	logger *slog.Logger,
) int {
	masterID := inv.Members[0].ID

	// Alias-table path runs FIRST and does not require iface.Name —
	// devices that report ports without ifDescr/ifName still need
	// member ownership when entAliasMappingTable is present.
	if ifIdx, ok := ifIndexByIface[iface]; ok && ifIdx > 0 {
		if id, found := router.routeIfIndex(ifIdx); found {
			ifName := ""
			if iface.Name != nil {
				ifName = *iface.Name
			}
			if _, dropped := inv.DroppedIDs[id]; dropped {
				logger.Warn("interface routed via alias table to a dropped member id; skipping",
					"ifName", ifName, "member_id", id)
				return -1
			}
			return id
		}
	}

	// ifName fallback requires iface.Name.
	if iface.Name == nil || *iface.Name == "" {
		return masterID
	}
	id, ok := ParseMemberID(*iface.Name)
	if !ok {
		return masterID
	}
	if _, dropped := inv.DroppedIDs[id]; dropped {
		logger.Warn("interface parsed to a dropped member id; skipping",
			"ifName", *iface.Name, "member_id", id)
		return -1
	}
	// Parsed id must correspond to an emitted member; else route to master.
	if _, isMember := memberByID[id]; !isMember {
		return masterID
	}
	return id
}
