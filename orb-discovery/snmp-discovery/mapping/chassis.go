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
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
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
// derived logical member id (see deriveMemberID); EntPhysicalIndex is
// the raw row index used for entAliasMappingTable chain walks.
// AssetTag is the trimmed entPhysicalAssetID value ("" when unset or not walked).
type ChassisMember struct {
	ID               int
	EntPhysicalIndex string
	Serial           string
	Model            string
	EntName          string
	ParentRelPos     int
	AssetTag         string
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
// Returns members sorted ascending by ID. Member id derivation uses
// the full 3-tier precedence in deriveMemberID (ParentRelPos > 0 →
// trailing-int parse of EntName → ordinal fallback).
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

	// Sort by entPhysicalIndex first so the ordinal fallback is
	// deterministic when neither parentRelPos nor entPhysicalName
	// provides an id signal.
	slices.SortFunc(members, func(a, b ChassisMember) int {
		ai, _ := strconv.Atoi(a.EntPhysicalIndex)
		bi, _ := strconv.Atoi(b.EntPhysicalIndex)
		return ai - bi
	})
	for i := range members {
		members[i].ID = deriveMemberID(members[i], i+1)
	}
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
// MUST carry every matcher field the rich master Device carries —
// divergence breaks the Diode plugin's matcher precedence cascade
// (asset_tag -> primary_ip4 -> primary_ip6 -> oob_ip -> name+site+tenant
// -> name+site -> rack+position+face -> virtual_chassis+vc_position)
// and creates ghost VCs.
//
// MUST NOT carry VirtualChassis (non-recursion — dodges the plugin's
// "Unable to resolve circular reference in entities" error) or
// VcPosition (would only feed matcher #8 which is unreachable behind
// the higher-precedence matchers above).
//
// primary_ip4/6 go through newIPMatchStub so AssignedObject is cleared,
// breaking the IP -> Interface -> Device cycle.
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
		PrimaryIp4: newIPMatchStub(master.PrimaryIp4),
		PrimaryIp6: newIPMatchStub(master.PrimaryIp6),
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

// trimSNMPString trims surrounding whitespace AND embedded NUL bytes
// from ENTITY-MIB DisplayString-like values. Many vendor agents pad
// short strings with trailing NUL bytes, which strings.TrimSpace leaves
// in place — a NUL-padded "FOC1234\x00" would otherwise compare unequal
// to "FOC1234" returned by another agent, breaking dedup and stable
// matching against NetBox on subsequent runs.
func trimSNMPString(s string) string {
	return strings.Trim(s, " \t\r\n\x00")
}

var trailingIntRe = regexp.MustCompile(`(\d+)\s*$`)

// deriveMemberID picks the logical member id with precedence:
//  1. ParentRelPos when > 0 (ENTITY-MIB standard signal)
//  2. Trailing integer in EntName ("Switch 1", "FPC 0", "Member 7")
//  3. ordinalFallback (the caller-supplied 1-based position after
//     sorting by entPhysicalIndex)
//
// ParentRelPos == 0 deliberately defers to (2)/(3): the column is
// often unpopulated and 0 is the "unknown / not in a relative
// position" sentinel per RFC 6933.
func deriveMemberID(m ChassisMember, ordinalFallback int) int {
	if m.ParentRelPos > 0 {
		return m.ParentRelPos
	}
	if match := trailingIntRe.FindString(m.EntName); match != "" {
		if id, err := strconv.Atoi(strings.TrimSpace(match)); err == nil {
			return id
		}
	}
	return ordinalFallback
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

// TranslateAsStack inspects the raw oids map for ENTITY-MIB chassis
// inventory. Three outcomes:
//
//   - 0 chassis rows with non-empty serial -> entities returned
//     unchanged (no Serial assignment possible).
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
