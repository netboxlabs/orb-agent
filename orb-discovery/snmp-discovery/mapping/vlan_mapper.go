package mapping

import (
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping/qbridge"
)

// OID prefixes for VlanMapper input.
const (
	oidDot1dBasePortIfIndex = ".1.3.6.1.2.1.17.1.4.1.2."
	oidDot1qPvid            = ".1.3.6.1.2.1.17.7.1.4.5.1.1."
	oidSysObjectIDScalar    = ".1.3.6.1.2.1.1.2.0"
	// juniperEnterprise is the sysObjectID prefix of the one vendor known to
	// publish Q-BRIDGE port lists as text by default.
	juniperEnterprise      = ".1.3.6.1.4.1.2636."
	oidDot1qVlanStaticName = ".1.3.6.1.2.1.17.7.1.4.3.1.1."
	// CISCO-VTP-MIB vtpVlanName. Cisco IOS and IOS-XE do not implement
	// dot1qVlanStaticName in the default SNMP context, so this is the only
	// place their VLAN database is readable. Indexed by
	// (managementDomainIndex, vlanIndex), so the VID is the LAST element.
	oidCiscoVtpVlanName = ".1.3.6.1.4.1.9.9.46.1.3.1.1.4."
	// dot1qVlanCurrentTable, the VLANs the device is actually running. Same
	// per-VLAN masks the static table carries, but INDEX { dot1qVlanTimeMark,
	// dot1qVlanIndex }, so the VLAN id is the LAST index element.
	oidDot1qVlanCurrentEgressPorts   = ".1.3.6.1.2.1.17.7.1.4.2.1.4."
	oidDot1qVlanCurrentUntaggedPorts = ".1.3.6.1.2.1.17.7.1.4.2.1.5."
	oidDot1qVlanStaticEgressPorts    = ".1.3.6.1.2.1.17.7.1.4.3.1.2."
	oidDot1qVlanStaticUntaggedPorts  = ".1.3.6.1.2.1.17.7.1.4.3.1.4."
	oidDot1qVlanStaticRowStatus      = ".1.3.6.1.2.1.17.7.1.4.3.1.5."
	oidIfAdminStatus                 = ".1.3.6.1.2.1.2.2.1.7."
	oidIfType                        = ".1.3.6.1.2.1.2.2.1.3."
	// ifDescr / ifName, consulted by ResolveSviVlans (svi_vlan.go). Both are
	// already walked for the interface-name resolver; SVI resolution reuses
	// them rather than requiring a separate walk.
	oidIfDescr = ".1.3.6.1.2.1.2.2.1.2."
	oidIfName  = ".1.3.6.1.2.1.31.1.1.1.1."
	// Cisco overlay
	oidCiscoVMVlan        = ".1.3.6.1.4.1.9.9.68.1.2.2.1.2."
	oidCiscoVMVoiceVlanID = ".1.3.6.1.4.1.9.9.68.1.5.1.1."
	// CISCOSB overlay (Cisco small-business: Catalyst 1200/1300, CBS/SG).
	// Both are indexed by ifIndex, not by bridge port.
	oidCiscoSBTrunkNativeVlan = ".1.3.6.1.4.1.9.6.1.101.48.61.1.1."
	oidCiscoSBAccessVlan      = ".1.3.6.1.4.1.9.6.1.101.48.62.1.1."
)

// ifTypeNumericToString maps a small subset of IANAifType numeric values
// to the strings qbridge.isL3Capable understands.
//
// IANAifType correspondences (RFC 2863 / IANA registry):
//
//	6   ethernetCsmacd  — standard Ethernet / Fast Ethernet
//	62  fastEther       — 100Base-TX (distinct from ethernetCsmacd on older gear)
//	117 gigabitEthernet — 1000Base-X / GbE interfaces
//	161 ieee8023adLag   — 802.3ad link aggregation group (LAG / LACP)
var ifTypeNumericToString = map[int]string{
	6:   "ethernetCsmacd",
	62:  "fastEther",
	117: "gigabitEthernet",
	161: "ieee8023adLag",
}

// VlanMapper bridges Q-BRIDGE / Cisco-overlay SNMP rows to diode.VLAN
// emission and *diode.Interface mutation. It is a postPassMapper:
// VlanMapper.Map is a no-op stub; the real work happens in PostMap.
type VlanMapper struct {
	logger  *slog.Logger
	options config.Options
}

// NewVlanMapper constructs a VlanMapper with the given policy options.
func NewVlanMapper(logger *slog.Logger, options config.Options) *VlanMapper {
	return &VlanMapper{logger: logger, options: options}
}

// Map is the row-scoped no-op required by the orbToEntityMapper interface.
func (m *VlanMapper) Map(
	_ map[ObjectIDIndex]*ObjectIDValue,
	_ *Entry,
	_ *EntityRegistry,
	_ *config.Defaults,
) diode.Entity {
	return nil
}

// PostMap performs the host-level VLAN classification pass.
func (m *VlanMapper) PostMap(
	allObjectIDs ObjectIDValueMap,
	registry *EntityRegistry,
	defaults *config.Defaults,
) []diode.Entity {
	// The walked rows arrive already normalised: the runner calls
	// ResolveJuniperVlanIndices once, before any consumer reads them, so a
	// Junos device that indexes dot1qVlanStaticTable internally reaches every
	// reader below keyed by the real 802.1Q tag. Normalising again here would
	// log the same refusal twice per target, and the map is shared with the
	// SVI resolver, which has to see the same keying this mapper does.
	gen := m.buildGenericRows(allObjectIDs)
	if len(gen.BasePortToIfIndex) == 0 {
		// No bridge port table — refuse Interface mutation. Still emit
		// VLAN entities below from the static table; they don't need
		// per-port translation.
		//
		// Log level depends on whether the device looks like it should
		// have had VLAN data: if any Q-BRIDGE / Cisco-overlay rows are
		// present, the missing bridge table is a real partial-data
		// condition (warn). Otherwise this is a routine non-switch
		// target (router, WLC, host, …) and the message is just noise
		// at debug.
		//
		// A vendor whose private VLAN table carries its own port
		// membership and its own way of naming ports (see
		// vendorTaggedMembership) does not need the bridge table, and
		// is applied here instead.
		vlanEntities := m.emitVLANs(allObjectIDs, defaults)
		if membership := vendorTaggedMembership(allObjectIDs, m.logger); len(membership) > 0 {
			ensureVLAN := m.vlanIndex(&vlanEntities, defaults)
			classifications := make(map[int]qbridge.Classification, len(membership))
			for ifIndex, vids := range membership {
				classifications[ifIndex] = qbridge.Classification{Mode: qbridge.ModeTrunk, Tagged: vids}
			}
			m.applyClassifications(registry, classifications, walkedIfTypes(allObjectIDs), ensureVLAN)
			return vlanEntities
		}
		if hasVLANSignal(allObjectIDs) {
			m.logger.Warn("vlan: missing dot1dBasePortIfIndex; skipping interface mutations",
				"reason", "bridge-port-translation-unavailable")
		} else {
			m.logger.Debug("vlan: no bridge port table and no VLAN OIDs walked; nothing to do",
				"reason", "non-switch-target")
		}
		return vlanEntities
	}

	infos, err := qbridge.ExtractGeneric(gen)
	if err != nil {
		m.logger.Warn("vlan: ExtractGeneric failed", "error", err)
		return m.emitVLANs(allObjectIDs, defaults)
	}
	cisco := m.buildCiscoRows(allObjectIDs)
	// Defense in depth: ApplyCisco is a no-op when both Cisco-overlay maps
	// are empty (the runner only walks vendor-scoped OIDs on a Cisco-matched
	// host, so on generic-only hosts we never reach this branch's payload).
	// Skip the call entirely when there's nothing to apply, both for clarity
	// and to keep the no-op explicit.
	if len(cisco.MembershipAccessVlan) > 0 || len(cisco.VoiceVlanByIfIndex) > 0 {
		qbridge.ApplyCisco(infos, cisco)
	}
	// CISCOSB last: on those switches dot1qPvid is actively wrong rather than
	// absent (it answers 1 on every port), so the private columns have to be
	// able to overrule whatever the generic pass and the IOS overlay concluded.
	// The two overlays never both answer in practice, since a device populates
	// either the IOS vmMembership table or the CISCOSB one.
	if ciscosb := m.buildCiscoSBRows(allObjectIDs); ciscosb.HasData() {
		qbridge.ApplyCiscoSB(infos, ciscosb)
	}

	// Build VLAN entities first — interface refs link to them by VID.
	vlanEntities := m.emitVLANs(allObjectIDs, defaults)
	ensureVLAN := m.vlanIndex(&vlanEntities, defaults)

	// Mutate interfaces in place. The registry holds *diode.Interface
	// instances InterfaceMapper produced; we look them up by ifIndex
	// using string-form ifIndex as ObjectIDIndex.
	classifications := make(map[int]qbridge.Classification, len(infos))
	for ifIndex, info := range infos {
		classifications[ifIndex] = qbridge.Classify(*info)
	}
	m.applyClassifications(registry, classifications, walkedIfTypes(allObjectIDs), ensureVLAN)
	return vlanEntities
}

// vlanIndex indexes the emitted VLAN entities by VID and returns the
// ensureVLAN lookup interface mutation uses.
//
// ensureVLAN returns the *diode.VLAN for vid, creating a stub when:
//   - no static-name entry exists for vid, AND
//   - options.CreateUnknownVlans is true.
//
// This mirrors device-discovery PR #378's translate._ensure_vlan behavior:
// classic Cisco IOS exposes vmVlan/dot1qPvid VIDs without advertising them
// via dot1qVlanStaticName, so ports classify as access but the index is
// empty — the stub ensures NetBox never receives mode=access with a nil
// untagged_vlan reference. Stubs are appended to *vlanEntities so the
// caller's returned slice carries them.
func (m *VlanMapper) vlanIndex(vlanEntities *[]diode.Entity, defaults *config.Defaults) func(int) *diode.VLAN {
	vlanByVid := make(map[int]*diode.VLAN, len(*vlanEntities))
	for _, e := range *vlanEntities {
		v, ok := e.(*diode.VLAN)
		if !ok || v.Vid == nil {
			continue
		}
		vlanByVid[int(*v.Vid)] = v
	}
	return func(vid int) *diode.VLAN {
		if existing, ok := vlanByVid[vid]; ok {
			return existing
		}
		createUnknown := m.options.CreateUnknownVlans == nil || *m.options.CreateUnknownVlans
		if !createUnknown {
			return nil
		}
		stub := &diode.VLAN{
			Vid:  int64Ptr(int64(vid)),
			Name: StringPtr("VLAN" + strconv.Itoa(vid)),
		}
		applyVLANDefaults(stub, defaults)
		vlanByVid[vid] = stub
		*vlanEntities = append(*vlanEntities, stub)
		return stub
	}
}

// verifiedInterface returns the walked *diode.Interface for ifIndex, or
// nil. Placeholder interfaces fabricated by GetOrCreateEntity for
// ipAddressIfIndex references that no interface PDUs ever populated are
// skipped: mutating those would leak VLAN/mode fields into nested
// IPAddress.AssignedObject payloads and ingest incomplete interface data.
func verifiedInterface(registry *EntityRegistry, ifIndex int) *diode.Interface {
	raw := registry.GetEntity(InterfaceEntityType, ObjectIDIndex(strconv.Itoa(ifIndex)))
	iface, ok := raw.(*diode.Interface)
	if !ok || iface == nil || !registry.IsInterfaceVerified(iface) {
		return nil
	}
	return iface
}

// applyClassification mutates iface to carry the classified VLAN refs.
// Modes ModeRouted and ModeUnknown are no-ops (matches PR #378).
// ensureVLAN is called for every referenced VID; it may return nil when
// options.CreateUnknownVlans is false and the VID has no static name entry.
func applyClassification(iface *diode.Interface, c qbridge.Classification, ensureVLAN func(int) *diode.VLAN) {
	mode := classificationToNetboxMode(c.Mode)
	if mode == "" {
		return
	}
	iface.Mode = StringPtr(mode)
	if c.Untagged != nil {
		if v := ensureVLAN(*c.Untagged); v != nil {
			iface.UntaggedVlan = v
		}
	}
	if len(c.Tagged) > 0 {
		tagged := make([]*diode.VLAN, 0, len(c.Tagged))
		for _, vid := range c.Tagged {
			if v := ensureVLAN(vid); v != nil {
				tagged = append(tagged, v)
			}
		}
		if len(tagged) > 0 {
			iface.TaggedVlans = tagged
		}
	}
}

func classificationToNetboxMode(m qbridge.Mode) string {
	switch m {
	case qbridge.ModeAccess:
		return "access"
	case qbridge.ModeTrunk:
		return "tagged"
	case qbridge.ModeTrunkAll:
		return "tagged-all"
	}
	return ""
}

// applyVLANDefaults applies the defaults.VLAN fields (Description, Tags,
// Tenant, Group, Status) to v. Status is only written when
// defaults.VLAN.Status is explicitly set; callers that already derived
// a status from dot1qVlanStaticRowStatus rely on that earlier write
// taking precedence (emitVLANs sets v.Status from row status before
// reaching this helper for named VLANs; stubs from ensureVLAN have no
// row status and pick up defaults.VLAN.Status here when configured).
// Tags merge defaults.VLAN.Tags + top-level defaults.Tags, mirroring
// the IPAddress/Interface/Device mapper convention.
func applyVLANDefaults(v *diode.VLAN, defaults *config.Defaults) {
	if defaults == nil {
		return
	}
	vd := defaults.VLAN
	if vd.Description != "" {
		v.Description = StringPtr(vd.Description)
	}

	// Collect tags from both entity-specific (defaults.VLAN.Tags) and
	// top-level (defaults.Tags) defaults — mirrors the pattern used by
	// IPAddressMapper, InterfaceMapper, and DeviceMapper (mappers.go).
	var tags []*diode.Tag
	for _, t := range vd.Tags {
		t := t // capture loop variable
		tags = append(tags, &diode.Tag{Name: &t})
	}
	for _, t := range defaults.Tags {
		t := t // capture loop variable
		tags = append(tags, &diode.Tag{Name: &t})
	}
	if len(tags) > 0 {
		v.Tags = tags
	}

	if vd.Tenant != "" {
		v.Tenant = &diode.Tenant{Name: StringPtr(vd.Tenant)}
	}
	if vd.Group.Name != "" {
		name := vd.Group.Name
		group := &diode.VLANGroup{Name: &name, Slug: toSlug(&name)}
		setVLANGroupScope(group, vd.Group, defaults.Site)
		v.Group = group
	}
	if vd.Status != "" {
		v.Status = StringPtr(vd.Status)
	}
}

// setVLANGroupScope attaches the configured scope to a VLAN group. An
// explicit scope_* wins; otherwise defaults.site applies, so the string
// form of vlan.group keeps its site scope. NetBox Locations are unique
// within their site, so a Location scope carries defaults.site when set.
func setVLANGroupScope(group *diode.VLANGroup, g config.VLANGroupParameters, defaultSite string) {
	switch {
	case g.ScopeSiteGroup != "":
		group.Scope = &diode.SiteGroup{Name: StringPtr(g.ScopeSiteGroup)}
	case g.ScopeRegion != "":
		group.Scope = &diode.Region{Name: StringPtr(g.ScopeRegion)}
	case g.ScopeLocation != "":
		loc := &diode.Location{Name: StringPtr(g.ScopeLocation)}
		if defaultSite != "" {
			loc.Site = &diode.Site{Name: StringPtr(defaultSite)}
		}
		group.Scope = loc
	case g.ScopeSite != "":
		group.Scope = &diode.Site{Name: StringPtr(g.ScopeSite)}
	case defaultSite != "":
		group.Scope = &diode.Site{Name: StringPtr(defaultSite)}
	}
}

// recordRow stores one dot1qVlanCurrentTable row under its VLAN and time mark.
func recordRow(rows map[int]map[int]string, vid, mark int, mask string) {
	byMark := rows[vid]
	if byMark == nil {
		byMark = map[int]string{}
		rows[vid] = byMark
	}
	byMark[mark] = mask
}

// allCurrentVlans is every VLAN either column mentions.
func allCurrentVlans(egress, untagged map[int]map[int]string) map[int]struct{} {
	out := make(map[int]struct{}, len(egress)+len(untagged))
	for vid := range egress {
		out[vid] = struct{}{}
	}
	for vid := range untagged {
		out[vid] = struct{}{}
	}
	return out
}

// oneSnapshot picks the egress and untagged masks of one VLAN from the SAME
// moment in time.
//
// dot1qVlanCurrentTable is INDEX { dot1qVlanTimeMark, dot1qVlanIndex }, and a
// TimeFilter index means the same VLAN is answered once per time mark the agent
// still holds — with different masks, since a mark is when that row last
// changed. Taking whichever the walk map yielded last made membership depend on
// Go's map iteration order, so a switch answering VLAN 1 under two marks
// alternated between two NetBox states on every poll. Observed on recorded
// walks from three vendors. This is the same collect-then-resolve the VLAN name
// and VTP readers use, and for the same reason.
//
// The two columns are walked separately, so a VLAN that changes between the two
// walks answers one column before the change and the other after. Taking each
// column's own latest row would then combine halves of two different snapshots
// and report a port as tagged where it is untagged, or the reverse, until the
// next poll.
//
// The newest mark both columns share is therefore preferred. Where they share
// none — a VLAN only one column mentions, or an agent that has already aged one
// of them out — each column's own newest is used, which is the best available
// and no worse than not reading the table at all.
func oneSnapshot(egress, untagged map[int]string) (string, string) {
	if egress == nil || untagged == nil {
		return newestMask(egress), newestMask(untagged)
	}
	shared := make([]int, 0, len(egress))
	for mark := range egress {
		if _, ok := untagged[mark]; ok {
			shared = append(shared, mark)
		}
	}
	common, found := newestMark(shared)
	if !found {
		// Both columns answered and no mark is common to them. Taking each
		// one's newest is the very pairing this function exists to prevent,
		// just narrower: the masks would come from two moments, and the port
		// would be published tagged where it is untagged or the reverse. There
		// is no snapshot here, so the VLAN contributes none; the caller drops
		// it. Losing a VLAN is recoverable at the next poll, a wrong tagging
		// mode written over NetBox is not.
		return "", ""
	}
	return egress[common], untagged[common]
}

// newestMask returns the mask under the newest time mark in one column.
func newestMask(byMark map[int]string) string {
	marks := make([]int, 0, len(byMark))
	for mark := range byMark {
		marks = append(marks, mark)
	}
	newest, found := newestMark(marks)
	if !found {
		return ""
	}
	return byMark[newest]
}

// newestMark folds markIsNewer over a set of time marks.
//
// The marks are sorted first. markIsNewer is a wrap-aware comparison, not an
// ordering: three marks spread more than half the space apart are each "newer"
// than the next, so folding over them in the order a Go map happens to yield
// picks a different winner from run to run. Sorting makes the answer the same
// every poll, which is the whole point of resolving a snapshot at all. A device
// holding marks that far apart would have to keep a row for months; the sort
// costs nothing on the handful of marks a real agent retains.
func newestMark(marks []int) (int, bool) {
	if len(marks) == 0 {
		return 0, false
	}
	sort.Ints(marks)
	newest := marks[0]
	for _, mark := range marks[1:] {
		if markIsNewer(mark, newest) {
			newest = mark
		}
	}
	return newest, true
}

// isEmptyPortMask reports whether a port list names no port: a PortList bitmap
// of zero bytes, or no value at all.
//
// Tested on the bytes, not on how they would read as text. A bitmap byte can
// be any value, and several of the low ones are printable: 0x20 is the ASCII
// space and sets port 3, 0x30 is "0" and sets ports 3 and 4. Treating those as
// empty would discard real membership, which is what this guard exists to
// avoid doing.
//
// A Junos text list of "0" is therefore read as naming a port here. That errs
// toward merging a row rather than dropping one, which is the safe direction,
// and the combination is unobserved: no Junos device is known to publish this
// table at all.
func isEmptyPortMask(mask string) bool {
	for i := 0; i < len(mask); i++ {
		if mask[i] != 0 {
			return false
		}
	}
	return true
}

// timeMarkWrap is where dot1qVlanTimeMark restarts. It is a TimeFilter over
// TimeTicks, hundredths of a second since the agent came up, so it wraps after
// a little under 497 days of uptime.
const timeMarkWrap = 1 << 32

// markIsNewer compares two time marks allowing for that wrap.
//
// A plain comparison is wrong on a switch up long enough to have wrapped: a row
// changed just before the wrap holds a mark near the ceiling while one changed
// just after holds a small one, so the larger number is the older row and
// membership would revert to a stale snapshot whenever two rows straddle it.
//
// Compared the way serial numbers are (RFC 1982): a is newer when the forward
// distance to it is less than half the space. That is exact for marks closer
// together than half the wrap, which is any pair a device could plausibly hold
// — the agent keeps snapshots for minutes, not months — and degrades to plain
// magnitude for everything else.
func markIsNewer(a, b int) bool {
	if a == b {
		return false
	}
	forward := (a - b) % timeMarkWrap
	if forward < 0 {
		forward += timeMarkWrap
	}
	return forward < timeMarkWrap/2
}

// currentVlanRow reads the VLAN id and time mark out of a
// dot1qVlanCurrentTable OID.
//
// The table is INDEX { dot1qVlanTimeMark, dot1qVlanIndex }, so the suffix is
// two elements and the id is the second. Taking the first, as the static
// table's single-element suffix allows, would read every row as the time mark
// — usually 0, which is not a VLAN, so every row would be discarded.
func currentVlanRow(oid, prefix string) (vid, mark int, ok bool) {
	suffix := strings.TrimPrefix(oid, prefix)
	dot := strings.IndexByte(suffix, '.')
	if dot < 0 {
		return 0, 0, false
	}
	mark, okMark := atoi(suffix[:dot])
	vid, okVid := atoi(suffix[dot+1:])
	if !okMark || !okVid {
		return 0, 0, false
	}
	return vid, mark, true
}

// vlanCatalogPresent reports whether this device named a VLAN of its own.
//
// The sources are every place the walk could learn a VLAN identity from: the
// static table's names, row statuses and membership masks, the current table's
// membership masks, the Cisco VTP catalog, the Huawei catalog and the Juniper
// enterprise table's names.
//
// dot1qPvid is deliberately not among them. Whether a PVID means anything is
// the question this answers, so counting it would make every device its own
// corroboration.
//
// The current table counts because a device publishing it has told us which
// VLANs it is running and which ports are in them — more than the static table
// gives on some switches. Such a device is normally classified from that
// membership and never reaches the default-PVID question.
//
// A row only counts when something usable can be read out of it. Every source
// but one is keyed by a VLAN id, so the row is evidence only if that id names a
// VLAN NetBox could hold: a table answering nothing but an out-of-range index,
// or a suffix that will not parse, has named no VLAN however many rows it has,
// and letting it pass would bypass the refusal and hand those ports back the
// access VLAN 1 it exists to withhold.
//
// The exception is the Juniper enterprise table, whose suffix is the device's
// internal index rather than a VLAN id. There the name itself is the evidence.
//
// Read from the walked OIDs rather than from what the merge kept, so a static
// row naming a VLAN counts even where no port is in it: the VLAN is in the
// device's database whether or not anything is using it today. The current
// table's two columns are the exception, being masks rather than names, and one
// naming no port is not read as a catalog entry.
// vlanCatalogSource is one place a VLAN identity can be read from, with the
// shape of the index its rows carry.
type vlanCatalogSource struct {
	prefix string
	// elements the index must have. The VLAN id is the last of them: the
	// VLAN-keyed tables carry one, the VTP catalog's (domain, vlan) and the
	// current table's (timeMark, vlan) carry two.
	elements int
	// maskRow says the value is a port mask rather than a name or a status.
	maskRow bool
}

var vlanCatalogSources = []vlanCatalogSource{
	{prefix: oidDot1qVlanStaticName, elements: 1},
	{prefix: oidDot1qVlanStaticRowStatus, elements: 1},
	{prefix: oidDot1qVlanStaticEgressPorts, elements: 1},
	{prefix: oidDot1qVlanStaticUntaggedPorts, elements: 1},
	// The Huawei catalog is a VLAN catalog like any other: a device publishing
	// it has named VLANs of its own, whether or not it answers Q-BRIDGE at all.
	{prefix: oidHwVlanIndex, elements: 1},
	{prefix: oidHwVlanName, elements: 1},
	{prefix: oidHwVlanRowStatus, elements: 1},
	{prefix: oidCiscoVtpVlanName, elements: 2},
}

// The current table is deliberately absent from that list. Unlike every other
// source its rows are masks rather than names or row statuses, so whether one
// names a VLAN depends on which snapshot is read, and it is answered in
// buildGenericRows from the snapshot the merge resolved rather than from the
// rows as walked.

func vlanCatalogPresent(all ObjectIDValueMap) bool {
	for oid, v := range all {
		// The Juniper enterprise table is keyed by the device's internal index
		// rather than a VLAN id, so there the name itself is the evidence.
		if strings.HasPrefix(oid, oidJnxExVlanName) {
			if trimSNMPString(v.Value) != "" {
				return true
			}
			continue
		}
		for _, src := range vlanCatalogSources {
			if !strings.HasPrefix(oid, src.prefix) {
				continue
			}
			if !namesAVlanAt(strings.TrimPrefix(oid, src.prefix), src.elements) {
				break
			}
			if src.maskRow && isEmptyPortMask(v.Value) {
				break
			}
			return true
		}
	}
	return false
}

// namesAVlanAt reports whether an OID suffix is an index of exactly the
// expected shape whose last element is a VLAN id NetBox could hold.
//
// The arity is checked, not just the last element. A suffix with one component
// too many is a row the readers reject — currentVlanRow will not parse
// "0.10.1" — and reading a VLAN id off the end of it would count as a catalog
// a row from which nothing can be derived, waiving the default-PVID refusal on
// the strength of a malformed OID.
func namesAVlanAt(suffix string, elements int) bool {
	parts := strings.Split(suffix, ".")
	if len(parts) != elements {
		return false
	}
	return namesAVlan(parts[elements-1])
}

// namesAVlan reports whether an OID suffix element is a VLAN id NetBox could
// hold, using the same range the rest of the package does.
func namesAVlan(element string) bool {
	vid, ok := atoi(element)
	return ok && qbridge.CoerceVid(vid) != nil
}

// buildGenericRows extracts Q-BRIDGE + BRIDGE-MIB rows from the host's
// flat ObjectIDValueMap.
func (m *VlanMapper) buildGenericRows(all ObjectIDValueMap) qbridge.GenericRows {
	rows := qbridge.GenericRows{
		BasePortToIfIndex: map[int]int{},
		PortPvid:          map[int]int{},
		VlanEgressPorts:   map[int][]byte{},
		VlanUntaggedPorts: map[int][]byte{},
		IfAdminStatus:     map[int]int{},
		IfTypes:           map[int]string{},

		VlanEgressFromCurrent:   map[int]struct{}{},
		VlanUntaggedFromCurrent: map[int]struct{}{},
	}
	// dot1qPortVlanTable is INDEX { dot1dBasePort } per RFC 4363, so the OID
	// suffix is a bridge port number, NOT an ifIndex. Collect raw bridge-port-
	// keyed PVIDs first; translate to ifIndex after the loop once
	// BasePortToIfIndex is fully populated.
	bridgePortPvid := map[int]int{}
	currentEgress, currentUntagged := map[int]map[int]string{}, map[int]map[int]string{}
	for oid, v := range all {
		switch {
		case strings.HasPrefix(oid, oidDot1dBasePortIfIndex):
			bp, ok1 := atoi(strings.TrimPrefix(oid, oidDot1dBasePortIfIndex))
			ifx, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				rows.BasePortToIfIndex[bp] = ifx
			}
		case strings.HasPrefix(oid, oidDot1qPvid):
			bp, ok1 := atoi(strings.TrimPrefix(oid, oidDot1qPvid))
			vid, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				bridgePortPvid[bp] = vid
			}
		case strings.HasPrefix(oid, oidDot1qVlanStaticEgressPorts):
			vid, ok := atoi(strings.TrimPrefix(oid, oidDot1qVlanStaticEgressPorts))
			if ok {
				rows.VlanEgressPorts[vid] = []byte(v.Value)
			}
		case strings.HasPrefix(oid, oidDot1qVlanStaticUntaggedPorts):
			vid, ok := atoi(strings.TrimPrefix(oid, oidDot1qVlanStaticUntaggedPorts))
			if ok {
				rows.VlanUntaggedPorts[vid] = []byte(v.Value)
			}
		case strings.HasPrefix(oid, oidDot1qVlanCurrentEgressPorts):
			if vid, mark, ok := currentVlanRow(oid, oidDot1qVlanCurrentEgressPorts); ok {
				recordRow(currentEgress, vid, mark, v.Value)
			}
		case strings.HasPrefix(oid, oidDot1qVlanCurrentUntaggedPorts):
			if vid, mark, ok := currentVlanRow(oid, oidDot1qVlanCurrentUntaggedPorts); ok {
				recordRow(currentUntagged, vid, mark, v.Value)
			}
		case strings.HasPrefix(oid, oidIfAdminStatus):
			ifx, ok1 := atoi(strings.TrimPrefix(oid, oidIfAdminStatus))
			s, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				rows.IfAdminStatus[ifx] = s
			}
		case strings.HasPrefix(oid, oidIfType):
			ifx, ok1 := atoi(strings.TrimPrefix(oid, oidIfType))
			n, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				if name, found := ifTypeNumericToString[n]; found {
					rows.IfTypes[ifx] = name
				}
			}
		}
	}
	// Translate bridge-port-keyed PVIDs to ifIndex using the now-complete map.
	for bp, vid := range bridgePortPvid {
		if ifx, ok := rows.BasePortToIfIndex[bp]; ok {
			rows.PortPvid[ifx] = vid
		}
	}
	rows.TextPortLists = isJuniper(all)

	// The static table is the configured intent and wins wherever it speaks.
	// The current table fills VLANs it never mentions, which is the case this
	// exists for: a switch can run a VLAN, and place ports in it untagged,
	// while listing neither in dot1qVlanStaticTable nor in dot1qPvid. Merged
	// per VLAN rather than per table, so a device whose static table covers
	// some VLANs and whose current table covers others is read from both.
	//
	// A VLAN the current table mentions but places nobody in is skipped: such
	// a row is not membership.
	//
	// It was added because the extractor read the mere presence of an untagged
	// row for a port's PVID as "the device publishes one for that VLAN and left
	// this port out", withdrawing the PVID; a ProCurve publishing six all-zero
	// VLANs beside 23 ports with real PVIDs lost every one of them. Every
	// consumer of a merged row now gates on provenance instead, so removing
	// this skip changes no port on any recorded walk. It stays for what it
	// costs: two of them publish all 4094 VLANs empty, and merging those means
	// carrying 4094 masks and scanning them once per port, for rows that say
	// nothing.
	currentNamedAVlan := false
	for vid := range allCurrentVlans(currentEgress, currentUntagged) {
		egress, untagged := oneSnapshot(currentEgress[vid], currentUntagged[vid])
		if isEmptyPortMask(egress) && isEmptyPortMask(untagged) {
			continue
		}
		if _, ok := rows.VlanEgressPorts[vid]; !ok && currentEgress[vid] != nil {
			rows.VlanEgressPorts[vid] = []byte(egress)
			rows.VlanEgressFromCurrent[vid] = struct{}{}
		}
		if _, ok := rows.VlanUntaggedPorts[vid]; !ok && currentUntagged[vid] != nil {
			rows.VlanUntaggedPorts[vid] = []byte(untagged)
			rows.VlanUntaggedFromCurrent[vid] = struct{}{}
		}
		// This VLAN survived resolution with a port in it, which is what makes
		// it evidence the device has VLANs of its own. Judged here rather than
		// over the walked rows so the answer is the snapshot that was actually
		// used: a VLAN whose newest snapshot is empty is dropped above, and a
		// stale non-empty row from an older mark must not go on licensing the
		// default PVID after every port has left the VLAN.
		//
		// Still only for an id NetBox could hold. RFC 4363 lets this table be
		// keyed by an internal identifier, and a row under one names no VLAN
		// however many ports are in it.
		if qbridge.CoerceVid(vid) != nil {
			currentNamedAVlan = true
		}
	}

	// An untagged member is an egress member: RFC 4363 defines the untagged
	// ports as those that transmit this VLAN's egress packets untagged, so
	// they are a subset. membershipFromMasks walks the egress map and only
	// consults untagged masks for VIDs it finds there, so a VLAN whose egress
	// column is unsupported or whose separate walk was truncated would have
	// its untagged membership ignored entirely.
	for vid, mask := range rows.VlanUntaggedPorts {
		if _, ok := rows.VlanEgressPorts[vid]; ok {
			continue
		}
		rows.VlanEgressPorts[vid] = mask
		if _, ok := rows.VlanUntaggedFromCurrent[vid]; ok {
			rows.VlanEgressFromCurrent[vid] = struct{}{}
		}
	}

	rows.VlanCatalogPresent = vlanCatalogPresent(all) || currentNamedAVlan
	return rows
}

// buildCiscoSBRows extracts the CISCOSB private-MIB per-port VLAN columns,
// keyed by ifIndex.
func (m *VlanMapper) buildCiscoSBRows(all ObjectIDValueMap) qbridge.CiscoSBRows {
	rows := qbridge.CiscoSBRows{
		AccessVlan: map[int]int{},
		NativeVlan: map[int]int{},
	}
	for oid, v := range all {
		switch {
		case strings.HasPrefix(oid, oidCiscoSBAccessVlan):
			ifx, ok1 := atoi(strings.TrimPrefix(oid, oidCiscoSBAccessVlan))
			vid, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				rows.AccessVlan[ifx] = vid
			}
		case strings.HasPrefix(oid, oidCiscoSBTrunkNativeVlan):
			ifx, ok1 := atoi(strings.TrimPrefix(oid, oidCiscoSBTrunkNativeVlan))
			vid, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				rows.NativeVlan[ifx] = vid
			}
		}
	}
	return rows
}

// buildCiscoRows extracts Cisco overlay rows.
func (m *VlanMapper) buildCiscoRows(all ObjectIDValueMap) qbridge.CiscoRows {
	rows := qbridge.CiscoRows{
		MembershipAccessVlan: map[int]int{},
		VoiceVlanByIfIndex:   map[int]int{},
	}
	for oid, v := range all {
		switch {
		case strings.HasPrefix(oid, oidCiscoVMVlan):
			ifx, ok1 := atoi(strings.TrimPrefix(oid, oidCiscoVMVlan))
			vid, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				rows.MembershipAccessVlan[ifx] = vid
			}
		case strings.HasPrefix(oid, oidCiscoVMVoiceVlanID):
			ifx, ok1 := atoi(strings.TrimPrefix(oid, oidCiscoVMVoiceVlanID))
			vid, ok2 := atoi(v.Value)
			if ok1 && ok2 {
				rows.VoiceVlanByIfIndex[ifx] = vid
			}
		}
	}
	return rows
}

// vlanNameRow is one VLAN-name PDU: the OID it arrived on plus its raw
// value. Collecting rows before resolving them is what keeps the outcome
// independent of Go's map iteration order — see mergeVLANNames.
type vlanNameRow struct {
	oid   string
	value string
}

// vlanNamesByVid returns the VLAN names the DEVICE reported, keyed by VID.
// It is a pure read of the walked OIDs: it never stubs, and never invents
// a name.
//
// A VID present with an empty name had a name row whose value was empty
// (or NUL padding). Callers that require a device-supplied name must treat
// that as no name at all; emitVLANs is the one caller that instead applies
// its VLAN<vid> default.
func vlanNamesByVid(all ObjectIDValueMap) map[int]string {
	var rows []vlanNameRow
	for oid, v := range all {
		if strings.HasPrefix(oid, oidDot1qVlanStaticName) ||
			strings.HasPrefix(oid, oidCiscoVtpVlanName) {
			rows = append(rows, vlanNameRow{oid: oid, value: v.Value})
		}
	}
	names := mergeVLANNames(rows, vendorVlanCatalog(all).Names)
	if !isJuniper(all) || !everyNameCarriesItsTagSuffix(names) {
		return names
	}
	// Junos ELS reports a bridge domain as "<name>+<tag>", so the VLAN an
	// operator calls VL156 arrives as VL156+156. Scoped to Juniper because a
	// plus and a number in another vendor's name is just a name.
	for vid, name := range names {
		names[vid] = stripVlanNameTagSuffix(name, vid)
	}
	return names
}

// everyNameCarriesItsTagSuffix reports whether EVERY named VLAN on the device
// ends in "+<its own id>".
//
// Stripping renames VLANs in NetBox, which Diode PATCHes over whatever the
// operator has there, so it needs evidence rather than plausibility — the same
// bar the index rekey is held to. A device convention is uniform: the switch
// that decorates one bridge domain decorates all of them. Operator naming is
// not, so a single VLAN an operator happened to call "site+100" no longer
// makes the agent shorten it, and no longer drags every other VLAN on that
// switch through a rename with it.
//
// One conforming name is enough, and requiring two was worse. The count can
// only ever include names short enough to read, so on a switch whose names
// mostly run past the column bound it is a count of the few short ones — and a
// hard threshold sitting in a small number flaps: deleting one short-named VLAN
// pushed an eleven-VLAN switch below it and renamed a DIFFERENT VLAN on the
// next ingest, then renamed it back. A rename of operator data that recurs is
// worse than the case the threshold guarded, which is a device holding exactly
// one readable conforming name and nothing contradicting it.
//
// The discriminating work is done by the veto above, not by the count: any
// readable name WITHOUT the suffix means the device has no such convention.
// The count only establishes that something was actually observed.
//
// Measured: on the reported ELS switch 5 of 5 names carry the suffix, and on
// the pre-ELS switch 0 of 39 do. Neither is a borderline case.
func everyNameCarriesItsTagSuffix(names map[int]string) bool {
	named := 0
	for vid, name := range names {
		// No name is evidence of nothing.
		if name == "" {
			continue
		}
		// Whether the name CARRIES the suffix is asked first, and length never
		// overrides it. A suffix that is still visible cannot have been cut
		// off, so such a name is evidence of the convention however long it is
		// — discarding it would be the same device-wide rename in mirror
		// image, since dropping conforming names can put the device under the
		// count below.
		//
		// A name that is nothing BUT the suffix counts as carrying it:
		// stripVlanNameTagSuffix deliberately leaves that one alone, because
		// removing it would leave the VLAN nameless, and reading it as
		// counter-evidence would let it veto the convention for the device.
		if name == "+"+strconv.Itoa(vid) || stripVlanNameTagSuffix(name, vid) != name {
			named++
			continue
		}
		// The suffix is absent. That is only counter-evidence if it could have
		// been there: RFC 4363 bounds this column at 32 octets, so a name plus
		// suffix running past that arrives with the suffix cut away. Reading
		// that as the convention being broken would turn one long VLAN name
		// into a device-wide rename of every OTHER VLAN on the switch, back and
		// forth as that VLAN is configured and removed.
		//
		// Length ON the bound is the proxy for "was cut", deliberately an
		// equality: a name LONGER than the bound proves this agent does not cut
		// at the bound, so it cannot have lost a suffix that way, and it is the
		// strongest counter-evidence a device offers. The proxy is imperfect in
		// the other direction — trimming strips NUL padding as well as
		// whitespace, so a name cut at the bound with a NUL terminator arrives
		// at 31 and reads as a genuine absence.
		if len(name) == dot1qVlanStaticNameMax {
			continue
		}
		return false
	}
	return named > 0
}

// mergeVLANNames resolves one name per VID from the collected name rows.
//
// dot1qVlanStaticName is authoritative and the vendor catalogs — the Cisco
// VTP rows read here, plus whatever the private-table extractors reduced to
// vendorNames (see vlan_huawei.go) — are the fallback for the devices that
// do not populate it. Each vendor table is walked only behind its own
// vendor gate, so on one device at most one of them answers and they share
// the fallback tier without an ordering between them. Precedence is applied
// once, after every row has been read, rather than as each row arrives:
// resolving it in arrival order let an empty dot1q name erase a VTP name
// (or not) depending on which OID the map yielded first, so the emitted
// name flapped between polls and the VLAN was rewritten on every ingest.
//
// Values are stripped of the NUL padding and whitespace many vendor agents
// append; NetBox/PostgreSQL rejects NUL bytes in text fields, and a
// NUL-only name must collapse to "" so it counts as no name.
func mergeVLANNames(rows []vlanNameRow, vendorNames map[int]string) map[int]string {
	dot1q := map[int]string{}
	vendor := make(map[int]string, len(vendorNames))
	for vid, name := range vendorNames {
		vendor[vid] = name
	}
	vtpOID := map[int]string{}
	for _, r := range rows {
		name := trimSNMPString(r.value)
		switch {
		case strings.HasPrefix(r.oid, oidDot1qVlanStaticName):
			// dot1qVlanStaticTable is indexed by the VID alone, so at most
			// one row per VID reaches this branch.
			if vid, ok := atoi(strings.TrimPrefix(r.oid, oidDot1qVlanStaticName)); ok {
				dot1q[vid] = name
			}
		case strings.HasPrefix(r.oid, oidCiscoVtpVlanName):
			vid, ok := vtpVidFromOID(r.oid)
			if !ok {
				continue
			}
			if held, seen := vendor[vid]; !seen || preferVtpRow(held, vtpOID[vid], name, r.oid) {
				vendor[vid], vtpOID[vid] = name, r.oid
			}
		}
	}
	out := make(map[int]string, len(dot1q)+len(vendor))
	for vid, name := range vendor {
		out[vid] = name
	}
	for vid, name := range dot1q {
		// A named VID never loses its name to an empty row of the other
		// column, whichever column that is.
		if name == "" && out[vid] != "" {
			continue
		}
		out[vid] = name
	}
	return out
}

// vtpVidFromOID pulls the VID out of a vtpVlanName OID. The index is
// domain.vlan, so the VID is the trailing element.
func vtpVidFromOID(oid string) (int, bool) {
	suffix := strings.TrimPrefix(oid, oidCiscoVtpVlanName)
	last := suffix
	if i := strings.LastIndex(suffix, "."); i >= 0 {
		last = suffix[i+1:]
	}
	return atoi(last)
}

// vlanNameConflicts reports VIDs whose VTP rows carry different non-empty
// names. One VID can appear under more than one VTP management domain, and
// those are different Layer 2 domains: NetBox itself permits one VID in
// several VLAN groups.
//
// Emission still needs a single name per VID and picks one deterministically,
// which is fine for a display name. Corroboration cannot: an SVI that names
// that VID does not say which domain it means, the agent emits one VLAN entity
// for the VID either way, and the association it would produce cannot be
// retracted. So a conflicting VID is treated as uncorroborated.
func vlanNameConflicts(all ObjectIDValueMap) map[int]bool {
	names := map[int]string{}
	conflicts := map[int]bool{}
	for oid, v := range all {
		if !strings.HasPrefix(oid, oidCiscoVtpVlanName) {
			continue
		}
		vid, ok := vtpVidFromOID(oid)
		if !ok {
			continue
		}
		name := trimSNMPString(v.Value)
		if name == "" {
			continue
		}
		if held, seen := names[vid]; seen && held != name {
			conflicts[vid] = true
			continue
		}
		names[vid] = name
	}
	return conflicts
}

// preferVtpRow reports whether a candidate VTP row should replace the one
// already held for a VID. One VID can appear under more than one VTP
// management domain: a populated name wins, and ties break on the lowest
// OID so the winner is the same on every poll rather than whichever row
// the map happened to yield first.
func preferVtpRow(heldName, heldOID, name, oid string) bool {
	if (heldName == "") != (name == "") {
		return heldName == ""
	}
	return oid < heldOID
}

// emitVLANs scans dot1qVlanStaticName / RowStatus and constructs one
// *diode.VLAN per discovered VID. Names default to "VLAN<vid>" when the
// SNMP value is empty (matches device-discovery behavior). Status comes
// from defaults.VLAN.Status; if empty, derived from RowStatus
// (active(1)->active, notInService(2)->reserved, else unset).
//
// A device that publishes its VLAN database only in a private table (see
// vendorVlanCatalog) contributes the same three facts through the
// vendor-neutral vlanCatalog: every VID it lists, the names it supplies,
// and its RowStatus where it has one, run through the same derivation. A
// VID the catalog lists without a name is a nameless VLAN and is gated
// exactly like a status-only dot1q row. Where both tables report a VID,
// dot1qVlanStaticRowStatus wins over the catalog's status, exactly as
// dot1qVlanStaticName wins over its name.
//
// CreateUnknownVlans gating: the option is *bool. nil is treated as
// true (matches device-discovery PR #378's _ensure_vlan default and is
// the value Manager.applyDefaults installs when the policy YAML omits
// the options block). When the option is explicitly set to false, VIDs
// whose dot1qVlanStaticName row is absent (or empty) are skipped here
// — only VLANs with a real name from the device are emitted. The same
// gate also suppresses stub creation in ensureVLAN (see below).
func (m *VlanMapper) emitVLANs(all ObjectIDValueMap, defaults *config.Defaults) []diode.Entity {
	type pending struct {
		name      string
		rowStatus int
	}
	byVid := map[int]*pending{}
	for vid, name := range vlanNamesByVid(all) {
		byVid[vid] = &pending{name: name}
	}
	ensure := func(vid int) *pending {
		p, exists := byVid[vid]
		if !exists {
			p = &pending{}
			byVid[vid] = p
		}
		return p
	}
	// Vendor catalog first, dot1qVlanStaticTable second, so the standard
	// column's RowStatus overwrites the private table's for any VID both
	// report — the same precedence names get, and applied by ordering the
	// two passes rather than by whichever row a map iteration yields last.
	// A VID the catalog lists is registered even when it carries no name
	// and no status: the index row alone is what says the VLAN exists.
	catalog := vendorVlanCatalog(all)
	for vid := range catalog.Vids {
		ensure(vid)
	}
	for vid, st := range catalog.RowStatus {
		ensure(vid).rowStatus = st
	}
	for oid, v := range all {
		if !strings.HasPrefix(oid, oidDot1qVlanStaticRowStatus) {
			continue
		}
		vid, ok := atoi(strings.TrimPrefix(oid, oidDot1qVlanStaticRowStatus))
		if !ok {
			continue
		}
		st, ok2 := atoi(v.Value)
		if !ok2 {
			continue
		}
		ensure(vid).rowStatus = st
	}
	out := make([]diode.Entity, 0, len(byVid))
	for vid, p := range byVid {
		if vid < 1 || vid > 4094 {
			continue
		}
		// When create_unknown_vlans is false, skip VIDs that have no
		// dot1qVlanStaticName row (name == ""). A status-only row with
		// no name is treated as "unknown" and suppressed.
		createUnknown := m.options.CreateUnknownVlans == nil || *m.options.CreateUnknownVlans
		if !createUnknown && p.name == "" {
			continue
		}
		name := p.name
		if name == "" {
			name = "VLAN" + strconv.Itoa(vid)
		}
		v := &diode.VLAN{
			Vid:  int64Ptr(int64(vid)),
			Name: StringPtr(name),
		}
		if status := resolveVLANStatus(p.rowStatus, defaults); status != "" {
			v.Status = StringPtr(status)
		}
		applyVLANDefaults(v, defaults)
		out = append(out, v)
	}
	return out
}

func resolveVLANStatus(rowStatus int, defaults *config.Defaults) string {
	if defaults != nil && defaults.VLAN.Status != "" {
		return defaults.VLAN.Status
	}
	switch rowStatus {
	case 1: // active
		return "active"
	case 2: // notInService
		return "reserved"
	}
	return ""
}

// atoi is strconv.Atoi with a single-return ok flag.
func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// hasVLANSignal reports whether any VLAN-related OID was walked for the
// host — Q-BRIDGE static catalog / per-port PVID, Cisco-overlay
// vmMembership / vmVoiceVlanId, or any private VLAN catalog a vendor
// extractor reduced (vendorVlanCatalog). Used by PostMap to decide whether a
// missing dot1dBasePortIfIndex is a real partial-data condition (warn)
// or just a routine non-switch target (debug).
func hasVLANSignal(all ObjectIDValueMap) bool {
	prefixes := [...]string{
		oidDot1qVlanStaticName,
		oidCiscoVtpVlanName,
		oidDot1qVlanStaticEgressPorts,
		oidDot1qVlanStaticUntaggedPorts,
		oidDot1qVlanStaticRowStatus,
		oidDot1qVlanCurrentEgressPorts,
		oidDot1qVlanCurrentUntaggedPorts,
		oidDot1qPvid,
		oidCiscoVMVlan,
		oidCiscoVMVoiceVlanID,
		oidCiscoSBAccessVlan,
		oidCiscoSBTrunkNativeVlan,
	}
	for oid := range all {
		for _, p := range prefixes {
			if strings.HasPrefix(oid, p) {
				return true
			}
		}
	}
	return !vendorVlanCatalog(all).empty()
}

// int64Ptr is a local helper for *int64 values (diode.VLAN.Vid is *int64).
func int64Ptr(v int64) *int64 {
	return &v
}

// walkedIfTypes reads IF-MIB ifType for every ifIndex in the walk, keyed by
// ifIndex and left in the numeric form the agent reported. Switchport
// placement is decided on this value rather than on the NetBox type the
// interface carries, because that type is resolved from the interface's
// NAME first: every name that parses as a child — a Junos unit, but equally
// a channelized lane or a GPON ONU port — is typed virtual before ifType is
// consulted at all.
func walkedIfTypes(oids ObjectIDValueMap) map[int]string {
	out := make(map[int]string)
	for oid, v := range oids {
		if !strings.HasPrefix(oid, oidIfType) {
			continue
		}
		if ifIndex, ok := atoi(strings.TrimPrefix(oid, oidIfType)); ok {
			out[ifIndex] = strings.TrimSpace(v.Value)
		}
	}
	return out
}

// verifiedInterfacesByName indexes the walked interfaces by name for
// switchport-target resolution. Excluded names are left out so a unit never
// binds its switchport configuration to an interface the operator's
// exclude patterns removed from the payload.
func verifiedInterfacesByName(registry *EntityRegistry) map[string][]*diode.Interface {
	bucket := registry.entities[InterfaceEntityType]
	ifaces := make([]*diode.Interface, 0, len(bucket))
	for _, e := range bucket {
		iface, ok := e.(*diode.Interface)
		if !ok || iface == nil || iface.Name == nil {
			continue
		}
		if !registry.IsInterfaceVerified(iface) || registry.IsInterfaceExcluded(*iface.Name) {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	return interfacesByName(ifaces)
}

// switchportTarget returns the interface that should carry the switchport
// configuration of a classified bridge port.
//
// Bridge ports are ifIndexes, and on Junos the ifIndex in
// dot1dBasePortIfIndex is the logical unit (xe-0/0/17.0, ae8.0) rather than
// the port it runs on. NetBox models mode / untagged_vlan / tagged_vlans on
// the switchport itself, and a NETCONF discovery of the same device puts
// them there, so a unit is resolved back to its port.
//
// Only a LOGICAL interface hands its configuration over, and the decision
// is made on the ifType the device reported for that ifIndex — not on the
// emitted NetBox type, which is derived from the name for anything that
// parses as a child and would therefore answer "virtual" to a question it
// was never asked. A name-shaped child is not necessarily a logical one: a
// channelized lane (Aruba CX 1/1/11:3, ifType 6) and a GPON ONU port
// (BDCOM GPON0/2:1, ifType 1) both parse as children of an interface that
// is in the walk, yet each is a switchport in its own right and keeps what
// the device reported for it. Units (ifType 53 / 135 / 136) and aggregate
// units (ifType 161) hand over, so ae8.0 resolves onto ae8 — aggregates are
// switchports too.
//
// When the unit's port is absent from the walk, or its name is ambiguous,
// the unit itself is kept: the membership the device reported is still true
// of that interface, and dropping it would lose discovered data to gain
// tidiness.
func (m *VlanMapper) switchportTarget(
	iface *diode.Interface,
	ifType string,
	byName map[string][]*diode.Interface,
) *diode.Interface {
	// A physical interface is the switchport, whatever its name looks like.
	// An interface the walk carries no ifType for is left alone for the same
	// reason: moving its configuration would be acting on evidence the
	// device never gave.
	if !isLogicalIfType(ifType) {
		return iface
	}
	parent, isSub, reason := parentInterfaceFor(strDeref(iface.Name), byName)
	switch {
	case parent != nil:
		return parent
	case isSub:
		m.logger.Warn("vlan: keeping switchport configuration on the logical unit",
			"interface", strDeref(iface.Name), "reason", reason)
	}
	return iface
}

// mergedClassification accumulates the classifications of every bridge port
// that resolves to one switchport, with the unit names that contributed.
type mergedClassification struct {
	class            qbridge.Classification
	sources          []string
	untaggedConflict bool
}

// merge folds src into the accumulator. One physical port carrying several
// bridging units is a real configuration (flexible VLAN tagging), and the
// port's switchport state is the combination: every unit's tagged VLANs, and
// the trunkiest mode any of them reported. Two units claiming DIFFERENT
// untagged VLANs contradict each other — a port has one native VLAN — so the
// untagged assignment is dropped and the tagged union kept, rather than
// picking whichever unit the walk happened to yield first.
func (a *mergedClassification) merge(src qbridge.Classification, source string) {
	a.sources = append(a.sources, source)
	if len(a.sources) == 1 {
		a.class = src
		return
	}
	if src.Mode > a.class.Mode {
		a.class.Mode = src.Mode
	}
	a.class.Tagged = unionVids(a.class.Tagged, src.Tagged)
	switch {
	case src.Untagged == nil:
	case a.class.Untagged == nil:
		a.class.Untagged = src.Untagged
	case *a.class.Untagged != *src.Untagged:
		a.untaggedConflict = true
	}
}

// withoutVid returns vids with drop removed, keeping order.
func withoutVid(vids []int, drop int) []int {
	out := vids[:0:0]
	for _, vid := range vids {
		if vid != drop {
			out = append(out, vid)
		}
	}
	return out
}

// unionVids returns the sorted, deduplicated union of two VID lists.
func unionVids(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, list := range [][]int{a, b} {
		for _, vid := range list {
			if _, dup := seen[vid]; dup {
				continue
			}
			seen[vid] = struct{}{}
			out = append(out, vid)
		}
	}
	sort.Ints(out)
	return out
}

// applyClassifications places each classified bridge port's switchport
// configuration on the interface that should carry it, after resolving
// logical units to their ports and combining the units that share one.
//
// Bridge ports are visited in ifIndex order so that a device reporting
// several units of one port produces the same payload on every poll.
func (m *VlanMapper) applyClassifications(
	registry *EntityRegistry,
	classifications map[int]qbridge.Classification,
	ifTypes map[int]string,
	ensureVLAN func(int) *diode.VLAN,
) {
	if len(classifications) == 0 {
		return
	}
	byName := verifiedInterfacesByName(registry)

	ifIndexes := make([]int, 0, len(classifications))
	for ifIndex := range classifications {
		ifIndexes = append(ifIndexes, ifIndex)
	}
	sort.Ints(ifIndexes)

	merged := map[*diode.Interface]*mergedClassification{}
	order := make([]*diode.Interface, 0, len(ifIndexes))
	for _, ifIndex := range ifIndexes {
		c := classifications[ifIndex]
		// Routed and unknown ports carry no switchport configuration, so
		// they neither claim a target nor dilute one that another unit of
		// the same port does claim.
		if classificationToNetboxMode(c.Mode) == "" {
			continue
		}
		iface := verifiedInterface(registry, ifIndex)
		if iface == nil {
			continue
		}
		target := m.switchportTarget(iface, ifTypes[ifIndex], byName)
		acc, seen := merged[target]
		if !seen {
			acc = &mergedClassification{}
			merged[target] = acc
			order = append(order, target)
		}
		acc.merge(c, strDeref(iface.Name))
	}

	for _, target := range order {
		acc := merged[target]
		if acc.untaggedConflict {
			// A port has one native VLAN, so contradicting units settle
			// nothing. Drop the contested assignment and keep what the
			// units agree on; with no tagged VLANs left there is nothing
			// to say about the port, and emitting access with no VLAN
			// would be worse than emitting nothing.
			acc.class.Untagged = nil
			// ModeTrunkAll carries its wildcard in the mode, not in
			// Tagged, so an empty list there still says the port is a
			// trunk carrying everything — that survives the conflict.
			if len(acc.class.Tagged) == 0 && acc.class.Mode != qbridge.ModeTrunkAll {
				m.logger.Warn("vlan: units of one port report different untagged VLANs and nothing else; leaving it unclassified",
					"interface", strDeref(target.Name), "units", acc.sources)
				continue
			}
			m.logger.Warn("vlan: units of one port report different untagged VLANs; keeping the tagged VLANs only",
				"interface", strDeref(target.Name), "units", acc.sources)
		}
		// A trunk carrying everything says so in the mode and carries no
		// tagged list — that is what Classify emits for a wildcard, and
		// what the conflict branch above relies on. Merging a wildcard
		// unit with one that listed VLANs must not leave that subset
		// beside it: the two contradict each other, and NetBox discards
		// tagged VLANs on any non-tagged mode the next time it saves the
		// interface, so the list is noise that outlives nothing.
		if acc.class.Mode == qbridge.ModeTrunkAll {
			acc.class.Tagged = nil
		}
		// Classify never leaves the native VLAN in the tagged set, and a
		// merge must not reintroduce it: one unit reporting a VID untagged
		// while another reports it tagged describes one port whose native
		// VLAN is that VID, not a port that is both.
		if acc.class.Untagged != nil {
			acc.class.Tagged = withoutVid(acc.class.Tagged, *acc.class.Untagged)
		}
		if len(acc.sources) > 1 {
			m.logger.Debug("vlan: combined logical units onto their port",
				"interface", strDeref(target.Name), "units", acc.sources)
		}
		applyClassification(target, acc.class, ensureVLAN)
	}
}
