package mapping

import (
	"sort"
	"strconv"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// parseNetworkInstanceVlanPath extracts (vid, leaf) from an OpenConfig
// network-instance VLAN state path. The network-instance name is ignored — NetBox
// VLAN identity is vid + group/site, not the network-instance. leaf is name|status;
// any other path returns ok=false.
func parseNetworkInstanceVlanPath(path string) (vid, leaf string, ok bool) {
	const niList = "/network-instances/network-instance"
	if !strings.HasPrefix(path, niList+"[") {
		return "", "", false
	}
	rest := path[len(niList):] // "[name=default]/vlans/vlan[vlan-id=10]/state/name"
	_, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", false
	}
	const vlanList = "/vlans/vlan"
	if !strings.HasPrefix(rest, vlanList+"[") {
		return "", "", false
	}
	rest = rest[len(vlanList):]
	vid, rest, ok = firstKeyVal(rest)
	if !ok {
		return "", "", false
	}
	const state = "/state/"
	if !strings.HasPrefix(rest, state) {
		return "", "", false
	}
	leaf = rest[len(state):]
	switch leaf {
	case "name", "status":
		return vid, leaf, true
	}
	return "", "", false
}

// mapVlanStatus maps the OpenConfig VLAN status enum to a NetBox vlan status.
// NetBox has no "suspended", so SUSPENDED -> reserved; everything else -> active.
func mapVlanStatus(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "SUSPENDED") {
		return "reserved"
	}
	return "active"
}

// slugify lower-cases and replaces each run of non-[a-z0-9] with a single hyphen,
// trimming leading/trailing hyphens. Used for the VLANGroup slug (NetBox requires one).
func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevHyphen = false
		} else if b.Len() > 0 && !prevHyphen {
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

type vlanDef struct{ name, status string }

// translateVlanDefinitions reads VLAN name/status out of the network-instance
// subtree, keyed by vid (deduped across network-instances; deterministic via a
// sorted path scan). Out-of-range vids are skipped (safeVid).
func translateVlanDefinitions(snap map[string]any) map[int64]vlanDef {
	out := map[int64]vlanDef{}
	paths := make([]string, 0, len(snap))
	for p := range snap {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		vidStr, leaf, ok := parseNetworkInstanceVlanPath(path)
		if !ok {
			continue
		}
		vid, okVid := safeVid(vidStr)
		if !okVid {
			continue
		}
		d := out[vid]
		switch leaf {
		case "name":
			d.name = toStr(snap[path])
		case "status":
			d.status = toStr(snap[path])
		}
		out[vid] = d
	}
	return out
}

// setVlanGroupScope attaches the configured scope to a VLAN group. An
// explicit scope_* wins; otherwise the device site applies, so the string
// form of vlan.group keeps its site scope. NetBox Locations are unique
// within their site, so a Location scope carries the device site when
// there is one. Scope is only assigned a real value: a typed-nil *diode.Site
// would make the interface non-nil and serialize as an empty site.
func setVlanGroupScope(g *diode.VLANGroup, p config.VlanGroupParameters, site *diode.Site) {
	switch {
	case p.ScopeSiteGroup != "":
		g.Scope = &diode.SiteGroup{Name: strptr(p.ScopeSiteGroup)}
	case p.ScopeRegion != "":
		g.Scope = &diode.Region{Name: strptr(p.ScopeRegion)}
	case p.ScopeLocation != "":
		loc := &diode.Location{Name: strptr(p.ScopeLocation)}
		if site != nil {
			loc.Site = site
		}
		g.Scope = loc
	case p.ScopeSite != "":
		g.Scope = &diode.Site{Name: strptr(p.ScopeSite)}
	case site != nil:
		g.Scope = site
	}
}

// vlanBuilder constructs deduped *diode.VLAN entities with real-or-placeholder
// name/status and the policy vlan defaults (scoped group, tenant, role, tags,
// description). The same rich VLAN is shared between interface refs and the
// top-level entity (VLAN has no back-ref to Interface/Device -> DAG, no cycle).
type vlanBuilder struct {
	site   *diode.Site
	defs   map[int64]vlanDef
	group  *diode.VLANGroup
	tenant *diode.Tenant
	role   *diode.Role
	tags   []*diode.Tag
	desc   string
	cache  map[int64]*diode.VLAN
	order  []int64
}

func newVlanBuilder(dev *diode.Device, defaults *config.Defaults, defs map[int64]vlanDef) *vlanBuilder {
	b := &vlanBuilder{defs: defs, cache: map[int64]*diode.VLAN{}}
	if dev != nil {
		b.site = dev.Site
	}
	if defaults != nil {
		v := defaults.Vlan
		// Only create the group when the name yields a non-empty slug — NetBox
		// requires VLANGroup.slug to be non-empty, so a name with no [a-z0-9] runes
		// (slug == "") would make ingestion fail. Skip the group in that case (the
		// VLANs are still emitted, just ungrouped).
		if slug := slugify(v.Group.Name); v.Group.Name != "" && slug != "" {
			g := &diode.VLANGroup{Name: strptr(v.Group.Name), Slug: strptr(slug)}
			setVlanGroupScope(g, v.Group, b.site)
			b.group = g
		}
		b.tenant = diodeTenant(v.Tenant)
		if v.Role != "" {
			b.role = &diode.Role{Name: strptr(v.Role)}
		}
		// VLAN tags = policy-level tags + vlan-level tags (defaults.tags applies to
		// all entities, mirroring the Device path).
		b.tags = toTags(append(append([]string{}, defaults.Tags...), v.Tags...))
		b.desc = v.Description
	}
	return b
}

func (b *vlanBuilder) get(vid int64) *diode.VLAN {
	if v, ok := b.cache[vid]; ok {
		return v
	}
	id := vid
	name := "VLAN" + strconv.FormatInt(vid, 10)
	status := "active"
	if d, ok := b.defs[vid]; ok {
		if n := strings.TrimSpace(d.name); n != "" {
			name = n
		}
		status = mapVlanStatus(d.status)
	}
	v := &diode.VLAN{Vid: &id, Name: strptr(name), Status: strptr(status), Site: b.site}
	if b.group != nil {
		v.Group = b.group
	}
	if b.tenant != nil {
		v.Tenant = b.tenant
	}
	if b.role != nil {
		v.Role = b.role
	}
	if len(b.tags) > 0 {
		v.Tags = b.tags
	}
	if b.desc != "" {
		v.Description = strptr(b.desc)
	}
	b.cache[vid] = v
	b.order = append(b.order, vid)
	return v
}

func (b *vlanBuilder) emitted() []diode.Entity {
	vids := append([]int64(nil), b.order...)
	sort.Slice(vids, func(i, j int) bool { return vids[i] < vids[j] })
	out := make([]diode.Entity, 0, len(vids))
	for _, vid := range vids {
		out = append(out, b.cache[vid])
	}
	return out
}

// UnscopedVLANWarning explains what a VLAN Diode cannot match costs. Kept beside
// CountUnscopedVLANs so the message and the condition stay together.
//
// NetBox stores unlimited same-VID VLANs when group is NULL: its (group, vid)
// constraint does not enforce uniqueness there. The Diode plugin fills that gap
// with its own criteria, and because it tests a criterion's condition against
// the payload as well as the stored rows, which one applies depends on what the
// agent sends. This backend always sets VLAN.site, so a group-less VLAN from
// here is matched on (vid, site), not on VID alone as it is in the backends
// that send no site.
//
// Either way the VLAN never matches the group-scoped VLANs an operator curated
// by hand, so ingestion duplicates them. Whether the same VID also collides
// across sites depends on whether anything separates them: a real site does, a
// real group scope does, and the "undefined" placeholder does not, being one
// record estate-wide.
//
// A group alone is not the whole remedy. With no defaults.site the group is
// scoped to the "undefined" placeholder, and a group scoped there cannot match
// the same group scoped to a real site: Diode matches a VLAN group by
// (scope_type, scope_id, name). Following "set a group" without also setting a
// site therefore buys a second group under a junk site plus the same duplicate
// VLANs, and would silence this warning while doing it.
//
// A site on the VLAN itself is deliberately NOT treated as a scope, even though
// Diode will match on (vid, site). It leaves the duplication against the
// operator's group-scoped VLANs untouched, and NetBox has deprecated assigning
// a VLAN directly to a site and will remove it in a future release.
const UnscopedVLANWarning = "discovered VLANs sent with no VLAN group, or with one whose scope " +
	"rests on the \"" + config.UndefinedPlaceholder + "\" placeholder; Diode cannot match these " +
	"against VLANs already scoped to a group in NetBox, so ingestion duplicates them, and, " +
	"unless a real site or a real group scope separates them, the same VID discovered at " +
	"different sites collides on one record; set BOTH " +
	"defaults.site and defaults.vlan.group in the policy"

// vlanGroupScopeSeparates reports whether a VLAN group's scope tells one estate
// from another. A scope resting on the "undefined" placeholder does not: every
// policy without a defaults.site produces the same one. Nor does a group with no
// scope at all, or a location with no site, which NetBox cannot even resolve.
//
// A site group or region is a real scope: both come straight from operator
// config, with no placeholder substitution anywhere in the builders.
func vlanGroupScopeSeparates(g *diode.VLANGroup) bool {
	switch scope := g.Scope.(type) {
	case nil:
		return false
	case *diode.Site:
		return scope != nil && scope.Name != nil &&
			*scope.Name != "" && *scope.Name != config.UndefinedPlaceholder
	case *diode.Location:
		if scope == nil || scope.Site == nil || scope.Site.Name == nil {
			return false
		}
		return *scope.Site.Name != "" && *scope.Site.Name != config.UndefinedPlaceholder
	}
	return true
}

// CountUnscopedVLANs counts top-level VLAN entities Diode cannot usefully
// separate: no group, or a group whose scope separates nothing.
//
// Only top-level entities are walked: every VLAN referenced from an interface is
// the same pointer as the top-level entity emitted for that VID, so counting
// both would report each VLAN many times over.
func CountUnscopedVLANs(entities []diode.Entity) int {
	n := 0
	for _, e := range entities {
		v, ok := e.(*diode.VLAN)
		if !ok || v == nil {
			continue
		}
		if v.Group == nil || !vlanGroupScopeSeparates(v.Group) {
			n++
		}
	}
	return n
}
