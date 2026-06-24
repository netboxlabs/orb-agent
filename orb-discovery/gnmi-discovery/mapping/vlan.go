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

// vlanBuilder constructs deduped *diode.VLAN entities with real-or-placeholder
// name/status and the policy vlan defaults (site-scoped group, tenant, role, tags,
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
		if slug := slugify(v.Group); v.Group != "" && slug != "" {
			g := &diode.VLANGroup{Name: strptr(v.Group), Slug: strptr(slug)}
			// Only set Scope when we have a real site. Assigning a typed-nil
			// *diode.Site to the Scope interface would make it non-nil, causing the
			// SDK to emit a bogus empty-site scope.
			if b.site != nil {
				g.Scope = b.site
			}
			b.group = g
		}
		if v.Tenant != "" {
			b.tenant = &diode.Tenant{Name: strptr(v.Tenant)}
		}
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
