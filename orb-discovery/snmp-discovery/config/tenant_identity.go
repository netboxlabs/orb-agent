package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Diode trims names and, when a tenant's name and group match no tenant,
// falls back to the slug of its name whatever its group. Two copies of a
// tenant whose names slugify alike can therefore resolve to one NetBox tenant,
// and written differently the entity is refused, the tenant is rewritten on
// every run, or a second tenant of that name is created.

// Python's \s also matches \v and \x1c-\x1f, which RE2's does not.
var (
	slugDrop     = regexp.MustCompile(`[^\w\t\n\v\f\r\x1c-\x1f -]`)
	slugCollapse = regexp.MustCompile(`[-\t\n\v\f\r\x1c-\x1f ]+`)
)

// slug returns Django's slugify of s, which Diode matches tenants by.
func slug(s string) string {
	var ascii strings.Builder
	for _, r := range norm.NFKD.String(s) {
		if r <= unicode.MaxASCII {
			ascii.WriteRune(r)
		}
	}
	s = slugDrop.ReplaceAllString(strings.ToLower(ascii.String()), "")
	return strings.Trim(slugCollapse.ReplaceAllString(s, "-"), "-_")
}

// trim strips what Python's str.strip does, which Diode applies to text: Go's
// whitespace set leaves out \x1c-\x1f.
func trim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f })
}

// sameName reports whether two trimmed names resolve alike: equal, or the
// same non-empty slug.
func sameName(a, b string) bool {
	return a == b || slug(a) != "" && slug(a) == slug(b)
}

// tenantConflict reports what makes two copies of one tenant disagree: "group"
// when their groups are one NetBox group written two ways, "tenant" when their
// names resolve to one tenant but the name, group, description, comments or
// tags differ, or "" when Diode can merge them.
func tenantConflict(a, b TenantParameters) string {
	nameA, nameB := trim(a.Name), trim(b.Name)
	groupA, groupB := trim(a.Group), trim(b.Group)
	switch {
	case nameA == "" || nameB == "":
		return ""
	case groupA != groupB && sameName(groupA, groupB):
		return "group"
	case !sameName(nameA, nameB):
		return ""
	case nameA != nameB || groupA != groupB,
		differ(a.Description, b.Description), differ(a.Comments, b.Comments),
		len(a.Tags) > 0 && len(b.Tags) > 0 && !slices.Equal(trimmed(a.Tags), trimmed(b.Tags)):
		return "tenant"
	}
	return ""
}

// differ reports whether two optional values are both set and disagree once
// trimmed. A blank value is set: Diode trims it to empty, which still clashes.
func differ(a, b string) bool {
	return a != "" && b != "" && trim(a) != trim(b)
}

func trimmed(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = trim(v)
	}
	return out
}

// ValidateVrfTenants refuses a VRF tenant Diode cannot match: one with no
// name, which goes out empty and leaves the VRF tenant-less, one on a VRF knob
// with no VRF name, which drops the VRF, and one written differently from
// another tenant default. One run sends every tenant default in full; Diode
// merges the copies that resolve to one tenant within an entity and refuses
// the entity when they disagree, and across entities rewrites the tenant on
// every run. Pairs without a VRF tenant are left as they were before VRF
// tenants existed, unless an address, prefix or VLAN tenant is written as more
// than a bare name, which only their new map form allows. Run it on the
// defaults a target actually uses.
func (d *Defaults) ValidateVrfTenants() error {
	type tenantAt struct {
		path   string
		tenant TenantParameters
		vrf    *VrfParameters
		// mapped marks a default that took the map form with VRF tenants;
		// written as more than a bare name it can disagree with others.
		mapped bool
	}
	copies := []tenantAt{
		{"defaults.tenant", d.Tenant, nil, false},
		{"defaults.ip_address.tenant", d.IPAddress.Tenant, nil, true},
		{"defaults.ip_address.vrf.tenant", d.IPAddress.Vrf.Tenant, &d.IPAddress.Vrf, false},
		{"defaults.ip_address.vrf_ipv4.tenant", d.IPAddress.VrfIpv4.Tenant, &d.IPAddress.VrfIpv4, false},
		{"defaults.ip_address.vrf_ipv6.tenant", d.IPAddress.VrfIpv6.Tenant, &d.IPAddress.VrfIpv6, false},
		{"defaults.prefix.tenant", d.Prefix.Tenant, nil, true},
		{"defaults.prefix.vrf.tenant", d.Prefix.Vrf.Tenant, &d.Prefix.Vrf, false},
		{"defaults.prefix.vrf_ipv4.tenant", d.Prefix.VrfIpv4.Tenant, &d.Prefix.VrfIpv4, false},
		{"defaults.prefix.vrf_ipv6.tenant", d.Prefix.VrfIpv6.Tenant, &d.Prefix.VrfIpv6, false},
		{"defaults.vlan.tenant", d.VLAN.Tenant, nil, true},
	}
	// The AF-agnostic vrf is never used when both per-family knobs are set.
	shadowed := map[*VrfParameters]bool{
		&d.IPAddress.Vrf: !d.IPAddress.VrfIpv4.IsZero() && !d.IPAddress.VrfIpv6.IsZero(),
		&d.Prefix.Vrf:    !d.Prefix.VrfIpv4.IsZero() && !d.Prefix.VrfIpv6.IsZero(),
	}
	kept := copies[:0]
	for _, c := range copies {
		if c.vrf == nil || !shadowed[c.vrf] {
			kept = append(kept, c)
		}
	}
	copies = kept
	for _, c := range copies {
		if c.vrf == nil || c.tenant.isZero() {
			continue
		}
		if trim(c.tenant.Name) == "" {
			return fmt.Errorf("%s has no name; a tenant is matched by its name", c.path)
		}
		if trim(c.vrf.Name) == "" {
			return fmt.Errorf("%s sets a tenant but no VRF name, so the VRF would be dropped",
				strings.TrimSuffix(c.path, ".tenant"))
		}
	}
	for i, first := range copies {
		for _, second := range copies[i+1:] {
			compared := func(c tenantAt) bool { return c.vrf != nil || c.mapped && c.tenant.rich() }
			if !compared(first) && !compared(second) {
				continue
			}
			switch tenantConflict(first.tenant, second.tenant) {
			case "group":
				return fmt.Errorf("%s and %s name the same NetBox tenant group in two ways; "+
					"write it the same way in both places", first.path, second.path)
			case "tenant":
				return fmt.Errorf("%s and %s name the same NetBox tenant but write it differently; "+
					"give it the same name, group, description, comments and tags, in the same order, in both places, "+
					"for example with a YAML anchor", first.path, second.path)
			}
		}
	}
	return nil
}
