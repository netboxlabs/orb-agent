package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Diode trims names and finds a tenant by the slug of its name, whatever its
// group. Two copies of a tenant in one entity whose names slugify alike
// therefore resolve to one NetBox tenant, and written differently the entity
// is refused or the tenant is rewritten on every run.

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
	nameA, nameB := strings.TrimSpace(a.Name), strings.TrimSpace(b.Name)
	groupA, groupB := strings.TrimSpace(a.Group), strings.TrimSpace(b.Group)
	switch {
	case groupA != groupB && sameName(groupA, groupB):
		return "group"
	case nameA == "" || nameB == "" || !sameName(nameA, nameB):
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
	return a != "" && b != "" && strings.TrimSpace(a) != strings.TrimSpace(b)
}

func trimmed(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.TrimSpace(v)
	}
	return out
}

// ValidateVrfTenants refuses the VRF tenant written differently from another
// tenant default. Every discovered VRF carries it, so an address carries its
// own tenant and its VRF's, a prefix likewise, and VLANs their own. Diode
// merges the copies that resolve to one tenant within an entity and refuses
// the entity when they disagree, and across entities rewrites the tenant on
// every run. Pairs without the VRF tenant are left as they were.
func (d *Defaults) ValidateVrfTenants() error {
	others := []struct {
		path   string
		tenant TenantParameters
	}{
		{"defaults.ip_address.tenant", d.IPAddress.Tenant},
		{"defaults.prefix.tenant", d.Prefix.Tenant},
		{"defaults.vlan.tenant", TenantParameters{Name: d.Vlan.Tenant}},
	}
	for _, other := range others {
		switch tenantConflict(d.Vrf.Tenant, other.tenant) {
		case "group":
			return fmt.Errorf("defaults.vrf.tenant and %s name the same NetBox tenant group in two ways; "+
				"write it the same way in both places", other.path)
		case "tenant":
			return fmt.Errorf("defaults.vrf.tenant and %s name the same NetBox tenant but write it differently; "+
				"give it the same name, group, description, comments and tags, in the same order, in both places, "+
				"for example with a YAML anchor", other.path)
		}
	}
	return nil
}
