package config

import (
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
	return a != "" && b != "" && trim(a) != trim(b)
}

func trimmed(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = trim(v)
	}
	return out
}
