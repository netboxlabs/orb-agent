package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The same tests sit next to each copy of tenant_identity.go.

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Acme Corp": "acme-corp",
		"Acme-Corp": "acme-corp",
		"Acme.Corp": "acmecorp",
		"Acme_Corp": "acme_corp",
		" _Acme_ ":  "acme",
		"a  -- b":   "a-b",
		"Café":      "cafe",
		"日本":        "",
		"a\vb":      "a-b",
		"a\x1cb":    "a-b",
	} {
		assert.Equal(t, want, slug(in), in)
	}
}

func TestTenantConflict(t *testing.T) {
	acme := TenantParameters{Name: "acme", Group: "customers", Description: "d", Comments: "c", Tags: []string{"a"}}
	with := func(f func(*TenantParameters)) TenantParameters {
		tp := acme
		tp.Tags = append([]string(nil), acme.Tags...)
		f(&tp)
		return tp
	}
	for _, tc := range []struct {
		name string
		a, b TenantParameters
		want string
	}{
		{name: "identical", a: acme, b: acme},
		{name: "fields on one side", a: acme, b: TenantParameters{Name: "acme", Group: "customers"}},
		{name: "fields on the other side", a: TenantParameters{Name: "acme", Group: "customers"}, b: acme},
		{name: "description padded", a: acme, b: with(func(tp *TenantParameters) { tp.Description = "d " })},
		{name: "description padded with a separator control", a: acme, b: with(func(tp *TenantParameters) { tp.Description = "d\x1f" })},
		{name: "tag padded", a: acme, b: with(func(tp *TenantParameters) { tp.Tags = []string{" a"} })},
		{name: "name padded", a: acme, b: with(func(tp *TenantParameters) { tp.Name = "acme\x1c" })},
		{name: "group padded", a: acme, b: with(func(tp *TenantParameters) { tp.Group = " customers" })},
		{name: "other tenant", a: acme, b: TenantParameters{Name: "globex", Group: "partners", Description: "x"}},
		{name: "names without a slug", a: TenantParameters{Name: "日本", Description: "x"}, b: TenantParameters{Name: "中国", Description: "y"}},
		{name: "no second tenant", a: acme},
		{name: "blank names", a: TenantParameters{Name: " ", Group: "customers"}, b: TenantParameters{Name: " ", Group: "Customers"}},
		{name: "blank name against a group written two ways", a: TenantParameters{Group: "customers"}, b: TenantParameters{Name: "acme", Group: "Customers"}},
		{name: "description", a: acme, b: with(func(tp *TenantParameters) { tp.Description = "x" }), want: "tenant"},
		{name: "comments", a: acme, b: with(func(tp *TenantParameters) { tp.Comments = "x" }), want: "tenant"},
		{name: "tags", a: acme, b: with(func(tp *TenantParameters) { tp.Tags = []string{"b"} }), want: "tenant"},
		{
			name: "tags reordered",
			a:    with(func(tp *TenantParameters) { tp.Tags = []string{"a", "b"} }),
			b:    with(func(tp *TenantParameters) { tp.Tags = []string{"b", "a"} }),
			want: "tenant",
		},
		{name: "blank description", a: acme, b: with(func(tp *TenantParameters) { tp.Description = "  " }), want: "tenant"},
		{name: "case", a: acme, b: with(func(tp *TenantParameters) { tp.Name = "Acme" }), want: "tenant"},
		{name: "slug alike", a: TenantParameters{Name: "Acme Corp"}, b: TenantParameters{Name: "Acme-Corp"}, want: "tenant"},
		{name: "accent", a: TenantParameters{Name: "Café"}, b: TenantParameters{Name: "Cafe"}, want: "tenant"},
		{name: "other group", a: acme, b: with(func(tp *TenantParameters) { tp.Group = "partners" }), want: "tenant"},
		{name: "ungrouped", a: acme, b: with(func(tp *TenantParameters) { tp.Group = "" }), want: "tenant"},
		{name: "group case", a: acme, b: TenantParameters{Name: "globex", Group: "Customers"}, want: "group"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tenantConflict(tc.a, tc.b))
		})
	}
}
