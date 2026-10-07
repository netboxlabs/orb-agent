package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestTenantParameters_UnmarshalScalar(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("tenant: acme\n"), &d)
	require.NoError(t, err)
	assert.Equal(t, "acme", d.Tenant.Name)
	assert.Empty(t, d.Tenant.Group)
}

func TestTenantParameters_UnmarshalMapping(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte(
		"tenant:\n  name: acme\n  group: customers\n  description: main tenant\n  comments: managed\n  tags: [a, b]\n"), &d)
	require.NoError(t, err)
	assert.Equal(t, "acme", d.Tenant.Name)
	assert.Equal(t, "customers", d.Tenant.Group)
	assert.Equal(t, "main tenant", d.Tenant.Description)
	assert.Equal(t, "managed", d.Tenant.Comments)
	assert.Equal(t, []string{"a", "b"}, d.Tenant.Tags)
}

func TestTenantParameters_UnmarshalNullAndReceiverReset(t *testing.T) {
	var tp TenantParameters
	require.NoError(t, yaml.Unmarshal([]byte("name: acme\ngroup: customers\n"), &tp))
	require.NoError(t, yaml.Unmarshal([]byte("plainname"), &tp))
	assert.Equal(t, "plainname", tp.Name)
	assert.Empty(t, tp.Group, "scalar re-decode must reset Group")

	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("tenant: null\n"), &d))
	assert.Empty(t, d.Tenant.Name)
}

func TestTenantParameters_UnmarshalBadKind(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("tenant:\n  - a\n  - b\n"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant: expected string or mapping")
}

func TestTenantParameters_UnmarshalMappingMissingName(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("tenant:\n  group: customers\n  tags: [a]\n"), &d)
	require.Error(t, err)
	assert.EqualError(t, err, "tenant: mapping requires name")
}

func TestVrfParameters_UnmarshalScalar(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("vrf: production\n"), &d))
	assert.Equal(t, VrfParameters{Name: "production"}, d.Vrf)
}

func TestVrfParameters_UnmarshalMapping(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte(
		"vrf:\n  name: production\n  rd: \"65000:100\"\n  description: d\n  comments: c\n  tags: [a, b]\n"+
			"  tenant:\n    name: acme\n    group: customers\n"), &d))
	assert.Equal(t, VrfParameters{
		Name:        "production",
		Rd:          "65000:100",
		Tenant:      TenantParameters{Name: "acme", Group: "customers"},
		Description: "d",
		Comments:    "c",
		Tags:        []string{"a", "b"},
	}, d.Vrf)
}

func TestVrfParameters_UnmarshalTenantScalar(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("vrf:\n  name: production\n  tenant: acme\n"), &d))
	assert.Equal(t, TenantParameters{Name: "acme"}, d.Vrf.Tenant)
}

func TestVrfParameters_UnmarshalAnchoredTenant(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte(
		"tenant: &owner\n  name: acme\n  group: customers\nvrf:\n  name: production\n  tenant: *owner\n"), &d))
	assert.Equal(t, TenantParameters{Name: "acme", Group: "customers"}, d.Tenant)
	assert.Equal(t, d.Tenant, d.Vrf.Tenant)
}

func TestVrfParameters_UnmarshalNullAndReceiverReset(t *testing.T) {
	var v VrfParameters
	require.NoError(t, yaml.Unmarshal([]byte("name: production\nrd: \"65000:100\"\ntenant: acme\n"), &v))
	require.NoError(t, yaml.Unmarshal([]byte("plainname"), &v))
	assert.Equal(t, VrfParameters{Name: "plainname"}, v, "scalar re-decode must reset the other fields")

	// yaml.v3 never calls UnmarshalYAML for a null node; this pins that.
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte("vrf: null\n"), &d))
	assert.Equal(t, VrfParameters{}, d.Vrf)
}

func TestVrfParameters_UnmarshalBadKind(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  - a\n  - b\n"), &d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vrf: expected string or mapping")
}

func TestVrfParameters_UnmarshalMappingMissingName(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  rd: \"65000:100\"\n  tenant: acme\n"), &d)
	require.Error(t, err)
	assert.EqualError(t, err, "vrf: mapping requires name")
}

func TestVrfParameters_UnmarshalUnknownKey(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  name: production\n  tennant: acme\n"), &d)
	require.Error(t, err)
	assert.EqualError(t, err, `vrf has no "tennant" key`)
}

func TestVrfParameters_UnmarshalUnknownKeyThroughMergeOrAlias(t *testing.T) {
	for _, tc := range []struct{ name, doc, err string }{
		{name: "merged", doc: "base: &b\n  name: v\n  tennant: acme\nvrf:\n  <<: *b\n", err: `vrf has no "tennant" key`},
		{name: "merged list", doc: "a: &a {name: v}\nb: &b {tennant: acme}\nvrf:\n  <<: [*a, *b]\n", err: `vrf has no "tennant" key`},
		{name: "merged into tenant", doc: "t: &t {name: acme, grup: g}\nvrf:\n  name: v\n  tenant:\n    <<: *t\n", err: `vrf.tenant has no "grup" key`},
		{name: "aliased tenant", doc: "t: &t {name: acme, grup: g}\nvrf:\n  name: v\n  tenant: *t\n", err: `vrf.tenant has no "grup" key`},
		{name: "aliased key", doc: "k: &k tenant\nvrf:\n  name: v\n  *k : acme\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d Defaults
			err := yaml.Unmarshal([]byte(tc.doc), &d)
			if tc.err == "" {
				require.NoError(t, err)
				assert.Equal(t, TenantParameters{Name: "acme"}, d.Vrf.Tenant)
				return
			}
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestVrfParameters_UnmarshalTenantUnknownKey(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  name: production\n  tenant:\n    name: acme\n    grup: customers\n"), &d)
	assert.EqualError(t, err, `vrf.tenant has no "grup" key`)
}

func TestVrfParameters_UnmarshalMergeKey(t *testing.T) {
	var d Defaults
	require.NoError(t, yaml.Unmarshal([]byte(
		"base: &base\n  name: production\n  rd: \"65000:100\"\nvrf:\n  <<: *base\n  tenant: acme\n"), &d))
	assert.Equal(t, VrfParameters{Name: "production", Rd: "65000:100", Tenant: TenantParameters{Name: "acme"}}, d.Vrf)
}

func TestVrfParameters_UnmarshalTenantMissingName(t *testing.T) {
	var d Defaults
	err := yaml.Unmarshal([]byte("vrf:\n  name: production\n  tenant:\n    group: customers\n"), &d)
	require.Error(t, err)
	assert.EqualError(t, err, "vrf.tenant: mapping requires name")

	for _, name := range []string{`""`, "~"} {
		err = yaml.Unmarshal([]byte("vrf:\n  name: production\n  tenant:\n    name: "+name+"\n"), &d)
		assert.EqualError(t, err, "vrf.tenant: mapping requires name", name)
	}
}

func TestDefaults_Validate(t *testing.T) {
	for _, tc := range []struct {
		name             string
		vrfRd, defaultRd string
		err              string
	}{
		{name: "neither"},
		{name: "vrf rd only", vrfRd: "65000:1"},
		{name: "defaults rd only", defaultRd: "65000:1"},
		{name: "equal", vrfRd: "65000:1", defaultRd: "65000:1"},
		{name: "equal once trimmed", vrfRd: "65000:1 ", defaultRd: " 65000:1"},
		{name: "blank vrf rd", vrfRd: " ", defaultRd: "65000:1"},
		{
			name: "conflict", vrfRd: "65000:1", defaultRd: "65000:2",
			err: `defaults.rd "65000:2" conflicts with defaults.vrf.rd "65000:1"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Defaults{Vrf: VrfParameters{Name: "MyVRF", Rd: tc.vrfRd}, Rd: tc.defaultRd}.Validate()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

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

func TestDefaults_ValidateTenantWrittenTwice(t *testing.T) {
	acme := TenantParameters{Name: "acme", Group: "customers", Description: "d", Comments: "c", Tags: []string{"a"}}
	with := func(f func(*TenantParameters)) TenantParameters {
		tp := acme
		tp.Tags = append([]string(nil), acme.Tags...)
		f(&tp)
		return tp
	}
	const (
		tenantErr = `defaults.tenant and defaults.vrf.tenant name the same NetBox tenant but write it differently`
		groupErr  = `defaults.tenant and defaults.vrf.tenant name the same NetBox tenant group in two ways`
	)
	for _, tc := range []struct {
		name    string
		ip, vrf TenantParameters
		err     string
	}{
		{name: "identical", ip: acme, vrf: acme},
		{name: "fields on one side", ip: acme, vrf: TenantParameters{Name: "acme", Group: "customers"}},
		{name: "fields on the vrf side", ip: TenantParameters{Name: "acme", Group: "customers"}, vrf: acme},
		{name: "description padded", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Description = "d " })},
		{name: "tag padded", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Tags = []string{" a"} })},
		{name: "name padded", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Name = "acme " })},
		{name: "group padded", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Group = " customers" })},
		{name: "other tenant", ip: acme, vrf: TenantParameters{Name: "globex", Group: "partners", Description: "x"}},
		{name: "names without a slug", ip: TenantParameters{Name: "日本", Description: "x"}, vrf: TenantParameters{Name: "中国", Description: "y"}},
		{name: "no vrf tenant", ip: acme},
		{name: "no ip tenant", vrf: acme},
		{name: "blank ip tenant name", ip: TenantParameters{Name: " ", Group: "customers"}},
		{name: "blank vrf tenant name", vrf: TenantParameters{Name: " ", Group: "customers"}},
		{name: "description", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Description = "x" }), err: tenantErr},
		{name: "comments", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Comments = "x" }), err: tenantErr},
		{name: "tags", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Tags = []string{"b"} }), err: tenantErr},
		{
			name: "tags reordered",
			ip:   with(func(tp *TenantParameters) { tp.Tags = []string{"a", "b"} }),
			vrf:  with(func(tp *TenantParameters) { tp.Tags = []string{"b", "a"} }),
			err:  tenantErr,
		},
		{name: "blank description", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Description = "  " }), err: tenantErr},
		{name: "case", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Name = "Acme" }), err: tenantErr},
		{name: "slug alike", ip: TenantParameters{Name: "Acme Corp"}, vrf: TenantParameters{Name: "Acme-Corp"}, err: tenantErr},
		{name: "accent", ip: TenantParameters{Name: "Café"}, vrf: TenantParameters{Name: "Cafe"}, err: tenantErr},
		{name: "other group", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Group = "partners" }), err: tenantErr},
		{name: "ungrouped", ip: acme, vrf: with(func(tp *TenantParameters) { tp.Group = "" }), err: tenantErr},
		{name: "group case", ip: acme, vrf: TenantParameters{Name: "globex", Group: "Customers"}, err: groupErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Defaults{Tenant: tc.ip, Vrf: VrfParameters{Name: "MyVRF", Tenant: tc.vrf}}.Validate()
			if tc.err == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.err)
		})
	}
}
