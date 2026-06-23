package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestOptions_ConfigCaptureEnabled(t *testing.T) {
	parse := func(y string) Options {
		var pc PolicyConfig
		require.NoError(t, yaml.Unmarshal([]byte(y), &pc))
		return pc.Options
	}
	// Unset → off.
	unset := parse("defaults: {}")
	assert.False(t, unset.ConfigCaptureEnabled())
	// Explicit true.
	o := parse("options:\n  capture_config: true\n")
	require.NotNil(t, o.CaptureConfig)
	assert.True(t, o.ConfigCaptureEnabled())
	// Explicit false (distinguishable from unset via the pointer).
	o = parse("options:\n  capture_config: false\n")
	require.NotNil(t, o.CaptureConfig)
	assert.False(t, o.ConfigCaptureEnabled())
	// Nil receiver is safe.
	var np *Options
	assert.False(t, np.ConfigCaptureEnabled())
}

func TestUnmarshal_NewDefaults(t *testing.T) {
	y := `
defaults:
  asset_tag: "/components/component[name=Chassis]/state/id"
  ip_address:
    role: mgmt
    tenant: acme
    tags: [ip]
    description: d
    comments: c
  vrf:
    tenant: acme
    description: vd
    comments: vc
    tags: [vrf]
`
	var pc PolicyConfig
	require.NoError(t, yaml.Unmarshal([]byte(y), &pc))
	assert.Equal(t, "/components/component[name=Chassis]/state/id", pc.Defaults.AssetTag)
	assert.Equal(t, "mgmt", pc.Defaults.IPAddress.Role)
	assert.Equal(t, "acme", pc.Defaults.IPAddress.Tenant)
	assert.Equal(t, []string{"ip"}, pc.Defaults.IPAddress.Tags)
	assert.Equal(t, "acme", pc.Defaults.Vrf.Tenant)
	assert.Equal(t, "vd", pc.Defaults.Vrf.Description)
	assert.Equal(t, []string{"vrf"}, pc.Defaults.Vrf.Tags)
}

func TestMergeDefaults_NewFieldsOverride(t *testing.T) {
	base := &Defaults{
		AssetTag:  "base-tag",
		IPAddress: IPAddressDefaults{Role: "base-role", Tenant: "base-tenant", Tags: []string{"a"}},
		Vrf:       VRFDefaults{Tenant: "base-vt", Tags: []string{"x"}},
	}
	over := &Defaults{
		AssetTag:  "over-tag",
		IPAddress: IPAddressDefaults{Role: "over-role", Tags: []string{"b"}},
		Vrf:       VRFDefaults{Description: "over-desc", Tags: []string{"y"}},
	}
	m := MergeDefaults(base, over)
	assert.Equal(t, "over-tag", m.AssetTag)
	assert.Equal(t, "over-role", m.IPAddress.Role)     // overridden
	assert.Equal(t, "base-tenant", m.IPAddress.Tenant) // not overridden → base kept
	assert.Equal(t, []string{"b"}, m.IPAddress.Tags)   // override slice wins
	assert.Equal(t, "base-vt", m.Vrf.Tenant)           // not overridden
	assert.Equal(t, "over-desc", m.Vrf.Description)    // overridden
	assert.Equal(t, []string{"y"}, m.Vrf.Tags)

	// Slices must not alias the inputs.
	m.IPAddress.Tags[0] = "mutated"
	assert.Equal(t, []string{"b"}, over.IPAddress.Tags, "merge must clone override slices")
}
