package mapping

import (
	"log/slog"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

func ipEntity(addr string) *diode.IPAddress {
	a := addr
	return &diode.IPAddress{Address: &a}
}

func boolPtr(b bool) *bool { return &b }

func TestDerivePrefixes_DedupesPerNetworkAndVrf(t *testing.T) {
	entities := []diode.Entity{
		ipEntity("10.0.0.1/24"),
		ipEntity("10.0.0.2/24"), // same network → deduped
		ipEntity("10.1.0.1/24"), // second network
		ipEntity("2001:db8::1/64"),
		ipEntity("bogus"), // unparseable → skipped
	}
	prefixes := DerivePrefixes(entities, nil, &config.Defaults{}, &config.Options{}, slog.Default())
	require.Len(t, prefixes, 3)
	got := make([]string, 0, 3)
	for _, p := range prefixes {
		got = append(got, *(p.(*diode.Prefix)).Prefix)
	}
	assert.Equal(t, []string{"10.0.0.0/24", "10.1.0.0/24", "2001:db8::/64"}, got)
}

func TestDerivePrefixes_DiscoveredVrfWinsOverPrefixDefaults(t *testing.T) {
	mgmtName := "MGMT"
	mgmt := &diode.VRF{Name: &mgmtName}
	defaults := &config.Defaults{
		Prefix: config.PrefixDefaults{
			Vrf:     config.VrfParameters{Name: "prefix-default"},
			VrfIpv6: config.VrfParameters{Name: "prefix-default-v6", Rd: "65000:6"},
		},
	}
	entities := []diode.Entity{
		ipEntity("10.0.0.1/24"),    // discovered VRF via vrfByAddress
		ipEntity("10.9.0.1/24"),    // falls to prefix defaults (ipv4 → vrf)
		ipEntity("2001:db8::1/64"), // falls to prefix defaults (ipv6 → vrf_ipv6)
	}
	vrfByAddress := map[string]*diode.VRF{"10.0.0.1/24": mgmt}
	prefixes := DerivePrefixes(entities, vrfByAddress, defaults, &config.Options{}, slog.Default())
	require.Len(t, prefixes, 3)
	byNet := map[string]*diode.Prefix{}
	for _, p := range prefixes {
		pp := p.(*diode.Prefix)
		byNet[*pp.Prefix] = pp
	}
	assert.Same(t, mgmt, byNet["10.0.0.0/24"].Vrf)
	require.NotNil(t, byNet["10.9.0.0/24"].Vrf)
	assert.Equal(t, "prefix-default", *byNet["10.9.0.0/24"].Vrf.Name)
	require.NotNil(t, byNet["2001:db8::/64"].Vrf)
	assert.Equal(t, "prefix-default-v6", *byNet["2001:db8::/64"].Vrf.Name)
	assert.Equal(t, "65000:6", *byNet["2001:db8::/64"].Vrf.Rd)
}

func TestDerivePrefixes_SameNetworkDifferentVrfsBothEmitted(t *testing.T) {
	redName, bluName := "RED", "BLU"
	red := &diode.VRF{Name: &redName}
	blu := &diode.VRF{Name: &bluName}
	entities := []diode.Entity{
		ipEntity("10.0.0.1/24"),
		ipEntity("10.0.0.2/24"),
	}
	vrfByAddress := map[string]*diode.VRF{
		"10.0.0.1/24": red,
		"10.0.0.2/24": blu,
	}
	prefixes := DerivePrefixes(entities, vrfByAddress, &config.Defaults{}, &config.Options{}, slog.Default())
	require.Len(t, prefixes, 2, "same network in two VRFs is two NetBox prefixes")
}

func TestDerivePrefixes_DefaultsAndExplicitScope(t *testing.T) {
	defaults := &config.Defaults{
		Tags: []string{"global"},
		Prefix: config.PrefixDefaults{
			Description: "derived",
			Role:        "lan",
			Tenant:      "net-ops",
			Tags:        []string{"prefix"},
			ScopeSite:   "DC-East",
		},
	}
	prefixes := DerivePrefixes(
		[]diode.Entity{ipEntity("10.0.0.1/24")},
		nil, defaults, &config.Options{}, slog.Default(),
	)
	require.Len(t, prefixes, 1)
	p := prefixes[0].(*diode.Prefix)
	assert.Equal(t, "derived", *p.Description)
	assert.Equal(t, "lan", *p.Role.Name)
	assert.Equal(t, "net-ops", *p.Tenant.Name)
	require.Len(t, p.Tags, 2)
	site, ok := p.Scope.(*diode.Site)
	require.True(t, ok)
	assert.Equal(t, "DC-East", *site.Name)
}

func TestDerivePrefixes_ScopeCascadeAndExplicitMode(t *testing.T) {
	on := true
	// Cascade on, no explicit scope: location (with site) wins.
	defaults := &config.Defaults{Site: "DC-1", Location: "Floor-2"}
	options := &config.Options{PropagateDefaultsToPrefixScope: &on}
	prefixes := DerivePrefixes([]diode.Entity{ipEntity("10.0.0.1/24")}, nil, defaults, options, slog.Default())
	loc, ok := prefixes[0].(*diode.Prefix).Scope.(*diode.Location)
	require.True(t, ok)
	assert.Equal(t, "Floor-2", *loc.Name)
	require.NotNil(t, loc.Site)
	assert.Equal(t, "DC-1", *loc.Site.Name)

	// Explicit scope_site puts the operator in explicit mode: the cascade
	// is skipped wholesale (no cascaded location can override it).
	defaults.Prefix.ScopeSite = "DC-Explicit"
	prefixes = DerivePrefixes([]diode.Entity{ipEntity("10.0.0.1/24")}, nil, defaults, options, slog.Default())
	site, ok := prefixes[0].(*diode.Prefix).Scope.(*diode.Site)
	require.True(t, ok)
	assert.Equal(t, "DC-Explicit", *site.Name)

	// Cascade off, nothing explicit: no scope.
	prefixes = DerivePrefixes([]diode.Entity{ipEntity("10.0.0.1/24")}, nil,
		&config.Defaults{Site: "DC-1"}, &config.Options{}, slog.Default())
	assert.Nil(t, prefixes[0].(*diode.Prefix).Scope)
}

func TestDerivePrefixes_SkipsZeroMaskAndV4Mapped(t *testing.T) {
	entities := []diode.Entity{
		// Agent quirk: ipAdEntNetMask 0.0.0.0 → /0. Must never become a
		// 0.0.0.0/0 container prefix.
		ipEntity("192.168.1.1/0"),
		// IPv4-mapped IPv6: ParseCIDR would reclassify to dotted-quad,
		// producing an IPv4 prefix that isn't the parent of its own
		// (IPv6) address object.
		ipEntity("::ffff:10.0.0.1/128"),
		// IPv6 default-route-mask analog.
		ipEntity("2001:db8::1/0"),
		// Sanity: a real network still derives.
		ipEntity("10.0.0.1/24"),
	}
	prefixes := DerivePrefixes(entities, nil, &config.Defaults{}, &config.Options{}, slog.Default())
	require.Len(t, prefixes, 1)
	assert.Equal(t, "10.0.0.0/24", *(prefixes[0].(*diode.Prefix)).Prefix)
}

func TestDerivePrefixes_NamelessPrefixVrfDropsWithoutPanic(t *testing.T) {
	defaults := &config.Defaults{
		Prefix: config.PrefixDefaults{
			Vrf: config.VrfParameters{Rd: "65000:1"}, // nameless → dropped + warned
		},
	}
	prefixes := DerivePrefixes(
		[]diode.Entity{ipEntity("10.0.0.1/24")},
		nil, defaults, &config.Options{}, slog.Default(),
	)
	require.Len(t, prefixes, 1)
	assert.Nil(t, prefixes[0].(*diode.Prefix).Vrf)
}

func TestPrefixEmissionEnabled_DefaultOnOptOut(t *testing.T) {
	assert.True(t, (&config.Options{}).PrefixEmissionEnabled())
	var nilOpts *config.Options
	assert.True(t, nilOpts.PrefixEmissionEnabled())
	assert.False(t, (&config.Options{EmitPrefixes: boolPtr(false)}).PrefixEmissionEnabled())
	assert.True(t, (&config.Options{EmitPrefixes: boolPtr(true)}).PrefixEmissionEnabled())
}
