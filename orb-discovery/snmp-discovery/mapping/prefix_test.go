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

func TestDerivePrefixes_SkipsHostAndIPv6LinkLocal(t *testing.T) {
	// A Prefix derived from a host address only restates it, and an fe80::
	// prefix is per-link churn. Both produced large volumes of spurious
	// prefixes on real networks. The IPAddress entities are untouched.
	for _, tc := range []struct {
		name string
		addr string
	}{
		{"ipv4 host prefix", "10.0.0.1/32"},
		{"ipv6 host prefix", "2001:db8::5/128"},
		{"ipv6 link-local, host length", "fe80::5a86:70f0:a8:e47f/128"},
		{"ipv6 link-local, /64", "fe80::42:acff:fe12:6/64"},
		{"ipv6 link-local at its own /10", "fe80::1/10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := DerivePrefixes(
				[]diode.Entity{ipEntity(tc.addr)},
				nil, &config.Defaults{}, &config.Options{}, slog.Default(),
			)
			assert.Empty(t, prefixes, "no prefix may be derived from %s", tc.addr)
		})
	}
}

func TestDerivePrefixes_KeepsOrdinaryNetworks(t *testing.T) {
	// The skip is narrowly scoped. IPv4 link-local and the loopback net are
	// ordinary networks by mask and keep the existing behavior; /31 and /127
	// are real point-to-point subnets, not host routes.
	for _, tc := range []struct {
		name string
		addr string
		want string
	}{
		{"ipv4 /24", "172.24.0.101/24", "172.24.0.0/24"},
		{"ipv4 /31 p2p", "10.1.1.0/31", "10.1.1.0/31"},
		{"ipv4 link-local", "169.254.10.5/16", "169.254.0.0/16"},
		{"ipv4 loopback net", "127.0.0.1/8", "127.0.0.0/8"},
		{"ipv6 /64", "2001:db8::1/64", "2001:db8::/64"},
		{"ipv6 /127 p2p", "2001:db8::2/127", "2001:db8::2/127"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := DerivePrefixes(
				[]diode.Entity{ipEntity(tc.addr)},
				nil, &config.Defaults{}, &config.Options{}, slog.Default(),
			)
			require.Len(t, prefixes, 1)
			assert.Equal(t, tc.want, *(prefixes[0].(*diode.Prefix)).Prefix)
		})
	}
}

func TestDerivePrefixes_SkippedAddressDoesNotDropSiblings(t *testing.T) {
	// A skipped address must not cost its neighbours their prefixes.
	entities := []diode.Entity{
		ipEntity("172.24.0.101/24"),
		ipEntity("10.0.0.1/32"),             // host prefix → skipped
		ipEntity("2001:db8::1/64"),          //
		ipEntity("fe80::42:acff:fe12:6/64"), // link-local → skipped
	}
	prefixes := DerivePrefixes(entities, nil, &config.Defaults{}, &config.Options{}, slog.Default())
	require.Len(t, prefixes, 2)
	got := make([]string, 0, 2)
	for _, p := range prefixes {
		got = append(got, *(p.(*diode.Prefix)).Prefix)
	}
	assert.Equal(t, []string{"172.24.0.0/24", "2001:db8::/64"}, got)
}
