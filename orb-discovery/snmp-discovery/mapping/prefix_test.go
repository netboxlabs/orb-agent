package mapping

import (
	"bytes"
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
	prefixes := DerivePrefixes(entities, nil, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default())
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
	prefixes := DerivePrefixes(entities, vrfByAddress, nil, nil, defaults, &config.Options{}, slog.Default())
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
	prefixes := DerivePrefixes(entities, vrfByAddress, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default())
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
		nil, nil, nil, defaults, &config.Options{}, slog.Default(),
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
	prefixes := DerivePrefixes([]diode.Entity{ipEntity("10.0.0.1/24")}, nil, nil, nil, defaults, options, slog.Default())
	loc, ok := prefixes[0].(*diode.Prefix).Scope.(*diode.Location)
	require.True(t, ok)
	assert.Equal(t, "Floor-2", *loc.Name)
	require.NotNil(t, loc.Site)
	assert.Equal(t, "DC-1", *loc.Site.Name)

	// Explicit scope_site puts the operator in explicit mode: the cascade
	// is skipped wholesale (no cascaded location can override it).
	defaults.Prefix.ScopeSite = "DC-Explicit"
	prefixes = DerivePrefixes([]diode.Entity{ipEntity("10.0.0.1/24")}, nil, nil, nil, defaults, options, slog.Default())
	site, ok := prefixes[0].(*diode.Prefix).Scope.(*diode.Site)
	require.True(t, ok)
	assert.Equal(t, "DC-Explicit", *site.Name)

	// Cascade off, nothing explicit: no scope.
	prefixes = DerivePrefixes([]diode.Entity{ipEntity("10.0.0.1/24")}, nil, nil, nil,
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
	prefixes := DerivePrefixes(entities, nil, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default())
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
		nil, nil, nil, defaults, &config.Options{}, slog.Default(),
	)
	require.Len(t, prefixes, 1)
	assert.Nil(t, prefixes[0].(*diode.Prefix).Vrf)
}

func TestDerivePrefixes_AttachesVlanOnlyWhenUnanimous(t *testing.T) {
	sviName := "svi-name"
	vlan10 := &diode.VLAN{Vid: int64Ptr(10), Name: strPtr("office")}
	vlan20 := &diode.VLAN{Vid: int64Ptr(20), Name: strPtr("voice")}
	opts := &config.Options{EmitPrefixVlan: &sviName}

	mk := func(addr string, iface *diode.Interface) *diode.IPAddress {
		a := addr
		return &diode.IPAddress{Address: &a, AssignedObject: iface}
	}
	ifA := &diode.Interface{Name: strPtr("Vlan10")}
	ifB := &diode.Interface{Name: strPtr("Vlan20")}
	idx := map[*diode.Interface]int{ifA: 1, ifB: 2}

	t.Run("unanimous", func(t *testing.T) {
		ents := []diode.Entity{mk("10.0.0.1/24", ifA), mk("10.0.0.2/24", ifA)}
		out := DerivePrefixes(ents, nil, map[int]*diode.VLAN{1: vlan10}, idx, nil, opts, slog.Default())
		require.Len(t, out, 1)
		assert.Same(t, vlan10, out[0].(*diode.Prefix).Vlan)
	})

	t.Run("conflicting", func(t *testing.T) {
		// One network reached from two interfaces in different VLANs.
		ents := []diode.Entity{mk("10.0.0.1/24", ifA), mk("10.0.0.2/24", ifB)}
		out := DerivePrefixes(ents, nil, map[int]*diode.VLAN{1: vlan10, 2: vlan20}, idx, nil, opts, slog.Default())
		require.Len(t, out, 1)
		assert.Nil(t, out[0].(*diode.Prefix).Vlan, "a contested VLAN must not be written")
	})

	t.Run("option off emits no vlan", func(t *testing.T) {
		ents := []diode.Entity{mk("10.0.0.1/24", ifA)}
		out := DerivePrefixes(ents, nil, map[int]*diode.VLAN{1: vlan10}, idx, nil, &config.Options{}, slog.Default())
		require.Len(t, out, 1)
		assert.Nil(t, out[0].(*diode.Prefix).Vlan)
	})

	t.Run("partial coverage attaches nothing", func(t *testing.T) {
		// One contributing address resolves, the other does not. Silence is
		// required: a half-attributed prefix is indistinguishable from a bug.
		ents := []diode.Entity{mk("10.0.0.1/24", ifA), mk("10.0.0.2/24", ifB)}
		out := DerivePrefixes(ents, nil, map[int]*diode.VLAN{1: vlan10}, idx, nil, opts, slog.Default())
		require.Len(t, out, 1)
		assert.Nil(t, out[0].(*diode.Prefix).Vlan)
	})
}

// A prefix nobody proposed a VLAN for is the ordinary case on an L3
// switch: one SVI alongside many routed subnets. Only a prefix where at
// least one contributing address proposed a VID and the association was
// still withheld is a genuine partial attribution worth a warning.
func TestDerivePrefixes_WarnsOnlyWhenAVlanWasActuallyProposed(t *testing.T) {
	sviName := "svi-name"
	opts := &config.Options{EmitPrefixVlan: &sviName}
	vlan10 := &diode.VLAN{Vid: int64Ptr(10), Name: strPtr("office")}

	mk := func(addr string, iface *diode.Interface) *diode.IPAddress {
		a := addr
		return &diode.IPAddress{Address: &a, AssignedObject: iface}
	}
	svi := &diode.Interface{Name: strPtr("Vlan10")}
	routedA := &diode.Interface{Name: strPtr("uplink-1")}
	routedB := &diode.Interface{Name: strPtr("uplink-2")}
	routedC := &diode.Interface{Name: strPtr("uplink-3")}
	idx := map[*diode.Interface]int{svi: 1, routedA: 2, routedB: 3, routedC: 4}
	sviVlans := map[int]*diode.VLAN{1: vlan10}

	t.Run("routed prefixes are silent", func(t *testing.T) {
		buf := &bytes.Buffer{}
		ents := []diode.Entity{
			mk("10.0.0.1/24", svi),
			mk("10.1.0.1/24", routedA),
			mk("10.2.0.1/24", routedB),
			mk("10.3.0.1/24", routedC),
		}
		out := DerivePrefixes(ents, nil, sviVlans, idx, nil, opts, newCapturingLogger(buf))
		require.Len(t, out, 4)
		assert.Same(t, vlan10, out[0].(*diode.Prefix).Vlan, "the SVI prefix still resolves")
		for _, p := range out[1:] {
			assert.Nil(t, p.(*diode.Prefix).Vlan, "a routed prefix carries no VLAN")
		}
		assert.NotContains(t, buf.String(), "contested or partial",
			"a prefix nobody proposed a VLAN for is not a contest")
	})

	t.Run("a genuinely partial prefix still warns", func(t *testing.T) {
		buf := &bytes.Buffer{}
		// One network reached from an SVI and from a routed interface: one
		// proposer, one abstainer. Withheld, and worth saying so.
		ents := []diode.Entity{mk("10.0.0.1/24", svi), mk("10.0.0.2/24", routedA)}
		out := DerivePrefixes(ents, nil, sviVlans, idx, nil, opts, newCapturingLogger(buf))
		require.Len(t, out, 1)
		assert.Nil(t, out[0].(*diode.Prefix).Vlan)
		assert.Contains(t, buf.String(), "contested or partial")
	})
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
				nil, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default(),
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
				nil, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default(),
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
	prefixes := DerivePrefixes(entities, nil, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default())
	require.Len(t, prefixes, 2)
	got := make([]string, 0, 2)
	for _, p := range prefixes {
		got = append(got, *(p.(*diode.Prefix)).Prefix)
	}
	assert.Equal(t, []string{"172.24.0.0/24", "2001:db8::/64"}, got)
}

func TestDerivePrefixes_EmitHostPrefixesOptsBackIn(t *testing.T) {
	// Operators who track loopback /32s as NetBox prefixes need a way to keep
	// them; before this option snmp-discovery could only disable prefixes
	// wholesale via emit_prefixes.
	opts := &config.Options{EmitHostPrefixes: boolPtr(true)}
	for _, tc := range []struct {
		name string
		addr string
		want string
	}{
		{"ipv4 host prefix", "10.0.0.1/32", "10.0.0.1/32"},
		{"ipv6 host prefix", "2001:db8::5/128", "2001:db8::5/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := DerivePrefixes(
				[]diode.Entity{ipEntity(tc.addr)},
				nil, nil, nil, &config.Defaults{}, opts, slog.Default(),
			)
			require.Len(t, prefixes, 1)
			assert.Equal(t, tc.want, *(prefixes[0].(*diode.Prefix)).Prefix)
		})
	}
}

func TestDerivePrefixes_EmitHostPrefixesDoesNotResurrectLinkLocal(t *testing.T) {
	// The link-local rule is ungated by the option on purpose: an fe80::x/128
	// is a link-local carrying host length, not a loopback worth tracking. If
	// it were gated, opting in to host prefixes would restore the exact noise
	// the skip removes.
	opts := &config.Options{EmitHostPrefixes: boolPtr(true)}
	for _, addr := range []string{
		"fe80::5a86:70f0:a8:e47f/128",
		"fe80::42:acff:fe12:6/64",
		"fe80::1/10",
		// Wide masks must stay suppressed with the opt-in on too.
		"fe80::1/8",
		"fe80::1/1",
	} {
		t.Run(addr, func(t *testing.T) {
			prefixes := DerivePrefixes(
				[]diode.Entity{ipEntity(addr)},
				nil, nil, nil, &config.Defaults{}, opts, slog.Default(),
			)
			assert.Empty(t, prefixes, "emit_host_prefixes must not resurrect %s", addr)
		})
	}
}

func TestOptions_HostPrefixEmissionEnabled(t *testing.T) {
	// Defaults to FALSE, the opposite of emit_prefixes. A nil receiver must be
	// safe: DerivePrefixes is called with whatever the policy supplied.
	assert.False(t, (*config.Options)(nil).HostPrefixEmissionEnabled(), "nil options")
	assert.False(t, (&config.Options{}).HostPrefixEmissionEnabled(), "unset")
	assert.False(t, (&config.Options{EmitHostPrefixes: boolPtr(false)}).HostPrefixEmissionEnabled())
	assert.True(t, (&config.Options{EmitHostPrefixes: boolPtr(true)}).HostPrefixEmissionEnabled())
}

func TestDerivePrefixes_HostPrefixesStaySuppressedWithNilOptions(t *testing.T) {
	// nil options must behave as the default (suppressed), not panic.
	prefixes := DerivePrefixes(
		[]diode.Entity{ipEntity("10.0.0.1/32"), ipEntity("172.24.0.101/24")},
		nil, nil, nil, &config.Defaults{}, nil, slog.Default(),
	)
	require.Len(t, prefixes, 1)
	assert.Equal(t, "172.24.0.0/24", *(prefixes[0].(*diode.Prefix)).Prefix)
}

func TestDerivePrefixes_LinkLocalJudgedOnAddressNotMaskedNetwork(t *testing.T) {
	// A mask of /8 or wider moves the masked network out of the fe80::/10 bit
	// pattern — fe80::1/8 masks to fe00:: and fe80::1/1 to 8000:: — so testing
	// network.IP let a colossal container prefix through for an address that is
	// plainly link-local. Agents do report nonsense masks, which is why the
	// zero-length guard above this check exists in the first place.
	for _, addr := range []string{
		"fe80::1/10",
		"fe80::1/9",
		"fe80::1/8",
		"fe80::1/1",
		"fe80::1/64",
		"fe80::1/128",
	} {
		t.Run(addr, func(t *testing.T) {
			prefixes := DerivePrefixes(
				[]diode.Entity{ipEntity(addr)},
				nil, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default(),
			)
			assert.Empty(t, prefixes,
				"%s is link-local by address; no prefix may be derived at any mask", addr)
		})
	}
}

func TestDerivePrefixes_WideMaskIPv4LinkLocalStillDerived(t *testing.T) {
	// The address-based test must not start suppressing IPv4: 169.254.0.0/16
	// is link-local to IsLinkLocalUnicast but stays in scope for emission.
	prefixes := DerivePrefixes(
		[]diode.Entity{ipEntity("169.254.10.5/16")},
		nil, nil, nil, &config.Defaults{}, &config.Options{}, slog.Default(),
	)
	require.Len(t, prefixes, 1)
	assert.Equal(t, "169.254.0.0/16", *(prefixes[0].(*diode.Prefix)).Prefix)
}
