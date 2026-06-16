package mapping

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadBundledBase(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, ok := store.Get("_base")
	require.True(t, ok)
	require.Equal(t, "/system/state/hostname", base.Device.Hostname)
	require.Equal(t, "/interfaces/interface", base.Interfaces.ListPath)
}

func TestOverlayInheritsBase(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(`
extends: _base
match:
  vendor: ACME
components:
  keys:
    serial: state/serial-number
`), 0o644))

	store, err := LoadProfiles(dir)
	require.NoError(t, err)
	p, ok := store.Get("acme")
	require.True(t, ok)
	// inherited from _base:
	require.Equal(t, "/system/state/hostname", p.Device.Hostname)
	require.Equal(t, "/interfaces/interface", p.Interfaces.ListPath)
	// overridden:
	require.Equal(t, "state/serial-number", p.Components.Keys["serial"])
	// untouched base key still present:
	require.Equal(t, "name", p.Components.Keys["name"])
}

func TestMatchFallsBackToBase(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	p := store.Match(MatchInput{Vendor: "TotallyUnknown"})
	require.Equal(t, "_base", p.Name)
}

// TestOverrideBadExtendsFallsBackToBundled verifies that an override reusing a
// bundled filename but with an unresolvable `extends` does NOT delete the
// built-in — the bundled profile is restored and remains selectable.
func TestOverrideBadExtendsFallsBackToBundled(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "arista_eos.yaml"), []byte(`
extends: nonexistent_parent
match:
  vendor: Arista
`), 0o600))
	store, err := LoadProfiles(dir)
	require.NoError(t, err)
	p := store.Match(MatchInput{Vendor: "Arista"})
	require.Equal(t, "arista_eos", p.Name, "bad override must fall back to bundled arista_eos, not delete it")
	require.Equal(t, "/system/state/hostname", p.Device.Hostname) // bundled inherits _base
}

// TestOverrideLeafOnlyKeepsBundledMatch verifies that a same-name override that
// changes only leaf paths (extends _base, omits match) keeps the bundled vendor
// criteria, so auto-detection still selects it instead of falling back to _base.
func TestOverrideLeafOnlyKeepsBundledMatch(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "arista_eos.yaml"), []byte(`
extends: _base
interfaces:
  keys:
    description: state/description
`), 0o600))
	store, err := LoadProfiles(dir)
	require.NoError(t, err)
	p := store.Match(MatchInput{Vendor: "Arista"})
	require.Equal(t, "arista_eos", p.Name, "leaf-only override must keep the bundled Arista match")
	require.Equal(t, "state/description", p.Interfaces.Keys["description"], "override leaf applied")
	require.Equal(t, "/system/state/hostname", p.Device.Hostname) // _base still inherited
}

// TestOverrideBadBaseDoesNotBreakChildren guards the order-independent fallback:
// a broken _base override must be restored before children that extend it are
// resolved, so a vendor overlay (arista_eos) isn't skipped because it happened to
// resolve against the bad _base first (map iteration order is randomized).
func TestOverrideBadBaseDoesNotBreakChildren(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "_base.yaml"), []byte(`
extends: missing_parent
`), 0o600))
	store, err := LoadProfiles(dir)
	require.NoError(t, err)
	// _base restored from the bundle, so it loads and children resolve against it.
	base, ok := store.Get("_base")
	require.True(t, ok)
	require.Equal(t, "/system/state/hostname", base.Device.Hostname)
	p := store.Match(MatchInput{Vendor: "Arista"})
	require.Equal(t, "arista_eos", p.Name, "vendor overlay must survive a broken _base override")
}

func TestMatchByVendor(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(`
extends: _base
match:
  vendor: ACME
`), 0o644))
	store, err := LoadProfiles(dir)
	require.NoError(t, err)
	p := store.Match(MatchInput{Vendor: "ACME Networks"})
	require.Equal(t, "acme", p.Name)
}

func TestMatchVendorAliases(t *testing.T) {
	// The bundled nvidia_cumulus overlay uses the alias list
	// "nvidia,cumulus,mellanox"; any of those org strings must resolve to it.
	store, err := LoadProfiles("")
	require.NoError(t, err)
	for _, vendor := range []string{
		"Cumulus Networks, Inc.",
		"NVIDIA Corporation",
		"Mellanox Technologies",
	} {
		p := store.Match(MatchInput{Vendor: vendor})
		require.Equal(t, "nvidia_cumulus", p.Name, "vendor %q should match nvidia_cumulus", vendor)
	}
	// Unknown vendor still falls back to _base.
	p := store.Match(MatchInput{Vendor: "Totally Unknown"})
	require.Equal(t, "_base", p.Name)
}

func TestMatchAliasSpecificityLongestWins(t *testing.T) {
	// Two overlays could match the input; the one whose LONGEST matched alias is
	// longer wins, regardless of name ordering.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "generic.yaml"), []byte(`
extends: _base
match:
  vendor: net
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "specific.yaml"), []byte(`
extends: _base
match:
  vendor: acme,acme networks
`), 0o644))
	store, err := LoadProfiles(dir)
	require.NoError(t, err)
	// "ACME Networks" contains "net" (len 3), "acme" (len 4), and
	// "acme networks" (len 13); the longest matched alias belongs to specific.
	p := store.Match(MatchInput{Vendor: "ACME Networks"})
	require.Equal(t, "specific", p.Name)
}

func TestSubscribePathsAreCuratedLeaves(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	paths := base.SubscribePaths()
	// device leaves + per-interface/-component wildcard leaves; never the bare list root
	require.Contains(t, paths, "/system/state/hostname")
	require.Contains(t, paths, "/interfaces/interface[name=*]/state/admin-status")
	require.NotContains(t, paths, "/interfaces/interface")
	for _, p := range paths {
		require.NotContains(t, p, "oper-status") // §6: volatile telemetry excluded
	}
}

func TestAllowsPath(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.True(t, base.AllowsPath("/system/state/hostname"))
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/state/admin-status"))
	require.True(t, base.AllowsPath("/components/component[name=Linecard1]/state/serial-no"))
	require.False(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/state/oper-status"))
	require.False(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/state/counters/in-octets"))
}

func TestSubscribePathsIncludeIPSubtree(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	paths := base.SubscribePaths()
	require.Contains(t, paths, "/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]/ipv4/addresses/address[ip=*]/state/prefix-length")
	require.Contains(t, paths, "/interfaces/interface[name=*]/subinterfaces/subinterface[index=*]/ipv6/addresses/address[ip=*]/state/prefix-length")
}

func TestAllowsPathIPSubtree(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length"))
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=100]/ipv6/addresses/address[ip=2001:db8::1]/state/prefix-length"))
	require.False(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/state/counters/in-pkts")) // not an address leaf
}

func TestSubscribePathsIncludeInterfaceEnrichment(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	paths := base.SubscribePaths()
	require.Contains(t, paths, "/interfaces/interface[name=*]/ethernet/state/port-speed")
	require.Contains(t, paths, "/interfaces/interface[name=*]/ethernet/state/mac-address")
	require.Contains(t, paths, "/interfaces/interface[name=*]/ethernet/state/aggregate-id")
}

func TestAllowsPathInterfaceEnrichment(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/ethernet/state/port-speed"))
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/ethernet/state/mac-address"))
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/ethernet/state/aggregate-id"))
	require.False(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/ethernet/state/counters/in-octets"))
}

func TestSubscribePathsIncludeSwitchedVlan(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	paths := base.SubscribePaths()
	require.Contains(t, paths, "/interfaces/interface[name=*]/ethernet/switched-vlan/state/interface-mode")
	require.Contains(t, paths, "/interfaces/interface[name=*]/ethernet/switched-vlan/state/trunk-vlans")
	require.Contains(t, paths, "/interfaces/interface[name=*]/aggregation/switched-vlan/state/access-vlan")
	require.Contains(t, paths, "/interfaces/interface[name=*]/aggregation/switched-vlan/state/native-vlan")
}

func TestAllowsPathSwitchedVlan(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/interface-mode"))
	require.True(t, base.AllowsPath("/interfaces/interface[name=Po1]/aggregation/switched-vlan/state/trunk-vlans"))
	require.False(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/counters/in"))
}

func TestSubscribePathsIncludeNIVlans(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	paths := base.SubscribePaths()
	require.Contains(t, paths, "/network-instances/network-instance[name=*]/vlans/vlan[vlan-id=*]/state/name")
	require.Contains(t, paths, "/network-instances/network-instance[name=*]/vlans/vlan[vlan-id=*]/state/status")
}

func TestAllowsPathNIVlans(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.True(t, base.AllowsPath("/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/name"))
	require.True(t, base.AllowsPath("/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/status"))
	require.False(t, base.AllowsPath("/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/tpid"))
}

func TestSubscribePathsIncludeVrf(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	paths := base.SubscribePaths()
	require.Contains(t, paths, "/network-instances/network-instance[name=*]/state/type")
	require.Contains(t, paths, "/network-instances/network-instance[name=*]/state/route-distinguisher")
	require.Contains(t, paths, "/network-instances/network-instance[name=*]/interfaces/interface[id=*]/state/interface")
	require.Contains(t, paths, "/network-instances/network-instance[name=*]/interfaces/interface[id=*]/state/subinterface")
}

func TestAllowsPathVrf(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.True(t, base.AllowsPath("/network-instances/network-instance[name=blue]/state/type"))
	require.True(t, base.AllowsPath("/network-instances/network-instance[name=blue]/state/route-distinguisher"))
	require.True(t, base.AllowsPath("/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/interface"))
	require.False(t, base.AllowsPath("/network-instances/network-instance[name=blue]/state/router-id"))
}

func TestSubscribePathsIncludeDuplex(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.Contains(t, base.SubscribePaths(), "/interfaces/interface[name=*]/ethernet/state/negotiated-duplex-mode")
	require.True(t, base.AllowsPath("/interfaces/interface[name=Ethernet1]/ethernet/state/negotiated-duplex-mode"))
}

func TestAllowsDelete(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.True(t, base.AllowsDelete("/interfaces/interface[name=Ethernet1]")) // list-entry delete
	require.True(t, base.AllowsDelete("/interfaces/interface"))                 // whole list (ancestor)
	require.True(t, base.AllowsDelete("/components/component[name=Linecard1]"))
	// network-instance deletes (VRF removal, and VLAN/interface entries beneath
	// it) must be honored so ON_CHANGE removals reconcile out of the model.
	require.True(t, base.AllowsDelete("/network-instances/network-instance[name=blue]"))
	require.True(t, base.AllowsDelete("/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]"))
	require.True(t, base.AllowsDelete("/network-instances/network-instance")) // whole list (ancestor)
	require.False(t, base.AllowsDelete("/acl/acl-sets"))
	// HIGH: a similarly-named sibling must NOT be treated as within scope
	require.False(t, base.AllowsDelete("/interfaces/interface-state"))
	require.False(t, base.AllowsDelete("/interfaces/interfaces"))
}

func TestMatchBundledVendorProfiles(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	cases := map[string]string{
		"Cisco":   "cisco",
		"Juniper": "juniper",
		"Huawei":  "huawei",
		"Dell":    "dell_os10",
		"SONiC":   "sonic",
	}
	for vendor, want := range cases {
		p := store.Match(MatchInput{Vendor: vendor})
		require.Equal(t, want, p.Name, "vendor %q should select %q", vendor, want)
		// Each overlay inherits _base paths (extends: _base).
		require.Equal(t, "/system/state/hostname", p.Device.Hostname, "%s inherits _base", want)
		require.Equal(t, "/interfaces/interface", p.Interfaces.ListPath, "%s inherits _base", want)
	}
	// An unknown vendor still falls back to _base.
	require.Equal(t, "_base", store.Match(MatchInput{Vendor: "TotallyUnknown"}).Name)
}
