package mapping

import (
	"math"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"
)

func TestParseSwitchedVlanPath(t *testing.T) {
	lp := "/interfaces/interface"
	for _, c := range []struct{ path, iface, leaf string }{
		{"/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/interface-mode", "Ethernet1", "interface-mode"},
		{"/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/access-vlan", "Ethernet1", "access-vlan"},
		{"/interfaces/interface[name=Po1]/aggregation/switched-vlan/state/trunk-vlans", "Po1", "trunk-vlans"},
		{"/interfaces/interface[name=Eth1/1]/ethernet/switched-vlan/state/native-vlan", "Eth1/1", "native-vlan"},
	} {
		iface, leaf, ok := parseSwitchedVlanPath(c.path, lp)
		require.True(t, ok, c.path)
		require.Equal(t, c.iface, iface)
		require.Equal(t, c.leaf, leaf)
	}
	for _, p := range []string{
		"/interfaces/interface[name=Ethernet1]/state/mtu",
		"/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/counters/in",
		"/interfaces/interface[name=Ethernet1]/ethernet/state/port-speed",
	} {
		_, _, ok := parseSwitchedVlanPath(p, lp)
		require.False(t, ok, p)
	}
}

func TestSafeVid(t *testing.T) {
	for _, in := range []any{1, 4094, "10", int64(100), float64(200), uint64(300), uint16(40)} {
		_, ok := safeVid(in)
		require.True(t, ok)
	}
	for _, in := range []any{0, 4095, -1, true, false, "x", "", nil} {
		_, ok := safeVid(in)
		require.False(t, ok)
	}
	// Out-of-range / non-finite floats are rejected BEFORE the int64 conversion
	// (an out-of-range float->int64 is implementation-defined in Go).
	for _, in := range []any{
		float64(0), float64(4095), float64(-1), 1e18,
		math.NaN(), math.Inf(1), math.Inf(-1),
	} {
		_, ok := safeVid(in)
		require.False(t, ok, "float %v must be rejected", in)
	}
	v, _ := safeVid("4094")
	require.Equal(t, int64(4094), v)
}

func TestExpandTrunkVlans(t *testing.T) {
	require.Equal(t, []int64{20, 30, 31, 32}, expandTrunkVlans([]any{float64(20), "30..32"}))
	require.Equal(t, []int64{100}, expandTrunkVlans("100"))                         // lone scalar
	require.Equal(t, []int64{1, 2, 3}, expandTrunkVlans([]any{"3", "1", "2", "2"})) // sort + dedup
	// clamp a malformed huge range to <=4094 entries (bound, no OOM)
	require.Len(t, expandTrunkVlans([]any{"1..999999"}), 4094)
	// out-of-range / reversed skipped
	require.Empty(t, expandTrunkVlans([]any{"5000..6000", "10..5", "x"}))
}

func TestOCVlanMode(t *testing.T) {
	require.Equal(t, "access", ocVlanMode["ACCESS"])
	require.Equal(t, "tagged", ocVlanMode["TRUNK"])
	_, ok := ocVlanMode["BOGUS"]
	require.False(t, ok)
}

func TestTranslateSwitchports(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1"), Site: &diode.Site{Name: strptr("lab")}}
	eth1 := &diode.Interface{Device: dev, Name: strptr("Ethernet1")}
	eth2 := &diode.Interface{Device: dev, Name: strptr("Ethernet2")}
	idx := map[string]*diode.Interface{"Ethernet1": eth1, "Ethernet2": eth2}
	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/interface-mode": "ACCESS",
		"/interfaces/interface[name=Ethernet1]/ethernet/switched-vlan/state/access-vlan":    float64(10),
		"/interfaces/interface[name=Ethernet2]/ethernet/switched-vlan/state/interface-mode": "TRUNK",
		"/interfaces/interface[name=Ethernet2]/ethernet/switched-vlan/state/native-vlan":    float64(1),
		"/interfaces/interface[name=Ethernet2]/ethernet/switched-vlan/state/trunk-vlans":    []any{float64(10), "20..21"},
	}
	b := newVlanBuilder(dev, nil, nil)
	translateSwitchports(base, snap, b, idx)

	require.Equal(t, "access", *eth1.Mode)
	require.Equal(t, int64(10), *eth1.UntaggedVlan.Vid)
	require.Equal(t, "VLAN10", *eth1.UntaggedVlan.Name) // placeholder (no defs)
	require.Empty(t, eth1.TaggedVlans)

	require.Equal(t, "tagged", *eth2.Mode)
	require.Equal(t, int64(1), *eth2.UntaggedVlan.Vid)
	var taggedVids []int64
	for _, v := range eth2.TaggedVlans {
		taggedVids = append(taggedVids, *v.Vid)
	}
	require.Equal(t, []int64{10, 20, 21}, taggedVids)

	// dedup: VLAN10 shared between eth1.UntaggedVlan and eth2.TaggedVlans
	require.Same(t, eth1.UntaggedVlan, findVlan(eth2.TaggedVlans, 10))

	emitted := map[int64]bool{}
	for _, e := range b.emitted() {
		emitted[*e.(*diode.VLAN).Vid] = true
	}
	require.Equal(t, map[int64]bool{1: true, 10: true, 20: true, 21: true}, emitted)
}

func findVlan(vs []*diode.VLAN, vid int64) *diode.VLAN {
	for _, v := range vs {
		if *v.Vid == vid {
			return v
		}
	}
	return nil
}
