package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"
)

func TestParseNetworkInstanceStatePath(t *testing.T) {
	for _, c := range []struct{ path, ni, leaf string }{
		{"/network-instances/network-instance[name=blue]/state/type", "blue", "type"},
		{"/network-instances/network-instance[name=blue]/state/route-distinguisher", "blue", "route-distinguisher"},
	} {
		ni, leaf, ok := parseNetworkInstanceStatePath(c.path)
		require.True(t, ok, c.path)
		require.Equal(t, c.ni, ni)
		require.Equal(t, c.leaf, leaf)
	}
	for _, p := range []string{
		"/network-instances/network-instance[name=blue]/state/router-id",
		"/network-instances/network-instance[name=blue]/vlans/vlan[vlan-id=10]/state/name",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/interface", // membership path, not NI state
		"/network-instances/network-instance[name=blue]/config/type",
		"/interfaces/interface[name=Ethernet1]/state/mtu",
	} {
		_, _, ok := parseNetworkInstanceStatePath(p)
		require.False(t, ok, p)
	}
}

func TestParseNetworkInstanceIfacePath(t *testing.T) {
	ni, id, leaf, ok := parseNetworkInstanceIfacePath("/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/interface")
	require.True(t, ok)
	require.Equal(t, "blue", ni)
	require.Equal(t, "Ethernet2", id)
	require.Equal(t, "interface", leaf)
	_, id, leaf, ok = parseNetworkInstanceIfacePath("/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2.100]/state/subinterface")
	require.True(t, ok)
	require.Equal(t, "Ethernet2.100", id)
	require.Equal(t, "subinterface", leaf)
	for _, p := range []string{
		"/network-instances/network-instance[name=blue]/state/type",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/id",
		"/interfaces/interface[name=Ethernet1]/state/mtu",
	} {
		_, _, _, ok := parseNetworkInstanceIfacePath(p)
		require.False(t, ok, p)
	}
}

func TestTranslateVrfs(t *testing.T) {
	snap := map[string]any{
		"/network-instances/network-instance[name=blue]/state/type":                                                "openconfig-network-instance-types:L3VRF",
		"/network-instances/network-instance[name=blue]/state/route-distinguisher":                                 "65000:1",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/interface":        "Ethernet2",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet2]/state/subinterface":     float64(0),
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet3.100]/state/interface":    "Ethernet3",
		"/network-instances/network-instance[name=blue]/interfaces/interface[id=Ethernet3.100]/state/subinterface": float64(100),
		"/network-instances/network-instance[name=green]/state/type":                                               "openconfig-network-instance-types:L3VRF",
		"/network-instances/network-instance[name=default]/state/type":                                             "openconfig-network-instance-types:DEFAULT_INSTANCE",
		"/network-instances/network-instance[name=default]/interfaces/interface[id=Ethernet1]/state/interface":     "Ethernet1",
	}
	ents, byIface := translateVrfs(snap, nil)

	require.Len(t, ents, 2)
	blue := ents[0].(*diode.VRF)
	green := ents[1].(*diode.VRF)
	require.Equal(t, "blue", *blue.Name)
	require.NotNil(t, blue.Rd)
	require.Equal(t, "65000:1", *blue.Rd)
	require.Equal(t, "green", *green.Name)
	require.Nil(t, green.Rd)

	require.Same(t, blue, byIface["Ethernet2"])
	require.Same(t, blue, byIface["Ethernet3.100"])
	require.Nil(t, byIface["Ethernet1"])
}
