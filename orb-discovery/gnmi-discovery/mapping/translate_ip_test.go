package mapping

import (
	"regexp"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"
)

func TestParseIPAddressPath(t *testing.T) {
	lp := "/interfaces/interface"
	iface, idx, fam, ip, leaf, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length", lp)
	require.True(t, ok)
	require.Equal(t, "Ethernet1", iface)
	require.Equal(t, "0", idx)
	require.Equal(t, "ipv4", fam)
	require.Equal(t, "10.0.0.1", ip)
	require.Equal(t, "state/prefix-length", leaf)
}

func TestParseIPAddressPathV6(t *testing.T) {
	lp := "/interfaces/interface"
	iface, idx, fam, ip, leaf, ok := parseIPAddressPath(
		"/interfaces/interface[name=Eth1/1]/subinterfaces/subinterface[index=100]/ipv6/addresses/address[ip=2001:db8::1]/state/prefix-length", lp)
	require.True(t, ok)
	require.Equal(t, "Eth1/1", iface) // slash in the interface key survives (split on ']')
	require.Equal(t, "100", idx)
	require.Equal(t, "ipv6", fam)
	require.Equal(t, "2001:db8::1", ip) // colons in the v6 key survive
	require.Equal(t, "state/prefix-length", leaf)
}

func TestParseIPAddressPathNonMatch(t *testing.T) {
	lp := "/interfaces/interface"
	for _, p := range []string{
		"/interfaces/interface[name=Ethernet1]/state/mtu",      // not an IP path
		"/system/state/hostname",                               // unrelated
		"/components/component[name=Chassis1]/state/serial-no", // unrelated
	} {
		_, _, _, _, _, ok := parseIPAddressPath(p, lp)
		require.False(t, ok, p)
	}
}

// TestTranslateIPsHonorsExcludes verifies that addresses on an interface matched
// by interface_exclude_patterns are dropped (so they aren't ingested via a stub
// interface, and translatePrefixes never derives prefixes from them).
func TestTranslateIPsHonorsExcludes(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length":    31,
		"/interfaces/interface[name=Management1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=192.0.2.1]/state/prefix-length": 24,
	}
	ents := translateIPs(base, snap, dev, nil, []*regexp.Regexp{regexp.MustCompile("^Management")})

	var addrs []string
	for _, e := range ents {
		if ip, ok := e.(*diode.IPAddress); ok {
			addrs = append(addrs, *ip.Address)
		}
	}
	require.Equal(t, []string{"10.0.0.1/31"}, addrs, "excluded Management1's IP must be dropped")
}

func TestTranslateIPsParentAndSubinterface(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	snap := map[string]any{
		// index 0 -> parent Ethernet1
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length": 31,
		// index 100 -> child Ethernet1.100
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=100]/ipv4/addresses/address[ip=192.0.2.1]/state/prefix-length": 24,
		// v6 on parent
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv6/addresses/address[ip=2001:db8::1]/state/prefix-length": 64,
		// missing prefix-length -> skipped (no prefix leaf for this ip)
		"/interfaces/interface[name=Ethernet2]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.9.9.9]/state/ip": "10.9.9.9",
	}
	ents := translateIPs(base, snap, dev, nil, nil)

	var ips []*diode.IPAddress
	var subifs []*diode.Interface
	for _, e := range ents {
		switch v := e.(type) {
		case *diode.IPAddress:
			ips = append(ips, v)
		case *diode.Interface:
			subifs = append(subifs, v)
		}
	}
	// 3 addresses with prefix-length; the no-prefix one is skipped
	require.Len(t, ips, 3)
	// exactly one child subinterface (Ethernet1.100), virtual, parent Ethernet1
	require.Len(t, subifs, 1)
	require.Equal(t, "Ethernet1.100", *subifs[0].Name)
	require.Equal(t, "virtual", *subifs[0].Type)
	require.Equal(t, "Ethernet1", *subifs[0].Parent.Name)

	byAddr := map[string]*diode.IPAddress{}
	for _, ip := range ips {
		byAddr[*ip.Address] = ip
	}
	require.Equal(t, "active", *byAddr["10.0.0.1/31"].Status)
	// index 0 -> assigned to parent Ethernet1
	require.Equal(t, "Ethernet1", *byAddr["10.0.0.1/31"].AssignedObject.(*diode.Interface).Name)
	// index 100 -> assigned to child subinterface
	require.Equal(t, "Ethernet1.100", *byAddr["192.0.2.1/24"].AssignedObject.(*diode.Interface).Name)
	// v6 present
	require.Contains(t, byAddr, "2001:db8::1/64")
	// the no-prefix-length address was skipped
	require.NotContains(t, byAddr, "10.9.9.9/")
}

func TestAssignPrimaryIP(t *testing.T) {
	mk := func() []diode.Entity {
		dev := &diode.Device{Name: strptr("r1")}
		return []diode.Entity{
			dev,
			&diode.IPAddress{Address: strptr("10.0.0.1/31"), AssignedObject: &diode.Interface{Device: dev, Name: strptr("Ethernet1")}},
			&diode.IPAddress{Address: strptr("2001:db8::1/64"), AssignedObject: &diode.Interface{Device: dev, Name: strptr("Ethernet1")}},
		}
	}

	// v4 match -> PrimaryIp4 retains the assigned interface (NetBox requires the
	// IP to be assigned to the device), with the cycle broken via a device copy
	// that has its primary IPs cleared. The return is the LIVE matched IPAddress
	// (the cycle-closer), still present in the entities slice.
	e := mk()
	got := AssignPrimaryIP(e, "10.0.0.1")
	require.NotNil(t, got, "must return the matched live IPAddress")
	require.Same(t, e[1], got, "must return the LIVE matched IPAddress (pointer identity), not a snapshot")
	p4 := e[0].(*diode.Device).PrimaryIp4
	require.NotNil(t, p4)
	require.Equal(t, "10.0.0.1/31", *p4.Address)
	pifc, ok := p4.AssignedObject.(*diode.Interface)
	require.True(t, ok, "primary IP must retain its assigned interface")
	require.Equal(t, "Ethernet1", *pifc.Name)
	require.NotNil(t, pifc.Device)
	require.Nil(t, pifc.Device.PrimaryIp4, "cycle break: embedded device copy has no primary IP")
	require.Nil(t, pifc.Device.PrimaryIp6)
	require.Nil(t, e[0].(*diode.Device).PrimaryIp6)

	// v6 match -> PrimaryIp6
	e = mk()
	got = AssignPrimaryIP(e, "2001:db8::1")
	require.NotNil(t, got)
	require.Same(t, e[2], got, "must return the LIVE matched v6 IPAddress")
	p6 := e[0].(*diode.Device).PrimaryIp6
	require.NotNil(t, p6)
	p6ifc, ok := p6.AssignedObject.(*diode.Interface)
	require.True(t, ok)
	require.Nil(t, p6ifc.Device.PrimaryIp6, "cycle break")
	require.Nil(t, e[0].(*diode.Device).PrimaryIp4)

	// no match -> unset, nil return
	e = mk()
	require.Nil(t, AssignPrimaryIP(e, "8.8.8.8"))
	require.Nil(t, e[0].(*diode.Device).PrimaryIp4)
	require.Nil(t, e[0].(*diode.Device).PrimaryIp6)

	// empty host -> no-op, nil return
	e = mk()
	require.Nil(t, AssignPrimaryIP(e, ""))
	require.Nil(t, e[0].(*diode.Device).PrimaryIp4)
}

// TestAssignPrimaryIPNoReferenceCycle is the regression guard for the
// Device -> IPAddress -> Interface -> Device cycle: after assignment, the rich
// emitted IPAddress AND the Device must both convert to proto without
// recursing forever. ConvertToProtoMessage is what the real gRPC client and
// the dry-run protojson marshal call; a cycle stack-overflows here, NOT in the
// recordingClient-based runner test (which never serializes).
// TestAssignPrimaryIPCanonicalIPv6 verifies the primary IP is matched by
// canonical address, not textual spelling: a non-canonical host literal
// (2001:0db8::1) must match a discovered 2001:db8::1/64.
func TestAssignPrimaryIPCanonicalIPv6(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1")}
	e := []diode.Entity{
		dev,
		&diode.IPAddress{Address: strptr("2001:db8::1/64"), AssignedObject: &diode.Interface{Device: dev, Name: strptr("Ethernet1")}},
	}
	AssignPrimaryIP(e, "2001:0db8::1") // non-canonical spelling of the same address
	require.NotNil(t, dev.PrimaryIp6, "non-canonical IPv6 host must still match")
	require.Equal(t, "2001:db8::1/64", *dev.PrimaryIp6.Address)
	require.Nil(t, dev.PrimaryIp4)
}

func TestAssignPrimaryIPNoReferenceCycle(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1")}
	rich := &diode.IPAddress{
		Address:        strptr("10.0.0.1/31"),
		AssignedObject: &diode.Interface{Device: dev, Name: strptr("Ethernet1")},
	}
	e := []diode.Entity{dev, rich}
	AssignPrimaryIP(e, "10.0.0.1")
	// Must not stack-overflow:
	require.NotNil(t, dev.ConvertToProtoMessage())
	require.NotNil(t, rich.ConvertToProtoMessage())
}

func TestAssignPrimaryIPCarriesVrf(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1")}
	vrf := &diode.VRF{Name: strptr("blue")}
	entities := []diode.Entity{
		dev,
		&diode.IPAddress{
			Address: strptr("10.7.7.7/32"), Vrf: vrf,
			AssignedObject: &diode.Interface{Device: dev, Name: strptr("Loopback0"), Vrf: vrf},
		},
	}
	AssignPrimaryIP(entities, "10.7.7.7")
	require.NotNil(t, dev.PrimaryIp4)
	require.Equal(t, "10.7.7.7/32", *dev.PrimaryIp4.Address)
	require.NotNil(t, dev.PrimaryIp4.AssignedObject) // assigned interface retained
	require.NotNil(t, dev.PrimaryIp4.Vrf)            // VRF carried for per-VRF matching
	require.Equal(t, "blue", *dev.PrimaryIp4.Vrf.Name)
}
