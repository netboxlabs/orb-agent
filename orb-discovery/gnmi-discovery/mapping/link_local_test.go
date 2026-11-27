package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

// linkLocalSnap has IPv6 link-locals at both ends of fe80::/10 next to a
// global address, addresses just outside that range, an IPv4 link-local,
// and a subinterface whose only address is a link-local.
func linkLocalSnap() map[string]any {
	const sub0 = "/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]"
	const sub20 = "/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=20]"
	return map[string]any{
		"/system/state/hostname": "r1",
		sub0 + "/ipv6/addresses/address[ip=2001:db8::1]/state/prefix-length":  64,
		sub0 + "/ipv6/addresses/address[ip=fe80::1]/state/prefix-length":      64,
		sub0 + "/ipv6/addresses/address[ip=febf:ffff::1]/state/prefix-length": 64,
		sub0 + "/ipv6/addresses/address[ip=fe7f:ffff::1]/state/prefix-length": 64,
		sub0 + "/ipv6/addresses/address[ip=fec0::1]/state/prefix-length":      64,
		sub0 + "/ipv4/addresses/address[ip=169.254.10.5]/state/prefix-length": 16,
		sub20 + "/ipv6/addresses/address[ip=fe80::2]/state/prefix-length":     64,
	}
}

func translatedIPs(t *testing.T, opts *config.Options) (ents []diode.Entity, addrs, prefixes, names []string) {
	t.Helper()
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, ok := store.Get("_base")
	require.True(t, ok)
	ents = TranslateWithOptions(base, linkLocalSnap(), &config.Defaults{}, "", opts, nil, nil)
	for _, e := range ents {
		switch v := e.(type) {
		case *diode.IPAddress:
			addrs = append(addrs, v.GetAddress())
		case *diode.Prefix:
			prefixes = append(prefixes, v.GetPrefix())
		case *diode.Interface:
			names = append(names, v.GetName())
		}
	}
	return ents, addrs, prefixes, names
}

var outsideIPv6LinkLocal = []string{"2001:db8::1/64", "fe7f:ffff::1/64", "fec0::1/64", "169.254.10.5/16"}

// A link-local address is only unique on its own link, while Diode matches an
// IP address by address and VRF, so it is not sent unless the policy opts in.
// The subinterface only a link-local revealed is still sent.
func TestTranslateWithOptions_IPv6LinkLocalAddressesNotSentByDefault(t *testing.T) {
	off := false
	for name, opts := range map[string]*config.Options{
		"no options":     nil,
		"defaults":       {},
		"explicitly off": {EmitIPv6LinkLocalAddresses: &off},
	} {
		t.Run(name, func(t *testing.T) {
			ents, addrs, _, names := translatedIPs(t, opts)
			assert.ElementsMatch(t, outsideIPv6LinkLocal, addrs)
			assert.Contains(t, names, "Ethernet1.20")
			assert.Nil(t, AssignPrimaryIP(ents, "fe80::1"), "a link-local that is not sent cannot be the primary IP")
		})
	}
}

func TestTranslateWithOptions_IPv6LinkLocalAddressesSentWithTheOptIn(t *testing.T) {
	on := true
	_, addrs, _, names := translatedIPs(t, &config.Options{EmitIPv6LinkLocalAddresses: &on})
	assert.ElementsMatch(t, append([]string{"fe80::1/64", "febf:ffff::1/64", "fe80::2/64"}, outsideIPv6LinkLocal...), addrs)
	assert.Contains(t, names, "Ethernet1.20")
}

// No prefix is derived from a link-local address, with or without the opt-in,
// as in the other discovery backends.
func TestTranslateWithOptions_NoIPv6LinkLocalPrefix(t *testing.T) {
	on := true
	for name, opts := range map[string]*config.Options{
		"default": nil,
		"opt-in":  {EmitIPv6LinkLocalAddresses: &on},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, prefixes, _ := translatedIPs(t, opts)
			assert.ElementsMatch(t, []string{"2001:db8::/64", "fe7f:ffff::/64", "fec0::/64", "169.254.0.0/16"}, prefixes)
		})
	}
}

// With emit_ip_addresses off no address is sent, link-local or not, and the
// rest of the run is as with addresses off alone.
func TestTranslateWithOptions_EmitIPAddressesOffOverridesTheLinkLocalOptIn(t *testing.T) {
	on, off := true, false
	ents, addrs, prefixes, names := translatedIPs(t, &config.Options{EmitIPAddresses: &off, EmitIPv6LinkLocalAddresses: &on})
	assert.Empty(t, addrs)
	assert.Contains(t, names, "Ethernet1.20")
	assert.ElementsMatch(t, []string{"2001:db8::/64", "fe7f:ffff::/64", "fec0::/64", "169.254.0.0/16"}, prefixes)
	assert.Nil(t, AssignPrimaryIP(ents, "2001:db8::1"))
}

// The OpenConfig ipv6-address type allows a zone, which a link-local can carry.
func TestTranslateWithOptions_ZonedIPv6LinkLocalNotSent(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, ok := store.Get("_base")
	require.True(t, ok)
	snap := map[string]any{
		"/system/state/hostname": "r1",
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv6/addresses/address[ip=fe80::1%Ethernet1]/state/prefix-length": 64,
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv6/addresses/address[ip=2001:db8::1]/state/prefix-length":       64,
	}
	var addrs []string
	for _, e := range TranslateWithOptions(base, snap, &config.Defaults{}, "", nil, nil, nil) {
		if ip, ok := e.(*diode.IPAddress); ok {
			addrs = append(addrs, ip.GetAddress())
		}
	}
	assert.Equal(t, []string{"2001:db8::1/64"}, addrs)
}

// Judged on the address: a mask wider than /10 moves the network out of
// fe80::/10 but not the address.
func TestIsIPv6LinkLocal(t *testing.T) {
	for cidr, want := range map[string]bool{
		"fe80::1/64":               true,
		"fe80::1/8":                true,
		"febf:ffff::1/64":          true,
		"FE80::1/64":               true,
		"fe80::1%Ethernet1/64":     true,
		"fe7f:ffff::1/64":          false,
		"fec0::1/64":               false,
		"169.254.10.5/16":          false,
		"::ffff:169.254.10.5/128":  false,
		"2001:db8::1/64":           false,
		"2001:db8::1%Ethernet1/64": false,
		"not-an-address":           false,
	} {
		assert.Equal(t, want, isIPv6LinkLocal(cidr), cidr)
	}
}

func TestOptions_IPv6LinkLocalAddressEmissionEnabled(t *testing.T) {
	on, off := true, false
	assert.False(t, (*config.Options)(nil).IPv6LinkLocalAddressEmissionEnabled())
	assert.False(t, (&config.Options{}).IPv6LinkLocalAddressEmissionEnabled())
	assert.False(t, (&config.Options{EmitIPv6LinkLocalAddresses: &off}).IPv6LinkLocalAddressEmissionEnabled())
	assert.True(t, (&config.Options{EmitIPv6LinkLocalAddresses: &on}).IPv6LinkLocalAddressEmissionEnabled())
}
