package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/gnmi-discovery/config"
	"github.com/stretchr/testify/require"
)

func ipEnt(addr string, vrf *diode.VRF) *diode.IPAddress {
	return &diode.IPAddress{Address: strptr(addr), Vrf: vrf}
}

func TestTranslatePrefixes(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1"), Site: &diode.Site{Name: strptr("lab")}}
	blue := &diode.VRF{Name: strptr("blue")}
	entities := []diode.Entity{
		dev,
		ipEnt("10.0.0.1/31", nil),
		ipEnt("10.0.0.2/31", nil),
		ipEnt("10.0.0.1/31", blue),
		ipEnt("192.0.2.5/24", nil),
		ipEnt("192.0.2.9/24", nil),
		ipEnt("2001:db8::1/64", nil),
		ipEnt("10.7.7.7/32", nil),
		ipEnt("bogus", nil),
	}
	defaults := &config.Defaults{Tags: []string{"global"}, Prefix: config.PrefixDefaults{Role: "mgmt", Tenant: "acme", Tags: []string{"auto"}}}
	ents := translatePrefixes(entities, dev, defaults)

	got := map[string]*diode.Prefix{}
	for _, e := range ents {
		p := e.(*diode.Prefix)
		k := *p.Prefix
		if p.Vrf != nil {
			k += "@" + *p.Vrf.Name
		}
		got[k] = p
	}
	require.Contains(t, got, "10.0.0.0/31")
	require.Contains(t, got, "10.0.0.0/31@blue")
	require.Contains(t, got, "10.0.0.2/31")
	require.Contains(t, got, "192.0.2.0/24")
	require.Contains(t, got, "2001:db8::/64")
	require.Contains(t, got, "10.7.7.7/32")
	require.Len(t, ents, 6)

	p := got["10.0.0.0/31"]
	require.Equal(t, "active", *p.Status)
	require.Equal(t, "lab", *p.Scope.(*diode.Site).Name)
	require.Nil(t, p.Vrf)
	require.Equal(t, "mgmt", *p.Role.Name)
	require.Equal(t, "acme", *p.Tenant.Name)
	// Prefix tags = global defaults.tags + prefix-level tags.
	pfxTags := map[string]bool{}
	for _, tg := range p.Tags {
		pfxTags[*tg.Name] = true
	}
	require.Len(t, p.Tags, 2)
	require.True(t, pfxTags["global"] && pfxTags["auto"])
	require.Equal(t, "blue", *got["10.0.0.0/31@blue"].Vrf.Name)
}

func TestTranslatePrefixesNilSiteAndCycle(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1")} // no Site
	ents := translatePrefixes([]diode.Entity{dev, ipEnt("10.0.0.1/31", nil)}, dev, nil)
	require.Len(t, ents, 1)
	p := ents[0].(*diode.Prefix)
	require.Nil(t, p.Scope)
	require.NotNil(t, p.ConvertToProtoMessage())
}
