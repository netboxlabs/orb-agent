package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Device gains an unconditional "active" status. (asset_tag is resolved by the
// runner post-Translate, not in translateDevice — see ResolveAssetTag tests.)
func TestTranslateDevice_Status(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	snap := map[string]any{"/system/state/hostname": "r1"}
	dev, _ := translateDevice(base, snap, &config.Defaults{}, "")
	require.NotNil(t, dev.Status)
	assert.Equal(t, "active", *dev.Status)
	assert.Nil(t, dev.AssetTag, "asset_tag is not set by translateDevice")
}

// IPAddress entities pick up the ip_address defaults.
func TestTranslateIPs_Defaults(t *testing.T) {
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length": 31,
	}
	defs := &config.Defaults{
		Tags: []string{"global"},
		IPAddress: config.IPAddressDefaults{
			Role: "mgmt", Tenant: "acme", Description: "desc", Comments: "c", Tags: []string{"ip"},
		},
	}
	ents := translateIPs(base, snap, dev, defs, nil)
	var ip *diode.IPAddress
	for _, e := range ents {
		if v, ok := e.(*diode.IPAddress); ok {
			ip = v
		}
	}
	require.NotNil(t, ip)
	require.NotNil(t, ip.Role)
	assert.Equal(t, "mgmt", *ip.Role)
	require.NotNil(t, ip.Tenant)
	assert.Equal(t, "acme", *ip.Tenant.Name)
	require.NotNil(t, ip.Description)
	assert.Equal(t, "desc", *ip.Description)
	require.NotNil(t, ip.Comments)
	assert.Equal(t, "c", *ip.Comments)
	// Tags = policy-level + ip_address-level.
	var tagNames []string
	for _, tg := range ip.Tags {
		tagNames = append(tagNames, *tg.Name)
	}
	assert.ElementsMatch(t, []string{"global", "ip"}, tagNames)
}

// VRF entities pick up the vrf defaults (Name/Rd still come from discovery).
func TestTranslateVrfs_Defaults(t *testing.T) {
	snap := map[string]any{
		"/network-instances/network-instance[name=blue]/state/type":                "openconfig-network-instance-types:L3VRF",
		"/network-instances/network-instance[name=blue]/state/route-distinguisher": "65000:1",
	}
	defs := &config.Defaults{
		Tags: []string{"global"},
		Vrf:  config.VRFDefaults{Tenant: "acme", Description: "d", Comments: "c", Tags: []string{"vrf"}},
	}
	ents, _ := translateVrfs(snap, defs)
	require.Len(t, ents, 1)
	v := ents[0].(*diode.VRF)
	assert.Equal(t, "blue", *v.Name)
	require.NotNil(t, v.Rd)
	assert.Equal(t, "65000:1", *v.Rd)
	require.NotNil(t, v.Tenant)
	assert.Equal(t, "acme", *v.Tenant.Name)
	require.NotNil(t, v.Description)
	assert.Equal(t, "d", *v.Description)
	require.NotNil(t, v.Comments)
	assert.Equal(t, "c", *v.Comments)
	var tagNames []string
	for _, tg := range v.Tags {
		tagNames = append(tagNames, *tg.Name)
	}
	assert.ElementsMatch(t, []string{"global", "vrf"}, tagNames)
}
