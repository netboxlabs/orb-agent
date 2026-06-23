package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/stretchr/testify/require"
)

func TestParseNetworkInstanceVlanPath(t *testing.T) {
	for _, c := range []struct{ path, vid, leaf string }{
		{"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/name", "10", "name"},
		{"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=20]/state/status", "20", "status"},
		{"/network-instances/network-instance[name=VRF-A]/vlans/vlan[vlan-id=99]/state/name", "99", "name"},
	} {
		vid, leaf, ok := parseNetworkInstanceVlanPath(c.path)
		require.True(t, ok, c.path)
		require.Equal(t, c.vid, vid)
		require.Equal(t, c.leaf, leaf)
	}
	for _, p := range []string{
		"/interfaces/interface[name=Ethernet1]/state/mtu",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/config/name",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/tpid",
		"/network-instances/network-instance[name=default]/protocols/protocol[x=y]/state/name",
	} {
		_, _, ok := parseNetworkInstanceVlanPath(p)
		require.False(t, ok, p)
	}
}

func TestMapVlanStatus(t *testing.T) {
	require.Equal(t, "active", mapVlanStatus("ACTIVE"))
	require.Equal(t, "reserved", mapVlanStatus("SUSPENDED"))
	require.Equal(t, "active", mapVlanStatus(""))
	require.Equal(t, "active", mapVlanStatus("whatever"))
	require.Equal(t, "reserved", mapVlanStatus("suspended"))
}

func TestSlugify(t *testing.T) {
	require.Equal(t, "lab-vlans", slugify("Lab VLANs"))
	require.Equal(t, "lab-vlans", slugify("  lab   vlans  "))
	require.Equal(t, "a-b-c", slugify("a/b.c"))
	require.Equal(t, "v100", slugify("v100"))
	require.Equal(t, "", slugify("!!!"))
}

func TestTranslateVlanDefinitions(t *testing.T) {
	snap := map[string]any{
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/name":   "users",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=10]/state/status": "ACTIVE",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=20]/state/name":   "voice",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=20]/state/status": "SUSPENDED",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=5000]/state/name": "bad",
	}
	defs := translateVlanDefinitions(snap)
	require.Len(t, defs, 2)
	require.Equal(t, "users", defs[10].name)
	require.Equal(t, "ACTIVE", defs[10].status)
	require.Equal(t, "voice", defs[20].name)
	require.Equal(t, "SUSPENDED", defs[20].status)
}

func TestVlanBuilder(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1"), Site: &diode.Site{Name: strptr("lab")}}
	defs := map[int64]vlanDef{10: {name: "users", status: "ACTIVE"}, 20: {name: "voice", status: "SUSPENDED"}}
	defaults := &config.Defaults{Tags: []string{"global"}, Vlan: config.VlanDefaults{Group: "Lab VLANs", Tenant: "acme", Role: "data", Tags: []string{"managed"}}}
	b := newVlanBuilder(dev, defaults, defs)

	v10 := b.get(10)
	require.Equal(t, int64(10), *v10.Vid)
	require.Equal(t, "users", *v10.Name)
	require.Equal(t, "active", *v10.Status)
	require.Equal(t, "lab", *v10.Site.Name)
	require.NotNil(t, v10.Group)
	require.Equal(t, "Lab VLANs", *v10.Group.Name)
	require.Equal(t, "lab-vlans", *v10.Group.Slug)
	scopeSite, ok := v10.Group.Scope.(*diode.Site)
	require.True(t, ok)
	require.Equal(t, "lab", *scopeSite.Name)
	require.Equal(t, "acme", *v10.Tenant.Name)
	require.Equal(t, "data", *v10.Role.Name)
	// VLAN tags = global defaults.tags + vlan-level tags.
	vlanTags := map[string]bool{}
	for _, tg := range v10.Tags {
		vlanTags[*tg.Name] = true
	}
	require.Len(t, v10.Tags, 2)
	require.True(t, vlanTags["global"] && vlanTags["managed"])

	v20 := b.get(20)
	require.Equal(t, "reserved", *v20.Status)

	v99 := b.get(99)
	require.Equal(t, "VLAN99", *v99.Name)
	require.Equal(t, "active", *v99.Status)

	require.Same(t, v10, b.get(10))

	ents := b.emitted()
	var vids []int64
	for _, e := range ents {
		vids = append(vids, *e.(*diode.VLAN).Vid)
	}
	require.Equal(t, []int64{10, 20, 99}, vids)
}

// A group with no device site must leave Scope nil (not a typed-nil *Site that
// would serialize as a bogus empty-site scope).
func TestVlanBuilderGroupNilSiteScope(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1")} // no Site
	b := newVlanBuilder(dev, &config.Defaults{Vlan: config.VlanDefaults{Group: "g"}}, nil)
	v := b.get(10)
	require.NotNil(t, v.Group)
	require.Nil(t, v.Group.Scope)
	require.Nil(t, v.Site)
	require.NotNil(t, v.ConvertToProtoMessage()) // serializes cleanly
}

// A group name with no [a-z0-9] runes slugifies to "" — NetBox requires a
// non-empty VLANGroup.slug, so no group must be created (VLANs stay ungrouped).
func TestVlanBuilderGroupEmptySlugSkipped(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1"), Site: &diode.Site{Name: strptr("lab")}}
	b := newVlanBuilder(dev, &config.Defaults{Vlan: config.VlanDefaults{Group: "!!!"}}, nil)
	v := b.get(10)
	require.Nil(t, v.Group, "group with empty slug must not be created")
}

func TestVlanGroupNoReferenceCycle(t *testing.T) {
	dev := &diode.Device{Name: strptr("r1"), Site: &diode.Site{Name: strptr("lab")}}
	b := newVlanBuilder(dev, &config.Defaults{Vlan: config.VlanDefaults{Group: "g"}}, nil)
	v := b.get(10)
	iface := &diode.Interface{Device: dev, Name: strptr("Ethernet1"), UntaggedVlan: v}
	require.NotNil(t, iface.ConvertToProtoMessage())
	require.NotNil(t, v.ConvertToProtoMessage())
}
