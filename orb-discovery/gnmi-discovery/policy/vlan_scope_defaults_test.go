package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// The whole chain, because the halves agreeing in isolation is exactly what hid
// the first version of this warning: applyDefaults writes a site, the translator
// stamps it on every VLAN, and the counter has to recognise it as no scope at
// all. A unit test of the counter alone cannot see that, and one of applyDefaults
// alone cannot either.
func TestDefaultedPolicyProducesVLANsTheWarningCounts(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	base, ok := store.Get("_base")
	require.True(t, ok)

	snap := map[string]any{
		"/system/state/hostname": "spine1",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=101]/state/name":   "Voice",
		"/network-instances/network-instance[name=default]/vlans/vlan[vlan-id=101]/state/status": "ACTIVE",
	}

	t.Run("no site and no group: the operator gets no usable scope and is warned", func(t *testing.T) {
		m := &Manager{}
		var policy config.Policy
		m.applyDefaults(&policy)
		require.Equal(t, config.UndefinedPlaceholder, policy.Config.Defaults.Site,
			"applyDefaults must still write the placeholder, or this test proves nothing")

		entities := mapping.Translate(base, snap, &policy.Config.Defaults, "")
		require.Positive(t, mapping.CountUnscopedVLANs(entities),
			"a defaulted policy emits VLANs scoped only to the placeholder site; "+
				"counting 0 here means the warning is dead code in a running agent")
	})

	t.Run("a group alone does not clear it, because the group lands on the placeholder too", func(t *testing.T) {
		m := &Manager{}
		var policy config.Policy
		policy.Config.Defaults.Vlan.Group.Name = "Site A VLANs"
		m.applyDefaults(&policy)

		entities := mapping.Translate(base, snap, &policy.Config.Defaults, "")
		require.Positive(t, mapping.CountUnscopedVLANs(entities),
			"vlan.group without defaults.site scopes the group to the placeholder, "+
				"which cannot match the operator's group under a real site")
	})

	t.Run("a real site and a group clears it", func(t *testing.T) {
		m := &Manager{}
		var policy config.Policy
		policy.Config.Defaults.Site = "Site A"
		policy.Config.Defaults.Vlan.Group.Name = "Site A VLANs"
		m.applyDefaults(&policy)

		entities := mapping.Translate(base, snap, &policy.Config.Defaults, "")
		require.Zero(t, mapping.CountUnscopedVLANs(entities))
	})

	t.Run("a real site without a group still warns: a site is not a scope", func(t *testing.T) {
		m := &Manager{}
		var policy config.Policy
		policy.Config.Defaults.Site = "Site A"
		m.applyDefaults(&policy)

		entities := mapping.Translate(base, snap, &policy.Config.Defaults, "")
		require.Positive(t, mapping.CountUnscopedVLANs(entities),
			"a group-less VLAN never matches the operator's group-scoped VLANs, "+
				"whatever its site; and NetBox is removing VLAN-to-site assignment")
	})

	t.Run("a location scope under the placeholder site does not clear it", func(t *testing.T) {
		m := &Manager{}
		var policy config.Policy
		policy.Config.Defaults.Vlan.Group.Name = "Campus VLANs"
		policy.Config.Defaults.Vlan.Group.ScopeLocation = "Floor 3"
		m.applyDefaults(&policy)

		entities := mapping.Translate(base, snap, &policy.Config.Defaults, "")
		require.Positive(t, mapping.CountUnscopedVLANs(entities),
			"the location hangs off defaults.site, so without a real site it is a "+
				"location under a site named undefined")
	})

	t.Run("a location scope under a real site clears it", func(t *testing.T) {
		m := &Manager{}
		var policy config.Policy
		policy.Config.Defaults.Site = "Site A"
		policy.Config.Defaults.Vlan.Group.Name = "Campus VLANs"
		policy.Config.Defaults.Vlan.Group.ScopeLocation = "Floor 3"
		m.applyDefaults(&policy)

		entities := mapping.Translate(base, snap, &policy.Config.Defaults, "")
		require.Zero(t, mapping.CountUnscopedVLANs(entities))
	})
}
