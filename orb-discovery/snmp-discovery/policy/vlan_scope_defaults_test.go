package policy

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

// The whole chain, because the halves agreeing in isolation is what hid two
// earlier versions of this warning: applyDefaults decides what site a policy
// really has, the VLAN mapper turns that into a group scope, and the counter has
// to recognise which of those scopes separate anything. Unit tests of any one
// piece cannot see a mismatch between them.
func TestDefaultedPolicyProducesVLANsTheWarningCounts(t *testing.T) {
	build := func(t *testing.T, site string, group config.VLANGroupParameters) []diode.Entity {
		t.Helper()
		m := &Manager{}
		policy := config.Policy{}
		policy.Config.Defaults.Site = site
		policy.Config.Defaults.VLAN.Group = group
		m.applyDefaults(&policy)
		require.NotEmpty(t, policy.Config.Defaults.Site,
			"applyDefaults must always leave a site, or this test proves nothing")
		return []diode.Entity{mapping.BuildVLANForTest(101, "Voice", &policy.Config.Defaults)}
	}

	t.Run("no site and no group", func(t *testing.T) {
		require.Positive(t, mapping.CountUnscopedVLANs(build(t, "", config.VLANGroupParameters{})))
	})

	t.Run("a group alone does not clear it: it lands on the placeholder site", func(t *testing.T) {
		require.Positive(t, mapping.CountUnscopedVLANs(
			build(t, "", config.VLANGroupParameters{Name: "Campus VLANs"})))
	})

	t.Run("a location scope under the placeholder site does not clear it", func(t *testing.T) {
		require.Positive(t, mapping.CountUnscopedVLANs(
			build(t, "", config.VLANGroupParameters{Name: "Campus VLANs", ScopeLocation: "Floor 3"})))
	})

	t.Run("a real site without a group still warns", func(t *testing.T) {
		require.Positive(t, mapping.CountUnscopedVLANs(build(t, "Site A", config.VLANGroupParameters{})))
	})

	t.Run("a real site and a group clears it", func(t *testing.T) {
		require.Zero(t, mapping.CountUnscopedVLANs(
			build(t, "Site A", config.VLANGroupParameters{Name: "Campus VLANs"})))
	})

	t.Run("a location under a real site clears it", func(t *testing.T) {
		require.Zero(t, mapping.CountUnscopedVLANs(
			build(t, "Site A", config.VLANGroupParameters{Name: "Campus VLANs", ScopeLocation: "Floor 3"})))
	})

	t.Run("an operator-supplied region clears it with no site", func(t *testing.T) {
		require.Zero(t, mapping.CountUnscopedVLANs(
			build(t, "", config.VLANGroupParameters{Name: "Campus VLANs", ScopeRegion: "Brussels"})))
	})
}
