package mapping

import (
	"testing"

	"github.com/netboxlabs/orb-discovery/gnmi-discovery/gnmi"
	"github.com/stretchr/testify/require"
)

func TestApplyUpdateAndSnapshot(t *testing.T) {
	m := NewDeviceModel()
	changed := m.Apply(gnmi.Notification{Updates: []gnmi.Update{
		{Path: "/system/state/hostname", Value: "r1"},
	}})
	require.True(t, changed)
	snap := m.Snapshot()
	require.Equal(t, "r1", snap["/system/state/hostname"])
}

func TestApplyNoChangeReturnsFalse(t *testing.T) {
	m := NewDeviceModel()
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/a", Value: 1}}})
	changed := m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/a", Value: 1}}})
	require.False(t, changed)
}

func TestApplyDeleteRemovesPath(t *testing.T) {
	m := NewDeviceModel()
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/a", Value: 1}}})
	changed := m.Apply(gnmi.Notification{Deletes: []string{"/a"}})
	require.True(t, changed)
	_, ok := m.Snapshot()["/a"]
	require.False(t, ok)
}

func TestApplyDeleteRemovesSubtree(t *testing.T) {
	m := NewDeviceModel()
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{
		{Path: "/interfaces/interface[name=Eth1]/state/mtu", Value: 9000},
		{Path: "/interfaces/interface[name=Eth1]/state/admin-status", Value: "UP"},
		{Path: "/interfaces/interface[name=Eth2]/state/mtu", Value: 1500},
	}})
	// delete the whole Eth1 list entry -> both its leaves go, Eth2 stays
	changed := m.Apply(gnmi.Notification{Deletes: []string{"/interfaces/interface[name=Eth1]"}})
	require.True(t, changed)
	snap := m.Snapshot()
	require.NotContains(t, snap, "/interfaces/interface[name=Eth1]/state/mtu")
	require.NotContains(t, snap, "/interfaces/interface[name=Eth1]/state/admin-status")
	require.Contains(t, snap, "/interfaces/interface[name=Eth2]/state/mtu")
}

func TestApplyNonComparableValueDoesNotPanic(t *testing.T) {
	m := NewDeviceModel()
	// a JSON_IETF container leaf can decode to a map; == would panic.
	require.NotPanics(t, func() {
		m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/x", Value: map[string]any{"k": 1}}}})
		// same logical value again -> equal, no change, still no panic
		m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/x", Value: map[string]any{"k": 1}}}})
	})
}

func TestTTLPruningKeep1(t *testing.T) {
	m := NewDeviceModel()
	// cycle 1: two paths
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{
		{Path: "/a", Value: 1}, {Path: "/b", Value: 2},
	}})
	m.EndCycle(1, true)
	// cycle 2: only /a seen -> with keep=1, /b (unseen this cycle) is pruned
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/a", Value: 1}}})
	pruned := m.EndCycle(1, true)
	require.Equal(t, []string{"/b"}, pruned)
	require.NotContains(t, m.Snapshot(), "/b")
	require.Contains(t, m.Snapshot(), "/a")
}

func TestTTLPruningKeep2ToleratesOneMissedCycle(t *testing.T) {
	m := NewDeviceModel()
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/a", Value: 1}, {Path: "/b", Value: 2}}})
	m.EndCycle(2, true)
	// one silent cycle: nothing applied; keep=2 must NOT prune /a or /b
	pruned := m.EndCycle(2, true)
	require.Empty(t, pruned)
	require.Contains(t, m.Snapshot(), "/a")
	require.Contains(t, m.Snapshot(), "/b")
	// a second consecutive silent cycle now exceeds the TTL -> both pruned
	pruned = m.EndCycle(2, true)
	require.ElementsMatch(t, []string{"/a", "/b"}, pruned)
	require.Empty(t, m.Snapshot())
}

func TestEndCycleNoPruneAdvancesOnly(t *testing.T) {
	m := NewDeviceModel()
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/a", Value: 1}}})
	// prune=false (empty-view guard): cycle advances but nothing is removed
	pruned := m.EndCycle(1, false)
	require.Empty(t, pruned)
	require.Contains(t, m.Snapshot(), "/a")
}

func TestSeenInCycle(t *testing.T) {
	m := NewDeviceModel()
	m.Apply(gnmi.Notification{Updates: []gnmi.Update{{Path: "/sys/host", Value: "r1"}}})
	require.True(t, m.SeenInCycle("/sys/host"))
	m.EndCycle(1, false) // advance; nothing applied in the new cycle yet
	require.False(t, m.SeenInCycle("/sys/host"))
}

// TestBeginSyncPrunesPathDeletedDuringReconnect reproduces the ON_CHANGE
// reconnect scenario: a path updated during steady-state and then deleted on the
// device while the stream was down must be pruned at the next sync. BeginSync
// puts the reconnect's initial dump in a fresh generation so EndCycle(keep=1) can
// see the stale path as absent. Without BeginSync the dump shares the
// steady-state cycle and the deleted path survives forever.
func TestBeginSyncPrunesPathDeletedDuringReconnect(t *testing.T) {
	up := func(p string, v any) gnmi.Notification {
		return gnmi.Notification{Updates: []gnmi.Update{{Path: p, Value: v}}}
	}
	m := NewDeviceModel()

	// Connection 1: initial dump of /a and /b, then sync+rotate(keep=1).
	m.BeginSync()
	m.Apply(up("/a", 1))
	m.Apply(up("/b", 1))
	require.Empty(t, m.EndCycle(1, true), "first sync prunes nothing")

	// Steady-state ON_CHANGE updates re-stamp BOTH /a and /b in the post-sync cycle.
	m.Apply(up("/a", 2))
	m.Apply(up("/b", 2))

	// Stream drops; /b is deleted on the device. Reconnect: the initial dump
	// carries only /a (the new full view).
	m.BeginSync()
	m.Apply(up("/a", 3))
	pruned := m.EndCycle(1, true)

	require.Equal(t, []string{"/b"}, pruned, "/b (absent from the reconnect dump) must be pruned")
	snap := m.Snapshot()
	require.NotContains(t, snap, "/b", "deleted path must not survive the reconnect")
	require.Contains(t, snap, "/a")
}

// TestSampleReconnectInitialSyncNeedsKeep1 documents why the SAMPLE initial
// sync_response prunes with keep=1 (authoritative full view) rather than the
// keep=2 tolerance used for ongoing prune ticks: a path re-stamped during
// steady-state and then deleted while the stream was down is still within the
// keep=2 window at the reconnect boundary, so keep=2 would leak it (re-ingesting
// a departed object) while keep=1 removes it immediately.
func TestSampleReconnectInitialSyncNeedsKeep1(t *testing.T) {
	up := func(p string, v any) gnmi.Notification {
		return gnmi.Notification{Updates: []gnmi.Update{{Path: p, Value: v}}}
	}
	// Drive both models through the identical SAMPLE lifecycle up to the
	// reconnect's initial sync, then prune with keep=1 vs keep=2.
	build := func() *DeviceModel {
		m := NewDeviceModel()
		m.BeginSync() // conn1
		m.Apply(up("/a", 1))
		m.Apply(up("/b", 1))
		m.EndCycle(1, true) // conn1 initial sync (authoritative)
		m.Apply(up("/a", 1))
		m.Apply(up("/b", 1)) // steady snapshot
		m.EndCycle(2, true)  // a prune tick (keep=2)
		m.Apply(up("/a", 1))
		m.Apply(up("/b", 1)) // steady snapshot (re-stamps /b)
		m.BeginSync()        // reconnect
		m.Apply(up("/a", 1)) // reconnect initial snapshot — /b gone from device
		return m
	}

	keep1 := build()
	require.Equal(t, []string{"/b"}, keep1.EndCycle(1, true), "keep=1 prunes the departed path at the reconnect sync")
	require.NotContains(t, keep1.Snapshot(), "/b")

	keep2 := build()
	require.Empty(t, keep2.EndCycle(2, true), "keep=2 would leak the departed path (the bug)")
	require.Contains(t, keep2.Snapshot(), "/b")
}
