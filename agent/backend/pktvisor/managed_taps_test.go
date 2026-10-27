package pktvisor_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

func remove(be interface {
	RemovePolicy(policies.PolicyData) error
}, name string,
) error {
	return be.RemovePolicy(policies.PolicyData{ID: "id-" + name, Name: name})
}

func TestRemoveDeletesAManagedTapWithItsLastPolicy(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p1", "fleet_netprobe")

	require.NoError(t, remove(be, "p1"))

	assert.Equal(t, []string{
		"DELETE /api/v1/policies/p1 200",
		"GET /api/v1/taps 200",
		"GET /api/v1/policies 200",
		"DELETE /api/v1/taps/fleet_netprobe 200",
	}, f.log())
	assert.False(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveKeepsAManagedTapStillInUse(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p1", "fleet_netprobe")
	f.addPolicy("p2", "fleet_netprobe")

	require.NoError(t, remove(be, "p1"))

	log := f.log()
	assert.Contains(t, log, "GET /api/v1/policies 200")
	assert.Empty(t, tapDeletes(log))
	assert.True(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveKeepsLocalTaps(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("edge", "pcap", nil, nil)
	f.addPolicy("p1", "edge")

	require.NoError(t, remove(be, "p1"))

	log := f.log()
	assert.Contains(t, log, "GET /api/v1/taps 200")
	assert.Empty(t, tapDeletes(log))
	assert.True(t, f.hasTap("edge"))
}

func TestRemoveKeepsAFleetNamedTapItDidNotCreate(t *testing.T) {
	cases := []struct {
		name      string
		tap       string
		inputType string
		config    map[string]any
		tags      map[string]any
	}{
		{"other input type", "fleet_netprobe", "pcap", nil, nil},
		{"with config", "fleet_flow", "flow", map[string]any{"port": 6343}, nil},
		{"with tags", "fleet_flow", "flow", nil, map[string]any{"site": "lab"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakePktvisor(t)
			be := startAgainst(t, f)
			f.addTap(c.tap, c.inputType, c.config, c.tags)
			f.addPolicy("p1", "elsewhere")

			require.NoError(t, remove(be, "p1"))

			assert.Empty(t, tapDeletes(f.log()))
			assert.True(t, f.hasTap(c.tap))
		})
	}
}

func TestRemoveSucceedsWhenCleanupFails(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)

	f.addPolicy("p1", "elsewhere")
	f.with(func() { f.failPolicyList = true })
	require.NoError(t, remove(be, "p1"))
	assert.Contains(t, f.log(), "GET /api/v1/policies 500")
	assert.Empty(t, tapDeletes(f.log()))

	f.clearLog()
	f.addPolicy("p1", "elsewhere")
	f.with(func() { f.failPolicyList = false; f.failTapList = true })
	require.NoError(t, remove(be, "p1"))
	assert.Contains(t, f.log(), "GET /api/v1/taps 500")
	assert.Empty(t, tapDeletes(f.log()))
	assert.True(t, f.hasTap("fleet_netprobe"))

	f.clearLog()
	f.addPolicy("p1", "elsewhere")
	f.with(func() { f.failTapList = false })
	require.NoError(t, remove(be, "p1"))
	assert.Contains(t, f.log(), "DELETE /api/v1/taps/fleet_netprobe 200")
	assert.False(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveKeepsAKeptTap(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p2", "elsewhere")
	pktvisor.KeepTap(be, "fleet_netprobe")

	require.NoError(t, remove(be, "p2"))

	assert.Empty(t, tapDeletes(f.log()))
	assert.True(t, f.hasTap("fleet_netprobe"))
}

func TestStartReleasesKeptTaps(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_netprobe", "netprobe", nil, nil)
	f.addPolicy("p2", "fleet_netprobe")
	pktvisor.KeepTap(be, "fleet_netprobe")

	require.NoError(t, be.FullReset(context.Background()))

	require.NoError(t, remove(be, "p2"))
	assert.Contains(t, f.log(), "DELETE /api/v1/policies/p2 200")
	assert.Contains(t, f.log(), "DELETE /api/v1/taps/fleet_netprobe 200")
	assert.False(t, f.hasTap("fleet_netprobe"))
}

func TestRemoveCleansUpWhenThePolicyIsAlreadyGone(t *testing.T) {
	f := newFakePktvisor(t)
	be := startAgainst(t, f)
	f.addTap("fleet_flow", "flow", nil, nil)

	err := remove(be, "p1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, f.log(), "DELETE /api/v1/policies/p1 404")
	assert.Contains(t, f.log(), "DELETE /api/v1/taps/fleet_flow 200")
	assert.False(t, f.hasTap("fleet_flow"))
}
