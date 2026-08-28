package fleet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/policies"
)

// A run's kind has to survive every hop to be worth anything, and it did not:
// the gnmi backend emitted it, PolicyStatusRun carried it, and convertToRunData
// then dropped it, so the heartbeat Fleet receives still had otherwise-identical
// sweep and flush runs with nothing to tell them apart. Testing the field at each
// struct in isolation is what let that gap sit unnoticed, so this covers the hop
// that was actually broken.
func TestRunKindReachesTheHeartbeat(t *testing.T) {
	infos := convertRunsToStateInfo([]policies.RunData{
		{ID: "s1", Status: "completed", Kind: "sweep", Targets: []string{"10.0.0.0/24"}},
		{ID: "f1", Status: "completed", Kind: "flush", Targets: []string{"10.0.0.1:9339"}},
		{ID: "x1", Status: "completed"}, // a backend that emits no kind
	})

	require.Len(t, infos, 3)
	require.Equal(t, "sweep", infos[0].Kind)
	require.Equal(t, "flush", infos[1].Kind)
	require.Empty(t, infos[2].Kind, "a backend that emits no kind is unaffected")
}
