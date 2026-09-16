package gnmidiscovery

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The backend emits both a `targets` array and a comma-joined `target`. A sweep
// run covering several scope entries has to reach the fleet as several targets,
// not as the single string "10.0.0.0/24,10.1.0.0/24".
func TestSweepRunTargetsAreDecodedAsAnArray(t *testing.T) {
	var resp gnmiStatusResponse
	require.NoError(t, json.Unmarshal([]byte(`{
	  "policies": [{
	    "name": "campus",
	    "status": "completed",
	    "runs": [{
	      "id": "r1",
	      "target": "10.0.0.0/24,10.1.0.0/24",
	      "targets": ["10.0.0.0/24", "10.1.0.0/24"],
	      "status": "completed",
	      "entity_count": 4
	    }]
	  }]
	}`), &resp))

	run := resp.Policies[0].Runs[0]
	require.Equal(t, []string{"10.0.0.0/24", "10.1.0.0/24"}, run.Targets)
}

// A payload from a backend that predates the array still yields its target: the
// singular field is the fallback, not the primary.
func TestASingularTargetIsStillHonouredAsAFallback(t *testing.T) {
	var resp gnmiStatusResponse
	require.NoError(t, json.Unmarshal([]byte(`{
	  "policies": [{
	    "name": "campus",
	    "runs": [{"id": "r1", "target": "10.0.0.11:6030"}]
	  }]
	}`), &resp))

	run := resp.Policies[0].Runs[0]
	require.Empty(t, run.Targets)
	require.Equal(t, "10.0.0.11:6030", run.Target)
}

func TestRunTargetsPrefersTheArray(t *testing.T) {
	require.Equal(t, []string{"a", "b"},
		runTargets([]string{"a", "b"}, "a,b"))
	require.Equal(t, []string{"10.0.0.11:6030"},
		runTargets(nil, "10.0.0.11:6030"), "the singular field is the fallback")
	require.Nil(t, runTargets(nil, ""), "a run with no target reports none")
}

// A sweep run and a flush run describe different things and complete at
// different times — a sweep of a named host finishes at once, while its first
// flush waits for debounce, subscribe and the initial sync. They can also carry
// the same target list, so without this nothing in the payload tells them apart
// and "any completed run" reads as "the policy ingested something".
func TestRunKindReachesTheFleetAsMetadata(t *testing.T) {
	var resp gnmiStatusResponse
	require.NoError(t, json.Unmarshal([]byte(`{
	  "policies": [{
	    "name": "campus",
	    "runs": [
	      {"id": "s1", "kind": "sweep", "status": "completed", "targets": ["10.0.0.0/24"]},
	      {"id": "f1", "kind": "flush", "status": "completed", "targets": ["10.0.0.1:9339"]}
	    ]
	  }]
	}`), &resp))

	require.Equal(t, "sweep", resp.Policies[0].Runs[0].Kind)
	require.Equal(t, "flush", resp.Policies[0].Runs[1].Kind)
}
