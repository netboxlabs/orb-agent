package policy

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Runs are the only channel the agent consumes: PolicyStatus carries {Name,
// Status, Runs} and nothing else, so a TargetStatus never leaves the container.
// PolicyStatusRun decodes `targets` and has no `target` field at all, which means
// every gnmi run — the pre-existing per-device ones included — reached the fleet
// with no target on it.
func TestRunSerializesTheTargetsFieldTheAgentActuallyReads(t *testing.T) {
	rs := NewRunStore()
	run := rs.CreateRun("p1", "10.0.0.1:9339")

	var decoded struct {
		Targets []string `json:"targets"`
	}
	raw, err := json.Marshal(run)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, []string{"10.0.0.1:9339"}, decoded.Targets)
}

// The sweep run is keyed apart from per-device runs. Without that, a policy whose
// only target is one host would have its sweep run and its device runs share a
// key and evict each other under the per-target cap.
func TestSweepRunDoesNotEvictThePerDeviceRunsOfTheSameHost(t *testing.T) {
	rs := NewRunStore()
	for range 3 {
		d := rs.CreateRun("p1", "10.0.0.5:9339")
		rs.UpdateRun("p1", "10.0.0.5:9339", d.ID, RunStatusCompleted, nil, 1)
	}
	sweep := rs.CreateSweepRun("p1", []string{"10.0.0.5:9339"})
	rs.FinishSweepRun("p1", sweep.ID, RunStatusCompleted, "1 of 1 address(es) answered", 1)

	runs := rs.GetRunsForPolicy("p1")
	require.Len(t, runs, 4, "three device runs plus the sweep run")
}

// The sweep run names the operator's own host strings, so an operator reading
// /status sees the CIDR they wrote rather than a synthesized pseudo-host.
func TestSweepRunCarriesTheOriginalHostStrings(t *testing.T) {
	rs := NewRunStore()
	sweep := rs.CreateSweepRun("p1", []string{"10.0.0.0/24", "switch-a.example.com"})
	require.Equal(t, []string{"10.0.0.0/24", "switch-a.example.com"}, sweep.Targets)
	require.Contains(t, sweep.Target, "10.0.0.0/24")
	require.Equal(t, RunStatusRunning, sweep.Status,
		"created at sweep start, so a hung sweep is visible while it runs")
}

// A successful sweep still has something to say, and UpdateRun fills Reason only
// from a non-nil error. Reporting the counts through a fabricated error would
// mark a healthy sweep failed.
func TestFinishSweepRunReportsCountsWithoutAnError(t *testing.T) {
	rs := NewRunStore()
	sweep := rs.CreateSweepRun("p1", []string{"10.0.0.0/24"})
	rs.FinishSweepRun("p1", sweep.ID, RunStatusCompleted, "3 of 254 address(es) answered", 3)

	runs := rs.GetRunsForPolicy("p1")
	require.Len(t, runs, 1)
	require.Equal(t, RunStatusCompleted, runs[0].Status)
	require.Equal(t, 3, runs[0].EntityCount)
	require.Contains(t, runs[0].Reason, "3 of 254")
}

// Sorting on CreatedAt buried the sweep run: it is created before every run it
// starts, so it is always the oldest thing in the store.
func TestRunsSortByMostRecentActivityNotCreation(t *testing.T) {
	rs := NewRunStore()
	sweep := rs.CreateSweepRun("p1", []string{"10.0.0.0/30"})
	device := rs.CreateRun("p1", "10.0.0.1:9339")
	rs.UpdateRun("p1", "10.0.0.1:9339", device.ID, RunStatusCompleted, nil, 7)

	time.Sleep(2 * time.Millisecond)
	rs.FinishSweepRun("p1", sweep.ID, RunStatusCompleted, "1 of 2 address(es) answered", 1)

	runs := rs.GetRunsForPolicy("p1")
	require.Equal(t, sweep.ID, runs[0].ID,
		"the sweep finished last, so it sorts first despite being created first")
}

// A range where nothing answered is the implementable form of "the policy
// failed": there is no path to failing the policy itself, so the operator has to
// be able to see it as a run.
func TestASweepThatFindsNothingIsReportedFailed(t *testing.T) {
	dialer := newPerHostDialer(nil)
	dialer.defaultCapsErr = dialingErr()
	r := newSweepRunner(t, "10.0.0.0/30", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		runs := r.Runs()
		return len(runs) == 1 && runs[0].Status == RunStatusFailed
	}, 3*time.Second, 10*time.Millisecond, "an empty range is a failed sweep run")

	run := r.Runs()[0]
	require.Equal(t, []string{"10.0.0.0/30"}, run.Targets)
	require.Zero(t, run.EntityCount)
	require.Contains(t, run.Reason, "did not answer",
		"a count is never reported without the reason behind it")
}

// A sweep that admits nothing must not kill the runner: exiting would take
// rescan with it and leave the policy permanently dead.
func TestAFailedSweepStillRescans(t *testing.T) {
	dialer := newPerHostDialer(nil)
	dialer.defaultCapsErr = dialingErr()
	r := newRescanRunner(t, "10.0.0.0/30", dialer, 60*time.Millisecond)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	require.Eventually(t, func() bool {
		return len(r.Runs()) >= 2
	}, 3*time.Second, 10*time.Millisecond, "the sweep keeps ticking after finding nothing")
}

// A /22 policy holds up to three runs for each of a thousand targets, and the
// agent marshals the whole list every 10s with a 2s budget before it restarts
// the backend. The cap is what keeps a large policy from becoming a restart loop.
func TestRunsForAPolicyAreCapped(t *testing.T) {
	rs := NewRunStore()
	for i := range 400 {
		host := fmt.Sprintf("10.0.%d.%d:9339", i/256, i%256)
		run := rs.CreateRun("p1", host)
		rs.UpdateRun("p1", host, run.ID, RunStatusCompleted, nil, 1)
	}
	require.LessOrEqual(t, len(rs.GetRunsForPolicy("p1")), maxRunsPerPolicy)
}

// The sweep run is the one record describing the policy as a whole, and a busy
// range produces device runs continuously — so it must not be what the cap drops.
func TestTheSweepRunSurvivesTheCap(t *testing.T) {
	rs := NewRunStore()
	sweep := rs.CreateSweepRun("p1", []string{"10.0.0.0/22"})
	rs.FinishSweepRun("p1", sweep.ID, RunStatusCompleted, "2 of 1022 address(es) answered", 2)

	for i := range 400 {
		host := fmt.Sprintf("10.0.%d.%d:9339", i/256, i%256)
		run := rs.CreateRun("p1", host)
		rs.UpdateRun("p1", host, run.ID, RunStatusCompleted, nil, 1)
	}

	var found bool
	for _, r := range rs.GetRunsForPolicy("p1") {
		if r.ID == sweep.ID {
			found = true
		}
	}
	require.True(t, found, "the sweep run is exempt from the cap")
}
