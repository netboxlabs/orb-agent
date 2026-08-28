package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
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

	run := sweepRunFor(t, r)
	require.Equal(t, RunStatusFailed, run.Status, "an empty range is a failed sweep run")
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

// A policy DELETE cancels the sweep mid-probe. That is how a sweep is supposed
// to end, so it must not be logged at Error: an operator removing policies would
// get a red line for every one of them.
func TestACanceledSweepIsNotLoggedAsAFailure(t *testing.T) {
	dialer := newPerHostDialer(nil)
	dialer.blockOn = make(chan struct{})

	var logs bytes.Buffer
	handler := slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})
	policy := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeAuto, DebounceMs: 10},
		Scope:  config.Scope{Targets: []config.Target{{Host: "10.0.0.0/24"}}},
	}
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	r, err := NewRunner(context.Background(), slog.New(handler), "p1", policy,
		&recordingClient{}, dialer, store)
	require.NoError(t, err)

	r.Start()
	require.Eventually(t, func() bool {
		return len(dialer.dialedHosts()) > 0
	}, 3*time.Second, 5*time.Millisecond)

	stopped := make(chan struct{})
	go func() { _ = r.Stop(); close(stopped) }()
	close(dialer.blockOn)
	<-stopped

	require.NotContains(t, logs.String(), "level=ERROR",
		"an ordinary policy removal must not log an error")
}

// entity_count reports how many targets the policy is subscribed to, not how
// many this particular tick newly admitted. A rescan that finds nothing new is
// the normal state of a healthy policy, and reporting 0 there would read as a
// policy that had stopped discovering anything.
func TestASweepReportsTheReachableTotalNotTheDelta(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.2:9339": dialingErr()})
	r := newRescanRunner(t, "10.0.0.0/30", dialer, 40*time.Millisecond)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	// Wait for a rescan tick that admitted nothing new: only .1 ever answers.
	require.Eventually(t, func() bool {
		for _, run := range r.Runs() {
			if run.Status == RunStatusCompleted && run.EntityCount == 1 &&
				strings.Contains(run.Reason, "1 subscribed") &&
				strings.Contains(run.Reason, "0 of 1 probed") {
				return true
			}
		}
		return false
	}, 3*time.Second, 10*time.Millisecond,
		"a tick with no newcomers still reports the one target that is subscribed")
}

// A named host is started without being probed, so it must never be reported as
// having answered. Folding it into the admitted count made an unreachable
// single-host policy read "1 of 1 probed address(es) answered" when nothing was
// probed at all.
func TestANamedHostIsNotReportedAsHavingAnswered(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{"10.0.0.5:9339": dialingErr()})
	r := newSweepRunner(t, "10.0.0.5", dialer)
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	run := sweepRunFor(t, r)

	require.NotContains(t, run.Reason, "answered",
		"nothing was probed, so nothing can have answered")
	require.Contains(t, run.Reason, "1 named target(s) started without probing")
	// Still subscribed, and still not a failure: naming the host is the operator
	// asserting it exists, and dropping it for being mid-reboot is the regression
	// the no-probe rule exists to avoid.
	require.Equal(t, RunStatusCompleted, run.Status)
	require.Equal(t, 1, run.EntityCount)
}

// A sweep that mixes both kinds must keep the two counts distinct rather than
// letting the pinned host inflate the answered figure.
func TestAMixedSweepSeparatesProbedAnswersFromNamedStarts(t *testing.T) {
	dialer := newPerHostDialer(map[string]error{
		"10.0.0.2:9339": dialingErr(),
		"10.0.0.3:9339": dialingErr(),
		"10.0.0.4:9339": dialingErr(),
		"10.0.0.5:9339": dialingErr(), // pinned, unreachable, never probed
		"10.0.0.6:9339": dialingErr(),
	})
	r := runnerWithTargets(t, []config.Target{
		{Host: "10.0.0.0/29"}, // .1-.6
		{Host: "10.0.0.5"},    // pinned inside it
	}, slog.New(slog.DiscardHandler))
	r.dialer = dialer
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	run := sweepRunFor(t, r)
	require.Contains(t, run.Reason, "1 of 5 probed address(es) answered",
		"the pinned host is not one of the five probed")
	require.Contains(t, run.Reason, "1 named target(s) started without probing")
	require.Contains(t, run.Reason, "4 did not answer")
	require.Equal(t, 2, run.EntityCount, "one probed answer plus one named start")
}

// sweepRunFor returns the policy's finished sweep run.
//
// It reads the store's sweep bucket rather than picking by position or by target
// list. Position is not an identifier — runs sort by most recent activity, so a
// device run that flushed after the sweep sorts ahead of it — and for a
// single-host policy the sweep run and that host's device run carry the same
// target list, so neither is a discriminator.
func sweepRunFor(t *testing.T, r *Runner) *Run {
	t.Helper()
	var found *Run
	require.Eventually(t, func() bool {
		r.runStore.mu.RLock()
		defer r.runStore.mu.RUnlock()
		for _, run := range r.runStore.runs[r.name][sweepRunKey] {
			if run.Status != RunStatusRunning {
				found = copyRun(run)
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "a finished sweep run")
	return found
}

// A run still in flight must survive the cap. Activity order drops it first: a
// run's UpdatedAt is stamped at creation and not touched again until it finishes,
// so the longer an ingest hangs the further it sinks. deriveStatus looks for
// RunStatusRunning in this result alone, so truncating the hung run made the
// policy report completed and hid the one record that explained it.
func TestAnInFlightRunSurvivesTheCap(t *testing.T) {
	rs := NewRunStore()
	hung := rs.CreateRun("p1", "10.0.0.9:9339") // created first, never finished

	for i := range 400 {
		host := fmt.Sprintf("10.0.%d.%d:9339", i/256, i%256)
		run := rs.CreateRun("p1", host)
		rs.UpdateRun("p1", host, run.ID, RunStatusCompleted, nil, 1)
	}

	runs := rs.GetRunsForPolicy("p1")
	require.LessOrEqual(t, len(runs), maxRunsPerPolicy, "still capped")

	var found bool
	for _, r := range runs {
		if r.ID == hung.ID {
			found = true
		}
	}
	require.True(t, found, "the hung run is the one thing that must not be dropped")
	require.Equal(t, string(RunStatusRunning), deriveStatus(runs),
		"a policy with a hung ingest must not report completed")
}

// If in-flight runs alone exceed the budget, the stalest are kept: they are the
// most stuck, and so the ones worth showing.
func TestWhenInFlightRunsExceedTheBudgetTheStalestAreKept(t *testing.T) {
	rs := NewRunStore()
	var first, last *Run
	for i := range maxRunsPerPolicy + 20 {
		host := fmt.Sprintf("10.0.1.%d:9339", i)
		run := rs.CreateRun("p1", host)
		if i == 0 {
			first = run
		}
		last = run
	}

	runs := rs.GetRunsForPolicy("p1")
	require.LessOrEqual(t, len(runs), maxRunsPerPolicy, "the payload stays bounded")

	ids := map[string]bool{}
	for _, r := range runs {
		ids[r.ID] = true
	}
	require.True(t, ids[first.ID], "the stalest in-flight run is kept")
	require.False(t, ids[last.ID], "the newest is what gets trimmed")
	require.Equal(t, string(RunStatusRunning), deriveStatus(runs))
}

// The sweep run still outranks everything, including in-flight device runs.
func TestTheSweepRunOutranksInFlightRuns(t *testing.T) {
	rs := NewRunStore()
	sweep := rs.CreateSweepRun("p1", []string{"10.0.0.0/22"})
	rs.FinishSweepRun("p1", sweep.ID, RunStatusCompleted, "2 subscribed", 2)
	for i := range maxRunsPerPolicy + 20 {
		rs.CreateRun("p1", fmt.Sprintf("10.0.1.%d:9339", i))
	}

	var found bool
	for _, r := range rs.GetRunsForPolicy("p1") {
		if r.ID == sweep.ID {
			found = true
		}
	}
	require.True(t, found, "the sweep run is still exempt")
}
