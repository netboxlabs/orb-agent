package policy

import (
	"context"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// scanRunner is a policy runner for scanning and crawling the fake agents
// behind factory, on scheduler, with the embedded mapping.
func scanRunner(t *testing.T, scheduler gocron.Scheduler, factory snmp.ClientFactory, schedule *string) *Runner {
	t.Helper()
	mappingConfig, err := loadMappingConfig()
	require.NoError(t, err)
	return &Runner{
		scheduler:        scheduler,
		ctx:              context.WithValue(context.Background(), policyKey, "p1"),
		ingestCtx:        context.Background(),
		client:           &recordingClient{},
		logger:           discardLogger(),
		timeout:          10 * time.Second,
		snmpTimeout:      3 * time.Second,
		snmpProbeTimeout: time.Second,
		scope: config.Scope{Authentication: config.Authentication{
			ProtocolVersion: snmp.ProtocolVersion2c, Community: "example-community",
		}},
		config:         config.PolicyConfig{Schedule: schedule, Defaults: config.Defaults{Site: "policy-site"}},
		ClientFactory:  factory,
		mappingConfig:  &mappingConfig,
		runStore:       NewRunStore(),
		activeHostJobs: make(map[string]uuid.UUID),
	}
}

// fakeClockScheduler is a scheduler on a fake clock set to now, in UTC.
func fakeClockScheduler(t *testing.T, now time.Time) (gocron.Scheduler, *clockwork.FakeClock) {
	t.Helper()
	clock := clockwork.NewFakeClockAt(now)
	scheduler, err := gocron.NewScheduler(gocron.WithClock(clock), gocron.WithLocation(time.UTC))
	require.NoError(t, err)
	t.Cleanup(func() { _ = scheduler.Shutdown() })
	return scheduler, clock
}

// A host a scheduled range scan finds is crawled right after the scan, not a
// whole period later, and then on the schedule.
func TestRangeHostCrawledRightAfterScan(t *testing.T) {
	tick := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	scheduler, clock := fakeClockScheduler(t, tick.Add(500*time.Millisecond))
	agents := newFakeAgents(time.Second)
	schedule := "*/5 * * * *"
	r := scanRunner(t, scheduler, agents.dial, &schedule)
	scheduler.Start()

	r.runScanWithOriginal(0, []config.Target{{Host: "192.0.2.1", Port: 161}}, "192.0.2.0/30")

	require.Eventually(t, func() bool { return agents.crawlCount("192.0.2.1", 161) == 1 }, 5*time.Second, 10*time.Millisecond,
		"crawled before 10:00:05 (the clock has not moved)")
	jobs := scheduler.Jobs()
	require.Len(t, jobs, 1)
	next, err := jobs[0].NextRun()
	require.NoError(t, err)
	assert.Equal(t, tick.Add(5*time.Minute), next.UTC(), "then on the schedule")

	clock.Advance(4*time.Minute + 59*time.Second)
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 1, agents.crawlCount("192.0.2.1", 161), "nothing more before 10:05")
	clock.Advance(time.Second)
	require.Eventually(t, func() bool { return agents.crawlCount("192.0.2.1", 161) == 2 }, 5*time.Second, 10*time.Millisecond,
		"crawled again at 10:05")
}

// A later scan that finds a host whose crawl job is already scheduled starts
// no second job, so the host is not crawled again out of turn.
func TestRangeHostWithActiveJobNotCrawledAgain(t *testing.T) {
	tick := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	scheduler, _ := fakeClockScheduler(t, tick.Add(500*time.Millisecond))
	agents := newFakeAgents(time.Second)
	schedule := "*/5 * * * *"
	r := scanRunner(t, scheduler, agents.dial, &schedule)
	scheduler.Start()

	r.runScanWithOriginal(0, []config.Target{{Host: "192.0.2.1", Port: 161}}, "192.0.2.0/30")
	require.Eventually(t, func() bool { return agents.crawlCount("192.0.2.1", 161) == 1 }, 5*time.Second, 10*time.Millisecond)

	r.runScanWithOriginal(0, []config.Target{{Host: "192.0.2.1", Port: 161}}, "192.0.2.0/30")
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, 1, agents.crawlCount("192.0.2.1", 161))
	assert.Len(t, scheduler.Jobs(), 1)
}

// The configured entries of a scheduled policy still wait for the first tick.
func TestScheduledEntriesWaitForFirstTick(t *testing.T) {
	agents := newFakeAgents(time.Second)
	r, store := newPolicyRunner(t, `
policies:
  p1:
    config:
      schedule: "0 0 1 1 *"
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.0/30
        - host: 192.0.2.5
`, agents.dial, &recordingClient{}, discardLogger())
	r.Start()
	time.Sleep(1500 * time.Millisecond)
	assert.Empty(t, store.GetRunsForPolicy("p1"))
	assert.Zero(t, agents.probeCount("192.0.2.1", 161)+agents.crawlCount("192.0.2.5", 161))
}
