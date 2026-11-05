package policy

import (
	"context"
	"log/slog"
	"maps"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// stopBound is how long a stop may take: well under the scheduler's stop
// timeout, ten seconds, which a stop that only waits for its jobs runs into.
const stopBound = 5 * time.Second

// busyHostPolicy crawls one host, with time enough that only a stop ends the
// crawl's walk.
const busyHostPolicy = `
policies:
  p1:
    config:
      timeout: 120
      snmp_timeout: 60
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.10
`

// busyRangePolicy scans a range, with time enough that only a stop ends the
// scan's probes.
const busyRangePolicy = `
policies:
  p1:
    config:
      timeout: 120
      snmp_timeout: 60
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.1-192.0.2.3
`

// stuckAgents stands in for agents that answer nothing: every walk lasts until
// its context ends. A host answers picks answers its probe at once instead.
// walking hears of each walk as it starts and of each probe answered.
type stuckAgents struct {
	answers  func(host string) bool
	walking  chan string
	inFlight atomic.Int64
	crawls   atomic.Int64
}

func newStuckAgents(answers func(host string) bool) *stuckAgents {
	return &stuckAgents{answers: answers, walking: make(chan string, 16)}
}

func (a *stuckAgents) dial(host string, _ uint16, _ int, timeout time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
	if timeout != defaultSNMPProbeTimeout {
		a.crawls.Add(1)
	} else if a.answers(host) {
		a.walking <- host
		return &rowWalker{rows: agentRows(host)}, nil
	}
	return &stuckWalker{agents: a, host: host}, nil
}

// await returns the next host whose walk started or whose probe answered.
func (a *stuckAgents) await(t *testing.T) string {
	t.Helper()
	select {
	case host := <-a.walking:
		return host
	case <-time.After(10 * time.Second):
		t.Fatal("no walk started")
		return ""
	}
}

type stuckWalker struct {
	agents *stuckAgents
	host   string
}

func (*stuckWalker) Connect() error { return nil }
func (*stuckWalker) Close() error   { return nil }

func (w *stuckWalker) Walk(ctx context.Context, _ string, _ int) (map[string]snmp.PDU, error) {
	w.agents.inFlight.Add(1)
	defer w.agents.inFlight.Add(-1)
	w.agents.walking <- w.host
	<-ctx.Done()
	return nil, ctx.Err()
}

// fakeNetworkManager is a policy manager whose policies reach SNMP agents
// through factory. shutdown cancels its context, as the process does when it
// is told to stop. The manager is stopped when the test ends.
func fakeNetworkManager(t *testing.T, logger *slog.Logger, client diode.Client, factory snmp.ClientFactory) (m *Manager, shutdown context.CancelFunc) {
	t.Helper()
	lookups, err := loadBuiltinLookups()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err = NewManager(ctx, logger, client, lookups.manufacturers)
	require.NoError(t, err)
	m.clientFactory = factory
	t.Cleanup(m.Stop)
	return m, cancel
}

func startPolicies(t *testing.T, m *Manager, policyYAML string) {
	t.Helper()
	policies, err := m.ParsePolicies([]byte(policyYAML))
	require.NoError(t, err)
	for name, p := range policies {
		require.NoError(t, m.StartPolicy(name, p))
	}
}

// A crawl still walking when its policy stops ends at once, whether the policy
// was deleted or the process is shutting down. Its run fails, but it is no
// failed discovery: one info line, no warning or error, no discovery_failure,
// nothing ingested, and its walk returns with it.
func TestStopEndsABusyCrawl(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(m *Manager, shutdown context.CancelFunc)
	}{
		{"the policy is deleted", func(m *Manager, _ context.CancelFunc) { m.StopPolicy("p1") }},
		{"the process shuts down", func(m *Manager, shutdown context.CancelFunc) { shutdown(); m.Stop() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			client := &recordingClient{}
			agents := newStuckAgents(func(string) bool { return false })
			m, shutdown := fakeNetworkManager(t, jsonLogger(logs), client, agents.dial)
			reader := useTestMeter(t)
			startPolicies(t, m, busyHostPolicy)
			require.Equal(t, "192.0.2.10", agents.await(t))
			logs.Reset()

			start := time.Now()
			tc.stop(m, shutdown)
			assert.Less(t, time.Since(start), stopBound, "the stop waited for the crawl")

			assert.False(t, m.HasPolicy("p1"))
			runs := m.runStore.GetRunsForTarget("p1", "192.0.2.10", 161)
			require.Len(t, runs, 1)
			assert.Equal(t, RunStatusFailed, runs[0].Status)
			assert.Equal(t, "context canceled", runs[0].Reason)
			assert.Eventually(t, func() bool { return agents.inFlight.Load() == 0 },
				stopBound, 10*time.Millisecond, "the walk ended with its crawl")
			assert.Empty(t, client.devicesOf("192.0.2.10"), "nothing ingested")
			assert.Empty(t, discoveryFailures(t, reader))
			assert.Empty(t, recordsAt(t, logs, "ERROR"))
			assert.Empty(t, recordsAt(t, logs, "WARN"))
			assert.Equal(t, []any{"SNMP crawl stopped with its policy"}, messages(t, logs, "INFO"))
		})
	}
}

// A scan still probing when its policy stops ends at once, and crawls nothing,
// not even the host it had already found. Its run fails, with one info line and
// no warning or error.
func TestStopEndsABusyScan(t *testing.T) {
	logs := &lockedBuffer{}
	client := &recordingClient{}
	agents := newStuckAgents(func(host string) bool { return host == "192.0.2.1" })
	m, _ := fakeNetworkManager(t, jsonLogger(logs), client, agents.dial)
	reader := useTestMeter(t)
	startPolicies(t, m, busyRangePolicy)
	// 192.0.2.1 answers its probe; the other two hold theirs.
	found := map[string]bool{}
	for range 3 {
		found[agents.await(t)] = true
	}
	require.Len(t, found, 3)
	r := m.policies["p1"]
	logs.Reset()

	start := time.Now()
	m.StopPolicy("p1")
	assert.Less(t, time.Since(start), stopBound, "the stop waited for the scan")

	assert.False(t, m.HasPolicy("p1"))
	runs := m.runStore.GetRunsForTarget("p1", "192.0.2.1-192.0.2.3", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "context canceled", runs[0].Reason)
	assert.Equal(t, 1, runs[0].EntityCount, "the host that answered before the stop")
	r.activeHostJobsMu.Lock()
	assert.Empty(t, r.activeHostJobs, "no crawl scheduled")
	r.activeHostJobsMu.Unlock()
	assert.Zero(t, agents.crawls.Load())
	assert.Eventually(t, func() bool { return agents.inFlight.Load() == 0 },
		stopBound, 10*time.Millisecond, "the probes ended with their scan")
	assert.Empty(t, client.devicesOf("192.0.2.1"), "nothing ingested")
	assert.Empty(t, discoveryFailures(t, reader))
	assert.Empty(t, recordsAt(t, logs, "ERROR"))
	assert.Empty(t, recordsAt(t, logs, "WARN"))
	infos := recordsAt(t, logs, "INFO")
	require.Len(t, infos, 1)
	assert.Equal(t, "SNMP probe scan stopped with its policy", infos[0]["msg"])
	assert.EqualValues(t, 1, infos[0]["responsive_target_count"])
}

// stoppingManufacturers stops the policy on the first manufacturer lookup,
// which the mapper makes on the crawl's goroutine once the walk is done.
type stoppingManufacturers struct {
	data.ManufacturerRetriever
	stop func()
}

func (m stoppingManufacturers) GetManufacturer(id string) (string, error) {
	m.stop()
	return m.ManufacturerRetriever.GetManufacturer(id)
}

// A crawl whose policy stops after the walk, before anything is sent, sends
// nothing: the policy that asked for it is gone.
func TestCrawlStoppedBeforeIngestSendsNothing(t *testing.T) {
	logs := &lockedBuffer{}
	client := &recordingClient{}
	factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		rows := agentRows(host)
		rows[oidSysObjectID] = snmp.PDU{Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.32473.1.1"}
		return &rowWalker{rows: rows}, nil
	}
	r, store := newPolicyRunner(t, singleTargetPolicy, factory, client, jsonLogger(logs))
	// Stop cancels the policy's context before anything else.
	r.manufacturers = stoppingManufacturers{ManufacturerRetriever: r.manufacturers, stop: r.cancel}
	reader := useTestMeter(t)
	logs.Reset()

	r.runWithMetadata(0, config.Target{Host: "192.0.2.1", Port: 161}, "")

	assert.Empty(t, client.devicesOf("192.0.2.1"), "nothing ingested")
	runs := store.GetRunsForTarget("p1", "192.0.2.1", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "context canceled", runs[0].Reason)
	assert.Empty(t, discoveryFailures(t, reader))
	assert.Empty(t, recordsAt(t, logs, "ERROR"))
	assert.Contains(t, messages(t, logs, "INFO"), "SNMP crawl stopped with its policy")
}

// sendingClient holds every ingest until its context ends, as a send to a
// slow Diode does, and says when one starts.
type sendingClient struct {
	recordingClient
	sending chan struct{}
}

func (c *sendingClient) Ingest(ctx context.Context, _ []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.sending <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

// A crawl whose policy stops while it is sending ends at once, with no error
// line: the send was cut short by the stop, not refused by Diode.
func TestCrawlStoppedWhileSendingIsNoFailure(t *testing.T) {
	logs := &lockedBuffer{}
	client := &sendingClient{sending: make(chan struct{}, 1)}
	r, store := newPolicyRunner(t, singleTargetPolicy, newFakeAgents(time.Second).dial, client, jsonLogger(logs))
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.runWithMetadata(0, config.Target{Host: "192.0.2.1", Port: 161}, "")
	}()
	<-client.sending
	logs.Reset()

	require.NoError(t, r.Stop())
	select {
	case <-done:
	case <-time.After(stopBound):
		t.Fatal("the send outlived the stop")
	}

	runs := store.GetRunsForTarget("p1", "192.0.2.1", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "context canceled", runs[0].Reason)
	assert.Empty(t, recordsAt(t, logs, "ERROR"))
	assert.Equal(t, []any{"SNMP crawl stopped with its policy"}, messages(t, logs, "INFO"))
}

// A job that asks the scheduler for its jobs while its policy stops, as a scan
// does before it schedules crawls, gets its answer, so the stop does not wait
// out the scheduler's stop timeout.
func TestStopAnswersAJobAskingTheScheduler(t *testing.T) {
	r, _ := newPolicyRunner(t, singleTargetPolicy, newFakeAgents(time.Second).dial, &recordingClient{}, discardLogger())
	running := make(chan struct{})
	_, err := r.scheduler.NewJob(gocron.OneTimeJob(gocron.OneTimeJobStartImmediately()),
		gocron.NewTask(func(ctx context.Context) {
			close(running)
			// gocron ends a job's context once the scheduler is stopping.
			<-ctx.Done()
			r.scheduler.Jobs()
		}))
	require.NoError(t, err)
	r.Start()
	<-running

	start := time.Now()
	assert.NoError(t, r.Stop())
	assert.Less(t, time.Since(start), stopBound, "the stop waited out the scheduler's timeout")
}

// unstoppableScheduler fails to stop, as a scheduler does whose job outlasts
// its stop timeout.
type unstoppableScheduler struct {
	gocron.Scheduler
}

func (unstoppableScheduler) StopJobs() error { return gocron.ErrStopJobsTimedOut }
func (unstoppableScheduler) Shutdown() error { return gocron.ErrStopSchedulerTimedOut }

func unstoppableRunner(t *testing.T, name string) *Runner {
	t.Helper()
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), policyKey, name))
	t.Cleanup(cancel)
	return &Runner{scheduler: unstoppableScheduler{notStartedScheduler(t)}, ctx: ctx, cancel: cancel, logger: discardLogger()}
}

// A policy whose runner does not stop cleanly is still removed, with a warning
// naming it, so a new version of it can start.
func TestStopPolicyRemovesAPolicyThatDidNotStopCleanly(t *testing.T) {
	logs := &lockedBuffer{}
	r := unstoppableRunner(t, "p1")
	m := &Manager{logger: jsonLogger(logs), policies: map[string]*Runner{"p1": r}}

	m.StopPolicy("p1")

	assert.False(t, m.HasPolicy("p1"))
	assert.Error(t, r.ctx.Err(), "its scans and crawls were told to stop")
	warns := recordsAt(t, logs, "WARN")
	require.Len(t, warns, 1)
	assert.Equal(t, "p1", warns[0]["policy"])
	assert.Equal(t, gocron.ErrStopSchedulerTimedOut.Error(), warns[0]["error"])
}

// Stopping the manager stops every policy, even when none stops cleanly.
func TestManagerStopStopsEveryPolicy(t *testing.T) {
	logs := &lockedBuffer{}
	runners := map[string]*Runner{
		"p1": unstoppableRunner(t, "p1"),
		"p2": unstoppableRunner(t, "p2"),
		"p3": unstoppableRunner(t, "p3"),
	}
	m := &Manager{logger: jsonLogger(logs), policies: maps.Clone(runners)}

	m.Stop()

	assert.Empty(t, m.policies)
	for name, r := range runners {
		assert.Error(t, r.ctx.Err(), "%s was told to stop", name)
	}
	assert.Len(t, recordsAt(t, logs, "WARN"), 3)
}
