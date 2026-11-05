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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
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
// With vendorOID set, a crawl's first walk answers at once, naming that
// sysObjectID, so the crawl goes on to the vendor's own walk. walking hears of
// each walk as it starts and of each probe answered.
type stuckAgents struct {
	answers   func(host string) bool
	vendorOID string
	walking   chan string
	inFlight  atomic.Int64
	crawls    atomic.Int64
}

func newStuckAgents(answers func(host string) bool) *stuckAgents {
	return &stuckAgents{answers: answers, walking: make(chan string, 16)}
}

func (a *stuckAgents) dial(host string, _ uint16, _ int, timeout time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
	if timeout != defaultSNMPProbeTimeout {
		if a.crawls.Add(1) == 1 && a.vendorOID != "" {
			rows := agentRows(host)
			rows[oidSysObjectID] = snmp.PDU{Type: gosnmp.ObjectIdentifier, Value: a.vendorOID}
			return &rowWalker{rows: rows}, nil
		}
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

// A crawl still walking when its policy stops ends at once, in its first walk
// or in its vendor's, whether the policy was deleted or the process is shutting
// down. Its run fails, but it is no failed discovery: one info line, no warning
// or error, no discovery_failure, nothing ingested, and its walk returns with it.
func TestStopEndsABusyCrawl(t *testing.T) {
	walks := []struct {
		name      string
		vendorOID string
	}{
		{"in its first walk", ""},
		// A numeric sysObjectID the vendor matchers map to a vendor with walks
		// of its own.
		{"in its vendor walk", ".1.3.6.1.4.1.2636.1.1.1.2.21"},
	}
	stops := []struct {
		name   string
		stop   func(m *Manager, shutdown context.CancelFunc)
		reason string
	}{
		{"the policy is deleted", func(m *Manager, _ context.CancelFunc) { m.StopPolicy("p1") }, "run interrupted: policy stopped"},
		{"the process shuts down", func(m *Manager, shutdown context.CancelFunc) { shutdown(); m.Stop() }, "context canceled"},
	}
	for _, walk := range walks {
		for _, tc := range stops {
			t.Run(walk.name+", "+tc.name, func(t *testing.T) {
				testStopEndsABusyCrawl(t, walk.vendorOID, tc.stop, tc.reason)
			})
		}
	}
}

func testStopEndsABusyCrawl(t *testing.T, vendorOID string, stop func(m *Manager, shutdown context.CancelFunc), reason string) {
	logs := &lockedBuffer{}
	client := &recordingClient{}
	agents := newStuckAgents(func(string) bool { return false })
	agents.vendorOID = vendorOID
	m, shutdown := fakeNetworkManager(t, jsonLogger(logs), client, agents.dial)
	reader := useTestMeter(t)
	startPolicies(t, m, busyHostPolicy)
	require.Equal(t, "192.0.2.10", agents.await(t))
	logs.Reset()

	start := time.Now()
	stop(m, shutdown)
	assert.Less(t, time.Since(start), stopBound, "the stop waited for the crawl")

	assert.False(t, m.HasPolicy("p1"))
	runs := m.runStore.GetRunsForTarget("p1", "192.0.2.10", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, reason, runs[0].Reason)
	assert.Eventually(t, func() bool { return agents.inFlight.Load() == 0 },
		stopBound, 10*time.Millisecond, "the walk ended with its crawl")
	assert.Empty(t, client.devicesOf("192.0.2.10"), "nothing ingested")
	assert.Empty(t, discoveryFailures(t, reader))
	assert.Empty(t, recordsAt(t, logs, "ERROR"))
	assert.Empty(t, recordsAt(t, logs, "WARN"))
	infos := recordsAt(t, logs, "INFO")
	require.Len(t, infos, 1)
	assert.Equal(t, "SNMP crawl stopped with its policy", infos[0]["msg"])
	assert.Equal(t, reason, infos[0]["error"], "the stop's cause, as the run gives")
}

// cancellingWalker stops the policy when walked, then returns its context's
// error at once, as the real client does once its context ends.
type cancellingWalker struct {
	stop func()
}

func (cancellingWalker) Connect() error { return nil }
func (cancellingWalker) Close() error   { return nil }

func (w cancellingWalker) Walk(ctx context.Context, _ string, _ int) (map[string]snmp.PDU, error) {
	w.stop()
	return nil, ctx.Err()
}

// A walk that ends with its policy's stop, or with the process shutting down,
// is a stopped crawl, whichever the crawl hears of first: the walk's error or
// the stop. Walks run to their end before the crawl waits, so both are ready
// when it looks and the runtime picks either; the stop is repeated so that
// both are taken.
func TestWalkEndingWithTheStopIsAStoppedCrawl(t *testing.T) {
	previous := startWalk
	startWalk = func(walk func()) { walk() }
	t.Cleanup(func() { startWalk = previous })

	for _, phase := range []struct {
		name      string
		vendorOID string
	}{
		{"in its first walk", ""},
		{"in its vendor walk", ".1.3.6.1.4.1.2636.1.1.1.2.21"},
	} {
		for _, stop := range []struct {
			name     string
			shutdown bool
			reason   string
		}{
			{"the policy is deleted", false, "run interrupted: policy stopped"},
			{"the process shuts down", true, "context canceled"},
		} {
			t.Run(phase.name+", "+stop.name, func(t *testing.T) {
				logs := &lockedBuffer{}
				var r *Runner
				var stopRun func()
				dials := 0
				factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
					dials++
					if phase.vendorOID != "" && dials == 1 {
						rows := agentRows(host)
						rows[oidSysObjectID] = snmp.PDU{Type: gosnmp.ObjectIdentifier, Value: phase.vendorOID}
						return &rowWalker{rows: rows}, nil
					}
					return cancellingWalker{stop: stopRun}, nil
				}
				// At info, which is all the test reads: debug costs most of the time.
				logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
				r, store := newPolicyRunner(t, singleTargetPolicy, factory, &recordingClient{}, logger)
				reader := useTestMeter(t)
				logs.Reset()

				const stops = 200
				for range stops {
					parent, shutdown := context.WithCancel(context.Background())
					r.ctx, r.cancel = context.WithCancelCause(context.WithValue(parent, policyKey, "p1"))
					stopRun = func() { r.cancel(errPolicyStopped) }
					if stop.shutdown {
						stopRun = shutdown
					}
					dials = 0
					r.runWithMetadata(0, config.Target{Host: "192.0.2.1", Port: 161}, "")
					shutdown()
				}

				assert.Empty(t, discoveryFailures(t, reader))
				assert.Zero(t, discoverySuccesses(t, reader))
				assert.Empty(t, recordsAt(t, logs, "WARN"))
				assert.Empty(t, recordsAt(t, logs, "ERROR"))
				assert.Len(t, stopLines(t, logs, "SNMP crawl stopped with its policy"), stops)
				for _, run := range store.GetRunsForTarget("p1", "192.0.2.1", 161) {
					assert.Equal(t, RunStatusFailed, run.Status)
					assert.Equal(t, stop.reason, run.Reason)
				}
			})
		}
	}
}

// A walk the crawl's own timeout ends is no stopped crawl, whichever the crawl
// hears of first: the walk's error or its deadline. In its first walk the crawl
// fails; in its vendor walk it fails, or goes on with its first walk's tables,
// as it always has.
func TestWalkEndingWithItsOwnTimeoutIsNoStop(t *testing.T) {
	previous := startWalk
	startWalk = func(walk func()) { walk() }
	t.Cleanup(func() { startWalk = previous })

	for _, phase := range []struct {
		name      string
		vendorOID string
	}{
		{"in its first walk", ""},
		{"in its vendor walk", ".1.3.6.1.4.1.2636.1.1.1.2.21"},
	} {
		t.Run(phase.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			client := &recordingClient{}
			dials, timedWalks := 0, 0
			factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
				dials++
				if phase.vendorOID != "" && dials == 1 {
					rows := agentRows(host)
					rows[oidSysObjectID] = snmp.PDU{Type: gosnmp.ObjectIdentifier, Value: phase.vendorOID}
					return &rowWalker{rows: rows}, nil
				}
				timedWalks++
				return silentWalker{}, nil
			}
			r, store := newPolicyRunner(t, singleTargetPolicy, factory, client, logger)
			// Time enough for the first walk to answer, when it is not the one
			// the timeout ends.
			r.timeout = 20 * time.Millisecond
			reader := useTestMeter(t)
			logs.Reset()

			const crawls = 30
			for range crawls {
				dials = 0
				r.runWithMetadata(0, config.Target{Host: "192.0.2.1", Port: 161}, "")
			}

			require.Equal(t, crawls, timedWalks, "every crawl reached the walk its timeout ends")
			failures := discoveryFailures(t, reader)
			for _, reason := range failures {
				assert.Equal(t, "context deadline exceeded", reason)
			}
			assert.Empty(t, stopLines(t, logs, "SNMP crawl stopped with its policy"))
			if phase.vendorOID == "" {
				assert.Len(t, failures, crawls)
				assert.Len(t, recordsAt(t, logs, "ERROR"), crawls)
				for _, run := range store.GetRunsForTarget("p1", "192.0.2.1", 161) {
					assert.Equal(t, RunStatusFailed, run.Status)
					assert.Equal(t, "context deadline exceeded", run.Reason)
				}
				return
			}
			// Each crawl either failed or went on and sent what its first
			// walk found.
			assert.Equal(t, crawls, len(failures)+len(client.devicesOf("192.0.2.1")))
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
	assert.Equal(t, "run interrupted: policy stopped", runs[0].Reason)
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
	assert.Equal(t, "run interrupted: policy stopped", infos[0]["error"])
	assert.EqualValues(t, 1, infos[0]["responsive_target_count"])
}

// stoppingHandler stops the policy as the crawl logs that its walks and
// mapping are done, the last thing it does before it sends.
type stoppingHandler struct {
	slog.Handler
	stop func()
}

func (h stoppingHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "SNMP crawl complete" {
		h.stop()
	}
	return h.Handler.Handle(ctx, record)
}

func (h stoppingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return stoppingHandler{h.Handler.WithAttrs(attrs), h.stop}
}

func (h stoppingHandler) WithGroup(name string) slog.Handler {
	return stoppingHandler{h.Handler.WithGroup(name), h.stop}
}

// A crawl whose policy stops once its walks and mapping are done, before it
// starts sending, sends nothing: the device was read with the settings of a
// policy that may already have been replaced. Its run is a stopped one, with
// something to send or not, and counts as neither a success nor a failure.
func TestCrawlStoppedBeforeIngestSendsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows map[string]snmp.PDU
	}{
		{"with something to send", agentRows("192.0.2.1")},
		{"with nothing to send", map[string]snmp.PDU{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			client := &recordingClient{}
			factory := func(string, uint16, int, time.Duration, *config.Authentication, *slog.Logger) (snmp.Walker, error) {
				return &rowWalker{rows: tc.rows}, nil
			}
			var r *Runner
			// Stop's first step: the ingest context stays open while Stop waits
			// for the crawl.
			logger := slog.New(stoppingHandler{jsonLogger(logs).Handler(), func() { r.cancel(errPolicyStopped) }})
			r, store := newPolicyRunner(t, singleTargetPolicy, factory, client, logger)
			reader := useTestMeter(t)
			logs.Reset()

			r.runWithMetadata(0, config.Target{Host: "192.0.2.1", Port: 161}, "")

			assert.Empty(t, client.devicesOf("192.0.2.1"), "nothing ingested")
			runs := store.GetRunsForTarget("p1", "192.0.2.1", 161)
			require.Len(t, runs, 1)
			assert.Equal(t, RunStatusFailed, runs[0].Status)
			assert.Equal(t, "run interrupted: policy stopped", runs[0].Reason)
			assert.Empty(t, discoveryFailures(t, reader))
			assert.Zero(t, discoverySuccesses(t, reader))
			assert.Empty(t, recordsAt(t, logs, "ERROR"))
			assert.NotContains(t, messages(t, logs, "INFO"), "no entities to ingest")
			stopLines := stopLines(t, logs, "SNMP crawl stopped with its policy")
			require.Len(t, stopLines, 1)
			assert.Equal(t, "run interrupted: policy stopped", stopLines[0]["error"])
		})
	}
}

// stopLines returns the info records logged with msg.
func stopLines(t *testing.T, logs *lockedBuffer, msg string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, record := range recordsAt(t, logs, "INFO") {
		if record["msg"] == msg {
			lines = append(lines, record)
		}
	}
	return lines
}

// stoppingJobsScheduler stops the policy when the scan asks for its jobs,
// which it does after its own stop check, before it schedules any crawl.
type stoppingJobsScheduler struct {
	gocron.Scheduler
	stop func()
}

func (s stoppingJobsScheduler) Jobs() []gocron.Job {
	s.stop()
	return s.Scheduler.Jobs()
}

// A scan whose policy stops after its stop check, while it schedules the
// crawls of what it found, is a stopped run all the same: those crawls never
// run. So is one that found nothing, which is not reported as finding nothing.
func TestScanStoppedWhileSchedulingIsAStoppedRun(t *testing.T) {
	for _, tc := range []struct {
		name       string
		answers    string
		responsive int
	}{
		{"a host answered", "192.0.2.1", 1},
		{"no host answered", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
				if host == tc.answers {
					return &rowWalker{rows: agentRows(host)}, nil
				}
				return failingWalker{}, nil
			}
			var cancel context.CancelCauseFunc
			r := scanRunner(t, stoppingJobsScheduler{notStartedScheduler(t), func() { cancel(errPolicyStopped) }}, factory, nil)
			r.ctx, cancel = context.WithCancelCause(r.ctx)
			t.Cleanup(func() { cancel(nil) })
			logs := &lockedBuffer{}
			r.logger = jsonLogger(logs)

			r.runScanWithOriginal(0, []config.Target{{Host: "192.0.2.1", Port: 161}, {Host: "192.0.2.2", Port: 161}}, "192.0.2.1-192.0.2.2")

			runs := r.runStore.GetRunsForTarget("p1", "192.0.2.1-192.0.2.2", 161)
			require.Len(t, runs, 1)
			assert.Equal(t, RunStatusFailed, runs[0].Status)
			assert.Equal(t, "run interrupted: policy stopped", runs[0].Reason)
			assert.Empty(t, recordsAt(t, logs, "WARN"))
			assert.NotContains(t, messages(t, logs, "INFO"), "SNMP probe scan complete")
			lines := stopLines(t, logs, "SNMP probe scan stopped with its policy")
			require.Len(t, lines, 1)
			assert.EqualValues(t, tc.responsive, lines[0]["responsive_target_count"])
		})
	}
}

// gatedClient holds each ingest until the test answers it or the ingest's
// context ends. A cancelled ingest fails the way the Diode SDK's does, with a
// gRPC status; with sentAsCancelled it succeeds instead, as a request that
// went out just as the stop landed. It keeps what it was sent, and counts the
// ingests begun, and those begun once their context had ended.
type gatedClient struct {
	recordingClient
	sentAsCancelled bool
	sending         chan struct{}
	answer          chan error
	begun           atomic.Int64
	late            atomic.Int64
}

func newGatedClient() *gatedClient {
	return &gatedClient{sending: make(chan struct{}, 16), answer: make(chan error)}
}

func (c *gatedClient) Ingest(ctx context.Context, entities []diode.Entity, opts ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	if ctx.Err() != nil {
		c.late.Add(1)
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	c.begun.Add(1)
	c.sending <- struct{}{}
	select {
	case err := <-c.answer:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		if !c.sentAsCancelled {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	return c.recordingClient.Ingest(ctx, entities, opts...)
}

func (c *gatedClient) awaitSending(t *testing.T) {
	t.Helper()
	select {
	case <-c.sending:
	case <-time.After(10 * time.Second):
		t.Fatal("nothing was sent")
	}
}

// withStopTimeout shortens how long a stop waits for running jobs.
func withStopTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	previous := schedulerStopTimeout
	schedulerStopTimeout = d
	t.Cleanup(func() { schedulerStopTimeout = previous })
}

// An ingest already under way when its policy stops is left to end while the
// stop waits for it, and ends as it would have: sent, or refused by Diode and
// logged as the error it is.
func TestStopLetsAnIngestUnderWayEnd(t *testing.T) {
	for _, tc := range []struct {
		name       string
		chunkLimit int
		answer     error
		wantStatus RunStatus
		wantReason string
	}{
		{"Diode takes it", 0, nil, RunStatusCompleted, ""},
		{"Diode takes every request of a target sent in several", 1, nil, RunStatusCompleted, ""},
		{"Diode refuses it", 0, status.Error(codes.Unavailable, "diode unavailable"), RunStatusFailed, "rpc error: code = Unavailable desc = diode unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.chunkLimit > 0 {
				withChunkLimit(t, tc.chunkLimit)
			}
			logs := &lockedBuffer{}
			client := newGatedClient()
			m, _ := fakeNetworkManager(t, jsonLogger(logs), client, newFakeAgents(time.Second).dial)
			reader := useTestMeter(t)
			startPolicies(t, m, busyHostPolicy)
			client.awaitSending(t)
			r := m.policies["p1"]
			logs.Reset()

			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				m.StopPolicy("p1")
			}()
			select {
			case <-r.ctx.Done():
			case <-time.After(stopBound):
				t.Error("the stop did not cancel the policy's context")
			}
			// Every request the crawl sends while the stop waits is answered.
			for answering := true; answering; {
				select {
				case client.answer <- tc.answer:
				case <-stopped:
					answering = false
				case <-time.After(stopBound):
					t.Error("the stop did not leave the ingest under way to end")
					<-stopped
					answering = false
				}
			}
			if t.Failed() {
				return
			}
			requests := int(client.begun.Load())

			assert.False(t, m.HasPolicy("p1"))
			runs := m.runStore.GetRunsForTarget("p1", "192.0.2.10", 161)
			require.Len(t, runs, 1)
			assert.Equal(t, tc.wantStatus, runs[0].Status)
			assert.Equal(t, tc.wantReason, runs[0].Reason)
			assert.Equal(t, tc.answer == nil, len(client.devicesOf("192.0.2.10")) == 1, "sent only if Diode took it")
			if tc.answer == nil {
				assert.Equal(t, requests, client.sentBatches(), "every request sent")
			}
			if tc.chunkLimit > 0 {
				assert.GreaterOrEqual(t, requests, 2)
			}
			assert.Zero(t, client.late.Load())
			assert.EqualValues(t, 1, discoverySuccesses(t, reader), "the crawl ended as it would have")
			assert.NotContains(t, messages(t, logs, "INFO"), "SNMP crawl stopped with its policy")
			assert.Empty(t, recordsAt(t, logs, "WARN"), "the stop ended cleanly")
			assert.Empty(t, discoveryFailures(t, reader))
			errs := recordsAt(t, logs, "ERROR")
			if tc.answer == nil {
				assert.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1)
			assert.Equal(t, "error ingesting entities", errs[0]["msg"])
			assert.Equal(t, tc.wantReason, errs[0]["error"])
		})
	}
}

// An ingest still under way when the stop's wait for it ends is cancelled
// before the stop returns, and nothing more is sent: not the rest of a target
// sent in several requests, whether the request in flight failed as it was
// cancelled or went out just as the stop landed. Its run is a stopped one: one
// info line saying how far the send got, no error, no discovery_failure.
func TestStopCancelsAnIngestThatOutlastsItsWait(t *testing.T) {
	for _, tc := range []struct {
		name            string
		sentAsCancelled bool
		wantInError     string
	}{
		{"the request in flight fails", false, "request 1 of "},
		{"the request in flight went out", true, "request 2 of "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withStopTimeout(t, 200*time.Millisecond)
			withChunkLimit(t, 1)
			logs := &lockedBuffer{}
			client := newGatedClient()
			client.sentAsCancelled = tc.sentAsCancelled
			m, _ := fakeNetworkManager(t, jsonLogger(logs), client, newFakeAgents(time.Second).dial)
			reader := useTestMeter(t)
			startPolicies(t, m, busyHostPolicy)
			client.awaitSending(t)
			logs.Reset()

			start := time.Now()
			m.StopPolicy("p1")
			assert.Less(t, time.Since(start), stopBound, "the stop waited past its timeout")

			assert.False(t, m.HasPolicy("p1"))
			var runs []*Run
			require.Eventually(t, func() bool {
				runs = m.runStore.GetRunsForTarget("p1", "192.0.2.10", 161)
				return len(runs) == 1 && runs[0].Status != RunStatusRunning
			}, stopBound, 10*time.Millisecond)
			assert.Equal(t, RunStatusFailed, runs[0].Status)
			assert.Equal(t, "run interrupted: policy stopped", runs[0].Reason)
			assert.Zero(t, client.late.Load(), "nothing sent once the stop ended the ingest")
			assert.Empty(t, recordsAt(t, logs, "ERROR"))
			assert.Empty(t, discoveryFailures(t, reader))
			assert.Zero(t, discoverySuccesses(t, reader))
			warns := recordsAt(t, logs, "WARN")
			require.Len(t, warns, 1)
			assert.Equal(t, "policy stopped; a job outlasted the stop's wait, and any send it had under way was cancelled", warns[0]["msg"])
			lines := stopLines(t, logs, "SNMP crawl stopped with its policy")
			require.Len(t, lines, 1)
			assert.Contains(t, lines[0]["error"], tc.wantInError)
			assert.Contains(t, lines[0]["error"], "entities already sent")
		})
	}
}

// An ingest the stop ends between two requests of a target says why on its
// stop line, after how far it got: the policy's stop, or the process shutting
// down. Here the first request goes out just as the stop lands, so the check
// before the second is what ends the send.
func TestIngestStoppedBetweenRequestsSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stop   func(m *Manager, shutdown context.CancelFunc)
		reason string
	}{
		{"the policy is deleted", func(m *Manager, _ context.CancelFunc) { m.StopPolicy("p1") }, "run interrupted: policy stopped"},
		{"the process shuts down", func(m *Manager, shutdown context.CancelFunc) { shutdown(); m.Stop() }, "context canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withStopTimeout(t, 200*time.Millisecond)
			withChunkLimit(t, 1)
			logs := &lockedBuffer{}
			client := newGatedClient()
			client.sentAsCancelled = true
			m, shutdown := fakeNetworkManager(t, jsonLogger(logs), client, newFakeAgents(time.Second).dial)
			startPolicies(t, m, busyHostPolicy)
			client.awaitSending(t)
			logs.Reset()

			tc.stop(m, shutdown)

			var runs []*Run
			require.Eventually(t, func() bool {
				runs = m.runStore.GetRunsForTarget("p1", "192.0.2.10", 161)
				return len(runs) == 1 && runs[0].Status != RunStatusRunning
			}, stopBound, 10*time.Millisecond)
			assert.Equal(t, tc.reason, runs[0].Reason)
			assert.EqualValues(t, 1, client.begun.Load(), "the second request was never begun")
			assert.Zero(t, client.late.Load())
			lines := stopLines(t, logs, "SNMP crawl stopped with its policy")
			require.Len(t, lines, 1)
			assert.Regexp(t, `^request 2 of \d+ failed, 1 of \d+ entities already sent: `+tc.reason+`$`, lines[0]["error"])
		})
	}
}

// The process shutting down ends an ingest under way at once, so the stops
// that follow have nothing to wait for. The run gives "context canceled", with
// one info line, no warning and no error, and nothing more is sent.
func TestShutdownEndsAnIngestUnderWay(t *testing.T) {
	for _, tc := range []struct {
		name       string
		chunkLimit int
	}{
		{"in one request", 0},
		{"in several requests", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.chunkLimit > 0 {
				withChunkLimit(t, tc.chunkLimit)
			}
			logs := &lockedBuffer{}
			client := newGatedClient()
			m, shutdown := fakeNetworkManager(t, jsonLogger(logs), client, newFakeAgents(time.Second).dial)
			reader := useTestMeter(t)
			startPolicies(t, m, busyHostPolicy)
			client.awaitSending(t)
			logs.Reset()

			start := time.Now()
			shutdown()
			m.Stop()
			assert.Less(t, time.Since(start), stopBound, "the stop waited for the ingest")

			var runs []*Run
			require.Eventually(t, func() bool {
				runs = m.runStore.GetRunsForTarget("p1", "192.0.2.10", 161)
				return len(runs) == 1 && runs[0].Status != RunStatusRunning
			}, stopBound, 10*time.Millisecond)
			assert.Equal(t, RunStatusFailed, runs[0].Status)
			assert.Equal(t, "context canceled", runs[0].Reason)
			assert.Zero(t, client.late.Load(), "nothing sent once shutdown ended the ingest")
			assert.Empty(t, recordsAt(t, logs, "WARN"))
			assert.Empty(t, recordsAt(t, logs, "ERROR"))
			assert.Empty(t, discoveryFailures(t, reader))
			assert.Zero(t, discoverySuccesses(t, reader))
			lines := stopLines(t, logs, "SNMP crawl stopped with its policy")
			require.Len(t, lines, 1)
		})
	}
}

// sentBatches returns how many ingests the client took.
func (c *recordingClient) sentBatches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.batches)
}

// A crawl or scan that starts once its policy has stopped does nothing and
// records nothing: the policy may already run again under its name.
func TestRunStartingAfterItsPolicyStoppedRecordsNothing(t *testing.T) {
	logs := &lockedBuffer{}
	client := &recordingClient{}
	agents := newFakeAgents(time.Second)
	r, store := newPolicyRunner(t, singleTargetPolicy, agents.dial, client, jsonLogger(logs))
	require.NoError(t, r.Stop())
	logs.Reset()

	r.runWithMetadata(0, config.Target{Host: "192.0.2.1", Port: 161}, "")
	r.runScanWithOriginal(0, []config.Target{{Host: "192.0.2.2", Port: 161}, {Host: "192.0.2.3", Port: 161}}, "192.0.2.2-192.0.2.3")

	assert.Empty(t, store.GetAllPoliciesWithRuns())
	assert.Zero(t, agents.crawlCount("192.0.2.1", 161))
	assert.Zero(t, agents.probeCount("192.0.2.2", 161))
	assert.Empty(t, client.devicesOf("192.0.2.1"))
	assert.Empty(t, logs.String())
}

// shutdownCounter counts the shutdowns of the scheduler it wraps.
type shutdownCounter struct {
	gocron.Scheduler
	shutdowns atomic.Int64
}

func (s *shutdownCounter) Shutdown() error {
	s.shutdowns.Add(1)
	return s.Scheduler.Shutdown()
}

// A policy NewRunner refuses leaves no scheduler running behind it.
func TestRefusedPolicyLeavesNoScheduler(t *testing.T) {
	var made []*shutdownCounter
	previous := newScheduler
	newScheduler = func(options ...gocron.SchedulerOption) (gocron.Scheduler, error) {
		s, err := previous(options...)
		if err != nil {
			return nil, err
		}
		counted := &shutdownCounter{Scheduler: s}
		made = append(made, counted)
		return counted, nil
	}
	t.Cleanup(func() { newScheduler = previous })

	badSchedule := "not a schedule"
	target := config.Scope{Targets: []config.Target{{Host: "192.0.2.1", Port: 161}}}
	for name, p := range map[string]config.Policy{
		"timeout not above snmp_timeout": {Config: config.PolicyConfig{Timeout: 5, SNMPTimeout: 5}, Scope: target},
		"a job the scheduler refuses":    {Config: config.PolicyConfig{Schedule: &badSchedule}, Scope: target},
	} {
		_, err := NewRunner(context.Background(), discardLogger(), "p1", p, nil, newFakeAgents(time.Second).dial,
			&config.Mapping{}, nil, nil, NewRunStore())
		require.Error(t, err, name)
	}
	require.Len(t, made, 2)
	for _, s := range made {
		assert.EqualValues(t, 1, s.shutdowns.Load())
	}
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
	parent := context.WithValue(context.Background(), policyKey, name)
	ctx, cancel := context.WithCancelCause(parent)
	ingestCtx, cancelIngest := context.WithCancelCause(parent)
	t.Cleanup(func() { cancel(nil); cancelIngest(nil) })
	return &Runner{
		scheduler: unstoppableScheduler{notStartedScheduler(t)}, ctx: ctx, cancel: cancel,
		ingestCtx: ingestCtx, cancelIngest: cancelIngest, logger: discardLogger(),
	}
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
	assert.Equal(t, "policy stopped; a job outlasted the stop's wait, and any send it had under way was cancelled", warns[0]["msg"])
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
