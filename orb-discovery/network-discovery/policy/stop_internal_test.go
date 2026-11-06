package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/metrics"
)

// blockingNmap runs until it is killed, as a long scan does.
const blockingNmap = "exec sleep 30"

// oneHostNmap prints the XML of a scan that found one host.
const oneHostNmap = `cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host>
<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
EOF`

// noHostsNmap prints the XML of a scan that found no hosts, with a warning on
// stderr as nmap often writes.
const noHostsNmap = `echo 'Warning: 192.0.2.10 did not respond' >&2
cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
<runstats><finished exit="success"/><hosts up="0" down="1" total="1"/></runstats>
</nmaprun>
EOF`

// fakeNmap puts a shell script named nmap first on PATH, so a scan runs it
// instead of nmap and nothing touches the network. The script creates the
// returned marker file when it starts.
func fakeNmap(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake nmap is a shell script")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	body := "#!/bin/sh\ntouch '" + marker + "'\n" + script + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nmap"), []byte(body), 0o700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

// waitForNmap waits until the fake nmap has started.
func waitForNmap(t *testing.T, marker string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}, 30*time.Second, 10*time.Millisecond, "the fake nmap did not start")
}

// shortStopTimeout makes Stop give up waiting for a running job quickly.
func shortStopTimeout(t *testing.T) {
	t.Helper()
	saved := schedulerStopTimeout
	schedulerStopTimeout = 100 * time.Millisecond
	t.Cleanup(func() { schedulerStopTimeout = saved })
}

// fakeClient counts ingests started, returned and delivered. An ingest whose
// context is cancelled fails with the status error grpc-go returns, which is
// not context.Canceled; with err set, a released ingest fails with err. With
// release set, an ingest signals ingesting and waits for release or for its
// context to end.
type fakeClient struct {
	ingests   atomic.Int32
	returned  atomic.Int32
	delivered atomic.Int32
	ingesting chan struct{}
	release   chan struct{}
	err       error
}

func (c *fakeClient) Ingest(ctx context.Context, _ []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.ingests.Add(1)
	defer c.returned.Add(1)
	if c.release != nil {
		c.ingesting <- struct{}{}
		select {
		case <-c.release:
		case <-ctx.Done():
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if c.err != nil {
		return nil, c.err
	}
	c.delivered.Add(1)
	return &diodepb.IngestResponse{}, nil
}

func (c *fakeClient) IngestProto(context.Context, []*diodepb.Entity, ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	return &diodepb.IngestResponse{}, nil
}

func (c *fakeClient) Close() error { return nil }

// logBuffer collects JSON log records written from any goroutine.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// records returns each record logged at level.
func (b *logBuffer) records(t *testing.T, level string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	data := bytes.Clone(b.buf.Bytes())
	b.mu.Unlock()
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var record map[string]any
		require.NoError(t, dec.Decode(&record))
		if record["level"] == level {
			out = append(out, record)
		}
	}
	return out
}

// useTestMeter records the policy metrics where the test can read them.
func useTestMeter(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	metrics.UseMeterForTesting(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	t.Cleanup(func() { metrics.UseMeterForTesting(nil) })
	return reader
}

// sumOf returns the total recorded on the integer sum named name.
func sumOf(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				n += dp.Value
			}
		}
	}
	return n
}

// waitForRun waits for the policy's latest run to reach status and returns it.
func waitForRun(t *testing.T, store *RunStore, policyName string, status RunStatus) *Run {
	t.Helper()
	var latest *Run
	require.Eventually(t, func() bool {
		runs := store.GetRunsForPolicy(policyName)
		if len(runs) == 0 {
			return false
		}
		latest = runs[len(runs)-1]
		return latest.Status == status
	}, 30*time.Second, 10*time.Millisecond, "no %s run for %s", status, policyName)
	return latest
}

func scanPolicy() config.Policy {
	return config.Policy{Scope: config.Scope{Targets: []string{"192.0.2.0/24"}}}
}

// Stopping a policy while its scan runs ends the scan, so the stop returns at
// once, the policy is gone, and the same name starts a new runner.
func TestStopPolicyDuringAScanFreesTheName(t *testing.T) {
	started := fakeNmap(t, blockingNmap)
	m := NewManager(context.Background(), slog.New(slog.DiscardHandler), &fakeClient{})
	t.Cleanup(m.Stop)

	require.NoError(t, m.StartPolicy("p1", scanPolicy()))
	waitForNmap(t, started)
	old := m.policies["p1"]

	start := time.Now()
	m.StopPolicy("p1")
	assert.Less(t, time.Since(start), 5*time.Second, "the stop waited for the scan")
	assert.False(t, m.HasPolicy("p1"), "the stopped policy is still registered")

	require.NoError(t, m.StartPolicy("p1", scanPolicy()))
	assert.NotSame(t, old, m.policies["p1"], "the name did not start a new runner")
}

// A scan cut short by its policy stopping is not a failed discovery: its nmap
// is killed, nothing is ingested, nothing is logged at ERROR, and its run says
// why it ended.
func TestScanStoppedWithItsPolicyIsNotAFailure(t *testing.T) {
	started := fakeNmap(t, blockingNmap)
	reader := useTestMeter(t)
	logs := &logBuffer{}
	client := &fakeClient{}
	m := NewManager(context.Background(), logs.logger(), client)
	t.Cleanup(m.Stop)

	require.NoError(t, m.StartPolicy("p1", scanPolicy()))
	waitForNmap(t, started)
	m.StopPolicy("p1")

	assert.Zero(t, client.ingests.Load(), "a stopped scan ingested")
	assert.Zero(t, sumOf(t, reader, "discovery_failure"), "a stopped scan counted as a failed discovery")
	assert.Empty(t, logs.records(t, "ERROR"))
	var stopped []map[string]any
	for _, record := range logs.records(t, "INFO") {
		if record["msg"] == "nmap scan stopped with its policy" {
			stopped = append(stopped, record)
		}
	}
	require.Len(t, stopped, 1)
	assert.Equal(t, "p1", stopped[0]["policy"])
	assert.Equal(t, "signal: killed", stopped[0]["error"], "the scan did not end with its nmap killed")

	runs := m.runStore.GetRunsForPolicy("p1")
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "run interrupted: policy stopped", runs[0].Reason)
	assert.Zero(t, sumOf(t, reader, "active_policies"))
}

// A scan that runs out of the policy's own timeout still fails its run, warns
// about the timeout, and counts as a failed discovery.
func TestScanTimeoutStillFailsTheRun(t *testing.T) {
	fakeNmap(t, blockingNmap)
	reader := useTestMeter(t)
	logs := &logBuffer{}
	client := &fakeClient{}
	store := NewRunStore()
	r, err := NewRunner(context.Background(), logs.logger(), "p1", scanPolicy(), client, store)
	require.NoError(t, err)
	r.timeout = 100 * time.Millisecond
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })

	run := waitForRun(t, store, "p1", RunStatusFailed)
	assert.True(t, strings.HasPrefix(run.Reason, "nmap scan timed out after 100ms: "), run.Reason)

	warnings := logs.records(t, "WARN")
	require.Len(t, warnings, 1)
	assert.Equal(t, "nmap scan timed out; consider increasing policy timeout", warnings[0]["msg"])
	assert.Equal(t, "p1", warnings[0]["policy"])
	errs := logs.records(t, "ERROR")
	require.Len(t, errs, 1)
	assert.Equal(t, "error running scanner", errs[0]["msg"])
	assert.Equal(t, "p1", errs[0]["policy"])
	assert.Equal(t, int64(1), sumOf(t, reader, "discovery_failure"))
	assert.Zero(t, client.ingests.Load())
}

// A stop waits for an ingest already underway and lets it finish.
func TestStopLetsAnIngestUnderwayFinish(t *testing.T) {
	fakeNmap(t, oneHostNmap)
	logs := &logBuffer{}
	client := &fakeClient{ingesting: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(client.release) })
	t.Cleanup(release)
	store := NewRunStore()
	r, err := NewRunner(context.Background(), logs.logger(), "p1", scanPolicy(), client, store)
	require.NoError(t, err)
	// Diode answers once the stop starts waiting for jobs.
	var cancelledFirst bool
	r.scheduler = &hookedScheduler{Scheduler: r.scheduler, beforeStopJobs: func() {
		cancelledFirst = r.ctx.Err() != nil
		release()
	}}
	r.Start()

	select {
	case <-client.ingesting:
	case <-time.After(30 * time.Second):
		t.Fatal("the scan did not reach its ingest")
	}
	require.NoError(t, r.Stop())
	assert.Equal(t, int32(1), client.returned.Load(), "the stop returned before the ingest finished")
	assert.True(t, cancelledFirst, "the stop waited for jobs before cancelling the runner")

	run := waitForRun(t, store, "p1", RunStatusCompleted)
	assert.Equal(t, 1, run.EntityCount)
	assert.Equal(t, int32(1), client.delivered.Load())
	assert.Empty(t, logs.records(t, "ERROR"))
}

// hookedScheduler runs beforeStopJobs when a stop starts waiting for jobs.
type hookedScheduler struct {
	gocron.Scheduler
	beforeStopJobs func()
}

func (s *hookedScheduler) StopJobs() error {
	s.beforeStopJobs()
	return s.Scheduler.StopJobs()
}

// waitForStop waits until a stop has cancelled the runner.
func waitForStop(t *testing.T, r *Runner) {
	t.Helper()
	select {
	case <-r.ctx.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("the stop did not cancel the runner")
	}
}

// Once Stop returns, the policy sends nothing: an ingest still running when
// the stop gives up waiting is cancelled, and its run ends as a stopped run.
func TestStopCancelsAnIngestItGaveUpWaitingFor(t *testing.T) {
	fakeNmap(t, oneHostNmap)
	shortStopTimeout(t)
	reader := useTestMeter(t)
	logs := &logBuffer{}
	client := &fakeClient{ingesting: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(client.release) })
	t.Cleanup(release)
	store := NewRunStore()
	r, err := NewRunner(context.Background(), logs.logger(), "p1", scanPolicy(), client, store)
	require.NoError(t, err)
	r.Start()

	select {
	case <-client.ingesting:
	case <-time.After(30 * time.Second):
		t.Fatal("the scan did not reach its ingest")
	}
	require.Error(t, r.Stop(), "the stop did not report giving up on the ingest")
	// Diode answers only after the stop has returned.
	release()

	run := waitForRun(t, store, "p1", RunStatusFailed)
	assert.Equal(t, "run interrupted: policy stopped", run.Reason)
	assert.Zero(t, client.delivered.Load(), "the stopped policy delivered an ingest")
	assert.Empty(t, logs.records(t, "ERROR"))
	assert.Zero(t, sumOf(t, reader, "discovery_failure"))
	var stopped []map[string]any
	for _, record := range logs.records(t, "INFO") {
		if record["msg"] == "ingest stopped with its policy" {
			stopped = append(stopped, record)
		}
	}
	require.Len(t, stopped, 1)
	assert.Equal(t, "p1", stopped[0]["policy"])
	assert.Equal(t, status.FromContextError(context.Canceled).Err().Error(), stopped[0]["error"])
}

// pausingHandler holds the record whose message is msg until proceed is
// closed, after signalling reached, so a test can act at that point of a run.
type pausingHandler struct {
	slog.Handler
	msg     string
	reached chan struct{}
	proceed chan struct{}
}

func (h *pausingHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == h.msg {
		select {
		case h.reached <- struct{}{}:
		default:
		}
		<-h.proceed
	}
	return h.Handler.Handle(ctx, record)
}

// A policy that stops after its scan returns and before its ingest starts
// sends nothing: the results are dropped and the run ends as a stopped run.
func TestStopBetweenScanAndIngestSendsNothing(t *testing.T) {
	fakeNmap(t, oneHostNmap)
	reader := useTestMeter(t)
	logs := &logBuffer{}
	// "discovery complete" is logged once the scan has returned its hosts,
	// before the entities are built and ingested.
	pause := &pausingHandler{
		Handler: slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}),
		msg:     "discovery complete",
		reached: make(chan struct{}, 1),
		proceed: make(chan struct{}),
	}
	proceed := sync.OnceFunc(func() { close(pause.proceed) })
	t.Cleanup(proceed)
	client := &fakeClient{}
	store := NewRunStore()
	r, err := NewRunner(context.Background(), slog.New(pause), "p1", scanPolicy(), client, store)
	require.NoError(t, err)
	r.Start()

	select {
	case <-pause.reached:
	case <-time.After(30 * time.Second):
		t.Fatal("the scan did not return its hosts")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.Stop() }()
	waitForStop(t, r)
	proceed()
	require.NoError(t, <-stopped)

	assert.Zero(t, client.ingests.Load(), "the stopped policy started an ingest")
	runs := store.GetRunsForPolicy("p1")
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "run interrupted: policy stopped", runs[0].Reason)
	assert.Empty(t, logs.records(t, "ERROR"))
	assert.Zero(t, sumOf(t, reader, "discovery_failure"))
	var skipped []map[string]any
	for _, record := range logs.records(t, "INFO") {
		if record["msg"] == "ingest skipped: policy stopped" {
			skipped = append(skipped, record)
		}
	}
	require.Len(t, skipped, 1)
	assert.Equal(t, "p1", skipped[0]["policy"])
	assert.Equal(t, "run interrupted: policy stopped", skipped[0]["reason"])
}

// A policy that stops once its scan has returned is a stopped run however the
// scan ended: a scan that found no hosts is not a completed discovery.
func TestStopAfterAScanWithNoHostsIsAStoppedRun(t *testing.T) {
	fakeNmap(t, noHostsNmap)
	reader := useTestMeter(t)
	logs := &logBuffer{}
	// "run finished with warnings" is logged as soon as the scan returns.
	pause := &pausingHandler{
		Handler: slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}),
		msg:     "run finished with warnings",
		reached: make(chan struct{}, 1),
		proceed: make(chan struct{}),
	}
	proceed := sync.OnceFunc(func() { close(pause.proceed) })
	t.Cleanup(proceed)
	client := &fakeClient{}
	store := NewRunStore()
	r, err := NewRunner(context.Background(), slog.New(pause), "p1", scanPolicy(), client, store)
	require.NoError(t, err)
	r.Start()

	select {
	case <-pause.reached:
	case <-time.After(30 * time.Second):
		t.Fatal("the scan did not return")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.Stop() }()
	waitForStop(t, r)
	proceed()
	require.NoError(t, <-stopped)

	runs := store.GetRunsForPolicy("p1")
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "run interrupted: policy stopped", runs[0].Reason)
	assert.Zero(t, sumOf(t, reader, "discovery_success"), "a stopped scan counted as a successful discovery")
	assert.Zero(t, sumOf(t, reader, "discovery_failure"))
	assert.Zero(t, client.ingests.Load())
	assert.Empty(t, logs.records(t, "ERROR"))
	var stoppedRecords []map[string]any
	for _, record := range logs.records(t, "INFO") {
		if record["msg"] == "nmap scan stopped with its policy" {
			stoppedRecords = append(stoppedRecords, record)
		}
	}
	require.Len(t, stoppedRecords, 1)
	assert.Equal(t, "p1", stoppedRecords[0]["policy"])
	assert.NotContains(t, stoppedRecords[0], "error", "the scan returned no error to log")
}

// A genuine Diode error that lands while Stop waits for the ingest is still
// an ingest failure: it is logged at ERROR and its run keeps the real error.
func TestIngestErrorDuringTheStopWaitIsStillAnError(t *testing.T) {
	fakeNmap(t, oneHostNmap)
	logs := &logBuffer{}
	client := &fakeClient{
		ingesting: make(chan struct{}),
		release:   make(chan struct{}),
		err:       status.Error(codes.Unavailable, "diode unavailable"),
	}
	release := sync.OnceFunc(func() { close(client.release) })
	t.Cleanup(release)
	store := NewRunStore()
	r, err := NewRunner(context.Background(), logs.logger(), "p1", scanPolicy(), client, store)
	require.NoError(t, err)
	r.Start()

	select {
	case <-client.ingesting:
	case <-time.After(30 * time.Second):
		t.Fatal("the scan did not reach its ingest")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.Stop() }()
	waitForStop(t, r)
	release()
	require.NoError(t, <-stopped)

	run := waitForRun(t, store, "p1", RunStatusFailed)
	assert.Equal(t, "rpc error: code = Unavailable desc = diode unavailable", run.Reason)
	errs := logs.records(t, "ERROR")
	require.Len(t, errs, 1)
	assert.Equal(t, "error ingesting entities", errs[0]["msg"])
	assert.Equal(t, "rpc error: code = Unavailable desc = diode unavailable", errs[0]["error"])
}

// A policy whose job cannot be scheduled leaves no scheduler goroutine behind.
func TestNewRunnerWithABadScheduleLeavesNoScheduler(t *testing.T) {
	bad := "not a schedule"
	policy := config.Policy{
		Config: config.PolicyConfig{Schedule: &bad},
		Scope:  config.Scope{Targets: []string{"192.0.2.0/24"}},
	}
	before := runtime.NumGoroutine()
	for range 20 {
		_, err := NewRunner(context.Background(), slog.New(slog.DiscardHandler), "p1", policy, &fakeClient{}, NewRunStore())
		require.Error(t, err)
	}
	require.Eventually(t, func() bool { return runtime.NumGoroutine() <= before+2 }, 5*time.Second, 10*time.Millisecond,
		"the schedulers of runners that failed to build are still running")
}

// stopFailingScheduler reports an error from StopJobs, as a scheduler does
// when a job overruns its stop timeout, and records whether it was shut down.
type stopFailingScheduler struct {
	gocron.Scheduler
	shutDown atomic.Bool
}

func (s *stopFailingScheduler) StopJobs() error {
	_ = s.Scheduler.StopJobs()
	return errors.New("stop failed")
}

func (s *stopFailingScheduler) Shutdown() error {
	s.shutDown.Store(true)
	return s.Scheduler.Shutdown()
}

// Stopping the manager stops and drops every policy even when one of them
// fails to stop; that one is logged, its scheduler is still shut down, and
// each policy leaves the active count once.
func TestManagerStopStopsEveryPolicy(t *testing.T) {
	reader := useTestMeter(t)
	logs := &logBuffer{}
	m := NewManager(context.Background(), logs.logger(), &fakeClient{})
	yearly := "0 0 1 1 *"
	idle := config.Policy{
		Config: config.PolicyConfig{Schedule: &yearly},
		Scope:  config.Scope{Targets: []string{"192.0.2.0/24"}},
	}
	names := []string{"p1", "p2", "p3"}
	for _, name := range names {
		require.NoError(t, m.StartPolicy(name, idle))
	}
	require.Equal(t, int64(3), sumOf(t, reader, "active_policies"))
	failing := &stopFailingScheduler{Scheduler: m.policies["p2"].scheduler}
	m.policies["p2"].scheduler = failing

	m.Stop()

	for _, name := range names {
		assert.False(t, m.HasPolicy(name), "%s is still registered", name)
	}
	assert.Zero(t, sumOf(t, reader, "active_policies"))
	assert.True(t, failing.shutDown.Load(), "the scheduler that failed to stop was not shut down")
	warnings := logs.records(t, "WARN")
	require.Len(t, warnings, 1)
	assert.Equal(t, "p2", warnings[0]["policy"])
	assert.Contains(t, warnings[0]["error"], "stop failed")
}
