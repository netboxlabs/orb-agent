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

// fakeNmap puts a shell script named nmap first on PATH, so a scan runs it
// instead of nmap and nothing touches the network.
func fakeNmap(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake nmap is a shell script")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nmap"), []byte("#!/bin/sh\n"+script+"\n"), 0o700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// fakeClient counts ingests. With release set, an ingest signals ingesting and
// waits for release; it fails with its context's error, as a gRPC call does.
type fakeClient struct {
	ingests   atomic.Int32
	ingesting chan struct{}
	release   chan struct{}
}

func (c *fakeClient) Ingest(ctx context.Context, _ []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.ingests.Add(1)
	if c.release != nil {
		c.ingesting <- struct{}{}
		<-c.release
	}
	return &diodepb.IngestResponse{}, ctx.Err()
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
	}, 10*time.Second, 10*time.Millisecond, "no %s run for %s", status, policyName)
	return latest
}

func scanPolicy() config.Policy {
	return config.Policy{Scope: config.Scope{Targets: []string{"192.0.2.0/24"}}}
}

// Stopping a policy while its scan runs ends the scan, so the stop returns at
// once, the policy is gone, and the same name starts a new runner.
func TestStopPolicyDuringAScanFreesTheName(t *testing.T) {
	fakeNmap(t, blockingNmap)
	m := NewManager(context.Background(), slog.New(slog.DiscardHandler), &fakeClient{})
	t.Cleanup(m.Stop)

	require.NoError(t, m.StartPolicy("p1", scanPolicy()))
	waitForRun(t, m.runStore, "p1", RunStatusRunning)
	old := m.policies["p1"]

	start := time.Now()
	m.StopPolicy("p1")
	assert.Less(t, time.Since(start), 5*time.Second, "the stop waited for the scan")
	assert.False(t, m.HasPolicy("p1"), "the stopped policy is still registered")

	require.NoError(t, m.StartPolicy("p1", scanPolicy()))
	assert.NotSame(t, old, m.policies["p1"], "the name did not start a new runner")
}

// A scan cut short by its policy stopping is not a failed discovery: nothing
// is ingested, nothing is logged at ERROR, and its run says why it ended.
func TestScanStoppedWithItsPolicyIsNotAFailure(t *testing.T) {
	fakeNmap(t, blockingNmap)
	reader := useTestMeter(t)
	logs := &logBuffer{}
	client := &fakeClient{}
	m := NewManager(context.Background(), logs.logger(), client)
	t.Cleanup(m.Stop)

	require.NoError(t, m.StartPolicy("p1", scanPolicy()))
	waitForRun(t, m.runStore, "p1", RunStatusRunning)
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

// A stop leaves an ingest that has already started to finish, as it did
// before stops cancelled scans.
func TestStopLetsAnIngestUnderwayFinish(t *testing.T) {
	fakeNmap(t, oneHostNmap)
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
	case <-time.After(10 * time.Second):
		t.Fatal("the scan did not reach its ingest")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.Stop() }()
	require.Eventually(t, func() bool { return r.ctx.Err() != nil }, 5*time.Second, 10*time.Millisecond,
		"the stop did not cancel the runner")
	release()
	require.NoError(t, <-stopped)

	run := waitForRun(t, store, "p1", RunStatusCompleted)
	assert.Equal(t, 1, run.EntityCount)
	assert.Empty(t, logs.records(t, "ERROR"))
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
