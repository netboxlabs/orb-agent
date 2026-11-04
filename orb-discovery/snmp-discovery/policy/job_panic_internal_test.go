package policy

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/metrics"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// useTestMeter records the runner's metrics where the test can read them.
func useTestMeter(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	metrics.UseMeterForTesting(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	t.Cleanup(func() { metrics.UseMeterForTesting(nil) })
	return reader
}

// discoveryFailures returns the error attribute of each discovery failure
// recorded.
func discoveryFailures(t *testing.T, reader *sdkmetric.ManualReader) []string {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var reasons []string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "discovery_failure" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				reason, _ := dp.Attributes.Value("error")
				for range dp.Value {
					reasons = append(reasons, reason.AsString())
				}
			}
		}
	}
	return reasons
}

// messages returns the message of each record at level.
func messages(t *testing.T, logs *lockedBuffer, level string) []any {
	t.Helper()
	var msgs []any
	for _, record := range logRecords(t, logs.String()) {
		if record["level"] == level {
			msgs = append(msgs, record["msg"])
		}
	}
	return msgs
}

// panickingWalker panics on its first walk while armed, then answers as the
// agent at its host does.
type panickingWalker struct {
	rowWalker
	armed *atomic.Bool
}

func (w *panickingWalker) Walk(ctx context.Context, oid string, identifierSize int) (map[string]snmp.PDU, error) {
	if w.armed.CompareAndSwap(true, false) {
		panic("walk failure")
	}
	return w.rowWalker.Walk(ctx, oid, identifierSize)
}

// panickingManufacturers panics on its first lookup while armed. The mapper
// looks a manufacturer up on the crawl's own goroutine.
type panickingManufacturers struct {
	data.ManufacturerRetriever
	armed *atomic.Bool
}

func (m *panickingManufacturers) GetManufacturer(id string) (string, error) {
	if m.armed.CompareAndSwap(true, false) {
		panic("mapping failure")
	}
	return m.ManufacturerRetriever.GetManufacturer(id)
}

// discoverySuccesses returns how many discoveries were recorded as
// successful.
func discoverySuccesses(t *testing.T, reader *sdkmetric.ManualReader) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "discovery_success" {
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					n += dp.Value
				}
			}
		}
	}
	return n
}

// panickingScheduler panics when asked to schedule a job.
type panickingScheduler struct {
	gocron.Scheduler
}

func (panickingScheduler) NewJob(gocron.JobDefinition, gocron.Task, ...gocron.JobOption) (gocron.Job, error) {
	panic("scheduler failure")
}

func errorRecords(t *testing.T, logs *lockedBuffer) []map[string]any {
	t.Helper()
	var errs []map[string]any
	for _, record := range logRecords(t, logs.String()) {
		if record["level"] == "ERROR" {
			errs = append(errs, record)
		}
	}
	return errs
}

const singleTargetPolicy = `
policies:
  p1:
    config:
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.1
`

// A crawl that panics, in its walk or on the job's own goroutine while
// mapping, fails its run, counts as a failed discovery and not a successful
// one, and logs one error with the stack; the process and the policy carry on.
func TestCrawlPanicFailsItsRun(t *testing.T) {
	for _, tc := range []struct {
		name         string
		inWalk       bool
		wantInReason string
	}{
		{name: "in the walk", inWalk: true, wantInReason: "walk failure"},
		{name: "in the job, while mapping", inWalk: false, wantInReason: "mapping failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			walkArmed, mappingArmed := &atomic.Bool{}, &atomic.Bool{}
			walkArmed.Store(tc.inWalk)
			mappingArmed.Store(!tc.inWalk)
			factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
				rows := agentRows(host)
				rows[oidSysObjectID] = snmp.PDU{Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.32473.1.1"}
				return &panickingWalker{rowWalker: rowWalker{rows: rows}, armed: walkArmed}, nil
			}
			r, store := newPolicyRunner(t, singleTargetPolicy, factory, &recordingClient{}, jsonLogger(logs))
			r.manufacturers = &panickingManufacturers{ManufacturerRetriever: r.manufacturers, armed: mappingArmed}
			reader := useTestMeter(t)
			logs.Reset()

			r.Start()
			require.Eventually(t, func() bool {
				runs := store.GetRunsForTarget("p1", "192.0.2.1", 161)
				return len(runs) == 1 && runs[0].Status != RunStatusRunning
			}, 10*time.Second, 20*time.Millisecond)

			run := store.GetRunsForTarget("p1", "192.0.2.1", 161)[0]
			assert.Equal(t, RunStatusFailed, run.Status)
			assert.True(t, strings.HasPrefix(run.Reason, "panic: "), run.Reason)
			assert.Contains(t, run.Reason, tc.wantInReason)
			m := &Manager{runStore: store, policies: map[string]*Runner{"p1": r}}
			require.Len(t, m.GetPolicyStatuses(), 1)
			assert.Equal(t, string(RunStatusFailed), m.GetPolicyStatuses()[0].Status, "not stuck at running")

			errs := errorRecords(t, logs)
			require.Len(t, errs, 1, "one error record")
			assert.Equal(t, "p1", errs[0]["policy"])
			assert.Equal(t, "192.0.2.1", errs[0]["host"])
			assert.Contains(t, errs[0]["stack"], "goroutine")
			assert.Empty(t, messages(t, logs, "WARN"), "the panic is reported once, by the error")
			assert.Equal(t, []string{"panic"}, discoveryFailures(t, reader))
			assert.Zero(t, discoverySuccesses(t, reader))

			// The policy is still usable: its next crawl completes, and
			// counts as a success.
			r.runWithMetadata(config.Target{Host: "192.0.2.1", Port: 161}, "")
			runs := store.GetRunsForTarget("p1", "192.0.2.1", 161)
			require.Len(t, runs, 2)
			assert.Equal(t, RunStatusCompleted, runs[1].Status)
			assert.Equal(t, int64(1), discoverySuccesses(t, reader))
			assert.Equal(t, []string{"panic"}, discoveryFailures(t, reader))
		})
	}
}

// withExampleVendor adds a vendor matched by the documentation enterprise
// number, with one OID of its own to walk, for the test's duration.
func withExampleVendor(t *testing.T, r *Runner) string {
	t.Helper()
	previous := defaultVendorMatchers
	defaultVendorMatchers = append(slices.Clone(previous), VendorMatcher{
		Vendor: "example", SysObjectIDPrefixes: []string{".1.3.6.1.4.1.32473."},
	})
	t.Cleanup(func() { defaultVendorMatchers = previous })
	mappingConfig := *r.mappingConfig
	mappingConfig.Entries = append(slices.Clone(mappingConfig.Entries), config.MappingEntry{
		OID: ".1.3.6.1.4.1.32473.1.1", Entity: "chassis_inventory", Field: "vendorSerial", Vendor: "example",
	})
	r.mappingConfig = &mappingConfig
	return ".1.3.6.1.4.1.32473.1.1"
}

// A panic in the vendor walk fails the crawl like one in the first walk,
// rather than leaving the crawl to carry on with the generic walk.
func TestVendorWalkPanicFailsItsRun(t *testing.T) {
	logs := &lockedBuffer{}
	var sessions atomic.Int32
	armed := &atomic.Bool{}
	armed.Store(true)
	var sysObjectID string
	factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		rows := agentRows(host)
		rows[oidSysObjectID] = snmp.PDU{Type: gosnmp.ObjectIdentifier, Value: sysObjectID}
		// The first session is the generic walk, the second the vendor's.
		if sessions.Add(1) == 2 {
			return &panickingWalker{rowWalker: rowWalker{rows: rows}, armed: armed}, nil
		}
		return &rowWalker{rows: rows}, nil
	}
	r, store := newPolicyRunner(t, singleTargetPolicy, factory, &recordingClient{}, jsonLogger(logs))
	sysObjectID = withExampleVendor(t, r)
	reader := useTestMeter(t)
	logs.Reset()

	r.runWithMetadata(config.Target{Host: "192.0.2.1", Port: 161}, "")

	require.Equal(t, int32(2), sessions.Load(), "the vendor walk ran")
	runs := store.GetRunsForTarget("p1", "192.0.2.1", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "panic: walk failure", runs[0].Reason)
	errs := errorRecords(t, logs)
	require.Len(t, errs, 1, "one error record")
	assert.Equal(t, "192.0.2.1", errs[0]["host"])
	assert.Contains(t, errs[0]["stack"], "goroutine")
	assert.Empty(t, messages(t, logs, "WARN"), "not reported as a failed vendor walk")
	assert.Equal(t, []string{"panic"}, discoveryFailures(t, reader))
}

// A scan that panics fails its run and logs one error with the stack.
func TestScanPanicFailsItsRun(t *testing.T) {
	logs := &lockedBuffer{}
	agents := newFakeAgents(time.Second)
	r, store := newPolicyRunner(t, `
policies:
  p1:
    config:
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.0/30
`, agents.dial, &recordingClient{}, jsonLogger(logs))
	r.scheduler = panickingScheduler{Scheduler: r.scheduler}
	logs.Reset()

	r.runScanWithOriginal([]config.Target{{Host: "192.0.2.1", Port: 161}, {Host: "192.0.2.2", Port: 161}}, "192.0.2.0/30")

	runs := store.GetRunsForTarget("p1", "192.0.2.0/30", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, "panic: scheduler failure", runs[0].Reason)
	m := &Manager{runStore: store, policies: map[string]*Runner{"p1": r}}
	assert.Equal(t, string(RunStatusFailed), m.GetPolicyStatuses()[0].Status)

	errs := errorRecords(t, logs)
	require.Len(t, errs, 1, "one error record")
	assert.Equal(t, "p1", errs[0]["policy"])
	assert.Equal(t, "192.0.2.0/30", errs[0]["target"])
	assert.Contains(t, errs[0]["stack"], "goroutine")
}

// recordsAt returns the records logged at level.
func recordsAt(t *testing.T, logs *lockedBuffer, level string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, record := range logRecords(t, logs.String()) {
		if record["level"] == level {
			records = append(records, record)
		}
	}
	return records
}

// A probe that panics counts as no answer, and its worker goes on probing the
// rest of the range. Only the first panic of a scan is logged with its stack;
// the rest are counted.
func TestProbePanicKeepsTheWorker(t *testing.T) {
	var targets []config.Target
	for i := 1; i <= 254; i++ {
		targets = append(targets, config.Target{Host: fmt.Sprintf("192.0.2.%d", i), Port: 161})
	}
	for i := 1; i <= 46; i++ {
		targets = append(targets, config.Target{Host: fmt.Sprintf("198.51.100.%d", i), Port: 161})
	}
	last := targets[len(targets)-1].Host
	factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		if host != last {
			panic("probe failure")
		}
		return &rowWalker{rows: agentRows(host)}, nil
	}
	scheduler := notStartedScheduler(t)
	r := scanRunner(t, scheduler, factory, nil)
	logs := &lockedBuffer{}
	r.logger = jsonLogger(logs)

	r.runScanWithOriginal(targets, "192.0.2.1-198.51.100.46")

	assert.Len(t, scheduler.Jobs(), 1, "the one host that answered, after 256 workers each hit a panic")
	runs := r.runStore.GetRunsForTarget("p1", "192.0.2.1-198.51.100.46", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusCompleted, runs[0].Status)
	errs := errorRecords(t, logs)
	require.Len(t, errs, 1, "the first panic, with its stack")
	assert.Contains(t, errs[0]["stack"], "goroutine")
	assert.NotEmpty(t, errs[0]["host"])
	var complete []map[string]any
	for _, record := range recordsAt(t, logs, "INFO") {
		if record["msg"] == "SNMP probe scan complete" {
			complete = append(complete, record)
		}
	}
	require.Len(t, complete, 1)
	assert.InDelta(t, len(targets)-1, complete[0]["panicked_probes"], 0, "the count, once")
}

// A scan that fails says in its reason, and on its failure line, how many of
// its probes panicked.
func TestProbePanicsCountedWhenTheScanFails(t *testing.T) {
	targets := []config.Target{{Host: "192.0.2.1", Port: 161}, {Host: "192.0.2.2", Port: 161}, {Host: "192.0.2.3", Port: 161}}
	panicking := func(string, uint16, int, time.Duration, *config.Authentication, *slog.Logger) (snmp.Walker, error) {
		panic("probe failure")
	}
	silentLast := func(host string, port uint16, retries int, timeout time.Duration, auth *config.Authentication, logger *slog.Logger) (snmp.Walker, error) {
		if host == "192.0.2.3" {
			return silentWalker{}, nil
		}
		return panicking(host, port, retries, timeout, auth, logger)
	}
	for _, tc := range []struct {
		name       string
		factory    snmp.ClientFactory
		timeout    time.Duration
		stop       bool
		wantReason *regexp.Regexp
		wantLine   string
	}{
		{
			name:       "no host answers",
			factory:    panicking,
			timeout:    10 * time.Second,
			wantReason: regexp.MustCompile(`^no hosts responded to SNMP probe; 3 probes panicked, the log has the first one's stack$`),
			wantLine:   "no hosts responded to SNMP probe",
		},
		{
			name:       "the policy stops",
			factory:    silentLast,
			timeout:    10 * time.Second,
			stop:       true,
			wantReason: regexp.MustCompile(`^context canceled; 2 probes panicked, the log has the first one's stack$`),
			wantLine:   "SNMP probe scan interrupted",
		},
		{
			name:       "the scan runs out of time",
			factory:    silentLast,
			timeout:    300 * time.Millisecond,
			wantReason: regexp.MustCompile(`^context deadline exceeded \(.*\); 2 probes panicked, the log has the first one's stack$`),
			wantLine:   "SNMP probe scan interrupted",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := scanRunner(t, notStartedScheduler(t), tc.factory, nil)
			r.timeout = tc.timeout
			if tc.stop {
				ctx, cancel := context.WithCancel(r.ctx)
				r.ctx = ctx
				time.AfterFunc(300*time.Millisecond, cancel)
			}
			logs := &lockedBuffer{}
			r.logger = jsonLogger(logs)

			r.runScanWithOriginal(targets, "192.0.2.1-3")

			runs := r.runStore.GetRunsForTarget("p1", "192.0.2.1-3", 161)
			require.Len(t, runs, 1)
			assert.Equal(t, RunStatusFailed, runs[0].Status)
			assert.Regexp(t, tc.wantReason, runs[0].Reason)
			assert.Len(t, errorRecords(t, logs), 1)
			var lines []map[string]any
			for _, record := range recordsAt(t, logs, "WARN") {
				if record["msg"] == tc.wantLine {
					lines = append(lines, record)
				}
			}
			require.Len(t, lines, 1)
			assert.NotNil(t, lines[0]["panicked_probes"])
		})
	}
}

// A panic outside any run is still recovered by the scheduler, and logged.
func TestJobPanicOutsideARunIsLogged(t *testing.T) {
	logs := &lockedBuffer{}
	r, _ := newPolicyRunner(t, singleTargetPolicy, newFakeAgents(time.Second).dial, &recordingClient{}, jsonLogger(logs))
	_, err := r.scheduler.NewJob(gocron.OneTimeJob(gocron.OneTimeJobStartImmediately()),
		gocron.NewTask(func() { panic("job failure") }))
	require.NoError(t, err)
	logs.Reset()

	r.Start()
	require.Eventually(t, func() bool {
		for _, record := range errorRecords(t, logs) {
			if strings.Contains(fmt.Sprint(record["error"]), "panic: job failure") {
				assert.Equal(t, "p1", record["policy"])
				assert.Contains(t, record["stack"], "goroutine")
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)
}
