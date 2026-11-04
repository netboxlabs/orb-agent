package policy

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// silentWalker is an address nothing answers on: its walk lasts until the
// scan stops waiting.
type silentWalker struct{}

func (silentWalker) Connect() error { return nil }
func (silentWalker) Close() error   { return nil }
func (silentWalker) Walk(ctx context.Context, _ string, _ int) (map[string]snmp.PDU, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// mostlySilentRange is 300 addresses of which only the first answers.
func mostlySilentRange(answered func()) ([]config.Target, snmp.ClientFactory) {
	return silentRange(func(host string) bool { return host == "192.0.2.1" }, answered)
}

// silentRange is 300 addresses of which only those answers picks answer.
func silentRange(answers func(host string) bool, answered func()) ([]config.Target, snmp.ClientFactory) {
	var targets []config.Target
	for i := 1; i <= 254; i++ {
		targets = append(targets, config.Target{Host: fmt.Sprintf("192.0.2.%d", i), Port: 161})
	}
	for i := 1; i <= 46; i++ {
		targets = append(targets, config.Target{Host: fmt.Sprintf("198.51.100.%d", i), Port: 161})
	}
	factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		if answers(host) {
			answered()
			return &rowWalker{rows: agentRows(host)}, nil
		}
		return silentWalker{}, nil
	}
	return targets, factory
}

func notStartedScheduler(t *testing.T) gocron.Scheduler {
	t.Helper()
	scheduler, err := gocron.NewScheduler()
	require.NoError(t, err)
	t.Cleanup(func() { _ = scheduler.Shutdown() })
	return scheduler
}

// A scan that runs out of its own time still crawls the hosts it found, and
// its failed run says how far it got.
func TestTimedOutScanCrawlsWhatItFound(t *testing.T) {
	targets, factory := mostlySilentRange(func() {})
	scheduler := notStartedScheduler(t)
	r := scanRunner(t, scheduler, factory, nil)
	r.timeout = 300 * time.Millisecond

	r.runScanWithOriginal(targets, "192.0.2.1-198.51.100.46")

	assert.Len(t, scheduler.Jobs(), 1, "the host that answered is crawled")
	runs := r.runStore.GetRunsForTarget("p1", "192.0.2.1-198.51.100.46", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assert.Equal(t, 1, runs[0].EntityCount)
	assertStartedProbing(t, runs[0].Reason, 1)
}

// assertStartedProbing checks a timed-out scan's reason over 300 addresses:
// every worker started a probe, the tail was never reached.
func assertStartedProbing(t *testing.T, reason string, responded int) {
	t.Helper()
	m := regexp.MustCompile(`^context deadline exceeded \(started probing (\d+) of 300 addresses, (\d+) responded; raise timeout to probe them all\)$`).
		FindStringSubmatch(reason)
	require.NotNil(t, m, reason)
	started, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	assert.GreaterOrEqual(t, started, maxProbeWorkers, "every worker took an address")
	assert.Less(t, started, 300, "the tail was never reached")
	assert.Equal(t, strconv.Itoa(responded), m[2])
}

// A scan that runs out of time before any address answers schedules nothing,
// and still says how far it got.
func TestTimedOutScanWithNoAnswer(t *testing.T) {
	targets, factory := silentRange(func(string) bool { return false }, func() {})
	scheduler := notStartedScheduler(t)
	r := scanRunner(t, scheduler, factory, nil)
	r.timeout = 300 * time.Millisecond

	r.runScanWithOriginal(targets, "192.0.2.1-198.51.100.46")

	assert.Empty(t, scheduler.Jobs())
	runs := r.runStore.GetRunsForTarget("p1", "192.0.2.1-198.51.100.46", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusFailed, runs[0].Status)
	assertStartedProbing(t, runs[0].Reason, 0)
}

// A scan cut short because its policy stopped schedules nothing, whichever
// way the policy's context ended.
func TestStoppedPolicyScanSchedulesNothing(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		answered := make(chan struct{}, 1)
		targets, factory := mostlySilentRange(func() { answered <- struct{}{} })
		scheduler := notStartedScheduler(t)
		r := scanRunner(t, scheduler, factory, nil)
		ctx, cancel := context.WithCancel(r.ctx)
		r.ctx = ctx

		done := make(chan struct{})
		go func() {
			defer close(done)
			r.runScanWithOriginal(targets, "192.0.2.1-198.51.100.46")
		}()
		<-answered
		time.Sleep(50 * time.Millisecond)
		cancel()
		<-done

		assert.Empty(t, scheduler.Jobs())
		runs := r.runStore.GetRunsForTarget("p1", "192.0.2.1-198.51.100.46", 161)
		require.Len(t, runs, 1)
		assert.Equal(t, RunStatusFailed, runs[0].Status)
		assert.Equal(t, "context canceled", runs[0].Reason)
	})
	t.Run("ended by its own deadline", func(t *testing.T) {
		targets, factory := mostlySilentRange(func() {})
		scheduler := notStartedScheduler(t)
		r := scanRunner(t, scheduler, factory, nil)
		ctx, cancel := context.WithTimeout(r.ctx, 300*time.Millisecond)
		t.Cleanup(cancel)
		r.ctx = ctx

		r.runScanWithOriginal(targets, "192.0.2.1-198.51.100.46")

		assert.Empty(t, scheduler.Jobs())
		runs := r.runStore.GetRunsForTarget("p1", "192.0.2.1-198.51.100.46", 161)
		require.Len(t, runs, 1)
		assert.Equal(t, "context deadline exceeded", runs[0].Reason)
	})
}

func TestWorstScanTime(t *testing.T) {
	for _, tc := range []struct {
		addresses int
		want      time.Duration
	}{
		{1, time.Second},
		{256, time.Second},
		{257, 2 * time.Second},
		{1022, 4 * time.Second},
	} {
		assert.Equal(t, tc.want, worstScanTime(tc.addresses, time.Second), "%d addresses", tc.addresses)
	}
}

// The policy warns at load about a range its timeout may not cover, and says
// nothing about one it does.
func TestLoadWarnsAboutARangeTheTimeoutMayNotCover(t *testing.T) {
	policy := func(probeTimeout int) string {
		return `
policies:
  p1:
    config:
      timeout: 3
      snmp_timeout: 1
      snmp_probe_timeout: ` + strconv.Itoa(probeTimeout) + `
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.0/30
        - host: 192.0.2.9
`
	}
	warnings := func(probeTimeout int) []map[string]any {
		logs := &lockedBuffer{}
		newPolicyRunner(t, policy(probeTimeout), newFakeAgents(time.Second).dial, &recordingClient{}, jsonLogger(logs))
		var warns []map[string]any
		for _, record := range logRecords(t, logs.String()) {
			if record["level"] == "WARN" {
				warns = append(warns, record)
			}
		}
		return warns
	}

	warns := warnings(4)
	require.Len(t, warns, 1)
	assert.Equal(t, "192.0.2.0/30", warns[0]["target"])
	assert.Equal(t, "4s", warns[0]["probe_time"])
	assert.Equal(t, "3s", warns[0]["timeout"])
	assert.Equal(t, "p1", warns[0]["policy"])

	assert.Empty(t, warnings(3), "a scan that can just finish")
	assert.Empty(t, warnings(2))
}
