package policy

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// sampleSession streams one snapshot every 10 ms, as SAMPLE does. The first
// connection's stream fails after failAfter snapshots, so a target flushes
// several times on one connection and then reconnects.
type sampleSession struct {
	gnmi.FakeSession
	snapshot  gnmi.Notification
	failAfter int
	subs      atomic.Int32
}

func (s *sampleSession) Subscribe(ctx context.Context, _ gnmi.Mode, _ []string, _ int) (<-chan gnmi.Notification, <-chan error, error) {
	first := s.subs.Add(1) == 1
	notes := make(chan gnmi.Notification)
	errs := make(chan error, 1)
	go func() {
		defer close(notes)
		defer close(errs)
		for i := 0; ; i++ {
			if first && i == s.failAfter {
				errs <- errors.New("connection reset")
				return
			}
			select {
			case notes <- s.snapshot:
			case <-ctx.Done():
				return
			}
			select {
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				return
			}
		}
	}()
	return notes, errs, nil
}

// sessionDialer hands out the same session on every dial and counts them.
type sessionDialer struct {
	sess  gnmi.Session
	dials atomic.Int32
}

func (d *sessionDialer) Dial(context.Context, gnmi.TargetSpec) (gnmi.Session, error) {
	d.dials.Add(1)
	return d.sess, nil
}

// lagWarningSnapshot is a device whose two member ports name aggregates that
// were not discovered, so each flush skips two LAG memberships.
func lagWarningSnapshot() gnmi.Notification {
	return gnmi.Notification{SyncDone: true, Updates: []gnmi.Update{
		{Path: "/system/state/hostname", Value: "sw1"},
		{Path: "/interfaces/interface[name=Ethernet1]/state/type", Value: "iana-if-type:ethernetCsmacd"},
		{Path: "/interfaces/interface[name=Ethernet1]/ethernet/state/aggregate-id", Value: "Port-Channel1"},
		{Path: "/interfaces/interface[name=Ethernet2]/state/type", Value: "iana-if-type:ethernetCsmacd"},
		{Path: "/interfaces/interface[name=Ethernet2]/ethernet/state/aggregate-id", Value: "Port-Channel2"},
	}}
}

// A skipped LAG membership names the policy and host, and is logged once per
// connection: SAMPLE flushes on every interval, so without the gate the warning
// repeats for as long as the target stays connected.
func TestRunnerLogsLagWarningsOncePerConnectionWithContext(t *testing.T) {
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)

	const host = "192.0.2.10:57400"
	sess := &sampleSession{snapshot: lagWarningSnapshot(), failAfter: 8}
	dialer := &sessionDialer{sess: sess}
	client := &recordingClient{}
	logs := &syncBuf{}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: config.ModeSample, SampleIntervalMs: 20, DebounceMs: 5,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{{Host: host}}},
	}
	r, err := NewRunner(context.Background(), slog.New(slog.NewTextHandler(logs, nil)),
		"p1", pol, client, dialer, store)
	require.NoError(t, err)
	r.backoffBase = 10 * time.Millisecond
	r.Start()

	// The first connection flushes on several intervals before its stream
	// fails; then the second flushes several times too.
	require.Eventually(t, func() bool { return dialer.dials.Load() >= 2 }, 3*time.Second, 5*time.Millisecond)
	require.GreaterOrEqual(t, client.count(), 2)
	second := client.count()
	require.Eventually(t, func() bool { return client.count() >= second+3 }, 3*time.Second, 5*time.Millisecond)
	require.NoError(t, r.Stop())

	lines := strings.Split(logs.String(), "\n")
	for _, agg := range []string{"Port-Channel1", "Port-Channel2"} {
		var got []string
		for _, l := range lines {
			if strings.Contains(l, "lag: aggregate interface not discovered") && strings.Contains(l, "aggregate="+agg) {
				got = append(got, l)
			}
		}
		assert.Len(t, got, 2, "once per connection for %s, over two connections", agg)
		for _, l := range got {
			assert.Contains(t, l, "policy=p1")
			assert.Contains(t, l, "host="+host)
		}
	}
}
