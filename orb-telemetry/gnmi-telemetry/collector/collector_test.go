package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/profiles"
)

func loadStore(t *testing.T) *profiles.Store {
	t.Helper()
	st, err := profiles.LoadProfiles("", nil)
	require.NoError(t, err)
	return st
}

// streamOf answers SubscribeMany with the given notifications, then blocks
// until ctx is done.
func streamOf(notes ...gnmi.Notification) func(ctx context.Context, subs []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
	return func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
		out := make(chan gnmi.Notification)
		errs := make(chan error, 1)
		go func() {
			defer close(out)
			defer close(errs)
			for _, n := range notes {
				select {
				case out <- n:
				case <-ctx.Done():
					return
				}
			}
			<-ctx.Done()
		}()
		return out, errs, nil
	}
}

func sample(octets uint64, ts int64) gnmi.Notification {
	return gnmi.Notification{Timestamp: ts, Updates: []gnmi.Update{
		{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: octets},
		{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
		{Path: "/system/memory/state/physical", Value: uint64(16744919040)},
		{Path: "/lldp/interfaces/interface[name=e1]/state/counters/frame-in", Value: uint64(1)},
	}}
}

func waitFor(t *testing.T, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func target(host, id string) config.Target {
	return config.EffectiveTarget(config.Scope{}, config.Target{Host: host, ID: id})
}

func TestCollectTargetExportsMatchedUpdatesAndDropsTheRest(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Vendor: "Nokia", Encodings: []string{"PROTO"}},
		SubscribeManyFn: streamOf(sample(1394, time.Now().UnixNano())),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("10.0.0.1", "42"), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))

	waitFor(t, 3*time.Second, func() bool {
		got := collect(t, reader)
		_, a := got["gnmi.if_in_octets"]
		_, b := got["gnmi.if_oper_status"]
		_, m := got["gnmi.memory_physical"]
		return a && b && m
	})
	got := collect(t, reader)
	sum := got["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1394), sum.DataPoints[0].Value)
	for k, want := range map[string]string{"device_ip": "10.0.0.1", "policy": "p", "netbox_id": "42", "interface_name": "e1"} {
		v, ok := sum.DataPoints[0].Attributes.Value(attribute.Key(k))
		require.True(t, ok, k)
		assert.Equal(t, want, v.AsString(), k)
	}
	g := got["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
	assert.Equal(t, 1.0, g.DataPoints[0].Value)
	_, unmatched := got["gnmi.x"]
	assert.False(t, unmatched, "an unmatched path yields no metric")
	up, ok := got["gnmi.target_up"].Data.(metricdata.Gauge[int64])
	require.True(t, ok, "target_up is exported")
	require.Len(t, up.DataPoints, 1)
	assert.Equal(t, int64(1), up.DataPoints[0].Value)
	mode, _ := up.DataPoints[0].Attributes.Value("mode")
	assert.Equal(t, "on_change", mode.AsString())

	subs := sess.Subscriptions()
	require.NotEmpty(t, subs)
	modes := map[string]gnmi.Mode{}
	for _, s := range subs {
		modes[s.Path] = s.Mode
		if s.Path != "/platform/control[slot=*]/memory" {
			assert.Equal(t, "openconfig", s.Origin, s.Path)
		}
		if s.Mode == gnmi.Sample {
			assert.Equal(t, 30000, s.SampleIntervalMs, s.Path)
		}
	}
	assert.Equal(t, gnmi.Sample, modes["/interfaces/interface[name=*]/state/counters"])
	assert.Equal(t, gnmi.OnChange, modes["/interfaces/interface[name=*]/state/oper-status"])
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Equal(t, "nokia_srlinux", st[0].Profile)
	assert.Equal(t, "on_change", st[0].Mode)
	assert.True(t, st[0].Up)
}

func TestSrlOverlayUsesNativeOriginForItsSubscription(t *testing.T) {
	testReader(t)
	sess := &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{Vendor: "Nokia"}, SubscribeManyFn: streamOf()}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool { return len(sess.Subscriptions()) > 0 })
	var native *gnmi.Subscription
	subs := sess.Subscriptions()
	for i := range subs {
		if subs[i].Path == "/platform/control[slot=*]/memory" {
			native = &subs[i]
		}
	}
	require.NotNil(t, native)
	assert.Equal(t, "", native.Origin)
}

// Capabilities reports a NOS without a vendor, so an overlay written for that
// NOS is reachable only when selection passes the NOS along.
func TestProfileSelectionUsesTheDetectedNOS(t *testing.T) {
	testReader(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme_nos.yaml"), []byte(
		"extends: _base\nmatch: {nos: sonic}\n"), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	sess := &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{NOS: "SONiC"}, SubscribeManyFn: streamOf()}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Profile != ""
	})
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Equal(t, "acme_nos", st[0].Profile)
}

func TestModeLadderOnSynchronousRejection(t *testing.T) {
	reader := testReader(t)
	var calls atomic.Int64
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(_ context.Context, subs []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			calls.Add(1)
			for _, s := range subs {
				if s.Mode == gnmi.OnChange {
					return nil, nil, status.Error(codes.InvalidArgument, "on_change not supported")
				}
			}
			return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
		},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{{Path: "/system/memory/state/physical", Value: uint64(1)}}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 50 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Mode == "get"
	})
	// The status flips to get before the first poll, so only data proves polling.
	waitFor(t, 3*time.Second, func() bool { _, ok := collect(t, reader)["gnmi.memory_physical"]; return ok })
	assert.GreaterOrEqual(t, calls.Load(), int64(2), "on_change was refused, then sample, before polling")
	assert.Equal(t, int64(2), fallbacks(t, reader), "two steps down the ladder: on_change to sample, sample to get")
}

func TestModeLadderOnAnEarlyStreamFailure(t *testing.T) {
	testReader(t)
	var calls atomic.Int64
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, subs []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			calls.Add(1)
			for _, s := range subs {
				if s.Mode == gnmi.OnChange {
					// The target accepts the RPC, answers the sync response, then
					// rejects on the stream, which is how gnmic surfaces an
					// unsupported mode. The sync response is handed over before
					// the error exists, so the consumer always sees it first and
					// a bare sync response must not count as data.
					out := make(chan gnmi.Notification)
					errs := make(chan error, 1)
					go func() {
						defer close(out)
						defer close(errs)
						select {
						case out <- gnmi.Notification{SyncDone: true}:
						case <-ctx.Done():
							return
						}
						errs <- status.Error(codes.InvalidArgument, "on_change not supported")
					}()
					return out, errs, nil
				}
			}
			return streamOf(sample(1, time.Now().UnixNano()))(ctx, subs)
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Mode == "sample"
	})
	for _, s := range sess.Subscriptions() {
		assert.Equal(t, gnmi.Sample, s.Mode, "the second request is all SAMPLE")
	}
	assert.Equal(t, int64(2), calls.Load(), "one on_change request, then one sample request")
}

func TestForcedSampleNeverAsksOnChange(t *testing.T) {
	testReader(t)
	sess := &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{}, SubscribeManyFn: streamOf()}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "sample", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool { return len(sess.Subscriptions()) > 0 })
	for _, s := range sess.Subscriptions() {
		assert.Equal(t, gnmi.Sample, s.Mode)
	}
}

// A forced mode has one rung, and a target that accepts the RPC then rejects
// on the stream refuses that rung as surely as one that refuses it outright.
// Both have to reach Get, or the loop reopens the unsupported stream for ever.
func TestForcedModeFallsToGetOnAnEarlyStreamFailure(t *testing.T) {
	reader := testReader(t)
	var calls atomic.Int64
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			calls.Add(1)
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				select {
				case out <- gnmi.Notification{SyncDone: true}:
				case <-ctx.Done():
					return
				}
				errs <- status.Error(codes.InvalidArgument, "on_change not supported")
			}()
			return out, errs, nil
		},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{{Path: "/system/memory/state/physical", Value: uint64(1)}}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 50 * time.Millisecond, Mode: "on_change", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Mode == "get"
	})
	// The status flips to get before the first poll, so only data proves polling.
	waitFor(t, 3*time.Second, func() bool { _, ok := collect(t, reader)["gnmi.memory_physical"]; return ok })
	assert.Equal(t, int64(1), calls.Load(), "a forced ladder has one rung, and the stream refusal spends it")
	assert.Equal(t, int64(1), fallbacks(t, reader), "one step down the ladder: the forced rung to get")
}

func TestDeleteWithdrawsTheElementsSeries(t *testing.T) {
	reader := testReader(t)
	ts := time.Now().UnixNano()
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: streamOf(
			gnmi.Notification{Timestamp: ts, Updates: []gnmi.Update{
				{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(1)},
				{Path: "/interfaces/interface[name=e2]/state/counters/in-octets", Value: uint64(2)},
			}},
			gnmi.Notification{Timestamp: ts + 1, Deletes: []string{"/interfaces/interface[name=e1]"}},
		),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	// The condition names the survivor, so the poll cannot return on the
	// instant between the two stores of the first notification.
	waitFor(t, 3*time.Second, func() bool {
		m, ok := collect(t, reader)["gnmi.if_in_octets"]
		if !ok {
			return false
		}
		pts := m.Data.(metricdata.Sum[int64]).DataPoints
		if len(pts) != 1 {
			return false
		}
		v, _ := pts[0].Attributes.Value("interface_name")
		return v.AsString() == "e2"
	})
}

// A delete of a single leaf sits below every subscription rather than above
// one, so the prefix pass matches nothing and the series would stand until it
// went stale, and for good if it streams on change.
func TestLeafDeleteWithdrawsOnlyThatSeries(t *testing.T) {
	reader := testReader(t)
	ts := time.Now().UnixNano()
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: streamOf(
			gnmi.Notification{Timestamp: ts, Updates: []gnmi.Update{
				{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(1)},
				{Path: "/interfaces/interface[name=e1]/state/counters/out-octets", Value: uint64(2)},
			}},
			gnmi.Notification{Timestamp: ts + 1, Deletes: []string{"/interfaces/interface[name=e1]/state/counters/in-octets"}},
		),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	// The condition names the survivor, so it cannot pass on the instant
	// between the two stores of the first notification.
	waitFor(t, 3*time.Second, func() bool {
		got := collect(t, reader)
		out, ok := got["gnmi.if_out_octets"]
		if !ok || len(out.Data.(metricdata.Sum[int64]).DataPoints) != 1 {
			return false
		}
		in, ok := got["gnmi.if_in_octets"]
		return !ok || len(in.Data.(metricdata.Sum[int64]).DataPoints) == 0
	})
}

// A delete between the two extremes, deeper than the subscription path and
// shallower than the metric's leaf, matched neither the prefix pass nor the
// exact-leaf pass, so the series stood until it went stale.
func TestIntermediateDeleteWithdrawsTheNestedLeaf(t *testing.T) {
	reader := testReader(t)
	ts := time.Now().UnixNano()
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: streamOf(
			gnmi.Notification{Timestamp: ts, Updates: []gnmi.Update{
				{Path: "/system/cpus/cpu[index=0]/state/total/instant", Value: 12.5},
				{Path: "/system/cpus/cpu[index=0]/state/user/instant", Value: 3.5},
			}},
			gnmi.Notification{Timestamp: ts + 1, Deletes: []string{"/system/cpus/cpu[index=0]/state/total"}},
		),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	// The condition names the survivor, so it cannot pass on the instant
	// between the two stores of the first notification.
	waitFor(t, 3*time.Second, func() bool {
		got := collect(t, reader)
		user, ok := got["gnmi.cpu_user"]
		if !ok || len(user.Data.(metricdata.Gauge[float64]).DataPoints) != 1 {
			return false
		}
		total, ok := got["gnmi.cpu_utilization"]
		return !ok || len(total.Data.(metricdata.Gauge[float64]).DataPoints) == 0
	})
}

// A container delete names an ancestor of several subscriptions and carries no
// keys, so the series it withdraws are bounded by the metrics of the
// subscriptions it matched, not by the target and policy alone.
func TestContainerDeleteWithdrawsOnlyThatSubtree(t *testing.T) {
	reader := testReader(t)
	ts := time.Now().UnixNano()
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: streamOf(
			gnmi.Notification{Timestamp: ts, Updates: []gnmi.Update{
				{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(1)},
				{Path: "/system/memory/state/physical", Value: uint64(16744919040)},
			}},
			gnmi.Notification{Timestamp: ts + 1, Deletes: []string{"/interfaces"}},
		),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	// The condition holds only after the delete: the counter had a point until
	// then, and it names the survivor, so it cannot pass between the two stores
	// of the first notification either.
	waitFor(t, 3*time.Second, func() bool {
		got := collect(t, reader)
		mem, ok := got["gnmi.memory_physical"]
		if !ok || len(mem.Data.(metricdata.Gauge[float64]).DataPoints) != 1 {
			return false
		}
		counters, ok := got["gnmi.if_in_octets"]
		return !ok || len(counters.Data.(metricdata.Sum[int64]).DataPoints) == 0
	})
}

func TestForgetPolicyStopsTheLoopAndWithdrawsSeries(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{}, SubscribeManyFn: streamOf(sample(1, time.Now().UnixNano()))}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool { _, ok := collect(t, reader)["gnmi.if_in_octets"]; return ok })
	c.ForgetPolicy("p")
	got := collect(t, reader)
	if m, ok := got["gnmi.if_in_octets"]; ok {
		assert.Empty(t, m.Data.(metricdata.Sum[int64]).DataPoints)
	}
	assert.Empty(t, c.TargetStatuses("p"))
}

// slowCloseSession delays Close, the one thing a loop does after its stream
// ends, so a CollectTarget that does not wait for the old loop returns first.
type slowCloseSession struct {
	*gnmi.FakeSession
	done  *atomic.Bool
	delay time.Duration
}

func (s *slowCloseSession) Close() error {
	time.Sleep(s.delay)
	s.done.Store(true)
	return s.FakeSession.Close()
}

// firstSlowDialer hands the first dial the slow-closing session.
type firstSlowDialer struct {
	sess  *gnmi.FakeSession
	slow  *slowCloseSession
	dials atomic.Int64
}

func (d *firstSlowDialer) Dial(_ context.Context, _ gnmi.TargetSpec) (gnmi.Session, error) {
	if d.dials.Add(1) == 1 {
		return d.slow, nil
	}
	return d.sess, nil
}

func TestReplacingATargetWaitsForTheOldLoop(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{}, SubscribeManyFn: streamOf(sample(1, time.Now().UnixNano()))}
	var oldClosed atomic.Bool
	dialer := &firstSlowDialer{sess: sess, slow: &slowCloseSession{FakeSession: sess, done: &oldClosed, delay: 100 * time.Millisecond}}
	c := New(dialer, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), opts))
	waitFor(t, 3*time.Second, func() bool { _, ok := collect(t, reader)["gnmi.if_in_octets"]; return ok })
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), opts))
	assert.True(t, oldClosed.Load(), "the replaced loop released its session before CollectTarget returned")
	assert.Len(t, c.TargetStatuses("p"), 1, "one loop per policy and host")
}

func TestReconnectAfterStreamError(t *testing.T) {
	testReader(t)
	var attempts atomic.Int64
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			attempts.Add(1)
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				select {
				case out <- sample(1, time.Now().UnixNano()):
				case <-ctx.Done():
				}
				errs <- errors.New("stream reset")
				close(out)
				close(errs)
			}()
			return out, errs, nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 3 })
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Contains(t, st[0].LastError, "stream reset")
	assert.Equal(t, "on_change", st[0].Mode, "a stream that delivered data keeps its mode on reconnect")
}

// An ON_CHANGE leaf refreshes only when it changes, so its series carries no
// age. The SAMPLE counter in the same notification is withdrawn once the
// stream goes quiet, which is what proves the gauge is treated differently.
func TestOnChangeSeriesAreNeverStale(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: streamOf(gnmi.Notification{Timestamp: time.Now().UnixNano(), Updates: []gnmi.Update{
			{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
			{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(3)},
		}}),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 50 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		got := collect(t, reader)
		_, gauge := got["gnmi.if_oper_status"]
		_, counter := got["gnmi.if_in_octets"]
		return gauge && counter
	})
	waitFor(t, 3*time.Second, func() bool {
		m, ok := collect(t, reader)["gnmi.if_in_octets"]
		return !ok || len(m.Data.(metricdata.Sum[int64]).DataPoints) == 0
	})
	g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
	require.True(t, ok, "the on_change gauge outlives the counter's age")
	require.Len(t, g.DataPoints, 1)
	assert.Equal(t, 1.0, g.DataPoints[0].Value)
}

// An ON_CHANGE series carries no age, so an element removed while the stream
// was down is never withdrawn on its own: the replacement stream's initial
// dump simply does not mention it. The reconnected stream's first sync
// response is what says the dump is complete, and every never-stale series of
// this target older than that stream goes with it.
func TestReconnectReconcilesOnChangeSeries(t *testing.T) {
	reader := testReader(t)
	var attempts atomic.Int64
	// The replacement stream holds its dump until the test has seen both
	// series, so the window the eviction closes is not one the test has to
	// catch between polls.
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			attempt := attempts.Add(1)
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			notes := []gnmi.Notification{
				{Updates: []gnmi.Update{{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"}}},
				{SyncDone: true},
			}
			if attempt == 1 {
				notes = []gnmi.Notification{
					{Updates: []gnmi.Update{
						{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(11)},
					}},
					{SyncDone: true},
				}
			}
			go func() {
				defer close(out)
				defer close(errs)
				if attempt > 1 {
					select {
					case <-resume:
					case <-ctx.Done():
						return
					}
				}
				for _, n := range notes {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				if attempt == 1 {
					errs <- errors.New("stream reset")
					return
				}
				<-ctx.Done()
			}()
			return out, errs, nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A long interval keeps the SAMPLE counter fresh for the whole test, so
	// what happens to it is the eviction's doing rather than its own age.
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		return ok && len(g.DataPoints) == 2
	})
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		name, has := g.DataPoints[0].Attributes.Value("interface_name")
		return has && name.AsString() == "e2"
	})
	sum, ok := collect(t, reader)["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	require.True(t, ok, "the aged counter is untouched by the eviction")
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(11), sum.DataPoints[0].Value)
	iface, has := sum.DataPoints[0].Attributes.Value("interface_name")
	require.True(t, has)
	assert.Equal(t, "e1", iface.AsString(), "an aged series is withdrawn by its own age, not by the reconcile")
}

// pointFor reads one stored series of a metric, whatever attributes it
// carries, which is where a counter's reset bookkeeping lives: it is not
// exported, and it is what an evict-then-rewrite would quietly discard.
func pointFor(c *Collector, metric string) (point, bool) {
	c.store.mu.RLock()
	defer c.store.mu.RUnlock()
	for k, pt := range c.store.series {
		if k.metric == metric {
			return *pt, true
		}
	}
	return point{}, false
}

// A sync response may carry updates of its own, and the Get producers build
// exactly that. Reconciling before they are applied would evict the series the
// same notification is about to write and then write it back as a new one,
// losing what the store knows about it.
func TestASyncCarryingUpdatesKeepsTheSeriesItRestates(t *testing.T) {
	testReader(t)
	dir := t.TempDir()
	// An on_change counter, so the series is ageless and the reconcile is
	// entitled to evict it, and so the loss has something to show: a reset.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(`
extends: _base
match: {vendor: acme}
subscriptions:
  - path: /interfaces/interface[name=*]/state/counters
    mode: on_change
    attributes: {interface_name: name}
    metrics:
      - {leaf: in-octets, name: if_in_octets, type: counter, unit: By}
`), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	var attempts atomic.Int64
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "acme"},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			attempt := attempts.Add(1)
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			// The replacement stream answers with one notification that both
			// restates the counter, lower than before, and closes the dump.
			notes := []gnmi.Notification{{SyncDone: true, Updates: []gnmi.Update{
				{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(20)},
			}}}
			if attempt == 1 {
				notes = []gnmi.Notification{
					{Updates: []gnmi.Update{{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(100)}}},
					{SyncDone: true},
				}
			}
			go func() {
				defer close(out)
				defer close(errs)
				if attempt > 1 {
					select {
					case <-resume:
					case <-ctx.Done():
						return
					}
				}
				for _, n := range notes {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				if attempt == 1 {
					errs <- errors.New("stream reset")
					return
				}
				<-ctx.Done()
			}()
			return out, errs, nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 30 * time.Second, Mode: "on_change", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		pt, ok := pointFor(c, "if_in_octets")
		return ok && pt.i == 100 && pt.maxAge == 0
	})
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	waitFor(t, 3*time.Second, func() bool {
		pt, ok := pointFor(c, "if_in_octets")
		return ok && pt.i == 20 && pt.resets == 1
	})
}

// A target that streamed on change and comes back on the SAMPLE rung restates
// every element it still carries, as an aged point this time. What it does not
// restate is still holding the ageless point the earlier stream left, so the
// reconcile has to run on whichever rung the replacement stream settled on.
func TestRungChangeReconcilesOnChangeSeries(t *testing.T) {
	reader := testReader(t)
	var attempts atomic.Int64
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, subs []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			attempt := attempts.Add(1)
			if attempt > 1 {
				for _, sub := range subs {
					if sub.Mode == gnmi.OnChange {
						return nil, nil, status.Error(codes.InvalidArgument, "on_change not supported")
					}
				}
			}
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			notes := []gnmi.Notification{
				{Updates: []gnmi.Update{{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"}}},
				{SyncDone: true},
			}
			if attempt == 1 {
				notes = []gnmi.Notification{
					{Updates: []gnmi.Update{
						{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
					}},
					{SyncDone: true},
				}
			}
			go func() {
				defer close(out)
				defer close(errs)
				if attempt > 1 {
					select {
					case <-resume:
					case <-ctx.Done():
						return
					}
				}
				for _, n := range notes {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				if attempt == 1 {
					errs <- errors.New("stream reset")
					return
				}
				<-ctx.Done()
			}()
			return out, errs, nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A long interval keeps the sampled restatement of e2 fresh for the whole
	// test, so the one point left at the end is the reconcile's doing.
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		return ok && len(g.DataPoints) == 2
	})
	// The refused on_change request spends one attempt, so the sample stream is
	// the third.
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 3 })
	close(resume)
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		name, has := g.DataPoints[0].Attributes.Value("interface_name")
		return has && name.AsString() == "e2"
	})
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Equal(t, "sample", st[0].Mode, "the replacement stream settled on another rung")
}

// A device whose clock lags by more than the staleness window must not blank
// itself: the window runs from arrival at the agent.
func TestStalenessUsesArrivalTimeNotDeviceTime(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: streamOf(gnmi.Notification{
			Timestamp: time.Now().Add(-2 * time.Second).UnixNano(),
			Updates:   []gnmi.Update{{Path: "/interfaces/interface[name=e1]/state/counters/in-octets", Value: uint64(7)}},
		}),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 200 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		m, ok := collect(t, reader)["gnmi.if_in_octets"]
		return ok && len(m.Data.(metricdata.Sum[int64]).DataPoints) == 1
	})
}

// The ladder reaches Get after a subscription the target rejected. A producer
// rejected on the stream keeps retrying its gRPC stream for the life of the
// poll loop unless the subscription is torn down first.
func TestGetRungStopsTheRejectedSubscription(t *testing.T) {
	testReader(t)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(context.Context, []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
		},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{{Path: "/system/memory/state/physical", Value: uint64(1)}}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 50 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Mode == "get" && sess.Stops() >= 1
	})
}

// A target without PROTO answers a Get with one update at the container path
// whose value is a decoded JSON object. Matching needs a path deeper than the
// subscription's, so the container has to be split into its leaves first.
func TestGetContainerResultIsFlattenedToLeaves(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(context.Context, []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
		},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{
			{Path: "/system/memory/state", Value: map[string]any{"physical": float64(4096), "reserved": "512"}},
		}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 50 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		got := collect(t, reader)
		_, physical := got["gnmi.memory_physical"]
		_, reserved := got["gnmi.memory_reserved"]
		return physical && reserved
	})
	got := collect(t, reader)
	assert.Equal(t, 4096.0, got["gnmi.memory_physical"].Data.(metricdata.Gauge[float64]).DataPoints[0].Value)
	assert.Equal(t, 512.0, got["gnmi.memory_reserved"].Data.(metricdata.Gauge[float64]).DataPoints[0].Value)
}

// A collector built before the meter exists must still register target_up:
// the first CollectTarget that finds a meter registers it.
func TestTargetUpRegistersWhenTheMeterArrivesLate(t *testing.T) {
	metrics.ResetMeter()
	sess := &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{}, SubscribeManyFn: streamOf(sample(1, time.Now().UnixNano()))}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.ensureTargetUp()
	reader := testReader(t)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool { _, ok := collect(t, reader)["gnmi.target_up"]; return ok })
}

// Every subscription of this profile carries an origin of its own, so Get
// polling has no path it can ask for. It has to say so rather than call Get
// with an empty path set on every tick.
func TestGetRungWithNoPollablePathReportsIt(t *testing.T) {
	testReader(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "native_only.yaml"), []byte(
		"match: {}\nsubscriptions:\n  - path: /platform/control[slot=*]/memory\n    mode: sample\n    origin: \"\"\n    attributes: {slot: slot}\n    metrics:\n      - {leaf: free, name: mem_free, type: gauge}\n"), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(context.Context, []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pinned := config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Profile: "native_only"})
	require.NoError(t, c.CollectTarget(ctx, pinned, Options{MetricsInterval: 50 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && strings.Contains(st[0].LastError, "nothing to poll")
	})
}

// The manager builds one collector per profile set and every one of them
// writes to the same SDK instrument per metric name, so the series bound they
// are given has to be one bound. A collector reaching it refuses the series
// and counts the refusal, whichever collector filled the allowance.
func TestCollectorsSharingABudgetRefuseSeriesPastIt(t *testing.T) {
	reader := testReader(t)
	budget := newBudget(1)
	newCollector := func(host string) *Collector {
		sess := &gnmi.FakeSession{
			Caps:            &gnmi.CapabilitiesResult{Vendor: "Nokia", Encodings: []string{"PROTO"}},
			SubscribeManyFn: streamOf(sample(1394, time.Now().UnixNano())),
		}
		c := NewWithShared(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil, budget, nil)
		t.Cleanup(c.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		require.NoError(t, c.CollectTarget(ctx, target(host, ""), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
		return c
	}

	first := newCollector("10.0.0.1")
	waitFor(t, 3*time.Second, func() bool {
		_, ok := collect(t, reader)["gnmi.if_in_octets"]
		return ok
	})
	require.Zero(t, drops(t, reader, "series_limit"), "the first collector's series fit the allowance")

	newCollector("10.0.0.2")
	waitFor(t, 3*time.Second, func() bool { return drops(t, reader, "series_limit") > 0 })

	sum := collect(t, reader)["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1, "the second collector's series is refused, not exported alongside")
	device, _ := sum.DataPoints[0].Attributes.Value("device_ip")
	assert.Equal(t, "10.0.0.1", device.AsString(), "the series the allowance already holds is the one kept")
	assert.Same(t, budget, first.Budget(), "the collector bounds itself on the budget it was given")
}

// A collector the manager releases is closed, and the series it was holding
// have to go back to the shared budget with it. The manager forgets every
// policy before it releases a collector, which frees them by the other path,
// so a collector that keeps its slots past Close costs the process an
// allowance nothing will ever export against again.
func TestClosingACollectorReturnsItsSeriesToTheBudget(t *testing.T) {
	reader := testReader(t)
	budget := newBudget(1)
	start := func(host string) *Collector {
		sess := &gnmi.FakeSession{
			Caps:            &gnmi.CapabilitiesResult{Vendor: "Nokia", Encodings: []string{"PROTO"}},
			SubscribeManyFn: streamOf(sample(1394, time.Now().UnixNano())),
		}
		c := NewWithShared(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil, budget, nil)
		t.Cleanup(c.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		require.NoError(t, c.CollectTarget(ctx, target(host, ""), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
		return c
	}
	deviceOf := func(host string) bool {
		m, ok := collect(t, reader)["gnmi.if_in_octets"]
		if !ok {
			return false
		}
		for _, pt := range m.Data.(metricdata.Sum[int64]).DataPoints {
			if v, ok := pt.Attributes.Value("device_ip"); ok && v.AsString() == host {
				return true
			}
		}
		return false
	}

	first := start("10.0.0.1")
	waitFor(t, 3*time.Second, func() bool { return deviceOf("10.0.0.1") })
	first.Close()

	start("10.0.0.2")
	waitFor(t, 3*time.Second, func() bool { return deviceOf("10.0.0.2") })
	assert.Zero(t, drops(t, reader, "series_limit"), "the closed collector's slots were free to take")
}

// gnmi.target_up is one series per target on an instrument every collector in
// the process writes to, so it draws on the same per-name allowance every
// profile metric draws on. A callback that observed a point per loop whatever
// the budget said would hand the SDK the series past the bound that the bound
// exists to keep it from folding into the overflow set. A loop refused a slot
// still collects: only its up point stands down, until an observation after a
// slot frees takes one.
func TestTargetUpIsBoundedByTheSharedBudget(t *testing.T) {
	reader := testReader(t)
	budget := newBudget(1)
	start := func(host string, notes ...gnmi.Notification) *Collector {
		sess := &gnmi.FakeSession{
			Caps:            &gnmi.CapabilitiesResult{Vendor: "Nokia", Encodings: []string{"PROTO"}},
			SubscribeManyFn: streamOf(notes...),
		}
		c := NewWithShared(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil, budget, nil)
		t.Cleanup(c.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		require.NoError(t, c.CollectTarget(ctx, target(host, ""), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
		return c
	}
	upDevices := func() []string {
		m, ok := collect(t, reader)["gnmi.target_up"]
		if !ok {
			return nil
		}
		var hosts []string
		for _, pt := range m.Data.(metricdata.Gauge[int64]).DataPoints {
			if v, ok := pt.Attributes.Value("device_ip"); ok {
				hosts = append(hosts, v.AsString())
			}
		}
		sort.Strings(hosts)
		return hosts
	}
	onlyUp := func(host string) bool {
		up := upDevices()
		return len(up) == 1 && up[0] == host
	}

	first := start("10.0.0.1", sample(1394, time.Now().UnixNano()))
	waitFor(t, 3*time.Second, func() bool { return onlyUp("10.0.0.1") })
	require.Zero(t, drops(t, reader, "series_limit"), "the first target's up point fits the allowance")

	// The second target's updates match no metric of the profile, so its loop
	// asks the budget for nothing but its up point and the refusal below is
	// that point's alone.
	start("10.0.0.2", gnmi.Notification{Updates: []gnmi.Update{{Path: "/nothing/the/profiles/name", Value: uint64(1)}}})
	waitFor(t, 3*time.Second, func() bool { return drops(t, reader, "unmatched_path") > 0 })
	assert.Equal(t, []string{"10.0.0.1"}, upDevices(), "the second loop observed a point past the bound")
	assert.Equal(t, int64(1), drops(t, reader, "series_limit"), "the refused up point is counted once for the target")

	first.ForgetPolicy("p")
	waitFor(t, 3*time.Second, func() bool { return onlyUp("10.0.0.2") })
}

// The SDK holds one instrument per metric name however many collectors write
// to it, so two profile sets that disagree about a name would have that one
// instrument export as two streams with different kinds or units. The first
// definition the process registers is the one it exports, and a series that
// disagrees is refused and counted rather than handed over.
func TestCollectorsSharingASchemaRegistryRefuseADisagreeingSeries(t *testing.T) {
	reader := testReader(t)
	// memory_free_native is a gauge in bytes in the bundled SR Linux overlay.
	// This override makes it a counter; it is the only profile in its own store
	// that names it, so the store loads.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nokia_srlinux.yaml"), []byte(
		"extends: _base\nmatch: {vendor: nokia}\nsubscriptions:\n  - path: /platform/control[slot=*]/memory\n    mode: sample\n    origin: \"\"\n    attributes:\n      slot: slot\n    metrics:\n      - {leaf: free, name: memory_free_native, type: counter, unit: By}\n"), 0o600))
	disagreeing, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)

	schemas := NewSchemas()
	start := func(host string, store *profiles.Store) *Collector {
		sess := &gnmi.FakeSession{
			Caps: &gnmi.CapabilitiesResult{Vendor: "Nokia", Encodings: []string{"PROTO"}},
			SubscribeManyFn: streamOf(gnmi.Notification{Timestamp: time.Now().UnixNano(), Updates: []gnmi.Update{
				{Path: "/platform/control[slot=A]/memory/free", Value: uint64(1024)},
			}}),
		}
		c := NewWithShared(&gnmi.FakeDialer{Session: sess}, store, nil, nil, schemas)
		t.Cleanup(c.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		require.NoError(t, c.CollectTarget(ctx, target(host, ""), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
		return c
	}

	first := start("10.0.0.1", loadStore(t))
	waitFor(t, 3*time.Second, func() bool { _, ok := collect(t, reader)["gnmi.memory_free_native"]; return ok })
	require.Zero(t, drops(t, reader, "schema_conflict"), "the first definition of a name is the process's")

	start("10.0.0.2", disagreeing)
	waitFor(t, 3*time.Second, func() bool { return drops(t, reader, "schema_conflict") > 0 })

	got := collect(t, reader)
	g, ok := got["gnmi.memory_free_native"].Data.(metricdata.Gauge[float64])
	require.True(t, ok, "the name keeps the kind it was first exported with")
	require.Len(t, g.DataPoints, 1, "the disagreeing series is refused, not exported alongside")
	device, _ := g.DataPoints[0].Attributes.Value("device_ip")
	assert.Equal(t, "10.0.0.1", device.AsString(), "the series that defined the name is the one kept")
	assert.Same(t, schemas, first.Schemas(), "the collector registers against the registry it was given")
}

// A target that streamed on change, lost an element while it was disconnected
// and fell through to Get on reconnect opens no stream to reconcile against, so
// the ageless point the earlier stream left would stand for ever. The first
// complete Get snapshot says which elements the device still carries, the way a
// stream's first sync response does, and reconciles on the same terms.
func TestGetRungReconcilesAgelessSeries(t *testing.T) {
	reader := testReader(t)
	var attempts atomic.Int64
	// The ladder holds its refusals until the test has seen both series, so the
	// window the eviction closes is not one the test has to catch between polls.
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			if attempts.Add(1) > 1 {
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
			}
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				for _, n := range []gnmi.Notification{
					{Updates: []gnmi.Update{
						{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
					}},
					{SyncDone: true},
				} {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				errs <- errors.New("stream reset")
			}()
			return out, errs, nil
		},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{
			{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
		}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A long interval keeps the polled restatement of e2 fresh for the whole
	// test, so the one point left at the end is the reconcile's doing.
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		return ok && len(g.DataPoints) == 2
	})
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	// The condition names the survivor, so it cannot pass on the instant before
	// the snapshot restated e2 either.
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		name, has := g.DataPoints[0].Attributes.Value("interface_name")
		return has && name.AsString() == "e2"
	})
}

// A stream over a subtree with nothing in it answers the sync response and
// nothing else. That is the stream saying its dump is complete, so it is as
// good a sign of recovery as a value: without it the target stands at the error
// of the attempt before for as long as the subtree stays empty.
func TestASyncClearsAPriorError(t *testing.T) {
	testReader(t)
	var attempts atomic.Int64
	// The second stream waits until the test has seen the error it has to clear,
	// so the window is not one the test has to catch inside a backoff.
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			// The first stream ends with no error before any data, which spends
			// the forced rung and leaves the loop reporting the Get refusal
			// below it.
			if attempts.Add(1) == 1 {
				out := make(chan gnmi.Notification)
				errs := make(chan error)
				close(out)
				close(errs)
				return out, errs, nil
			}
			select {
			case <-resume:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				select {
				case out <- gnmi.Notification{SyncDone: true}:
				case <-ctx.Done():
					return
				}
				<-ctx.Done()
			}()
			return out, errs, nil
		},
		GetErr: errors.New("get refused"),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "on_change", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && strings.Contains(st[0].LastError, "get refused")
	})
	close(resume)
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Up && st[0].LastError == ""
	})
}

// Get polling asks only for the subscriptions that share the target's origin, so
// a snapshot says nothing at all about one that carries a native origin of its
// own. The reconciliation is bounded by the metrics the poll really asked for:
// an ageless series of a skipped subscription is not one any snapshot could
// restate, and evicting it would blank a subtree on the first poll.
func TestGetRungReconcilesOnlyTheMetricsItPolls(t *testing.T) {
	reader := testReader(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mixed_origin.yaml"), []byte(`
match: {}
subscriptions:
  - path: /interfaces/interface[name=*]/state/oper-status
    mode: on_change
    attributes: {interface_name: name}
    metrics:
      - {leaf: ., name: if_oper_status, type: gauge, enum: {UP: 1, DOWN: 0}}
  - path: /platform/control[slot=*]/state
    mode: on_change
    origin: ""
    attributes: {slot: slot}
    metrics:
      - {leaf: oper-state, name: control_oper_state, type: gauge, enum: {UP: 1, DOWN: 0}}
`), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	var attempts atomic.Int64
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			if attempts.Add(1) > 1 {
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
			}
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				for _, n := range []gnmi.Notification{
					{Updates: []gnmi.Update{
						{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
						{Path: "/platform/control[slot=A]/state/oper-state", Value: "UP"},
					}},
					{SyncDone: true},
				} {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				errs <- errors.New("stream reset")
			}()
			return out, errs, nil
		},
		// The snapshot restates one of the two polled elements and, being a Get
		// against the target's own origin, can say nothing about the native
		// subscription.
		GetResult: gnmi.Notification{Updates: []gnmi.Update{
			{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
		}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pinned := config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Profile: "mixed_origin"})
	require.NoError(t, c.CollectTarget(ctx, pinned, Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	points := func(name string) int {
		g, ok := collect(t, reader)[name].Data.(metricdata.Gauge[float64])
		if !ok {
			return 0
		}
		return len(g.DataPoints)
	}
	waitFor(t, 3*time.Second, func() bool { return points("gnmi.if_oper_status") == 2 && points("gnmi.control_oper_state") == 1 })
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	// The element the snapshot omits goes, the element it restates stays, and the
	// series of the subscription the poll never asked for stays with it.
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		name, has := g.DataPoints[0].Attributes.Value("interface_name")
		return has && name.AsString() == "e2" && points("gnmi.control_oper_state") == 1
	})
}

// A Get that recovers path by path returns what answered and calls that
// success. The first snapshot is what withdraws the ageless series an earlier
// on_change stream left, so it must withdraw them only under the paths it
// fetched: a path whose Get failed restates nothing because it was never read,
// and evicting under it would take an element the device still carries.
func TestGetRungReconcilesOnlyFetchedPaths(t *testing.T) {
	reader := testReader(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "two_paths.yaml"), []byte(`
match: {}
subscriptions:
  - path: /interfaces/interface[name=*]/state/oper-status
    mode: on_change
    attributes: {interface_name: name}
    metrics:
      - {leaf: ., name: if_oper_status, type: gauge, enum: {UP: 1, DOWN: 0}}
  - path: /platform/control[slot=*]/memory
    mode: on_change
    attributes: {slot: slot}
    metrics:
      - {leaf: free, name: control_memory_free, type: gauge, unit: By}
`), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	var attempts atomic.Int64
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			if attempts.Add(1) > 1 {
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
			}
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				for _, n := range []gnmi.Notification{
					{Updates: []gnmi.Update{
						{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
						{Path: "/platform/control[slot=A]/memory/free", Value: uint64(10)},
						{Path: "/platform/control[slot=B]/memory/free", Value: uint64(20)},
					}},
					{SyncDone: true},
				} {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				errs <- errors.New("stream reset")
			}()
			return out, errs, nil
		},
		// The poll asks for both paths; the target answers only the memory one,
		// so the snapshot restates slot A and says nothing at all about the
		// interfaces.
		GetPaths: []string{"/platform/control[slot=*]/memory"},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{
			{Path: "/platform/control[slot=A]/memory/free", Value: uint64(10)},
		}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pinned := config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Profile: "two_paths"})
	require.NoError(t, c.CollectTarget(ctx, pinned, Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	points := func(name string) int {
		g, ok := collect(t, reader)[name].Data.(metricdata.Gauge[float64])
		if !ok {
			return 0
		}
		return len(g.DataPoints)
	}
	waitFor(t, 3*time.Second, func() bool { return points("gnmi.if_oper_status") == 2 && points("gnmi.control_memory_free") == 2 })
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	// Under the fetched path the omitted element goes and the restated one
	// stays; both interface series stand, the snapshot having never read them.
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.control_memory_free"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		slot, has := g.DataPoints[0].Attributes.Value("slot")
		return has && slot.AsString() == "A"
	})
	assert.Equal(t, 2, points("gnmi.if_oper_status"), "a path the snapshot never fetched withdraws nothing")
}

// A path the first poll failed on and a later poll answered is reconciled by
// the first snapshot that fetches it, not left to the one-shot reconciliation
// of the first poll: an element that went while the target was disconnected
// keeps its ageless series otherwise, for as long as the poll runs.
func TestGetRungReconcilesAPathWhenItFirstRecovers(t *testing.T) {
	reader := testReader(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "two_paths.yaml"), []byte(`
match: {}
subscriptions:
  - path: /interfaces/interface[name=*]/state/oper-status
    mode: on_change
    attributes: {interface_name: name}
    metrics:
      - {leaf: ., name: if_oper_status, type: gauge, enum: {UP: 1, DOWN: 0}}
  - path: /platform/control[slot=*]/memory
    mode: on_change
    attributes: {slot: slot}
    metrics:
      - {leaf: free, name: control_memory_free, type: gauge, unit: By}
`), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	var attempts, polls atomic.Int64
	resume := make(chan struct{})
	const memory, interfaces = "/platform/control[slot=*]/memory", "/interfaces/interface[name=*]/state/oper-status"
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			if attempts.Add(1) > 1 {
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
			}
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				for _, n := range []gnmi.Notification{
					{Updates: []gnmi.Update{
						{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
						{Path: "/platform/control[slot=A]/memory/free", Value: uint64(10)},
					}},
					{SyncDone: true},
				} {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				errs <- errors.New("stream reset")
			}()
			return out, errs, nil
		},
		// The first poll answers only the memory path; every later one answers
		// the interfaces too, and by then e2 is gone.
		GetFn: func(_ context.Context, _ []string) (gnmi.Notification, error) {
			n := gnmi.Notification{Paths: []string{memory}, Updates: []gnmi.Update{
				{Path: "/platform/control[slot=A]/memory/free", Value: uint64(10)},
			}}
			if polls.Add(1) > 1 {
				n.Paths = append(n.Paths, interfaces)
				n.Updates = append(n.Updates, gnmi.Update{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"})
			}
			return n, nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pinned := config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Profile: "two_paths"})
	require.NoError(t, c.CollectTarget(ctx, pinned, Options{MetricsInterval: 50 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	points := func(name string) int {
		g, ok := collect(t, reader)[name].Data.(metricdata.Gauge[float64])
		if !ok {
			return 0
		}
		return len(g.DataPoints)
	}
	waitFor(t, 3*time.Second, func() bool { return points("gnmi.if_oper_status") == 2 && points("gnmi.control_memory_free") == 1 })
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	// The snapshot that first fetches the interfaces withdraws e2, the element
	// it omits; e1, which it restates, stands.
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		name, has := g.DataPoints[0].Attributes.Value("interface_name")
		return has && name.AsString() == "e1"
	})
	assert.Equal(t, 1, points("gnmi.control_memory_free"), "the path fetched from the first poll keeps its restated series")
}

// A subscription is atomic, so the transport prunes a path the target rejects
// and the stream that opens covers less than the profile. The sync response
// names what the stream carries, and the reconciliation covers that and the
// pruned path both: an ageless series under a pruned path is one no stream of
// this session will ever restate, so it goes with the elements the dump
// omitted rather than standing for ever on a value nothing can refresh.
func TestSyncWithdrawsThePrunedPathsSeries(t *testing.T) {
	reader := testReader(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "two_streams.yaml"), []byte(`
match: {}
subscriptions:
  - path: /interfaces/interface[name=*]/state/oper-status
    mode: on_change
    attributes: {interface_name: name}
    metrics:
      - {leaf: ., name: if_oper_status, type: gauge, enum: {UP: 1, DOWN: 0}}
  - path: /platform/control[slot=*]/memory
    mode: on_change
    attributes: {slot: slot}
    metrics:
      - {leaf: free, name: control_memory_free, type: gauge, unit: By}
`), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	const interfaces = "/interfaces/interface[name=*]/state/oper-status"
	var attempts atomic.Int64
	resume := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			attempt := attempts.Add(1)
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			// The replacement stream carries the interfaces subscription alone,
			// the memory path having been pruned, and its sync says so. It
			// restates one of the two interfaces and holds.
			notes := []gnmi.Notification{
				{Updates: []gnmi.Update{{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"}}},
				{SyncDone: true, Paths: []string{interfaces}},
			}
			if attempt == 1 {
				notes = []gnmi.Notification{
					{Updates: []gnmi.Update{
						{Path: "/interfaces/interface[name=e1]/state/oper-status", Value: "UP"},
						{Path: "/interfaces/interface[name=e2]/state/oper-status", Value: "UP"},
						{Path: "/platform/control[slot=A]/memory/free", Value: uint64(10)},
					}},
					{SyncDone: true},
				}
			}
			go func() {
				defer close(out)
				defer close(errs)
				if attempt > 1 {
					select {
					case <-resume:
					case <-ctx.Done():
						return
					}
				}
				for _, n := range notes {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				if attempt == 1 {
					errs <- errors.New("stream reset")
					return
				}
				<-ctx.Done()
			}()
			return out, errs, nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pinned := config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Profile: "two_streams"})
	require.NoError(t, c.CollectTarget(ctx, pinned, Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	points := func(name string) int {
		g, ok := collect(t, reader)[name].Data.(metricdata.Gauge[float64])
		if !ok {
			return 0
		}
		return len(g.DataPoints)
	}
	waitFor(t, 3*time.Second, func() bool { return points("gnmi.if_oper_status") == 2 && points("gnmi.control_memory_free") == 1 })
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	// Under the path the sync names the omitted interface goes and the restated
	// one stays; the series of the pruned subscription goes too, no stream of
	// this session being able to restate it.
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		name, has := g.DataPoints[0].Attributes.Value("interface_name")
		return has && name.AsString() == "e2"
	})
	waitFor(t, 3*time.Second, func() bool { return points("gnmi.control_memory_free") == 0 })
	assert.Equal(t, 0, points("gnmi.control_memory_free"), "a pruned subscription's series can never be refreshed and are withdrawn")
}

// A stream over a subtree the device carries nothing under answers its sync
// response and sends no data at all. The sync is the target accepting the
// stream, so a fault after it is a transport failure the same rung recovers
// from: reading it as a mode refusal would walk a working on_change
// subscription off the ladder the first time the connection dropped.
func TestASyncOnlyStreamKeepsItsModeOnALaterError(t *testing.T) {
	reader := testReader(t)
	var attempts atomic.Int64
	// The drop waits until the test has seen the mode the first stream settled
	// on, so what the reconnect keeps is not a window the test has to catch.
	drop := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			first := attempts.Add(1) == 1
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				select {
				case out <- gnmi.Notification{SyncDone: true}:
				case <-ctx.Done():
					return
				}
				if !first {
					<-ctx.Done()
					return
				}
				select {
				case <-drop:
				case <-ctx.Done():
					return
				}
				errs <- status.Error(codes.Unavailable, "connection reset")
			}()
			return out, errs, nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Mode == "on_change" && st[0].Up
	})
	close(drop)
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Up
	})
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Equal(t, "on_change", st[0].Mode, "a stream that synced and then dropped reconnects on the rung it held")
	onChange := false
	for _, s := range sess.Subscriptions() {
		if s.Mode == gnmi.OnChange {
			onChange = true
		}
	}
	assert.True(t, onChange, "the second request keeps the profile's own modes, not the all-SAMPLE rung")
	assert.Equal(t, int64(0), fallbacks(t, reader), "a drop after the sync is no mode refusal, so no step down the ladder")
}

// A stream the target accepted and then sent nothing on left consume waiting on
// the loop's context, which lives as long as the policy, with the target marked
// Up by the subscribe that opened it and no error to back off from. A stream's
// first response is due within the probe deadline, the bound the session gives
// a call of its own, and past it the attempt is an early failure like any other
// before the sync: a stalled on_change attempt falls to sample, then to Get.
func TestAStreamThatNeverAnswersAdvancesTheLadder(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		// The RPC is accepted and nothing follows it: two channels the target
		// never writes to and never closes.
		SubscribeManyFn: func(context.Context, []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			return make(chan gnmi.Notification), make(chan error), nil
		},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{{Path: "/system/memory/state/physical", Value: uint64(1)}}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{
		MetricsInterval: time.Second, Mode: "auto", PolicyName: "p", ProbeTimeout: 100 * time.Millisecond,
	}))
	waitFor(t, 2*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Mode == "get"
	})
	assert.Equal(t, int64(2), fallbacks(t, reader), "two silent streams: on_change to sample, sample to get")
}

// A target that accepts the subscription, sends one update of its initial dump
// and then goes quiet before the sync response is a stream nothing bounds: the
// first notification used to take the deadline away, so the loop held the
// target Up for ever, with no reconnect and no reconciliation, on a dump that
// never completed. Until the sync closes the dump every notification is due
// within the same probe deadline, and a dump that stalls past it is the stream
// failing rather than the mode being refused, so the loop backs off and opens
// another on the rung it holds.
func TestADumpThatStallsBeforeItsSyncReconnects(t *testing.T) {
	reader := testReader(t)
	var attempts atomic.Int64
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, subs []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			if attempts.Add(1) > 1 {
				return streamOf(gnmi.Notification{SyncDone: true}, sample(2, time.Now().UnixNano()))(ctx, subs)
			}
			// One update of the initial dump and then the target parks: no
			// sync response, no error and no close.
			out := make(chan gnmi.Notification)
			go func() {
				select {
				case out <- sample(1, time.Now().UnixNano()):
				case <-ctx.Done():
					return
				}
				<-ctx.Done()
			}()
			return out, make(chan error), nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{
		MetricsInterval: time.Second, Mode: "auto", PolicyName: "p", ProbeTimeout: 100 * time.Millisecond,
	}))
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Up && !st[0].LastNotification.IsZero()
	})
	assert.GreaterOrEqual(t, reconnects(t, reader), int64(1), "the stalled dump ended the attempt, and the loop dialled the target again")
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Equal(t, "on_change", st[0].Mode, "a dump that stalled after data reconnects on the rung it held")
	onChange := false
	for _, s := range sess.Subscriptions() {
		if s.Mode == gnmi.OnChange {
			onChange = true
		}
	}
	assert.True(t, onChange, "the second request keeps the profile's own modes, not the all-SAMPLE rung")
	assert.Equal(t, int64(0), fallbacks(t, reader), "a dump that stalled after data is no mode refusal, so no step down the ladder")
}

// A target that sends its initial dump in pieces has not stalled: each piece is
// due within the deadline of the one before it, not the whole dump within one,
// so a dump slower than the deadline overall still arrives. The sync response
// closes the dump and takes the deadline away for good, because a stream is
// quiet after its dump by design, an on_change subscription above all: a
// deadline left armed past the sync would cut a healthy stream at the first
// quiet spell and reconnect for ever.
func TestASlowDumpIsNotCutAndItsSyncEndsTheDeadline(t *testing.T) {
	reader := testReader(t)
	var attempts atomic.Int64
	synced := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			first := attempts.Add(1) == 1
			out := make(chan gnmi.Notification)
			go func() {
				// Two updates 60 ms apart, each inside the 100 ms deadline and
				// 120 ms in all, then the sync that closes the dump; after it
				// the stream says nothing for longer than the deadline.
				for _, n := range []gnmi.Notification{
					sample(1, time.Now().UnixNano()),
					sample(2, time.Now().UnixNano()),
					{SyncDone: true},
				} {
					select {
					case <-time.After(60 * time.Millisecond):
					case <-ctx.Done():
						return
					}
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				if first {
					close(synced)
				}
				<-ctx.Done()
			}()
			return out, make(chan error), nil
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{
		MetricsInterval: time.Second, Mode: "auto", PolicyName: "p", ProbeTimeout: 100 * time.Millisecond,
	}))
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow dump never reached its sync response")
	}
	// The quiet spell after the sync, longer than the deadline the dump ran
	// under, which the stream survives because the sync disarmed it.
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, int64(1), attempts.Load(), "one stream carried the whole dump and stayed up through the quiet spell after it")
	assert.Equal(t, int64(0), reconnects(t, reader), "a dump delivered in pieces and a quiet stream past its sync are no failure")
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.True(t, st[0].Up, "the stream that synced is still up")
	assert.Equal(t, "on_change", st[0].Mode, "and still on the rung it opened on")
}

// A stream that dropped before its sync response has said nothing about the
// mode it was asked for. gnmic surfaces a transport failure the same way it
// surfaces a refusal, so only the codes a target rejects a request under send
// the ladder on: an Unavailable under the initial dump is the connection going,
// and reading it as a refusal walked a forced on_change target onto SAMPLE, or
// off the stream altogether, until the process restarted.
func TestAPreSyncTransportErrorReconnectsOnTheSameRung(t *testing.T) {
	reader := testReader(t)
	var attempts atomic.Int64
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, subs []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			if attempts.Add(1) == 1 {
				// The RPC is accepted and the connection goes under the initial
				// dump: no sync response, no data, an Unavailable.
				errs := make(chan error, 1)
				errs <- status.Error(codes.Unavailable, "connection reset")
				return make(chan gnmi.Notification), errs, nil
			}
			return streamOf(gnmi.Notification{SyncDone: true}, sample(1, time.Now().UnixNano()))(ctx, subs)
		},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Up && !st[0].LastNotification.IsZero()
	})
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Equal(t, "on_change", st[0].Mode, "a stream that dropped before its sync reconnects on the rung it held")
	onChange := false
	for _, s := range sess.Subscriptions() {
		if s.Mode == gnmi.OnChange {
			onChange = true
		}
	}
	assert.True(t, onChange, "the second request keeps the profile's own modes, not the all-SAMPLE rung")
	assert.Equal(t, int64(0), fallbacks(t, reader), "a drop before the sync is no mode refusal, so no step down the ladder")
}

// A stream that ended with no error before it answered anything left no status
// to read, and a target dropping a subscription it will not serve is what it
// looks like, so the ladder moves on. This is the one pre-sync fault with no
// code of its own, besides the stream that answers nothing at all.
func TestAStreamThatClosesBeforeItAnswersAdvancesTheLadder(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		// The RPC is accepted and both channels close at once, with no
		// notification and no error behind them.
		SubscribeManyFn: func(context.Context, []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			out := make(chan gnmi.Notification)
			errs := make(chan error)
			close(out)
			close(errs)
			return out, errs, nil
		},
		GetResult: gnmi.Notification{Updates: []gnmi.Update{{Path: "/system/memory/state/physical", Value: uint64(1)}}},
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 50 * time.Millisecond, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Mode == "get"
	})
	// The status flips to get before the first poll, so only data proves polling.
	waitFor(t, 3*time.Second, func() bool { _, ok := collect(t, reader)["gnmi.memory_physical"]; return ok })
	assert.Equal(t, int64(2), fallbacks(t, reader), "two streams closed before they answered: on_change to sample, sample to get")
}

// A Get poll ran under the loop's context, which lives as long as the policy.
// A target that stops replying without closing the connection held that poll
// for ever: the loop stayed in it with Up still true, so the status reported a
// healthy target that had delivered nothing since, and there was no error to
// back off from and no reconnect. Each Get carries the policy's metrics
// interval as its deadline, since a poll that outlasts the interval it is due
// again in has failed, and a miss leaves the poll like any other Get error.
func TestAGetPollThatNeverAnswersFailsTheLoop(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(context.Context, []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			return nil, nil, status.Error(codes.Unimplemented, "streaming not supported")
		},
		GetBlocks: true,
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A forced mode has one rung, and the synchronous refusal spends it, so
	// the loop is on Get before the first poll.
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{
		MetricsInterval: 100 * time.Millisecond, Mode: "sample", PolicyName: "p",
	}))

	// The poll leaves rather than waits: the target goes down carrying the
	// error, and the loop that recorded it dials again.
	waitFor(t, time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && !st[0].Up && st[0].LastError != ""
	})
	waitFor(t, time.Second, func() bool { return reconnects(t, reader) > 0 })
}

// specDialer records the spec of every dial, which the shared FakeDialer
// discards.
type specDialer struct {
	sess *gnmi.FakeSession
	mu   sync.Mutex
	spec []gnmi.TargetSpec
}

func (d *specDialer) Dial(_ context.Context, spec gnmi.TargetSpec) (gnmi.Session, error) {
	d.mu.Lock()
	d.spec = append(d.spec, spec)
	d.mu.Unlock()
	return d.sess, nil
}

func (d *specDialer) specs() []gnmi.TargetSpec {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]gnmi.TargetSpec(nil), d.spec...)
}

// The session bounds each subscription-path probe by what the dial spec asked
// for, and the policy is what decides that: a probe left to the loop's own
// context outlives every reconnect the policy would otherwise make.
func TestTheDialSpecCarriesThePolicysProbeTimeout(t *testing.T) {
	testReader(t)
	sess := &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{}, SubscribeManyFn: streamOf(sample(1, time.Now().UnixNano()))}
	dialer := &specDialer{sess: sess}
	c := New(dialer, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{
		MetricsInterval: time.Second, Mode: "auto", PolicyName: "p", ProbeTimeout: 1500 * time.Millisecond,
	}))
	waitFor(t, 3*time.Second, func() bool { return len(dialer.specs()) > 0 })
	assert.Equal(t, 1500*time.Millisecond, dialer.specs()[0].ProbeTimeout, "the policy's probe timeout reaches the session that probes")
}

// perDialCapsDialer hands the first dial one session and every later dial
// another, so a reconnect can meet a target reporting other capabilities than
// the dial before it: a firmware upgrade that changes the advertised NOS, or
// an operator changing the override the target matches, looks like this.
type perDialCapsDialer struct {
	first, rest *gnmi.FakeSession
	dials       atomic.Int64
}

func (d *perDialCapsDialer) Dial(_ context.Context, _ gnmi.TargetSpec) (gnmi.Session, error) {
	if d.dials.Add(1) == 1 {
		return d.first, nil
	}
	return d.rest, nil
}

func (d *perDialCapsDialer) dialCount() int64 { return d.dials.Load() }

// A reconnect that selects another profile leaves the previous profile's
// ageless series with nothing to withdraw them: the new stream's sync names
// the paths it subscribed to, so the reconciliation is scoped to the metrics
// of the profile streaming now and never reaches a metric only the old
// profile carried. The profile change itself is what has to retire them.
func TestAProfileChangeOnReconnectWithdrawsTheOldSeries(t *testing.T) {
	reader := testReader(t)
	dir := t.TempDir()
	// A path and a metric name of its own, so nothing _base carries can
	// withdraw the series and nothing _base exports can be mistaken for it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(`
match: {vendor: acme}
subscriptions:
  - path: /acme/ports/port[name=*]/state/oper-status
    mode: on_change
    attributes: {port_name: name}
    metrics:
      - leaf: .
        name: acme_port_status
        type: gauge
        enum: {UP: 1, DOWN: 0}
`), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	// The first stream holds its error, and the replacement stream its dump,
	// until the test has seen the old profile's series exported. Nothing
	// bounds how long a series stays exported once the withdrawal is in
	// place, so a first stream free to end on its own would race the test to
	// the reader: the reconnect is a backoff away, and the series it retires
	// would be gone before the first read.
	reset := make(chan struct{})
	resume := make(chan struct{})
	acme := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "acme"},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				notes := []gnmi.Notification{
					{Updates: []gnmi.Update{{Path: "/acme/ports/port[name=e1]/state/oper-status", Value: "UP"}}},
					{SyncDone: true, Paths: []string{"/acme/ports/port[name=*]/state/oper-status"}},
				}
				for _, n := range notes {
					select {
					case out <- n:
					case <-ctx.Done():
						return
					}
				}
				select {
				case <-reset:
				case <-ctx.Done():
					return
				}
				errs <- errors.New("stream reset")
			}()
			return out, errs, nil
		},
	}
	base := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				select {
				case <-resume:
				case <-ctx.Done():
					return
				}
				// The sync names the paths this stream carries, which is what a
				// target answers, so the reconciliation speaks for the new
				// profile's metrics alone.
				select {
				case out <- gnmi.Notification{SyncDone: true, Paths: []string{"/interfaces/interface[name=*]/state/oper-status"}}:
				case <-ctx.Done():
					return
				}
				<-ctx.Done()
			}()
			return out, errs, nil
		},
	}
	dialer := &perDialCapsDialer{first: acme, rest: base}
	c := New(dialer, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 30 * time.Second, Mode: "on_change", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		g, ok := collect(t, reader)["gnmi.acme_port_status"].Data.(metricdata.Gauge[float64])
		return ok && len(g.DataPoints) == 1
	})
	close(reset)
	waitFor(t, 3*time.Second, func() bool { return dialer.dialCount() >= 2 })
	close(resume)
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Profile == "_base"
	})
	waitFor(t, 3*time.Second, func() bool {
		m, ok := collect(t, reader)["gnmi.acme_port_status"]
		return !ok || len(m.Data.(metricdata.Gauge[float64]).DataPoints) == 0
	})
	_, held := pointFor(c, "acme_port_status")
	assert.False(t, held, "the old profile's series is out of the store, not merely withheld")
}

// An error nothing has refreshed must not look newer on every poll: the
// instant belongs to the loop that recorded the failure, not to the read.
func TestALoopRecordsWhenItsErrorHappened(t *testing.T) {
	testReader(t)
	sess := &gnmi.FakeSession{CapsErr: errors.New("no capabilities")}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	// One failed attempt inside the test window, so a retry cannot restamp the
	// instant between the two reads below.
	c.backoffBase = time.Minute
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	before := time.Now()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].LastError != ""
	})
	first := c.TargetStatuses("p")
	require.Len(t, first, 1)
	at := first[0].LastErrorAt
	assert.False(t, at.Before(before), "the error is stamped no earlier than the loop started")
	assert.False(t, at.After(time.Now()), "the error is stamped no later than the read that found it")
	time.Sleep(50 * time.Millisecond)
	second := c.TargetStatuses("p")
	require.Len(t, second, 1)
	assert.Equal(t, at, second[0].LastErrorAt, "an unchanged failure keeps the instant it was recorded at")
}

// The vendor Capabilities derives is empty for an organization its mapping does
// not know, so a target of such a vendor reports the organization and nothing
// else. The overlay written for it has to be selected from that, or the target
// streams _base and none of the paths the overlay was written for.
func TestATargetSelectsAnOverlayFromTheOrganizationItReported(t *testing.T) {
	testReader(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(`
extends: _base
match: {vendor: acme}
`), 0o600))
	profileStore, err := profiles.LoadProfiles(dir, nil)
	require.NoError(t, err)
	sess := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Organizations: []string{"Acme Networks, Inc."}},
		SubscribeManyFn: streamOf(sample(1, time.Now().UnixNano())),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, profileStore, nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 30 * time.Second, Mode: "on_change", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && st[0].Profile != ""
	})
	st := c.TargetStatuses("p")
	require.Len(t, st, 1)
	assert.Equal(t, "acme", st[0].Profile, "the organization the target reported selected the overlay written for that vendor")
}

// failThenDialer refuses its first failures dials, which is what makes the
// loop's backoff climb, and hands every later one the same session. It records
// when each dial arrived, so the wait between two attempts, the climbed one and
// the one after a stream that served, is observable from the test.
type failThenDialer struct {
	mu       sync.Mutex
	at       []time.Time
	failures int
	sess     gnmi.Session
}

func (d *failThenDialer) Dial(_ context.Context, _ gnmi.TargetSpec) (gnmi.Session, error) {
	d.mu.Lock()
	d.at = append(d.at, time.Now())
	n := len(d.at)
	d.mu.Unlock()
	if n <= d.failures {
		return nil, errors.New("dial refused")
	}
	return d.sess, nil
}

func (d *failThenDialer) dials() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.at...)
}

// A stream over a subtree with nothing in it answers its sync response and no
// data at all, and a target holding one is serving as surely as one sending
// values. Read on the notification alone, such a target kept whatever backoff
// earlier failures had climbed to: every later drop waited the cap, however
// long the stream before it had been healthy.
func TestACompletedSyncResetsTheBackoff(t *testing.T) {
	testReader(t)
	// Held until the test has seen the sync, so the error that ends the
	// attempt cannot arrive before the sync it has to be judged against.
	seen := make(chan struct{})
	sess := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{},
		SubscribeManyFn: func(ctx context.Context, _ []gnmi.Subscription) (<-chan gnmi.Notification, <-chan error, error) {
			out := make(chan gnmi.Notification)
			errs := make(chan error, 1)
			go func() {
				defer close(out)
				defer close(errs)
				select {
				case out <- gnmi.Notification{SyncDone: true}:
				case <-ctx.Done():
					return
				}
				select {
				case <-seen:
				case <-ctx.Done():
					return
				}
				errs <- errors.New("stream reset")
			}()
			return out, errs, nil
		},
	}
	// Five refused dials take the backoff from its base to thirty-two times it,
	// far enough above the base that the wait after the stream that served says
	// which of the two the loop chose.
	dialer := &failThenDialer{failures: 5, sess: sess}
	c := New(dialer, loadStore(t), nil)
	c.backoffBase = 10 * time.Millisecond
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, c.CollectTarget(ctx, target("h", ""), Options{MetricsInterval: 30 * time.Second, Mode: "on_change", PolicyName: "p"}))

	waitFor(t, 5*time.Second, func() bool {
		st := c.TargetStatuses("p")
		return len(st) == 1 && !st[0].LastSync.IsZero()
	})
	climbed := dialer.dials()
	require.Len(t, climbed, 6, "the sixth dial is the first the dialer answered, and the five before it climbed the backoff")
	assert.GreaterOrEqual(t, climbed[5].Sub(climbed[4]), 16*c.backoffBase,
		"the backoff had climbed to thirty-two times its base by the last refused dial")

	released := time.Now()
	close(seen)
	waitFor(t, 5*time.Second, func() bool { return len(dialer.dials()) >= 7 })
	assert.Less(t, dialer.dials()[6].Sub(released), 10*c.backoffBase,
		"the attempt that answered its sync reset the backoff, so the reconnect did not wait the climbed one")
}
