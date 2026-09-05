package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
		"match: {}\nsubscriptions:\n  - path: /platform/control[slot=*]/memory\n    mode: sample\n    origin: \"\"\n    metrics:\n      - {leaf: free, name: mem_free, type: gauge}\n"), 0o600))
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
		c := NewWithBudget(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil, budget)
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
		c := NewWithBudget(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil, budget)
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
