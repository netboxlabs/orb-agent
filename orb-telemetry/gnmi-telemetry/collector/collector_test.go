package collector

import (
	"context"
	"errors"
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
