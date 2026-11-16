package collector

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
)

// pointsByDevice indexes the points of one metric by their device_ip.
func pointsByDevice[N int64 | float64](t *testing.T, pts []metricdata.DataPoint[N]) map[string]attribute.Set {
	t.Helper()
	out := map[string]attribute.Set{}
	for _, pt := range pts {
		ip, ok := pt.Attributes.Value("device_ip")
		require.True(t, ok)
		out[ip.AsString()] = pt.Attributes
	}
	return out
}

// Two targets of one policy carry their own attributes on every series they
// produce, the metric series and target_up alike, with the type each value
// was given, beside identity and profile attributes that are unchanged by
// them.
func TestCollectTarget_TargetAttributesReachTheirOwnSeries(t *testing.T) {
	reader := testReader(t)
	sess := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{Encodings: []string{"PROTO"}},
		SubscribeManyFn: streamOf(sample(1394, time.Now().UnixNano())),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := config.EffectiveTarget(config.Scope{Attributes: config.Attributes{"site": "dc-west"}},
		config.Target{Host: "10.0.0.1", ID: "42", Attributes: config.Attributes{"monitored": true, "rack_units": 2, "weight": 1.5}})
	b := config.EffectiveTarget(config.Scope{}, config.Target{Host: "10.0.0.2", Attributes: config.Attributes{"site": "dc-east"}})
	opts := Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}
	require.NoError(t, c.CollectTarget(ctx, a, opts))
	require.NoError(t, c.CollectTarget(ctx, b, opts))

	waitFor(t, 3*time.Second, func() bool {
		got := exported(t, reader)
		sum, ok := got["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
		up, upOK := got["gnmi.target_up"].Data.(metricdata.Gauge[int64])
		return ok && len(sum.DataPoints) == 2 && upOK && len(up.DataPoints) >= 2
	})
	got := exported(t, reader)

	octets := pointsByDevice(t, got["gnmi.if_in_octets"].Data.(metricdata.Sum[int64]).DataPoints)
	assert.Equal(t, attribute.NewSet(
		attribute.String("device_ip", "10.0.0.1"),
		attribute.String("netbox_id", "42"),
		attribute.String("interface_name", "e1"),
		attribute.String("site", "dc-west"),
		attribute.Bool("monitored", true),
		attribute.Int64("rack_units", 2),
		attribute.Float64("weight", 1.5),
	), octets["10.0.0.1"])
	assert.Equal(t, attribute.NewSet(
		attribute.String("device_ip", "10.0.0.2"),
		attribute.String("interface_name", "e1"),
		attribute.String("site", "dc-east"),
	), octets["10.0.0.2"])

	up := pointsByDevice(t, got["gnmi.target_up"].Data.(metricdata.Gauge[int64]).DataPoints)
	upA, upB := up["10.0.0.1"], up["10.0.0.2"]
	site, ok := upA.Value("site")
	require.True(t, ok, "target_up carries the target's attributes")
	assert.Equal(t, "dc-west", site.AsString())
	_, hasMode := upA.Value("mode")
	assert.True(t, hasMode, "beside its own mode")
	site, ok = upB.Value("site")
	require.True(t, ok)
	assert.Equal(t, "dc-east", site.AsString())
}

// The scope's policy key is reserved under the name the metrics package
// exports it with, and under the key earlier releases used.
func TestReservedAttributeName_CoversTheScopePolicyKey(t *testing.T) {
	assert.True(t, ReservedAttributeName(metrics.PolicyNameAttribute))
	assert.True(t, ReservedAttributeName("policy_name"))
}

func TestReservedAttributeName_IsTheCollectorsOwnDimensions(t *testing.T) {
	for _, name := range []string{"device_ip", "netbox_id", "orb.policy.name", "policy_name", "mode"} {
		assert.True(t, ReservedAttributeName(name), name)
	}
	assert.False(t, ReservedAttributeName("site"))
	assert.False(t, ReservedAttributeName("Device_IP"), "keys are case-sensitive")
}

// ProfileAttribute names every attribute a profile of the set promotes from
// a path key, and the first profile, by name, that does.
func TestProfileAttribute_NamesEveryKeyTheProfilesPromote(t *testing.T) {
	c := New(&gnmi.FakeDialer{}, loadStore(t), nil)
	defer c.Close()
	for key, want := range map[string]string{
		"interface_name": "_base",
		"component_name": "_base",
		"cpu_index":      "_base",
		"slot":           "nokia_srlinux",
	} {
		name, profile, ok := c.ProfileAttribute(key)
		assert.True(t, ok, key)
		assert.Equal(t, key, name, key)
		assert.Equal(t, want, profile, key)
	}
	for _, key := range []string{"site", "Interface_Name", "name", "if_in_octets"} {
		_, _, ok := c.ProfileAttribute(key)
		assert.False(t, ok, key)
	}

	// A key landing on a promoted attribute once translated to Prometheus
	// collides with it there.
	name, profile, ok := c.ProfileAttribute("interface.name")
	require.True(t, ok)
	assert.Equal(t, "interface_name", name)
	assert.Equal(t, "_base", profile)
}

// A delete selects a target's series by its identity alone, so a target
// carrying attributes still has the deleted element's series withdrawn.
func TestDeleteWithdrawsTheSeriesOfATargetWithAttributes(t *testing.T) {
	testReader(t)
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
	tgt := config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Attributes: config.Attributes{"site": "dc-west"}})
	require.NoError(t, c.CollectTarget(ctx, tgt, Options{MetricsInterval: time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		sum, ok := held(c, "p")["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
		if !ok || len(sum.DataPoints) != 1 {
			return false
		}
		iface, _ := sum.DataPoints[0].Attributes.Value("interface_name")
		return iface.AsString() == "e2"
	})
	sum := held(c, "p")["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	site, ok := sum.DataPoints[0].Attributes.Value("site")
	require.True(t, ok, "the survivor still carries the target's attributes")
	assert.Equal(t, "dc-west", site.AsString())
}

// A reconnected stream's sync withdraws the never-stale series its dump no
// longer restates, for a target carrying attributes as for any other.
func TestSyncReconcilesTheSeriesOfATargetWithAttributes(t *testing.T) {
	testReader(t)
	var attempts atomic.Int64
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
	tgt := config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Attributes: config.Attributes{"site": "dc-west"}})
	require.NoError(t, c.CollectTarget(ctx, tgt, Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}))
	waitFor(t, 3*time.Second, func() bool {
		g, ok := held(c, "p")["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		return ok && len(g.DataPoints) == 2
	})
	waitFor(t, 3*time.Second, func() bool { return attempts.Load() >= 2 })
	close(resume)
	waitFor(t, 3*time.Second, func() bool {
		g, ok := held(c, "p")["gnmi.if_oper_status"].Data.(metricdata.Gauge[float64])
		if !ok || len(g.DataPoints) != 1 {
			return false
		}
		name, has := g.DataPoints[0].Attributes.Value("interface_name")
		return has && name.AsString() == "e2"
	})
}

// Starting a target again for the same policy and host replaces its loop. A
// series keeps the attributes it was created with, so when the new target's
// differ, the old loop's series are withdrawn and the new loop's carry the
// new attributes.
func TestCollectTarget_AReplacedTargetWithOtherAttributesStartsAfresh(t *testing.T) {
	testReader(t)
	sess := &gnmi.FakeSession{
		Caps:            &gnmi.CapabilitiesResult{},
		SubscribeManyFn: streamOf(sample(1394, time.Now().UnixNano())),
	}
	c := New(&gnmi.FakeDialer{Session: sess}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := Options{MetricsInterval: 30 * time.Second, Mode: "auto", PolicyName: "p"}

	sites := func() []string {
		sum, ok := held(c, "p")["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
		if !ok {
			return nil
		}
		var out []string
		for _, pt := range sum.DataPoints {
			site, _ := pt.Attributes.Value("site")
			out = append(out, site.AsString())
		}
		return out
	}
	withSite := func(site string) config.Target {
		return config.EffectiveTarget(config.Scope{}, config.Target{Host: "h", Attributes: config.Attributes{"site": site}})
	}

	require.NoError(t, c.CollectTarget(ctx, withSite("dc-west"), opts))
	waitFor(t, 3*time.Second, func() bool { return slices.Equal(sites(), []string{"dc-west"}) })

	require.NoError(t, c.CollectTarget(ctx, withSite("dc-east"), opts))
	waitFor(t, 3*time.Second, func() bool { return slices.Equal(sites(), []string{"dc-east"}) })
}
