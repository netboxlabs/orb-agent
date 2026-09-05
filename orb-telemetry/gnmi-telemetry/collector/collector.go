// Package collector holds one gNMI stream per target, matches its updates
// to the profile's metrics, and exports the last value of every series.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/profiles"
)

// errEarlyStreamFailure marks a stream that ended before its first
// notification. gnmic accepts the RPC and reports an unsupported mode on the
// stream, so this is how a rejected mode looks; the ladder moves on.
var errEarlyStreamFailure = errors.New("subscription failed before any data")

// Options is what a policy hands the collector for each target.
type Options struct {
	MetricsInterval time.Duration
	Mode            string
	PolicyName      string
}

// TargetStatus is one target's state for the API.
type TargetStatus struct {
	Host             string    `json:"host"`
	Mode             string    `json:"mode"`
	Profile          string    `json:"profile"`
	Up               bool      `json:"up"`
	LastNotification time.Time `json:"last_notification"`
	LastError        string    `json:"last_error,omitempty"`
}

type loopKey struct{ policy, host string }

type loop struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	status TargetStatus
}

func (l *loop) update(fn func(*TargetStatus)) {
	l.mu.Lock()
	fn(&l.status)
	l.mu.Unlock()
}

func (l *loop) snapshot() TargetStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status
}

// Collector drives targets. One instance serves every policy that shares a
// profile set; series are keyed by policy so ForgetPolicy withdraws exactly
// that policy's.
type Collector struct {
	dialer      gnmi.Dialer
	profiles    *profiles.Store
	logger      *slog.Logger
	store       *store
	exporter    *exporter
	loopsMu     sync.Mutex
	loops       map[loopKey]*loop
	backoffBase time.Duration
	closed      bool
	upOnce      sync.Once
}

// New builds a collector over a profile store.
func New(dialer gnmi.Dialer, profileStore *profiles.Store, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	st := newStore(metrics.CardinalityLimit - 1)
	return &Collector{
		dialer: dialer, profiles: profileStore, logger: logger, store: st,
		exporter: newExporter(st, logger), loops: map[loopKey]*loop{}, backoffBase: time.Second,
	}
}

// ensureTargetUp registers the gnmi.target_up gauge once: 1 while a target
// has a live stream or poll, 0 while it reconnects.
func (c *Collector) ensureTargetUp() {
	c.upOnce.Do(func() {
		m := metrics.GetMeter()
		if m == nil {
			return
		}
		inst, err := m.Int64ObservableGauge("gnmi.target_up")
		if err != nil {
			c.logger.Error("failed to create target_up", "error", err)
			return
		}
		reg, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
			c.loopsMu.Lock()
			defer c.loopsMu.Unlock()
			for k, l := range c.loops {
				s := l.snapshot()
				v := int64(0)
				if s.Up {
					v = 1
				}
				o.ObserveInt64(inst, v, metric.WithAttributes(
					attribute.String("device_ip", k.host), attribute.String("policy", k.policy), attribute.String("mode", s.Mode)))
			}
			return nil
		}, inst)
		if err != nil {
			c.logger.Error("failed to register target_up", "error", err)
			return
		}
		c.exporter.register(reg)
	})
}

// CollectTarget starts the target's loop and returns. A second call for the
// same policy and host stops the first loop and waits for it before starting.
func (c *Collector) CollectTarget(ctx context.Context, target config.Target, opts Options) error {
	if opts.MetricsInterval <= 0 {
		return errors.New("metrics interval must be positive")
	}
	switch opts.Mode {
	case "", "auto", "on_change", "sample":
	default:
		return fmt.Errorf("mode %q is not auto, on_change or sample", opts.Mode)
	}
	c.ensureTargetUp()
	k := loopKey{opts.PolicyName, target.Host}
	loopCtx, cancel := context.WithCancel(ctx)
	l := &loop{cancel: cancel, done: make(chan struct{}), status: TargetStatus{Host: target.Host}}
	c.loopsMu.Lock()
	if c.closed {
		c.loopsMu.Unlock()
		cancel()
		return errors.New("collector is closed")
	}
	old := c.loops[k]
	c.loops[k] = l
	c.loopsMu.Unlock()
	if old != nil {
		old.cancel()
		<-old.done
	}
	metrics.GetTargetsActive().Add(ctx, 1)
	go func() {
		defer close(l.done)
		defer metrics.GetTargetsActive().Add(context.Background(), -1)
		c.run(loopCtx, target, opts, l)
	}()
	return nil
}

// run is the per-target loop: dial, subscribe with the ladder, consume,
// reconnect with backoff until the context ends.
func (c *Collector) run(ctx context.Context, target config.Target, opts Options, l *loop) {
	backoff := c.backoffBase
	first := true
	for ctx.Err() == nil {
		if !first {
			metrics.GetReconnects().Add(ctx, 1)
		}
		first = false
		noted := l.snapshot().LastNotification
		err := c.runOnce(ctx, target, opts, l)
		l.update(func(s *TargetStatus) { s.Up = false })
		if ctx.Err() != nil {
			return
		}
		if l.snapshot().LastNotification.After(noted) {
			// An attempt that delivered data earns a fresh window: a target
			// that failed twice at startup must not wait the cap after a day
			// of healthy streaming.
			backoff = c.backoffBase
		}
		if err != nil {
			c.logger.Warn("gnmi target loop error", "policy", opts.PolicyName, "host", target.Host, "error", err)
			l.update(func(s *TargetStatus) { s.LastError = err.Error() })
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff = time.Duration(math.Min(float64(backoff*2), float64(30*time.Second)))
	}
}

func (c *Collector) runOnce(ctx context.Context, target config.Target, opts Options, l *loop) error {
	tls := target.ResolvedTLS()
	sess, err := c.dialer.Dial(ctx, gnmi.TargetSpec{
		Host: net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))), Username: target.ResolvedUsername(), Password: target.ResolvedPassword(),
		SkipVerify: tls.SkipVerify, Insecure: tls.Insecure, Origin: target.ResolvedOrigin(),
		CAFile: tls.CAFile, CertFile: tls.CertFile, KeyFile: tls.KeyFile,
	})
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()

	caps, err := sess.Capabilities(ctx)
	if err != nil {
		return fmt.Errorf("capabilities: %w", err)
	}
	profile := c.selectProfile(target, caps)
	l.update(func(s *TargetStatus) { s.Profile = profile.Name })

	subs := c.subscriptions(profile, target, opts)
	intervalMs := int(opts.MetricsInterval / time.Millisecond)
	ladder := []string{"on_change", "sample"}
	switch opts.Mode {
	case "sample":
		ladder = []string{"sample"}
	case "on_change":
		ladder = []string{"on_change"}
	}
	for _, rung := range ladder {
		notes, errs, err := sess.SubscribeMany(ctx, forceMode(subs, rung, intervalMs))
		if err != nil {
			// A cancelled context refuses every rung; counting that as a
			// fallback would report a downgrade on every clean stop.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			metrics.GetModeFallbacks().Add(ctx, 1)
			c.logger.Info("gnmi subscribe refused, trying the next mode", "host", target.Host, "mode", rung, "error", err)
			continue
		}
		l.update(func(s *TargetStatus) { s.Mode = rung; s.Up = true })
		err = c.consume(ctx, notes, errs, target, opts, profile, l)
		if errors.Is(err, errEarlyStreamFailure) && ctx.Err() == nil && opts.Mode != "on_change" && opts.Mode != "sample" {
			metrics.GetModeFallbacks().Add(ctx, 1)
			c.logger.Info("gnmi stream ended before data, trying the next mode", "host", target.Host, "mode", rung, "error", err)
			continue
		}
		return err
	}
	metrics.GetModeFallbacks().Add(ctx, 1)
	l.update(func(s *TargetStatus) { s.Mode = "get"; s.Up = true })
	return c.poll(ctx, sess, subs, target, opts, profile, l)
}

// subscriptions builds the profile's subscriptions for a target, with the
// profile's per-subscription origin or the target's.
func (c *Collector) subscriptions(p *profiles.Profile, target config.Target, opts Options) []gnmi.Subscription {
	out := make([]gnmi.Subscription, 0, len(p.Subscriptions))
	for _, s := range p.Subscriptions {
		origin := target.ResolvedOrigin()
		if s.Origin != nil {
			origin = *s.Origin
		}
		mode := gnmi.Sample
		if s.Mode == "on_change" {
			mode = gnmi.OnChange
		}
		out = append(out, gnmi.Subscription{Path: s.Path, Origin: origin, Mode: mode, SampleIntervalMs: int(opts.MetricsInterval / time.Millisecond)})
	}
	return out
}

// forceMode applies a ladder rung: "on_change" keeps the profile's modes,
// "sample" makes every subscription SAMPLE at the interval.
func forceMode(subs []gnmi.Subscription, rung string, intervalMs int) []gnmi.Subscription {
	if rung != "sample" {
		return subs
	}
	out := make([]gnmi.Subscription, len(subs))
	for i, s := range subs {
		s.Mode = gnmi.Sample
		s.SampleIntervalMs = intervalMs
		out[i] = s
	}
	return out
}

func (c *Collector) selectProfile(target config.Target, caps *gnmi.CapabilitiesResult) *profiles.Profile {
	if target.Profile != "" {
		if p, ok := c.profiles.Get(target.Profile); ok {
			return p
		}
		c.logger.Warn("pinned profile not found, matching by vendor", "host", target.Host, "profile", target.Profile)
	}
	p := c.profiles.Match(profiles.MatchInput{Vendor: caps.Vendor})
	if p.Name == "_base" {
		metrics.GetProfileFallbacks().Add(context.Background(), 1)
	}
	return p
}

// consume applies notifications until the stream ends or errors. A stream
// that ends before its first notification is reported as an early failure.
func (c *Collector) consume(ctx context.Context, notes <-chan gnmi.Notification, errs <-chan error, target config.Target, opts Options, p *profiles.Profile, l *loop) error {
	productive := false
	early := func(err error) error {
		if productive {
			return err
		}
		return fmt.Errorf("%w: %v", errEarlyStreamFailure, err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-errs:
			if ok && err != nil {
				return early(err)
			}
			if !ok {
				errs = nil
			}
		case n, ok := <-notes:
			if !ok {
				select {
				case err := <-errs:
					if err != nil {
						return early(err)
					}
				default:
				}
				return early(errors.New("stream closed"))
			}
			if n.SyncDone && len(n.Updates) == 0 && len(n.Deletes) == 0 {
				continue
			}
			productive = true
			metrics.GetNotifications().Add(ctx, 1)
			c.apply(ctx, n, target, opts, p)
			l.update(func(s *TargetStatus) { s.LastNotification = time.Now(); s.LastError = "" })
		}
	}
}

// poll is the last rung: Get at the interval. The session's origin is the
// target's, so a subscription with another origin is skipped here and
// logged once; a native overlay path is only reachable by streaming.
func (c *Collector) poll(ctx context.Context, sess gnmi.Session, subs []gnmi.Subscription, target config.Target, opts Options, p *profiles.Profile, l *loop) error {
	paths := make([]string, 0, len(subs))
	for _, s := range subs {
		if s.Origin != target.ResolvedOrigin() {
			c.logger.Info("gnmi get polling skips a subscription with its own origin", "host", target.Host, "path", s.Path)
			continue
		}
		paths = append(paths, s.Path)
	}
	ticker := time.NewTicker(opts.MetricsInterval)
	defer ticker.Stop()
	for {
		n, err := sess.GetOnce(ctx, paths)
		if err != nil {
			return err
		}
		if n.Timestamp == 0 {
			n.Timestamp = time.Now().UnixNano()
		}
		c.apply(ctx, n, target, opts, p)
		l.update(func(s *TargetStatus) { s.LastNotification = time.Now(); s.LastError = "" })
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// apply matches every update to a profile metric and stores it; a delete
// withdraws the series of the deleted element and everything under it.
func (c *Collector) apply(ctx context.Context, n gnmi.Notification, target config.Target, opts Options, p *profiles.Profile) {
	base := []attribute.KeyValue{attribute.String("device_ip", target.Host), attribute.String("policy", opts.PolicyName)}
	if target.ID != "" {
		base = append(base, attribute.String("netbox_id", target.ID))
	}
	ts := n.Timestamp
	if ts == 0 {
		ts = time.Now().UnixNano()
	}
	maxAge := staleAfterIntervals * opts.MetricsInterval
	for _, u := range n.Updates {
		sub, m, keys, ok := matchUpdate(p, u.Path)
		if !ok {
			metrics.GetUpdatesDropped().Add(ctx, 1, metric.WithAttributes(attribute.String("reason", "unmatched_path")))
			continue
		}
		attrs := append(append([]attribute.KeyValue(nil), base...), promoted(sub, keys)...)
		var stored bool
		switch m.Type {
		case "counter":
			v, ok := counterValue(*m, u.Value)
			if !ok {
				metrics.GetUpdatesDropped().Add(ctx, 1, metric.WithAttributes(attribute.String("reason", "unconvertible_value")))
				continue
			}
			stored = c.exporter.observeCounter(m.Name, m.Unit, attrs, v, ts, maxAge)
		default:
			v, ok := gaugeValue(*m, u.Value)
			if !ok {
				metrics.GetUpdatesDropped().Add(ctx, 1, metric.WithAttributes(attribute.String("reason", "unconvertible_value")))
				continue
			}
			stored = c.exporter.observeGauge(m.Name, m.Unit, attrs, v, ts, maxAge)
		}
		if !stored {
			metrics.GetUpdatesDropped().Add(ctx, 1, metric.WithAttributes(attribute.String("reason", "series_limit")))
		}
	}
	for _, d := range n.Deletes {
		for i := range p.Subscriptions {
			sub := &p.Subscriptions[i]
			keys, ok := profiles.MatchPrefix(sub.Path, d)
			if !ok {
				continue
			}
			names := make(map[string]struct{}, len(sub.Metrics))
			for _, m := range sub.Metrics {
				names[m.Name] = struct{}{}
			}
			c.store.deleteMatching(names, append(append([]attribute.KeyValue(nil), base...), promoted(sub, keys)...))
		}
	}
}

// matchUpdate finds the subscription and metric an update path names,
// preferring the deepest subscription path so profile order is not
// load-bearing. A "." leaf matches the subscription path itself.
func matchUpdate(p *profiles.Profile, path string) (*profiles.Subscription, *profiles.Metric, map[string]string, bool) {
	var bestSub *profiles.Subscription
	var bestMetric *profiles.Metric
	var bestKeys map[string]string
	bestDepth := -1
	for i := range p.Subscriptions {
		sub := &p.Subscriptions[i]
		depth := profiles.Depth(sub.Path)
		if depth <= bestDepth {
			continue
		}
		if len(sub.Metrics) == 1 && sub.Metrics[0].Leaf == "." {
			if keys, ok := profiles.MatchPath(sub.Path, path); ok {
				bestSub, bestMetric, bestKeys, bestDepth = sub, &sub.Metrics[0], keys, depth
			}
			continue
		}
		leaf, keys, ok := profiles.SplitLeaf(sub.Path, path)
		if !ok {
			continue
		}
		for j := range sub.Metrics {
			if sub.Metrics[j].Leaf == leaf {
				bestSub, bestMetric, bestKeys, bestDepth = sub, &sub.Metrics[j], keys, depth
				break
			}
		}
	}
	return bestSub, bestMetric, bestKeys, bestSub != nil
}

// promoted turns the subscription's attribute map into attributes from the
// update's path keys.
func promoted(sub *profiles.Subscription, keys map[string]string) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(sub.Attributes))
	for attr, key := range sub.Attributes {
		if v, ok := keys[key]; ok {
			out = append(out, attribute.String(attr, v))
		}
	}
	return out
}

// ForgetPolicy stops the policy's loops, waits for them, and withdraws its
// series, in that order, so no loop writes after the withdrawal.
func (c *Collector) ForgetPolicy(policyName string) {
	c.loopsMu.Lock()
	var stopped []*loop
	for k, l := range c.loops {
		if k.policy == policyName {
			l.cancel()
			stopped = append(stopped, l)
			delete(c.loops, k)
		}
	}
	c.loopsMu.Unlock()
	for _, l := range stopped {
		<-l.done
	}
	c.store.forgetPolicy(policyName)
}

// TargetStatuses reports the policy's targets.
func (c *Collector) TargetStatuses(policyName string) []TargetStatus {
	c.loopsMu.Lock()
	defer c.loopsMu.Unlock()
	var out []TargetStatus
	for k, l := range c.loops {
		if k.policy == policyName {
			out = append(out, l.snapshot())
		}
	}
	return out
}

// Close stops every loop, waits, and unregisters every instrument.
func (c *Collector) Close() {
	c.loopsMu.Lock()
	c.closed = true
	var all []*loop
	for k, l := range c.loops {
		l.cancel()
		all = append(all, l)
		delete(c.loops, k)
	}
	c.loopsMu.Unlock()
	for _, l := range all {
		<-l.done
	}
	c.exporter.close()
}
