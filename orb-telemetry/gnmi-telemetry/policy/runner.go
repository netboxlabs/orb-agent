package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
)

type contextKey string

// policyKey carries the policy name on the runner's context.
const policyKey contextKey = "policy"

// Collector is the slice of the metrics collector a runner drives.
type Collector interface {
	CollectTarget(ctx context.Context, target config.Target, opts collector.Options) error
	ForgetPolicy(policyName string)
	TargetStatuses(policyName string) []collector.TargetStatus
	// ProfileAttribute reports whether the profile set promotes an attribute
	// key collides with, as written or in Prometheus, and names that
	// attribute and the first profile that promotes it.
	ProfileAttribute(key string) (name, profile string, ok bool)
}

// Runner owns one policy: it admits its targets, explicit ones directly and
// ranges through the sweep, hands each to the collector, and withdraws them
// when the policy stops.
type Runner struct {
	ctx        context.Context
	cancel     context.CancelFunc
	logger     *slog.Logger
	name       string
	policy     config.Policy
	interval   time.Duration
	collector  Collector
	dialer     gnmi.Dialer
	wg         sync.WaitGroup
	mu         sync.Mutex
	subscribed map[string]struct{}
	// sweepErr is the outcome of the last sweep when it left the policy with
	// nothing to collect: a failed expansion, or a range every address of
	// which refused the probe. A policy of one CIDR whose every address was
	// rejected used to report running with no targets and no error, for as
	// long as it ran; this is what the status reports instead. Cleared by a
	// sweep that admits or finds a live subscription.
	sweepErr   string
	sweepErrAt time.Time
}

// recordSweep keeps the outcome of a sweep that left the policy with nothing
// to collect, and clears it when a sweep no longer does.
func (r *Runner) recordSweep(outcome sweepOutcome, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case err != nil:
		r.sweepErr, r.sweepErrAt = "sweep failed: "+err.Error(), time.Now()
	case outcome.total() == 0 && outcome.rejected > 0:
		r.sweepErr = fmt.Sprintf("no target admitted: %d probed address(es) did not answer, e.g. %s", outcome.rejected, outcome.exampleReason)
		r.sweepErrAt = time.Now()
	default:
		r.sweepErr, r.sweepErrAt = "", time.Time{}
	}
}

// SweepError is the last sweep outcome that left the policy with nothing to
// collect, and when it was recorded; empty when the last sweep did not.
func (r *Runner) SweepError() (string, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sweepErr, r.sweepErrAt
}

// NewRunner validates what the runner needs and builds it; nothing starts
// until Start.
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, c Collector, dialer gnmi.Dialer) (*Runner, error) {
	if policy.Config.MetricsInterval == nil || *policy.Config.MetricsInterval < 1 || *policy.Config.MetricsInterval > config.MaxDurationSeconds {
		return nil, fmt.Errorf("policy %s: metrics_interval must be from 1 to %d seconds", name, config.MaxDurationSeconds)
	}
	if len(policy.Scope.Targets) == 0 {
		return nil, errors.New("policy has no targets")
	}
	if err := checkPolicyExpansion(policy.Scope.Targets); err != nil {
		return nil, err
	}
	// A policy that did not come through ParsePolicies has had no scope
	// inheritance, so each target takes the scope's attributes here, on a copy
	// of the targets the caller still holds. Merging is idempotent, so a
	// parsed policy is unchanged by it.
	policy.Scope.Targets = slices.Clone(policy.Scope.Targets)
	for i := range policy.Scope.Targets {
		t := &policy.Scope.Targets[i]
		t.Attributes = config.MergeAttributes(policy.Scope.Attributes, t.Attributes)
	}
	// The attributes are checked here as well as in validatePolicy so a
	// direct NewRunner call cannot slip past, and checked against the profile
	// set only here: the set is the collector's, which a policy only has once
	// it starts.
	if err := validateAttributes(policy.Scope); err != nil {
		return nil, fmt.Errorf("%s: invalid policy: %w", name, err)
	}
	if err := checkOverlappingAttributes(policy.Scope.Targets); err != nil {
		return nil, fmt.Errorf("%s: invalid policy: %w", name, err)
	}
	if err := checkProfileAttributes(name, policy.Scope, c); err != nil {
		return nil, err
	}
	if dialer == nil {
		// The logger travels with the dialer, so a session's own events reach
		// this runner's handler and level rather than the package default.
		dialer = &gnmi.GnmicDialer{Logger: logger}
	}
	rctx, cancel := context.WithCancel(context.WithValue(ctx, policyKey, name))
	return &Runner{
		ctx: rctx, cancel: cancel, logger: logger, name: name, policy: policy,
		interval: time.Duration(*policy.Config.MetricsInterval) * time.Second, collector: c, dialer: dialer,
		subscribed: map[string]struct{}{},
	}, nil
}

// Start subscribes explicit targets at once and runs the sweep for ranges.
func (r *Runner) Start() {
	if r.hasRangedTarget() {
		// sweep defers the matching Done.
		r.wg.Add(1)
		go r.sweep()
		return
	}
	for _, t := range r.policy.Scope.Targets {
		r.subscribe(t)
	}
}

// subscribeAfter waits the jitter, then starts a target the sweep already
// marked subscribed.
func (r *Runner) subscribeAfter(t config.Target, delay time.Duration) {
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.ctx.Done():
			return
		}
	}
	r.startTarget(t)
}

// launch marks a swept target subscribed and starts it in its own goroutine
// after delay. The mark happens before the goroutine, since this is what
// unsubscribed filters a rescan on: a target admitted here must not be probed
// again.
func (r *Runner) launch(t config.Target, delay time.Duration) {
	r.mu.Lock()
	r.subscribed[t.Host] = struct{}{}
	r.mu.Unlock()
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.subscribeAfter(t, delay)
	}()
}

// subscribe marks one explicit target and starts it, once.
func (r *Runner) subscribe(t config.Target) {
	r.mu.Lock()
	if _, ok := r.subscribed[t.Host]; ok {
		r.mu.Unlock()
		return
	}
	r.subscribed[t.Host] = struct{}{}
	r.mu.Unlock()
	r.startTarget(t)
}

// startTarget hands one target to the collector unless the policy stopped.
// ParsePolicies already set the port; the default here keeps a direct
// NewRunner caller from dialing host:0.
func (r *Runner) startTarget(t config.Target) {
	if r.ctx.Err() != nil {
		return
	}
	t.Port = resolvedPort(t.Port)
	err := r.collector.CollectTarget(r.ctx, t, collector.Options{
		MetricsInterval: r.interval, Mode: r.modeFor(t), PolicyName: r.name,
		// The field as written, not the resolved value: unset, it leaves the
		// session's own default in force, because the sweep's default is a
		// reachability check on an address while a path probe waits on a live
		// device's Get, and the shorter of the two would prune a slow but
		// healthy path for the session.
		ProbeTimeout: time.Duration(r.policy.Config.ProbeTimeoutMs) * time.Millisecond,
	})
	if err != nil {
		r.logger.Warn("target not started", "policy", r.name, "host", t.Host, "error", err)
	}
}

// modeFor is the target's mode, else the policy's, else auto.
func (r *Runner) modeFor(t config.Target) string {
	if t.Mode != "" {
		return t.Mode
	}
	if r.policy.Config.Mode != "" {
		return r.policy.Config.Mode
	}
	return "auto"
}

// Stop cancels the sweep and the targets, waits for the sweep, then withdraws
// the policy's series, so nothing subscribes after the withdrawal.
func (r *Runner) Stop() error {
	r.cancel()
	r.wg.Wait()
	r.collector.ForgetPolicy(r.name)
	return nil
}

// TargetStatuses reports the policy's targets from the collector.
func (r *Runner) TargetStatuses() []collector.TargetStatus {
	return r.collector.TargetStatuses(r.name)
}
