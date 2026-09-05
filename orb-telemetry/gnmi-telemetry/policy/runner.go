package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	if dialer == nil {
		dialer = &gnmi.GnmicDialer{}
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
	err := r.collector.CollectTarget(r.ctx, t, collector.Options{MetricsInterval: r.interval, Mode: r.modeFor(t), PolicyName: r.name})
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
