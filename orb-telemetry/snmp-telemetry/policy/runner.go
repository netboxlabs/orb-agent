package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/targets"
)

// Define a custom type for the context key
type contextKey string

// Define the policy key
const (
	policyKey          contextKey = "policy"
	defaultSNMPTimeout            = 5 * time.Second
)

// Collector is the slice of the metrics collector a runner drives. Naming it
// here keeps the runner's dependency narrow and the policy lifecycle testable.
type Collector interface {
	CollectTarget(ctx context.Context, target config.Target, auth *config.Authentication, policyName string, dial collector.DialOptions) error
	ForgetPolicy(policyName string)
}

// Runner represents the policy runner for SNMP metrics collection
type Runner struct {
	scheduler        gocron.Scheduler
	ctx              context.Context
	name             string
	metricsCollector Collector
	metricsInterval  time.Duration
	snmpTimeout      time.Duration
	retries          int
	config           config.PolicyConfig
	scope            config.Scope
	logger           *slog.Logger
	mu               sync.RWMutex
	lastErr          error
	lastErrAt        time.Time
	targetErrs       map[string]error // key from targetErrorKey; initialized in NewRunner
}

// NewRunner returns a new policy runner.
// metricsCollector is the shared collector for this policy's profiles directory —
// created once by the Manager and reused across all policies using the same dir.
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, metricsCollector Collector) (*Runner, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

	runner := &Runner{
		scheduler:        s,
		logger:           logger,
		name:             name,
		metricsCollector: metricsCollector,
		config:           policy.Config,
		scope:            policy.Scope,
		ctx:              context.WithValue(ctx, policyKey, name),
		targetErrs:       make(map[string]error),
	}

	if policy.Config.MetricsInterval == nil || *policy.Config.MetricsInterval <= 0 {
		return nil, fmt.Errorf("metrics_interval must be a positive integer")
	}
	runner.metricsInterval = time.Duration(*policy.Config.MetricsInterval) * time.Second

	runner.snmpTimeout = time.Duration(policy.Config.SNMPTimeout) * time.Second
	if runner.snmpTimeout <= 0 {
		runner.snmpTimeout = defaultSNMPTimeout
	}
	runner.retries = policy.Config.Retries
	if runner.retries < 0 {
		runner.retries = 0
	}
	// A single attempt that fills the interval can never produce a sample: the
	// run's deadline expires at or before the first request returns. That is
	// rejected, matching snmp-discovery.
	if runner.snmpTimeout >= runner.metricsInterval {
		return nil, fmt.Errorf("snmp_timeout (%s) must be less than metrics_interval (%s)", runner.snmpTimeout, runner.metricsInterval)
	}
	// Retries raise the ceiling for one request to snmp_timeout times
	// retries+1, but that ceiling is only reached against a device that never
	// answers. Warning rather than rejecting keeps a policy that collects
	// normally from being refused for its worst case. Attempts are capped
	// before the multiply so an outsized retries count cannot overflow it.
	attempts := min(int64(runner.retries)+1, int64(runner.metricsInterval/runner.snmpTimeout)+1)
	if ceiling := time.Duration(attempts) * runner.snmpTimeout; ceiling >= runner.metricsInterval {
		logger.Warn("SNMP retries can exceed the collection interval, a run against an unresponsive device will be cut short",
			"policy", config.SanitizeLogValue(name),
			"snmp_timeout", runner.snmpTimeout, "retries", runner.retries,
			"request_ceiling", ceiling, "metrics_interval", runner.metricsInterval)
	}

	// Charged over the whole policy before any target is expanded, since
	// expanding one allocates its whole address list up front. Guarded here as
	// well as in validatePolicy so a direct NewRunner call cannot slip past.
	if err := checkPolicyExpansion(runner.scope.Targets); err != nil {
		return nil, err
	}

	// Schedule a metrics job for each expanded target
	for _, target := range runner.scope.Targets {
		// Skipping the target instead would leave a policy with no job for it,
		// and a policy whose targets are all unexpandable would start with no
		// jobs at all and be reported as running while collecting nothing.
		expandedIPs, err := targets.Expand(target.Host)
		if err != nil {
			return nil, fmt.Errorf("expanding target %s: %w", target.Host, err)
		}
		for _, ip := range expandedIPs {
			t := config.Target{
				Host:           ip,
				Port:           target.Port,
				ID:             target.ID,
				Authentication: target.Authentication,
			}
			if t.Port == 0 {
				t.Port = 161
			}
			metricsTask := gocron.NewTask(runner.runMetrics, t)
			_, err = s.NewJob(gocron.DurationJob(runner.metricsInterval), metricsTask,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
			if err != nil {
				return nil, fmt.Errorf("scheduling metrics job for %s: %w", ip, err)
			}
		}
	}

	return runner, nil
}

// resolveTargetAuthentication returns the authentication to use for a target.
// Uses target-level auth if available, otherwise falls back to scope-level auth.
func (r *Runner) resolveTargetAuthentication(target config.Target) *config.Authentication {
	if target.Authentication != nil {
		return target.Authentication
	}
	return &r.scope.Authentication
}

// runMetrics collects SNMP operational metrics from a target using its matched profile.
func (r *Runner) runMetrics(target config.Target) {
	policyName := r.name
	r.logger.Debug("Running SNMP metrics collection", "host", config.SanitizeLogValue(target.Host), "policy", config.SanitizeLogValue(policyName))
	ctx, cancel := context.WithTimeout(r.ctx, r.metricsInterval)
	defer cancel()
	auth := r.resolveTargetAuthentication(target)
	targetKey := targetErrorKey(target, auth)
	dial := collector.DialOptions{Timeout: r.snmpTimeout, Retries: r.retries}
	if err := r.metricsCollector.CollectTarget(ctx, target, auth, policyName, dial); err != nil {
		r.logger.Warn("SNMP metrics collection failed", "host", config.SanitizeLogValue(target.Host), "policy", config.SanitizeLogValue(policyName), "error", err)
		r.SetTargetError(targetKey, err)
	} else {
		r.ClearTargetError(targetKey)
	}
}

// targetErrorKey names one entry of a policy's scope. Host and port alone do
// not: a policy may name the same endpoint more than once, and two such entries
// are told apart by their NetBox ID and by their SNMPv3 context name, the same
// dimensions the collector keys its observations by. Without them a healthy
// entry would clear a failing one's error and the policy would report itself
// healthy while half its targets were unreachable.
func targetErrorKey(target config.Target, auth *config.Authentication) string {
	key := fmt.Sprintf("%s:%d", target.Host, target.Port)
	if target.ID != "" {
		key += " id=" + target.ID
	}
	if auth != nil && auth.ContextName != "" {
		key += " context=" + auth.ContextName
	}
	return key
}

// SetTargetError records an error for a specific target.
// Uses targetErrorKey as the key. Protected by r.mu.
func (r *Runner) SetTargetError(target string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targetErrs[target] = err
	r.lastErrAt = time.Now()
	r.lastErr = r.buildCombinedError()
}

// ClearTargetError removes the error for a specific target.
// If all targets recover, clears lastErr and resets lastErrAt.
// Note: on partial recovery (some targets still failing), lastErrAt is NOT updated —
// it continues to reflect when errors were first recorded, not when the set last changed.
func (r *Runner) ClearTargetError(target string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.targetErrs, target)
	if len(r.targetErrs) == 0 {
		r.lastErr = nil
		r.lastErrAt = time.Time{} // reset stale timestamp when all targets recover
	} else {
		r.lastErr = r.buildCombinedError()
	}
}

// GetLastError returns when the combined error was last set and the combined error
// across all failing targets. Returns nil error when all targets are healthy.
func (r *Runner) GetLastError() (time.Time, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastErrAt, r.lastErr
}

// buildCombinedError builds a combined error string from all failing targets.
// MUST be called with r.mu held.
func (r *Runner) buildCombinedError() error {
	if len(r.targetErrs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(r.targetErrs))
	for target, err := range r.targetErrs {
		msgs = append(msgs, target+": "+err.Error())
	}
	return fmt.Errorf("metrics collection failed: %s", strings.Join(msgs, "; "))
}

// Start starts the policy runner
func (r *Runner) Start() {
	r.logger.Info("Starting policy runner", "policy", r.ctx.Value(policyKey))
	r.scheduler.Start()
}

// Stop stops the policy runner and drops the collector state it owns, so a
// deleted policy stops exporting instead of repeating its last observations
// for the life of the process. The drop happens even when the scheduler fails
// to unwind cleanly, and after Shutdown so no in-flight run can rewrite it.
func (r *Runner) Stop() error {
	err := r.scheduler.StopJobs()
	if err == nil {
		err = r.scheduler.Shutdown()
	}
	if r.metricsCollector != nil {
		r.metricsCollector.ForgetPolicy(r.name)
	}
	return err
}
