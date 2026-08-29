package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"

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
	CollectTarget(ctx context.Context, target config.Target, auth *config.Authentication, policyName string) error
	ForgetPolicy(policyName string)
}

// Runner represents the policy runner for SNMP metrics collection
type Runner struct {
	scheduler        gocron.Scheduler
	ctx              context.Context
	name             string
	metricsCollector Collector
	metricsInterval  time.Duration
	config           config.PolicyConfig
	scope            config.Scope
	logger           *slog.Logger
	mu               sync.RWMutex
	lastErr          error
	lastErrAt        time.Time
	targetErrs       map[string]error // key = "host:port"; initialized in NewRunner
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

	// Schedule a metrics job for each expanded target
	for _, target := range runner.scope.Targets {
		// Checked before expanding, which allocates the whole list up front.
		if err := checkTargetExpansion(target.Host); err != nil {
			return nil, err
		}
		expandedIPs, err := targets.Expand(target.Host)
		if err != nil {
			logger.Warn("Error expanding target host, skipping", "host", config.SanitizeLogValue(target.Host), "error", err)
			continue
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
	targetKey := fmt.Sprintf("%s:%d", target.Host, target.Port)
	if err := r.metricsCollector.CollectTarget(ctx, target, auth, policyName); err != nil {
		r.logger.Warn("SNMP metrics collection failed", "host", config.SanitizeLogValue(target.Host), "policy", config.SanitizeLogValue(policyName), "error", err)
		r.SetTargetError(targetKey, err)
	} else {
		r.ClearTargetError(targetKey)
	}
}

// SetTargetError records an error for a specific target.
// Uses "host:port" as the key. Protected by r.mu.
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
