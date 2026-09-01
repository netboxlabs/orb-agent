package policy

import (
	"context"
	"errors"
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
	// maxPolicySeconds bounds every duration a policy states in seconds. It is
	// config.MaxDurationSeconds rather than a number of its own: the same
	// multiply by time.Second wraps wherever this backend turns seconds into a
	// duration, so one bound covers the policy fields and the export period
	// flag alike, with the reasoning for the year stated once beside it.
	maxPolicySeconds = config.MaxDurationSeconds
)

// Collector is the slice of the metrics collector a runner drives. Naming it
// here keeps the runner's dependency narrow and the policy lifecycle testable.
type Collector interface {
	CollectTarget(ctx context.Context, target config.Target, auth *config.Authentication, policyName string, dial collector.DialOptions) error
	ForgetPolicy(policyName string)
}

// Runner represents the policy runner for SNMP metrics collection
type Runner struct {
	scheduler gocron.Scheduler
	// ctx bounds every collection this runner starts, and cancel ends them.
	// The scheduler's own job context is not enough: gocron can wait for a
	// running job but cannot cut it short, so a collection that outlasts its
	// stop timeout would go on writing after the policy was forgotten.
	ctx              context.Context
	cancel           context.CancelFunc
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
	targetErrs       map[targetKey]error // keyed by newTargetKey; initialized in NewRunner
}

// NewRunner returns a new policy runner.
// metricsCollector is the shared collector for this policy's profiles directory —
// created once by the Manager and reused across all policies using the same dir.
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, metricsCollector Collector) (*Runner, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithCancel(context.WithValue(ctx, policyKey, name))
	// Every path out of here but the last one drops the runner, so its context
	// would otherwise stay attached to the manager's for the life of the
	// process.
	built := false
	defer func() {
		if !built {
			cancel()
		}
	}()

	runner := &Runner{
		scheduler:        s,
		logger:           logger,
		name:             name,
		metricsCollector: metricsCollector,
		config:           policy.Config,
		scope:            policy.Scope,
		ctx:              runCtx,
		cancel:           cancel,
		targetErrs:       make(map[targetKey]error),
	}

	if policy.Config.MetricsInterval == nil || *policy.Config.MetricsInterval <= 0 {
		return nil, fmt.Errorf("metrics_interval must be a positive integer")
	}
	// Bounded before the multiply rather than after it: seconds past the bound
	// wrap to a small duration, and every check below would then compare the
	// wrapped values and pass. Guarded here as well as in validatePolicy so a
	// direct NewRunner call cannot slip past.
	if *policy.Config.MetricsInterval > maxPolicySeconds {
		return nil, fmt.Errorf("metrics_interval must be at most %d seconds", maxPolicySeconds)
	}
	runner.metricsInterval = time.Duration(*policy.Config.MetricsInterval) * time.Second

	if policy.Config.SNMPTimeout > maxPolicySeconds {
		return nil, fmt.Errorf("snmp_timeout must be at most %d seconds", maxPolicySeconds)
	}
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

	expanded, collapsed, err := runner.expandTargets()
	if err != nil {
		return nil, err
	}
	// One line per policy rather than one per duplicate: two overlapping
	// prefixes can collapse tens of thousands of addresses.
	if collapsed > 0 {
		logger.Info("Policy names the same device more than once, collapsing the repeats",
			"policy", config.SanitizeLogValue(name), "collapsed", collapsed, "devices", len(expanded))
	}

	// Schedule a metrics job for each expanded target
	for _, t := range expanded {
		metricsTask := gocron.NewTask(runner.runMetrics, t)
		if _, err := s.NewJob(gocron.DurationJob(runner.metricsInterval), metricsTask,
			gocron.WithSingletonMode(gocron.LimitModeReschedule)); err != nil {
			return nil, fmt.Errorf("scheduling metrics job for %s: %w", t.Host, err)
		}
	}

	built = true
	return runner, nil
}

// expandTargets expands the policy's scope into the devices this runner polls,
// one job each, and reports how many repeats it dropped.
//
// Two entries expanding to the same identity are one device. A prefix and an
// address inside it, or two overlapping prefixes, produce that repeat, and
// gocron's singleton mode bounds one job rather than one identity, so the
// repeat's job runs concurrently with the first's: a failed run erases the
// observations a successful one wrote, through forgetDevice, and a successful
// run clears the other's recorded error.
//
// The repeat is collapsed rather than refused. This package refuses a
// configuration with no working reading at all, a blank host or an SNMP
// timeout that fills the interval, but a prefix plus a member address says one
// unambiguous thing about that address. The identity is exactly what
// everything downstream keys on, so the two entries carry nothing to tell
// apart, and an operator wanting two entries for one endpoint gives them
// different IDs or context names, which the identity keeps.
//
// The identity is targetKey, the key this runner already records errors under,
// so it cannot drift from the host, port, NetBox ID and SNMP context that
// deviceKey is built from.
//
// checkPolicyExpansion charges the policy budget before this runs, against the
// notation rather than the collapsed result. Charging it afterwards would let
// a policy name one span as two overlapping prefixes and pay for one, and the
// allocation the budget bounds happens inside targets.Expand, before a repeat
// can be seen.
func (r *Runner) expandTargets() ([]config.Target, int, error) {
	var out []config.Target
	seen := make(map[targetKey]struct{})
	collapsed := 0
	for _, entry := range r.scope.Targets {
		// Skipping the target instead would leave a policy with no job for it,
		// and a policy whose targets are all unexpandable would start with no
		// jobs at all and be reported as running while collecting nothing.
		expandedIPs, err := targets.Expand(entry.Host)
		if err != nil {
			return nil, 0, fmt.Errorf("expanding target %s: %w", entry.Host, err)
		}
		for _, ip := range expandedIPs {
			t := config.Target{
				Host:           ip,
				Port:           entry.Port,
				ID:             entry.ID,
				Authentication: entry.Authentication,
			}
			if t.Port == 0 {
				t.Port = SNMPDefaultPort
			}
			// Keyed after the port default, so an entry leaving the port unset
			// and one naming 161 are the one endpoint they reach as.
			key := newTargetKey(t, r.resolveTargetAuthentication(t))
			if _, dup := seen[key]; dup {
				collapsed++
				continue
			}
			seen[key] = struct{}{}
			out = append(out, t)
		}
	}
	return out, collapsed, nil
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
	key := newTargetKey(target, auth)
	dial := collector.DialOptions{Timeout: r.snmpTimeout, Retries: r.retries}
	if err := r.metricsCollector.CollectTarget(ctx, target, auth, policyName, dial); err != nil {
		r.logger.Warn("SNMP metrics collection failed", "host", config.SanitizeLogValue(target.Host), "policy", config.SanitizeLogValue(policyName), "error", err)
		r.setTargetError(key, err)
	} else {
		r.clearTargetError(key)
	}
}

// targetKey names one entry of a policy's scope. Host and port alone do not: a
// policy may name the same endpoint more than once, and two such entries are
// told apart by their NetBox ID and by their SNMPv3 context name, the same
// dimensions the collector keys its observations by. Without them a healthy
// entry would clear a failing one's error and the policy would report itself
// healthy while half its targets were unreachable.
//
// A comparable struct rather than the fields joined into a string. Every field
// arrives over the API unrestricted, so any joined form has a pair of values
// that produces one key: an ID of "a context=b" with no context name against an
// ID of "a" with a context name of "b". This key is both the error map's key
// and the identity expandTargets collapses repeats on, so a collision there
// drops a target the operator asked for and it is never polled.
type targetKey struct {
	host    string
	port    uint16
	id      string
	context string
}

// newTargetKey builds the key for a target under the authentication resolved
// for it. Credentials are left out: the collector keys its observations the
// same way, and a secret has no exported attribute to carry it.
func newTargetKey(target config.Target, auth *config.Authentication) targetKey {
	key := targetKey{host: target.Host, port: target.Port, id: target.ID}
	if auth != nil {
		key.context = auth.ContextName
	}
	return key
}

// String renders the key for the status error message. Two distinct keys can
// render alike, which is why the map holds the struct: nothing parses this back.
func (k targetKey) String() string {
	s := fmt.Sprintf("%s:%d", k.host, k.port)
	if k.id != "" {
		s += " id=" + k.id
	}
	if k.context != "" {
		s += " context=" + k.context
	}
	return s
}

// setTargetError records an error for a specific target. Protected by r.mu.
func (r *Runner) setTargetError(target targetKey, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targetErrs[target] = err
	r.lastErrAt = time.Now()
	r.lastErr = r.buildCombinedError()
}

// clearTargetError removes the error for a specific target.
// If all targets recover, clears lastErr and resets lastErrAt.
// Note: on partial recovery (some targets still failing), lastErrAt is NOT
// updated: it continues to reflect when errors were first recorded, not when
// the set last changed.
func (r *Runner) clearTargetError(target targetKey) {
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
		msgs = append(msgs, target.String()+": "+err.Error())
	}
	return fmt.Errorf("metrics collection failed: %s", strings.Join(msgs, "; "))
}

// Start starts the policy runner
func (r *Runner) Start() {
	r.logger.Info("Starting policy runner", "policy", config.SanitizeLogValue(r.name))
	r.scheduler.Start()
}

// Stop stops the policy runner and drops the collector state it owns, so a
// deleted policy stops exporting instead of repeating its last observations
// for the life of the process.
//
// The order matters. Cancelling first ends a collection that is already
// running, which is the only thing that can: the scheduler can wait for one but
// not cut it short. StopJobs then has a wait it can finish, and it comes before
// the state is dropped so a run is not still writing when the drop happens.
// Shutdown runs whatever StopJobs reported, rather than leaving the scheduler
// behind when a job overran. ForgetPolicy comes last and unconditionally, so
// the policy stops exporting even if the scheduler did not unwind cleanly.
func (r *Runner) Stop() error {
	r.cancel()
	err := r.scheduler.StopJobs()
	err = errors.Join(err, r.scheduler.Shutdown())
	if r.metricsCollector != nil {
		r.metricsCollector.ForgetPolicy(r.name)
	}
	return err
}
