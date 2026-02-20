package policy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/metrics"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/targets"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Define a custom type for the context key
type contextKey string

// Define the policy key
const (
	policyKey               contextKey = "policy"
	defaultTimeout                     = 2 * time.Minute
	defaultSNMPTimeout                 = 5 * time.Second
	defaultSNMPProbeTimeout            = 1 * time.Second
	defaultSNMPProbeOID                = "1.3.6.1.2.1.1" // SNMPv2-MIB::system
)

// expandedTargetGroup represents a group of expanded targets with their original target string
type expandedTargetGroup struct {
	originalTarget string          // Original target string (e.g., "192.168.1.0/24")
	targets        []config.Target // Expanded targets
}

// Runner represents the policy runner
type Runner struct {
	scheduler        gocron.Scheduler
	ctx              context.Context
	tasks            []gocron.Task
	client           diode.Client
	logger           *slog.Logger
	timeout          time.Duration
	snmpTimeout      time.Duration
	snmpProbeTimeout time.Duration
	scope            config.Scope
	config           config.PolicyConfig
	ClientFactory    snmp.ClientFactory
	manufacturers    data.ManufacturerRetriever
	mappingConfig    *config.Mapping
	deviceLookup     data.DeviceRetriever
	runStore         *RunStore
}

// NewRunner returns a new policy runner
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client, ClientFactory snmp.ClientFactory, mappingConfig *config.Mapping, manufacturers data.ManufacturerRetriever, deviceLookup data.DeviceRetriever, runStore *RunStore) (*Runner, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

	runner := &Runner{
		scheduler:     s,
		client:        client,
		logger:        logger,
		ClientFactory: ClientFactory,
		manufacturers: manufacturers,
		mappingConfig: mappingConfig,
		deviceLookup:  deviceLookup,
		runStore:      runStore,
	}

	runner.timeout = time.Duration(policy.Config.Timeout) * time.Second
	if runner.timeout == 0 {
		runner.timeout = defaultTimeout
	}
	runner.snmpTimeout = time.Duration(policy.Config.SNMPTimeout) * time.Second
	if runner.snmpTimeout == 0 {
		runner.snmpTimeout = defaultSNMPTimeout
	}
	runner.snmpProbeTimeout = time.Duration(policy.Config.SNMPProbeTimeout) * time.Second
	if runner.snmpProbeTimeout == 0 {
		runner.snmpProbeTimeout = defaultSNMPProbeTimeout
	}
	if runner.timeout <= runner.snmpTimeout {
		return nil, fmt.Errorf("policy timeout (%s) must be greater than snmp_timeout (%s)", runner.timeout, runner.snmpTimeout)
	}
	runner.ctx = context.WithValue(ctx, policyKey, name)
	runner.scope = policy.Scope
	runner.config = policy.Config

	expandedTargetGroups := runner.expandTargetRanges(runner.scope.Targets)

	for _, group := range expandedTargetGroups {
		if len(group.targets) == 1 {
			// Create scan task for single target
			task := gocron.NewTask(runner.run, group.targets[0])
			if policy.Config.Schedule != nil {
				_, err = runner.scheduler.NewJob(gocron.CronJob(*policy.Config.Schedule, false), task,
					gocron.WithSingletonMode(gocron.LimitModeReschedule))
			} else {
				_, err = runner.scheduler.NewJob(gocron.OneTimeJob(
					gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), task,
					gocron.WithSingletonMode(gocron.LimitModeReschedule))
			}
			if err != nil {
				return nil, err
			}
			runner.tasks = append(runner.tasks, task)
			continue
		}
		// Create scan task for multiple targets with original target
		task := gocron.NewTask(runner.runScanWithOriginal, group.targets, group.originalTarget)
		_, err = runner.scheduler.NewJob(gocron.OneTimeJob(
			gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), task,
			gocron.WithSingletonMode(gocron.LimitModeReschedule))
		if err != nil {
			return nil, err
		}
		runner.tasks = append(runner.tasks, task)
	}
	return runner, nil
}

func (r *Runner) runScanWithOriginal(targets []config.Target, originalTarget string) {
	policyName := r.ctx.Value(policyKey).(string)

	// All expanded targets have the same port, get it from the first target
	port := uint16(161) // default
	if len(targets) > 0 {
		port = targets[0].Port
	}

	// Create run for the scan operation (includes port)
	scanRun := r.runStore.CreateRun(policyName, originalTarget, port, "")

	r.logger.Info("Starting SNMP probe scan", "policy", policyName, "target", originalTarget, "targetCount", len(targets))
	workerCount := min(256, len(targets))

	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()

	targetCh := make(chan config.Target)
	resultsCh := make(chan config.Target, workerCount)

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for range workerCount {
		go func() {
			defer wg.Done()
			for target := range targetCh {
				if r.probeTarget(ctx, target) {
					resultsCh <- target
				}
			}
		}()
	}

	go func() {
		defer close(targetCh)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			case targetCh <- target:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var responsive []config.Target
	for target := range resultsCh {
		responsive = append(responsive, target)
		r.logger.Debug("SNMP probe succeeded", "host", target.Host, "port", target.Port, "policy", policyName)
	}

	// Check if context was canceled or timed out
	if ctxErr := ctx.Err(); ctxErr != nil {
		r.logger.Warn("SNMP probe scan interrupted", "policy", policyName, "error", ctxErr, "responsiveTargetCount", len(responsive))
		r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusFailed, ctxErr, len(responsive))
		return
	}

	var err error
	for _, target := range responsive {
		task := gocron.NewTask(r.runWithMetadata, target, originalTarget)
		if r.config.Schedule != nil {
			_, err = r.scheduler.NewJob(gocron.CronJob(*r.config.Schedule, false), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
		} else {
			_, err = r.scheduler.NewJob(gocron.OneTimeJob(
				gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
		}
		if err != nil {
			r.logger.Error("failed to schedule crawl task for responsive target",
				"host", target.Host, "policy", policyName, "error", err)
			continue
		}
		r.tasks = append(r.tasks, task)
	}

	// Update scan run status
	r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusCompleted, nil, len(responsive))
	r.logger.Info("SNMP probe scan complete", "policy", policyName, "responsiveTargetCount", len(responsive))
}

// resolveTargetAuthentication returns the authentication to use for a target
// Uses target-level auth if available, otherwise falls back to policy-level auth
func (r *Runner) resolveTargetAuthentication(target config.Target) *config.Authentication {
	if target.Authentication != nil {
		r.logger.Debug("Using target-level authentication", "host", target.Host)
		return target.Authentication
	}

	r.logger.Debug("Using policy-level authentication (fallback)", "host", target.Host)
	return &r.scope.Authentication
}

// resolveTargetDefaults returns the defaults to use for a target
// Merges target-level override defaults with policy-level defaults
func (r *Runner) resolveTargetDefaults(target config.Target) *config.Defaults {
	if target.OverrideDefaults != nil {
		r.logger.Debug("Merging target-level override defaults", "host", target.Host)
		return config.MergeDefaults(&r.config.Defaults, target.OverrideDefaults)
	}

	r.logger.Debug("Using policy-level defaults", "host", target.Host)
	return &r.config.Defaults
}

func (r *Runner) probeTarget(ctx context.Context, target config.Target) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	auth := r.resolveTargetAuthentication(target)

	snmpClient, err := r.ClientFactory(target.Host, target.Port, 0, r.snmpProbeTimeout, auth, r.logger)
	if err != nil {
		return false
	}
	defer func() {
		_ = snmpClient.Close()
	}()

	if err := snmpClient.Connect(); err != nil {
		return false
	}

	_, err = snmpClient.Walk(defaultSNMPProbeOID, 0)
	return err == nil
}

// run runs the policy for a single target (no parent)
func (r *Runner) run(target config.Target) {
	r.runWithMetadata(target, "")
}

// runWithMetadata runs the policy with metadata tracking
func (r *Runner) runWithMetadata(target config.Target, parentTarget string) {
	policyName := r.ctx.Value(policyKey).(string)
	targetHost := target.Host
	targetPort := target.Port

	// Create run at start (includes port)
	run := r.runStore.CreateRun(policyName, targetHost, targetPort, parentTarget)

	// Track policy execution
	if rMetric := metrics.GetPolicyExecutions(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", r.ctx.Value(policyKey).(string)),
			))
	}
	startTime := time.Now()

	defer func() {
		if rMetric := metrics.GetDiscoveryLatency(); rMetric != nil {
			// Calculate duration in milliseconds
			duration := float64(time.Since(startTime).Milliseconds())
			rMetric.Record(r.ctx, duration, metric.WithAttributes(
				attribute.String("policy", policyName),
			))
		}
	}()

	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()

	entities, err := r.queryTarget(ctx, target)
	if err != nil {
		r.logger.Error("error querying target", "host", target.Host, "error", err, "policy", policyName)
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, err, 0)
		return
	}
	r.logger.Info("SNMP crawl complete", "host", target.Host, "policy", policyName, "entityCount", len(entities))

	if len(entities) == 0 {
		r.logger.Info("No entities to ingest", "host", target.Host, "policy", policyName)
		// Update run status to completed even if no entities
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusCompleted, nil, 0)
		return
	}

	r.logEntitiesForIngestion(entities)

	resp, err := r.client.Ingest(r.ctx, entities, diode.WithIngestMetadata(diode.Metadata{
		"policy_name": policyName,
		"run_id":      run.ID,
	}))
	if err != nil {
		r.logger.Error("error ingesting entities", "host", target.Host, "error", err, "policy", policyName)
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, err, len(entities))
	} else if resp != nil && resp.Errors != nil {
		ingestErr := fmt.Errorf("ingestion errors: %v", resp.Errors)
		r.logger.Error("error ingesting entities", "host", target.Host, "error", resp.Errors, "policy", policyName)
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, ingestErr, len(entities))
	} else {
		r.logger.Info("entities ingested successfully", "host", target.Host, "policy", policyName)
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusCompleted, nil, len(entities))
	}
}

func (r *Runner) logEntitiesForIngestion(entities []diode.Entity) {
	for _, entity := range entities {
		r.logger.Debug("Entity for ingestion", "entity", entity.ConvertToProtoMessage())
	}
}

func (r *Runner) queryTarget(ctx context.Context, target config.Target) ([]diode.Entity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetDefaults := r.resolveTargetDefaults(target)

	mappingConfig, err := mapping.NewConfig(r.mappingConfig.Entries, r.logger, r.manufacturers, r.deviceLookup, targetDefaults)
	if err != nil {
		r.logger.Error("Error creating mapping config", "error", err)
		return nil, err
	}
	objectIDs := mappingConfig.ObjectIDs()
	r.logger.Info("Querying target", "host", target.Host, "port", target.Port, "objectCount", len(objectIDs))

	mapper := mapping.NewObjectIDMapper(mappingConfig, r.logger, targetDefaults)
	policyName := r.ctx.Value(policyKey).(string)
	// Track discovery attempt
	if rMetric := metrics.GetDiscoveryAttempts(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	// Start timing the discovery
	startTime := time.Now()

	auth := r.resolveTargetAuthentication(target)

	host := snmp.NewHost(target.Host, target.Port, r.config.Retries, r.snmpTimeout, auth, r.logger, r.ClientFactory)

	type walkResult struct {
		oids mapping.ObjectIDValueMap
		err  error
	}
	// The buffered channel ensures the goroutine can always send its result and exit,
	// even if we have already returned due to context cancellation. The goroutine is
	// bounded by snmpTimeout (set on the SNMP client), so it is not a permanent leak.
	resultCh := make(chan walkResult, 1)
	go func() {
		oids, err := host.Walk(objectIDs)
		resultCh <- walkResult{oids, err}
	}()

	var oids mapping.ObjectIDValueMap
	select {
	case <-ctx.Done():
		if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
			rMetric.Add(r.ctx, 1,
				metric.WithAttributes(
					attribute.String("policy", policyName),
					attribute.String("error", ctx.Err().Error()),
				))
		}
		return nil, ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			r.logger.Warn("Error crawling host", "host", target.Host, "error", res.err)
			if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
				rMetric.Add(r.ctx, 1,
					metric.WithAttributes(
						attribute.String("policy", policyName),
						attribute.String("error", res.err.Error()),
					))
			}
			return nil, res.err
		}
		oids = res.oids
	}

	// Track successful discovery
	if rMetric := metrics.GetDiscoverySuccess(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	// Record discovery latency
	if rMetric := metrics.GetDiscoveryLatency(); rMetric != nil {
		rMetric.Record(r.ctx, time.Since(startTime).Seconds(),
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	entities := make([]diode.Entity, 0)
	entitiesForTarget := mapper.MapObjectIDsToEntity(oids)
	entities = append(entities, entitiesForTarget...)

	// Update discovered hosts gauge
	if rMetric := metrics.GetDiscoveredHosts(); rMetric != nil {
		rMetric.Record(r.ctx, int64(len(entitiesForTarget)),
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	return entities, nil
}

func (r *Runner) expandTargetRanges(configuredTargets []config.Target) []expandedTargetGroup {
	expandedGroups := make([]expandedTargetGroup, 0, len(configuredTargets))
	for _, target := range configuredTargets {
		originalHost := target.Host // Preserve original target string
		ips, err := targets.Expand(target.Host)
		if err != nil {
			r.logger.Warn("Error expanding target host", "host", target.Host, "error", err)
			continue
		}

		expandedTargets := make([]config.Target, len(ips))
		for i := range ips {
			expandedTargets[i] = config.Target{
				Host:             ips[i],
				Port:             target.Port,
				Authentication:   target.Authentication,
				OverrideDefaults: target.OverrideDefaults,
			}
		}
		expandedGroups = append(expandedGroups, expandedTargetGroup{
			originalTarget: originalHost,
			targets:        expandedTargets,
		})
	}
	return expandedGroups
}

// Start starts the policy runner
func (r *Runner) Start() {
	r.logger.Info("Starting policy runner", "policy", r.ctx.Value(policyKey))
	r.scheduler.Start()
}

// Stop stops the policy runner
func (r *Runner) Stop() error {
	if err := r.scheduler.StopJobs(); err != nil {
		return err
	}
	return r.scheduler.Shutdown()
}
