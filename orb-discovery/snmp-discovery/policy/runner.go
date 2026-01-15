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
	jobStore         *JobStore
}

// NewRunner returns a new policy runner
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client, ClientFactory snmp.ClientFactory, mappingConfig *config.Mapping, manufacturers data.ManufacturerRetriever, deviceLookup data.DeviceRetriever, jobStore *JobStore) (*Runner, error) {
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
		jobStore:      jobStore,
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
	runner.ctx = context.WithValue(ctx, policyKey, name)
	runner.scope = policy.Scope
	runner.config = policy.Config

	expandedTargets := runner.expandTargetRanges(runner.scope.Targets)

	for _, targets := range expandedTargets {
		if len(targets) == 1 {
			// Create scan task for single target
			task := gocron.NewTask(runner.run, targets[0])
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
		// Create scan task for multiple targets
		task := gocron.NewTask(runner.runScan, targets)
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

func (r *Runner) runScan(targets []config.Target) {
	policyName := r.ctx.Value(policyKey).(string)
	r.logger.Info("Starting SNMP probe scan", "policy", policyName, "targetCount", len(targets))
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
	var err error
	for _, target := range responsive {
		task := gocron.NewTask(r.run, target)
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
	r.logger.Info("SNMP probe scan complete", "policy", policyName, "responsiveTargetCount", len(responsive))
}

func (r *Runner) probeTarget(ctx context.Context, target config.Target) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	snmpClient, err := r.ClientFactory(target.Host, target.Port, 0, r.snmpProbeTimeout, &r.scope.Authentication, r.logger)
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

// run runs the policy
func (r *Runner) run(target config.Target) {
	policyName := r.ctx.Value(policyKey).(string)

	// Create job at start
	job := r.jobStore.CreateJob(policyName)

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

	entities := r.queryTarget(target)
	r.logger.Info("SNMP crawl complete", "host", target.Host, "policy", policyName, "entityCount", len(entities))

	if len(entities) == 0 {
		r.logger.Info("No entities to ingest", "host", target.Host, "policy", policyName)
		// Update job status to completed even if no entities
		r.jobStore.UpdateJob(policyName, job.ID, JobStatusCompleted, nil, 0)
		return
	}

	r.logEntitiesForIngestion(entities)

	resp, err := r.client.Ingest(ctx, entities, diode.WithIngestMetadata(diode.Metadata{
		"policy_name": policyName,
		"job_id":      job.ID,
	}))
	if err != nil {
		r.logger.Error("error ingesting entities", "host", target.Host, "error", err, "policy", policyName)
		r.jobStore.UpdateJob(policyName, job.ID, JobStatusFailed, err, len(entities))
	} else if resp != nil && resp.Errors != nil {
		ingestErr := fmt.Errorf("ingestion errors: %v", resp.Errors)
		r.logger.Error("error ingesting entities", "host", target.Host, "error", resp.Errors, "policy", policyName)
		r.jobStore.UpdateJob(policyName, job.ID, JobStatusFailed, ingestErr, len(entities))
	} else {
		r.logger.Info("entities ingested successfully", "host", target.Host, "policy", policyName)
		r.jobStore.UpdateJob(policyName, job.ID, JobStatusCompleted, nil, len(entities))
	}
}

func (r *Runner) logEntitiesForIngestion(entities []diode.Entity) {
	for _, entity := range entities {
		r.logger.Debug("Entity for ingestion", "entity", entity.ConvertToProtoMessage())
	}
}

func (r *Runner) queryTarget(target config.Target) []diode.Entity {
	mappingConfig, err := mapping.NewConfig(r.mappingConfig.Entries, r.logger, r.manufacturers, r.deviceLookup, &r.config.Defaults)
	if err != nil {
		r.logger.Error("Error creating mapping config", "error", err)
		return make([]diode.Entity, 0)
	}
	objectIDs := mappingConfig.ObjectIDs()
	r.logger.Info("Querying target", "target", target, "objectCount", len(objectIDs))

	entities := make([]diode.Entity, 0)

	mapper := mapping.NewObjectIDMapper(mappingConfig, r.logger, &r.config.Defaults)
	policyName := r.ctx.Value(policyKey).(string)
	// Track discovery attempt
	if rMetric := metrics.GetDiscoveryAttempts(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	// Start timing the discovery
	startTime := time.Now()

	host := snmp.NewHost(target.Host, target.Port, r.config.Retries, r.snmpTimeout, &r.scope.Authentication, r.logger, r.ClientFactory)
	oids, err := host.Walk(objectIDs)
	if err != nil {
		r.logger.Warn("Error crawling host", "host", target.Host, "error", err)
		// Track failed discovery
		if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
			policyName := r.ctx.Value(policyKey).(string)
			rMetric.Add(r.ctx, 1,
				metric.WithAttributes(
					attribute.String("policy", policyName),
					attribute.String("error", err.Error()),
				))
		}
		return entities
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

	entitiesForTarget := mapper.MapObjectIDsToEntity(oids)
	entities = append(entities, entitiesForTarget...)

	// Update discovered hosts gauge
	if rMetric := metrics.GetDiscoveredHosts(); rMetric != nil {
		rMetric.Record(r.ctx, int64(len(entitiesForTarget)),
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	return entities
}

func (r *Runner) expandTargetRanges(configuredTargets []config.Target) [][]config.Target {
	expandedMatrix := make([][]config.Target, 0, len(configuredTargets))
	for _, target := range configuredTargets {
		ips, err := targets.Expand(target.Host)
		if err != nil {
			r.logger.Warn("Error expanding target host", "host", target.Host, "error", err)
			continue
		}

		expandedTargets := make([]config.Target, len(ips))
		for i := range ips {
			expandedTargets[i] = config.Target{Host: ips[i], Port: target.Port}
		}
		expandedMatrix = append(expandedMatrix, expandedTargets)
	}
	return expandedMatrix
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
