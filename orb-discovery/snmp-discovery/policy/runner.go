package policy

import (
	"context"
	"log/slog"
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
	policyKey          contextKey = "policy"
	defaultTimeout                = 2 * time.Minute
	defaultSNMPTimeout            = 5 * time.Second
)

// Runner represents the policy runner
type Runner struct {
	scheduler     gocron.Scheduler
	ctx           context.Context
	task          gocron.Task
	client        diode.Client
	logger        *slog.Logger
	timeout       time.Duration
	snmpTimeout   time.Duration
	scope         config.Scope
	config        config.PolicyConfig
	ClientFactory snmp.ClientFactory
	manufacturers data.ManufacturerRetriever
	mappingConfig *config.Mapping
	deviceLookup  data.DeviceRetriever
}

// NewRunner returns a new policy runner
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client, ClientFactory snmp.ClientFactory, mappingConfig *config.Mapping, manufacturers data.ManufacturerRetriever, deviceLookup data.DeviceRetriever) (*Runner, error) {
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
	}

	runner.task = gocron.NewTask(runner.run)
	if policy.Config.Schedule != nil {
		_, err = runner.scheduler.NewJob(gocron.CronJob(*policy.Config.Schedule, false), runner.task, gocron.WithSingletonMode(gocron.LimitModeReschedule))
	} else {
		_, err = runner.scheduler.NewJob(gocron.OneTimeJob(
			gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), runner.task, gocron.WithSingletonMode(gocron.LimitModeReschedule))
	}
	if err != nil {
		return nil, err
	}
	runner.timeout = time.Duration(policy.Config.Timeout) * time.Second
	if runner.timeout == 0 {
		runner.timeout = defaultTimeout
	}
	runner.snmpTimeout = time.Duration(policy.Config.SNMPTimeout) * time.Second
	if runner.snmpTimeout == 0 {
		runner.snmpTimeout = defaultSNMPTimeout
	}
	runner.ctx = context.WithValue(ctx, policyKey, name)
	runner.scope = policy.Scope
	runner.config = policy.Config
	return runner, nil
}

// run runs the policy
func (r *Runner) run() {
	policyName := r.ctx.Value(policyKey).(string)
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

	r.logger.Info("Starting SNMP crawl of targets", slog.Any("targetCount", len(r.scope.Targets)))

	// Expand all targets
	expandedTargets := r.expandTargetRanges(r.scope.Targets)

	entities := r.queryTargets(expandedTargets)
	r.logger.Info("SNMP crawl complete", slog.Any("policy", r.ctx.Value(policyKey)), slog.Any("entityCount", len(entities)))

	if len(entities) == 0 {
		r.logger.Info("No entities to ingest", slog.Any("policy", r.ctx.Value(policyKey)))
		return
	}

	r.logEntitiesForIngestion(entities)

	resp, err := r.client.Ingest(ctx, entities, diode.WithIngestMetadata(diode.Metadata{
		"policy_name": policyName,
	}))
	if err != nil {
		r.logger.Error("error ingesting entities", slog.Any("error", err), slog.Any("policy", r.ctx.Value(policyKey)))
	} else if resp != nil && resp.Errors != nil {
		r.logger.Error("error ingesting entities", slog.Any("error", resp.Errors), slog.Any("policy", r.ctx.Value(policyKey)))
	} else {
		r.logger.Info("entities ingested successfully", slog.Any("policy", r.ctx.Value(policyKey)))
	}
}

func (r *Runner) logEntitiesForIngestion(entities []diode.Entity) {
	for _, entity := range entities {
		r.logger.Debug("Entity for ingestion", slog.Any("entity", entity.ConvertToProtoMessage()))
	}
}

func (r *Runner) queryTargets(expandedTargets []config.Target) []diode.Entity {
	mappingConfig := mapping.NewConfig(r.mappingConfig.Entries, r.logger, r.manufacturers, r.deviceLookup)
	objectIDs := mappingConfig.ObjectIDs()
	r.logger.Info("Querying targets", slog.Any("targetCount", len(expandedTargets)), slog.Any("objectCount", len(objectIDs)))

	entities := make([]diode.Entity, 0)

	for _, target := range expandedTargets {
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
			continue
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
	}
	return entities
}

func (r *Runner) expandTargetRanges(configuredTargets []config.Target) []config.Target {
	var expandedTargets []config.Target
	for _, target := range configuredTargets {
		ips, err := targets.Expand(target.Host)
		if err != nil {
			r.logger.Warn("Error expanding target host", "host", target.Host, "error", err)
			continue
		}
		for _, ip := range ips {
			expandedTargets = append(expandedTargets, config.Target{
				Host: ip,
				Port: target.Port,
			})
		}
	}
	return expandedTargets
}

// Start starts the policy runner
func (r *Runner) Start() {
	r.logger.Info("Starting policy runner", slog.Any("policy", r.ctx.Value(policyKey)))
	r.scheduler.Start()
}

// Stop stops the policy runner
func (r *Runner) Stop() error {
	if err := r.scheduler.StopJobs(); err != nil {
		return err
	}
	return r.scheduler.Shutdown()
}
