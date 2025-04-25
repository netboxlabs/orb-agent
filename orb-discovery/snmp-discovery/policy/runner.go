package policy

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
)

// Define a custom type for the context key
type contextKey string

// Define the policy key
const (
	policyKey      contextKey = "policy"
	defaultTimeout            = 2 * time.Minute
)

// Runner represents the policy runner
type Runner struct {
	scheduler         gocron.Scheduler
	ctx               context.Context
	task              gocron.Task
	client            diode.Client
	logger            *slog.Logger
	timeout           time.Duration
	scope             config.Scope
	config            config.PolicyConfig
	snmpClientFactory func(host string) snmp.Walker
}

// NewRunner returns a new policy runner
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client, snmpClientFactory func(host string) snmp.Walker) (*Runner, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

	runner := &Runner{
		scheduler:         s,
		client:            client,
		logger:            logger,
		snmpClientFactory: snmpClientFactory,
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
	runner.timeout = time.Duration(policy.Config.Timeout) * time.Minute
	if runner.timeout == 0 {
		runner.timeout = defaultTimeout
	}
	runner.ctx = context.WithValue(ctx, policyKey, name)
	runner.scope = policy.Scope
	runner.config = policy.Config
	return runner, nil
}

// run runs the policy
func (r *Runner) run() {
	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()

	r.logger.Info("Starting SNMP crawl...")
	mapper := snmp.NewObjectIDMapper()
	entities := make([]diode.Entity, 0)

	for _, target := range r.scope.Targets {
		host := snmp.NewHost(target, r.logger, r.snmpClientFactory, mapper.ObjectIDs())
		oids, err := host.Walk(target)
		if err != nil {
			r.logger.Warn("Error crawling host", "ip", target, "error", err)
			continue
		}
		entitiesForTarget := mapper.MapObjectIDsToEntity(oids)
		entities = append(entities, entitiesForTarget...)
	}
	r.logger.Info("SNMP crawl complete.")

	resp, err := r.client.Ingest(ctx, entities)
	if err != nil {
		r.logger.Error("error ingesting entities", slog.Any("error", err), slog.Any("policy", r.ctx.Value(policyKey)))
	} else if resp != nil && resp.Errors != nil {
		r.logger.Error("error ingesting entities", slog.Any("error", resp.Errors), slog.Any("policy", r.ctx.Value(policyKey)))
	} else {
		r.logger.Info("entities ingested successfully", slog.Any("policy", r.ctx.Value(policyKey)))
	}
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
