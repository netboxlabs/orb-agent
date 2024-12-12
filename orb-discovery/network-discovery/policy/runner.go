package policy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/go-co-op/gocron/v2"
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-discovery/network-discovery/config"
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
	scheduler gocron.Scheduler
	ctx       context.Context
	task      gocron.Task
	client    diode.Client
	logger    *slog.Logger
	timeout   time.Duration
	scope     config.Scope
	config    config.PolicyConfig
}

// NewRunner returns a new policy runner
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client) (*Runner, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

	runner := &Runner{
		scheduler: s,
		client:    client,
		logger:    logger,
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
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(r.scope.Targets...),
		nmap.WithPingScan(),
		nmap.WithNonInteractive(),
	)
	if err != nil {
		r.logger.Error("error creating scanner", slog.Any("error", err), slog.Any("policy", r.ctx.Value(policyKey)))
		return
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		r.logger.Warn("run finished with warnings", slog.String("warnings", fmt.Sprintf("%v", *warnings)))
	}
	if err != nil {
		r.logger.Error("error running scanner", slog.Any("error", err), slog.Any("policy", r.ctx.Value(policyKey)))
		return
	}

	entities := make([]diode.Entity, 0, len(result.Hosts))

	for _, host := range result.Hosts {
		ip := &diode.IPAddress{
			Address: diode.String(host.Addresses[0].Addr + "/32"),
		}
		if r.config.Defaults["description"] != "" {
			ip.Description = diode.String(r.config.Defaults["description"])
		}
		if r.config.Defaults["comments"] != "" {
			ip.Comments = diode.String(r.config.Defaults["comments"])
		}
		entities = append(entities, ip)
	}

	resp, err := r.client.Ingest(r.ctx, entities)
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
	r.scheduler.Start()
}

// Stop stops the policy runner
func (r *Runner) Stop() error {
	if err := r.scheduler.StopJobs(); err != nil {
		return err
	}
	return r.scheduler.Shutdown()
}
