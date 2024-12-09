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
const policyKey contextKey = "policy"

// Runner represents the policy runner
type Runner struct {
	scanner   *nmap.Scanner
	scheduler gocron.Scheduler
	ctx       context.Context
	cancel    context.CancelFunc
	task      gocron.Task
	client    diode.Client
	logger    *slog.Logger
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
	timeout := time.Duration(policy.Scope.Timeout) * time.Minute
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	runner.ctx = context.WithValue(ctx, policyKey, name)
	runner.ctx, runner.cancel = context.WithTimeout(runner.ctx, timeout)
	n, err := nmap.NewScanner(
		runner.ctx,
		nmap.WithTargets(policy.Scope.Targets...),
		nmap.WithPingScan(),
		nmap.WithNonInteractive(),
	)
	if err != nil {
		return nil, err
	}
	runner.scanner = n

	return runner, nil
}

// run runs the policy
func (r *Runner) run() error {
	defer r.cancel()
	result, warnings, err := r.scanner.Run()
	if len(*warnings) > 0 {
		r.logger.Warn("run finished with warnings", slog.String("warnings", fmt.Sprintf("%v", *warnings)))
	}
	if err != nil {
		return err
	}

	entities := make([]diode.Entity, 0, len(result.Hosts))

	for _, host := range result.Hosts {
		ip := &diode.IPAddress{
			Address: diode.String(host.Addresses[0].Addr + "/32"),
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

	return nil
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
