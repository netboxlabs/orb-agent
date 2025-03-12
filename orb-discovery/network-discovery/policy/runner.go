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

	var options []nmap.Option

	if len(r.scope.Ports) > 0 {
		nmap.WithPorts(r.scope.Ports...)
	}

	if len(r.scope.ExcludePorts) > 0 {
		nmap.WithPortExclusions(r.scope.ExcludePorts...)
	}

	if r.scope.FastMode != nil && *r.scope.FastMode {
		options = append(options, nmap.WithFastMode())
	}

	if r.scope.Timing != nil {
		options = append(options, nmap.WithTimingTemplate(nmap.Timing(*r.scope.Timing)))
	}

	if r.scope.TopPorts != nil {
		options = append(options, nmap.WithMostCommonPorts(*r.scope.TopPorts))
	}

	hasOtherScans := false
	selectedTCPScan := ""
	if len(r.scope.ScanTypes) > 0 {
		privilegedScans := map[string]func() nmap.Option{
			"udp":              nmap.WithUDPScan,
			"sctp_init":        nmap.WithSCTPInitScan,
			"sctp_cookie_echo": nmap.WithSCTPCookieEchoScan,
			"ip_protocol":      nmap.WithIPProtocolScan,
		}

		tcpScans := map[string]func() nmap.Option{
			"connect": nmap.WithConnectScan,
			"syn":     nmap.WithSYNScan,
			"ack":     nmap.WithACKScan,
			"window":  nmap.WithWindowScan,
			"null":    nmap.WithTCPNullScan,
			"fin":     nmap.WithTCPFINScan,
			"xmas":    nmap.WithTCPXmasScan,
			"maimon":  nmap.WithMaimonScan,
		}

		for _, scanType := range r.scope.ScanTypes {
			if fn, exists := tcpScans[scanType]; exists {
				if selectedTCPScan == "" { // Pick only one TCP scan
					options = append(options, fn())
					selectedTCPScan = scanType
					if scanType != "connect" {
						hasOtherScans = true
					}
				} else {
					r.logger.Warn("Skipping additional TCP scan due to conflict", "skipped_scan", scanType,
						"selected_scan", selectedTCPScan, slog.Any("policy", r.ctx.Value(policyKey)))

				}
			} else if fn, exists := privilegedScans[scanType]; exists {
				options = append(options, fn())
				hasOtherScans = true
			}
		}

		if hasOtherScans {
			options = append(options, nmap.WithPrivileged())
		}
	}

	if r.scope.MaxRetries != nil {
		options = append(options, nmap.WithMaxRetries(*r.scope.MaxRetries))
	}

	if r.scope.PingScan != nil && *r.scope.PingScan {
		if hasOtherScans || selectedTCPScan != "" {
			r.logger.Warn("Skipping ping scan because it is not valid with any other scan types",
				slog.Any("policy", r.ctx.Value(policyKey)))
		} else {
			options = append(options, nmap.WithPingScan())
		}
	}

	if len(options) == 0 {
		r.logger.Info("no custom options set, using ping scan (icmp)", slog.Any("policy", r.ctx.Value(policyKey)))
		options = append(options, nmap.WithPingScan())
	}
	options = append(options, nmap.WithNonInteractive())
	options = append(options, nmap.WithTargets(r.scope.Targets...))

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		r.logger.Error("error creating scanner", slog.Any("error", err), slog.Any("policy", r.ctx.Value(policyKey)))
		return
	}
	r.logger.Info("running scanner", slog.Any("targets", r.scope.Targets), slog.Any("policy", r.ctx.Value(policyKey)))
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
		if r.config.Defaults.Description != "" {
			ip.Description = diode.String(r.config.Defaults.Description)
		}
		if r.config.Defaults.Comments != "" {
			ip.Comments = diode.String(r.config.Defaults.Comments)
		}
		if len(r.config.Defaults.Tags) > 0 {
			var tags []*diode.Tag
			for _, tag := range r.config.Defaults.Tags {
				tags = append(tags, &diode.Tag{Name: diode.String(tag)})
			}
			ip.Tags = tags
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
