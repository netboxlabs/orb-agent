package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/go-co-op/gocron/v2"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-discovery/network-discovery/metrics"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Define a custom type for the context key
type contextKey string

// Define the policy key
const (
	policyKey      contextKey = "policy"
	defaultTimeout            = 2 * time.Minute
)

// targetInfo stores information about each target
type targetInfo struct {
	original string
	network  *net.IPNet
	mask     string
}

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
	targets   []targetInfo
}

// parseTargets parses the target specifications and returns targetInfo slice
func parseTargets(targets []string) []targetInfo {
	var result []targetInfo
	for _, target := range targets {
		if strings.Contains(target, "/") {
			info := targetInfo{original: target}
			_, network, err := net.ParseCIDR(target)
			if err == nil {
				info.network = network
				maskBits, _ := network.Mask.Size()
				info.mask = fmt.Sprintf("/%d", maskBits)
				result = append(result, info)
			}
		}
	}
	return result
}

// getIPWithMask returns the IP address with the appropriate mask based on the most specific target network
func (r *Runner) getIPWithMask(ipStr string, defaultMask string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr + defaultMask
	}

	var bestTarget *targetInfo
	var bestMask int
	for _, target := range r.targets {
		if target.network.Contains(ip) {
			maskBits, _ := target.network.Mask.Size()
			if bestTarget == nil || maskBits > bestMask {
				bestTarget = &target
				bestMask = maskBits
			}
		}
	}
	if bestTarget != nil {
		return ipStr + bestTarget.mask
	}
	return ipStr + defaultMask
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

	runner.targets = parseTargets(policy.Scope.Targets)

	return runner, nil
}

// run runs the policy
func (r *Runner) run() {
	policyName := r.ctx.Value(policyKey).(string)
	if rMetric := metrics.GetPolicyExecutions(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", policyName),
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

	var options []nmap.Option

	if len(r.scope.Ports) > 0 {
		options = append(options, nmap.WithPorts(r.scope.Ports...))
	}

	if len(r.scope.ExcludePorts) > 0 {
		options = append(options, nmap.WithPortExclusions(r.scope.ExcludePorts...))
	}

	if len(r.scope.DNSServers) > 0 {
		options = append(options, nmap.WithCustomDNSServers(r.scope.DNSServers...))
	}

	if r.scope.OSDetection != nil && *r.scope.OSDetection {
		options = append(options, nmap.WithOSDetection())
		options = append(options, nmap.WithPrivileged())
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

	if r.scope.ICMPEcho != nil && *r.scope.ICMPEcho {
		options = append(options, nmap.WithICMPEchoDiscovery())
	}

	if r.scope.ICMPTimestamp != nil && *r.scope.ICMPTimestamp {
		options = append(options, nmap.WithICMPTimestampDiscovery())
	}

	if r.scope.ICMPNetMask != nil && *r.scope.ICMPNetMask {
		options = append(options, nmap.WithICMPNetMaskDiscovery())
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
						"selected_scan", selectedTCPScan, slog.String("policy", policyName))
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
				slog.String("policy", policyName))
		} else {
			options = append(options, nmap.WithPingScan())
		}
	}

	options = append(options, nmap.WithNonInteractive())
	options = append(options, nmap.WithTargets(r.scope.Targets...))

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		r.logger.Error("error creating scanner", slog.Any("error", err), slog.String("policy", policyName))
		if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
			rMetric.Add(r.ctx, 1,
				metric.WithAttributes(
					attribute.String("policy", policyName),
					attribute.String("error", err.Error()),
				))
		}
		return
	}
	r.logger.Info("running scanner", slog.Any("targets", r.scope.Targets), slog.String("policy", policyName))
	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		r.logger.Warn("run finished with warnings", slog.String("warnings", fmt.Sprintf("%v", *warnings)))
	}
	if err != nil {
		r.logger.Error("error running scanner", slog.Any("error", err), slog.String("policy", policyName))
		if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
			rMetric.Add(r.ctx, 1,
				metric.WithAttributes(
					attribute.String("policy", policyName),
					attribute.String("error", err.Error()),
				))
		}
		return
	}

	// Record success count with host count attribute
	if rMetric := metrics.GetDiscoverySuccess(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", policyName),
			))
	}

	// Record discovered hosts as a dedicated gauge metric
	if hMetric := metrics.GetDiscoveredHosts(); hMetric != nil {
		hMetric.Record(r.ctx, int64(len(result.Hosts)),
			metric.WithAttributes(
				attribute.String("policy", policyName),
			))
	}

	entities := make([]diode.Entity, 0, len(result.Hosts))
	if len(result.Hosts) == 0 {
		r.logger.Warn("discovery complete: no hosts found", slog.Any("targets", r.scope.Targets),
			slog.String("policy", policyName))
		return
	}
	r.logger.Info("discovery complete", slog.Int("hosts_found", len(result.Hosts)), slog.String("policy", policyName))

	// Track discovered hosts
	processedEntries := make(map[string]bool)

	defaultMask := "/32"
	if r.config.Defaults.NetworkMask != nil && *r.config.Defaults.NetworkMask > 0 {
		defaultMask = fmt.Sprintf("/%d", *r.config.Defaults.NetworkMask)
	}

	for _, host := range result.Hosts {
		r.logger.Debug("processing host", slog.Any("host_address", host.Addresses), slog.Any("host_ports", host.Ports),
			slog.Any("host_hostnames", host.Hostnames), slog.String("policy", policyName))
		if len(host.Addresses) == 0 {
			continue
		}

		addr := host.Addresses[0].Addr
		if _, exists := processedEntries[addr]; exists {
			r.logger.Info("skipping already processed IP address", slog.String("ip_address", addr), slog.String("policy", policyName))
			continue
		}

		var ipAddr string
		if r.scope.UseTargetMasks != nil && !*r.scope.UseTargetMasks {
			ipAddr = addr + defaultMask
		} else {
			ipAddr = r.getIPWithMask(addr, defaultMask)
		}
		processedEntries[addr] = true

		ip := &diode.IPAddress{
			Address: diode.String(ipAddr),
		}
		if r.config.Defaults.Description != "" {
			ip.Description = diode.String(r.config.Defaults.Description)
		}
		hasComments := false
		if r.config.Defaults.Comments != "" {
			hasComments = true
			ip.Comments = diode.String(r.config.Defaults.Comments)
		}
		if r.config.Defaults.Vrf != "" {
			ip.Vrf = &diode.VRF{
				Name: diode.String(r.config.Defaults.Vrf),
				Rd:   diode.String(r.config.Defaults.Vrf),
			}
		}
		if r.config.Defaults.Tenant != "" {
			ip.Tenant = &diode.Tenant{
				Name: diode.String(r.config.Defaults.Tenant),
			}
		}
		if r.config.Defaults.Role != "" {
			ip.Role = diode.String(r.config.Defaults.Role)
		}
		if len(r.config.Defaults.Tags) > 0 {
			var tags []*diode.Tag
			for _, tag := range r.config.Defaults.Tags {
				tags = append(tags, &diode.Tag{Name: diode.String(tag)})
			}
			ip.Tags = tags
		}

		if host.Hostnames != nil {
			var fallbackHostname string
			for _, hostname := range host.Hostnames {
				fallbackHostname = strings.ToLower(hostname.Name)
				if hostname.Type == "PTR" {
					ip.DnsName = diode.String(strings.ToLower(hostname.Name))
					break
				}
			}
			if ip.DnsName == nil && fallbackHostname != "" {
				ip.DnsName = diode.String(fallbackHostname)
			}
		}

		if !hasComments {
			var metadata config.HostMetadata

			if host.ExtraPorts != nil {
				metadata.ExtraPorts = make([]config.ExtraPort, len(host.ExtraPorts))
				for i, extraPort := range host.ExtraPorts {
					metadata.ExtraPorts[i] = config.ExtraPort{
						State: extraPort.State,
						Count: extraPort.Count,
					}
				}
			}
			if host.Ports != nil {
				metadata.Ports = make([]config.Port, len(host.Ports))
				for i, port := range host.Ports {
					metadata.Ports[i] = config.Port{
						Number:   int(port.ID),
						Protocol: port.Protocol,
						Service:  port.Service.Name,
						State:    port.State.State,
					}
				}
			}
			data, err := json.Marshal(&metadata)
			if err != nil {
				r.logger.Error("error marshalling metadata", slog.Any("error", err), slog.String("policy", policyName))
			} else {
				ip.Comments = diode.String(string(data))
			}
		}

		entities = append(entities, ip)
	}

	resp, err := r.client.Ingest(r.ctx, entities)
	if err != nil {
		r.logger.Error("error ingesting entities", slog.Any("error", err), slog.String("policy", policyName))
	} else if resp != nil && resp.Errors != nil {
		r.logger.Error("error ingesting entities", slog.Any("error", resp.Errors), slog.String("policy", policyName))
	} else {
		r.logger.Info("entities ingested successfully", slog.String("policy", policyName))
	}
}

// Start starts the policy runner
func (r *Runner) Start() {
	if rMetric := metrics.GetActivePolicies(); rMetric != nil {
		rMetric.Add(r.ctx, 1)
	}
	r.scheduler.Start()
}

// Stop stops the policy runner
func (r *Runner) Stop() error {
	if err := r.scheduler.StopJobs(); err != nil {
		return err
	}
	if rMetric := metrics.GetActivePolicies(); rMetric != nil {
		rMetric.Add(r.ctx, -1)
	}
	return r.scheduler.Shutdown()
}
