package snmpdiscovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*snmpDiscoveryBackend)(nil)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	readinessBackoff    = 10
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	defaultExec         = "snmp-discovery"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "8070"
)

type snmpDiscoveryBackend struct {
	logger     *slog.Logger
	policyRepo policies.PolicyRepo
	exec       string

	apiHost     string
	apiPort     string
	apiProtocol string

	diodeTarget          string
	diodeClientID        string
	diodeClientSecret    string
	diodeAppNamePrefix   string
	diodeOtelEndpoint    string
	diodeDryRun          bool
	diodeDryRunOutputDir string
	diodeLogLevel        string

	startTime  time.Time
	proc       backend.Commander
	statusChan <-chan backend.CmdStatus
	cancelFunc context.CancelFunc
	ctx        context.Context
}

type info struct {
	Version   string  `json:"version"`
	UpTimeMin float64 `json:"up_time_seconds"`
}

// Register registers the snmp discovery backend
func Register() bool {
	backend.Register("snmp_discovery", &snmpDiscoveryBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

func (d *snmpDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons,
) error {
	d.logger = logger.With(slog.String("backend", "snmp_discovery"))
	d.policyRepo = repo

	var prs bool
	if d.apiHost, prs = config["host"].(string); !prs {
		d.apiHost = defaultAPIHost
	}
	if port, prs := config["port"]; prs {
		d.apiPort = fmt.Sprintf("%v", port)
	} else {
		d.apiPort = defaultAPIPort
	}

	d.diodeTarget = common.Diode.Target
	d.diodeClientID = common.Diode.ClientID
	d.diodeClientSecret = common.Diode.ClientSecret
	d.diodeAppNamePrefix = common.Diode.AgentName
	d.diodeDryRun = common.Diode.DryRun
	d.diodeDryRunOutputDir = common.Diode.DryRunOutputDir

	if target, prs := config["target"].(string); prs {
		d.diodeTarget = target
	}
	if clientID, prs := config["client_id"].(string); prs {
		d.diodeClientID = clientID
	}
	if clientSecret, prs := config["client_secret"].(string); prs {
		d.diodeClientSecret = clientSecret
	}
	if agentName, prs := config["agent_name"].(string); prs {
		d.diodeAppNamePrefix = agentName
	}
	if dryRun, prs := config["dry_run"].(bool); prs {
		d.diodeDryRun = dryRun
	}
	if dryRunOutputDir, prs := config["dry_run_output_dir"].(string); prs {
		d.diodeDryRunOutputDir = dryRunOutputDir
	}
	if logLevel, prs := config["log_level"].(string); prs {
		d.diodeLogLevel = logLevel
	} else if debug, prs := config["debug"].(bool); prs && debug {
		d.diodeLogLevel = "debug"
	}

	if common.Otlp.Grpc != "" {
		d.diodeOtelEndpoint = common.Otlp.Grpc
		d.logger.Info("snmp-discovery using OTLP metrics endpoint",
			slog.String("endpoint", d.diodeOtelEndpoint))
	}

	return nil
}

func (d *snmpDiscoveryBackend) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("snmp-discovery", d.proc, d.logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "detail")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

func (d *snmpDiscoveryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

	var pvOptions []string
	if d.diodeDryRun {
		pvOptions = []string{
			"--dry-run",
			"--dry-run-output-dir", d.diodeDryRunOutputDir,
			"--diode-app-name-prefix", d.diodeAppNamePrefix,
		}
	} else {
		pvOptions = []string{
			"--host", d.apiHost,
			"--port", d.apiPort,
			"--diode-target", d.diodeTarget,
			"--diode-client-id", d.diodeClientID,
			"--diode-client-secret", "********",
			"--diode-app-name-prefix", d.diodeAppNamePrefix,
		}
	}

	if d.diodeLogLevel != "" {
		pvOptions = append(pvOptions, "--log-level", d.diodeLogLevel)
		d.logger.Info("snmp-discovery using log level",
			slog.String("log_level", d.diodeLogLevel))
	}

	if d.diodeOtelEndpoint != "" {
		pvOptions = append(pvOptions, "--otel-endpoint", d.diodeOtelEndpoint)
		d.logger.Info("snmp-discovery using OTLP metrics endpoint",
			slog.String("endpoint", d.diodeOtelEndpoint))
	}

	d.logger.Info("snmp-discovery startup", slog.Any("arguments", pvOptions))

	if !d.diodeDryRun && len(pvOptions) > 9 {
		pvOptions[9] = d.diodeClientSecret
	}

	d.proc = backend.NewCmdOptions(backend.CmdOptions{
		Buffered:  false,
		Streaming: true,
	}, d.exec, pvOptions...)
	d.statusChan = d.proc.Start()

	// log STDOUT and STDERR lines streaming from Cmd
	doneChan := make(chan struct{})
	go func() {
		defer func() {
			if doneChan != nil {
				close(doneChan)
			}
		}()
		stdout := d.proc.GetStdout()
		stderr := d.proc.GetStderr()
		for stdout != nil || stderr != nil {
			select {
			case line, open := <-stdout:
				if !open {
					stdout = nil
					continue
				}
				d.logger.Info(line)
			case line, open := <-stderr:
				if !open {
					stderr = nil
					continue
				}
				d.logger.Error(line)
			}
		}
	}()

	// wait for simple startup errors
	time.Sleep(time.Second)

	status := d.proc.Status()

	if status.Error != nil {
		d.logger.Error("snmp-discovery startup error", slog.Any("error", status.Error))
		return status.Error
	}

	if status.Complete {
		err := d.proc.Stop()
		if err != nil {
			d.logger.Error("proc.Stop error", slog.Any("error", err))
		}
		return errors.New("snmp-discovery startup error, check log")
	}

	d.logger.Info("snmp-discovery process started", slog.Int("pid", status.PID))

	var version string
	var readinessErr error
	for backoff := 1; backoff <= readinessBackoff; backoff++ {
		if status := d.proc.Status(); status.Complete {
			err := d.proc.Stop()
			if err != nil {
				d.logger.Error("proc.Stop error", slog.Any("error", err))
			}
			return errors.New("snmp-discovery process ended unexpectedly, check log")
		}
		version, readinessErr = d.Version()
		if readinessErr == nil {
			d.logger.Info("snmp-discovery readiness ok, got version ",
				slog.String("network_discovery_version", version))
			break
		}
		backoffDuration := time.Duration(backoff) * time.Second
		d.logger.Info("snmp-discovery is not ready, trying again with backoff",
			slog.String("backoff backoffDuration", backoffDuration.String()))
		time.Sleep(backoffDuration)
	}

	if readinessErr != nil {
		d.logger.Error("snmp-discovery error on readiness", slog.Any("error", readinessErr))
		err := d.proc.Stop()
		if err != nil {
			d.logger.Error("proc.Stop error", slog.Any("error", err))
		}
		return readinessErr
	}

	return nil
}

func (d *snmpDiscoveryBackend) Stop(ctx context.Context) error {
	d.logger.Info("routine call to stop snmp-discovery", slog.Any("routine", ctx.Value(config.ContextKey("routine"))))
	defer d.cancelFunc()
	err := d.proc.Stop()
	finalStatus := <-d.statusChan
	if err != nil {
		d.logger.Error("snmp-discovery shutdown error", slog.Any("error", err))
	}
	d.logger.Info("snmp-discovery process stopped", slog.Int("pid", finalStatus.PID),
		slog.Int("exit_code", finalStatus.Exit))
	return nil
}

func (d *snmpDiscoveryBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(d.proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.logger.Error("failed to stop backend on restart procedure", slog.Any("error", err))
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "snmp-discovery"))
	// start it
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.logger.Error("failed to start backend on restart procedure", slog.Any("error", err))
		return err
	}
	return nil
}

func (d *snmpDiscoveryBackend) GetStartTime() time.Time {
	return d.startTime
}

func (d *snmpDiscoveryBackend) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("snmp-discovery", d.proc, d.logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

func (d *snmpDiscoveryBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	// first check process status
	runningStatus, errMsg, err := backend.GetRunningStatus(d.proc)
	// if it's not running, we're done
	if runningStatus != backend.Running {
		return runningStatus, errMsg, err
	}
	// if it's running, check REST API availability too
	if _, aiErr := d.Version(); aiErr != nil {
		// process is running, but REST API is not accessible
		return backend.BackendError, "process running, REST API unavailable", aiErr
	}
	return runningStatus, "", nil
}

func (d *snmpDiscoveryBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

func (d *snmpDiscoveryBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := d.RemovePolicy(data); err != nil {
			d.logger.Warn("policy failed to remove", slog.String("policy_id", data.ID),
				slog.String("policy_name", data.Name), slog.Any("error", err))
		}
	}

	d.logger.Debug("snmp-discovery policy apply", slog.String("policy_id", data.ID), slog.Any("data", data.Data))

	fullPolicy := map[string]any{
		"policies": map[string]any{
			data.Name: data.Data,
		},
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		d.logger.Warn("policy yaml marshal failure", slog.String("policy_id", data.ID), slog.String("policy_name", data.Name))
		return err
	}

	var resp map[string]any
	url := fmt.Sprintf("%s://%s:%s/api/v1/%s", d.apiProtocol, d.apiHost, d.apiPort, "policies")
	err = backend.CommonRequest("snmp-discovery", d.proc, d.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.logger.Warn("policy application failure", slog.String("policy_id", data.ID), slog.String("policy_name", data.Name))
		return err
	}

	return nil
}

func (d *snmpDiscoveryBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("snmp-discovery policy remove", slog.String("policy_id", data.ID))
	var resp any
	name := data.Name
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.apiProtocol, d.apiHost, d.apiPort, name)
	err := backend.CommonRequest("snmp-discovery", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}
