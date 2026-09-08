package snmpdiscovery

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

var _ backend.Backend = (*snmpDiscoveryBackend)(nil)

const (
	versionTimeout          = 2
	capabilitiesTimeout     = 5
	applyPolicyTimeout      = 10
	removePolicyTimeout     = 20
	statusTimeout           = 5
	defaultExec             = "snmp-discovery"
	defaultAPIHost          = "localhost"
	defaultAPIPort          = "8070"
	defaultIngestBufferSize = 512
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
	diodeTargetFromOtel  bool
	diodeDryRun          bool
	diodeDryRunOutputDir string
	diodeLogLevel        string
	ingestBufferSize     int

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

func parseIngestBufferSize(v any) (int, error) {
	var n int

	switch val := v.(type) {
	case int:
		n = val
	case int64:
		n = int(val)
	case float64:
		if val != float64(int64(val)) {
			return 0, fmt.Errorf("ingest_buffer_size must be a whole number, got %v", val)
		}
		n = int(val)
	case string:
		parsed, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("ingest_buffer_size: invalid integer %q: %w", val, err)
		}
		n = parsed
	default:
		return 0, fmt.Errorf("ingest_buffer_size must be an integer, got %T", v)
	}

	if n < 1 {
		return 0, fmt.Errorf("ingest_buffer_size must be >= 1, got %d", n)
	}

	return n, nil
}

func (d *snmpDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.logger = logger.With("backend", "snmp_discovery")
	d.policyRepo = repo
	d.diodeTargetFromOtel = false

	d.apiHost = backend.ConfigValueOrDefault(config, "host", defaultAPIHost)
	d.apiPort = backend.ConfigValueOrDefault(config, "port", defaultAPIPort)

	d.ingestBufferSize = defaultIngestBufferSize
	if v, prs := config["ingest_buffer_size"]; prs {
		size, err := parseIngestBufferSize(v)
		if err != nil {
			return fmt.Errorf("snmp_discovery: %w", err)
		}
		d.ingestBufferSize = size
	}

	d.diodeTarget = backend.ConfigValueOrDefault(config, "target", common.Diode.Target)
	d.diodeClientID = backend.ConfigValueOrDefault(config, "client_id", common.Diode.ClientID)
	d.diodeClientSecret = backend.ConfigValueOrDefault(config, "client_secret", common.Diode.ClientSecret)
	d.diodeAppNamePrefix = backend.ConfigValueOrDefault(config, "agent_name", common.Diode.AgentName)
	d.diodeDryRun = backend.ConfigValueOrDefault(config, "dry_run", common.Diode.DryRun)
	d.diodeDryRunOutputDir = backend.ConfigValueOrDefault(config, "dry_run_output_dir", common.Diode.DryRunOutputDir)

	if logLevel, prs := config["log_level"].(string); prs {
		d.diodeLogLevel = logLevel
	} else if debug, prs := config["debug"].(bool); prs && debug {
		d.diodeLogLevel = "debug"
	} else if logger.Enabled(context.Background(), slog.LevelDebug) {
		d.diodeLogLevel = "debug"
	}

	if common.Otlp.Grpc != "" {
		d.diodeOtelEndpoint = common.Otlp.Grpc
		d.logger.Info("snmp-discovery using OTLP metrics endpoint",
			"endpoint", d.diodeOtelEndpoint)
	}
	if d.diodeTarget == "" && d.diodeOtelEndpoint != "" {
		d.diodeTarget = d.diodeOtelEndpoint
		d.diodeTargetFromOtel = true
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

func (d *snmpDiscoveryBackend) buildArgs() []string {
	dOptions := []string{
		"--diode-app-name-prefix", d.diodeAppNamePrefix,
		"--host", d.apiHost,
		"--port", d.apiPort,
		"--ingest-buffer-size", fmt.Sprintf("%d", d.ingestBufferSize),
	}
	if d.diodeDryRun {
		dOptions = append([]string{
			"--dry-run",
			"--dry-run-output-dir", d.diodeDryRunOutputDir,
		}, dOptions...)
	} else {
		opts := []string{
			"--diode-target", d.diodeTarget,
		}
		if !d.diodeTargetFromOtel {
			opts = append(opts,
				"--diode-client-id", d.diodeClientID,
				"--diode-client-secret", d.diodeClientSecret,
			)
		}
		dOptions = append(opts, dOptions...)
	}

	if d.diodeLogLevel != "" {
		dOptions = append(dOptions, "--log-level", d.diodeLogLevel)
		d.logger.Info("snmp-discovery using log level",
			"log_level", d.diodeLogLevel)
	}

	if d.diodeOtelEndpoint != "" {
		dOptions = append(dOptions, "--otel-endpoint", d.diodeOtelEndpoint)
		d.logger.Info("snmp-discovery using OTLP endpoint",
			"endpoint", d.diodeOtelEndpoint)
	}

	return dOptions
}

func (d *snmpDiscoveryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

	args := d.buildArgs()

	d.logger.Info("snmp-discovery startup", "arguments", redact.Args(args))

	return backend.StartProcess(backend.StartSpec{
		Logger:         d.logger,
		NameDisplay:    "snmp-discovery",
		NameUnderscore: "snmp_discovery",
		Exec:           d.exec,
		Args:           args,
		LogLine:        d.logLineAdapter,
		SetProc: func(p backend.Commander, ch <-chan backend.CmdStatus) {
			d.proc = p
			d.statusChan = ch
		},
		ReadinessCheck: d.Version,
	})
}

// logLineAdapter routes a streamed stdout/stderr line to the snmp-discovery
// output normalizer with the level matching the source stream.
func (d *snmpDiscoveryBackend) logLineAdapter(line string, isStderr bool) {
	fallback := slog.LevelInfo
	if isStderr {
		fallback = slog.LevelError
	}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}

	msg := trimmed
	attrs := []slog.Attr(nil)
	level := fallback

	if parsedMsg, parsedAttrs, parsedLevel, ok := backend.NormalizeLogfmtLine(trimmed, fallback); ok {
		msg = parsedMsg
		attrs = parsedAttrs
		level = parsedLevel
	}

	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	d.logger.LogAttrs(ctx, level, msg, attrs...)
}

func (d *snmpDiscoveryBackend) Stop(ctx context.Context) error {
	d.logger.Info("routine call to stop snmp-discovery", "routine", ctx.Value(config.ContextKey("routine")))
	defer d.cancelFunc()
	backend.StopProcess(d.logger, d.proc, d.statusChan, backend.DefaultStopGracePeriod, "snmp_discovery")
	return nil
}

func (d *snmpDiscoveryBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(d.proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "snmp-discovery"))
	// start it
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.logger.Error("failed to start backend on restart procedure", "error", err)
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
			d.logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	d.logger.Debug("snmp-discovery policy apply", "policy_id", data.ID, "data", data.Data)

	fullPolicy := map[string]any{
		"policies": map[string]any{
			data.Name: data.Data,
		},
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		d.logger.Warn("policy yaml marshal failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	var resp map[string]any
	url := fmt.Sprintf("%s://%s:%s/api/v1/%s", d.apiProtocol, d.apiHost, d.apiPort, "policies")
	err = backend.CommonRequest("snmp-discovery", d.proc, d.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.logger.Warn("policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

func (d *snmpDiscoveryBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("snmp-discovery policy remove", "policy_id", data.ID)
	var resp any
	name := data.Name
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	}
	segment, err := backend.PolicyPathSegment(name)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.apiProtocol, d.apiHost, d.apiPort, segment)
	err = backend.CommonRequest("snmp-discovery", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}

func (d *snmpDiscoveryBackend) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	var resp backend.StatusResponse
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("snmp-discovery", d.proc, d.logger, url, &resp, http.MethodGet,
		http.NoBody, "application/json", statusTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return resp.Policies, nil
}
