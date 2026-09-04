package devicediscovery

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

var _ backend.Backend = (*deviceDiscoveryBackend)(nil)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	statusTimeout       = 5
	defaultExec         = "device-discovery"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "8072"
)

type deviceDiscoveryBackend struct {
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

	startTime  time.Time
	proc       backend.Commander
	statusChan <-chan backend.CmdStatus
	cancelFunc context.CancelFunc
	ctx        context.Context
}

type info struct {
	Version   string  `json:"version"`
	UpTimeMin float64 `json:"up_time_min"`
}

// Register registers the backend
func Register() bool {
	backend.Register("device_discovery", &deviceDiscoveryBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

func (d *deviceDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.logger = logger.With("backend", "device_discovery")
	d.policyRepo = repo
	d.diodeTargetFromOtel = false

	d.apiHost = backend.ConfigValueOrDefault(config, "host", defaultAPIHost)
	d.apiPort = backend.ConfigValueOrDefault(config, "port", defaultAPIPort)

	d.diodeTarget = backend.ConfigValueOrDefault(config, "target", common.Diode.Target)
	d.diodeClientID = backend.ConfigValueOrDefault(config, "client_id", common.Diode.ClientID)
	d.diodeClientSecret = backend.ConfigValueOrDefault(config, "client_secret", common.Diode.ClientSecret)
	d.diodeAppNamePrefix = backend.ConfigValueOrDefault(config, "agent_name", common.Diode.AgentName)
	d.diodeDryRun = backend.ConfigValueOrDefault(config, "dry_run", common.Diode.DryRun)
	d.diodeDryRunOutputDir = backend.ConfigValueOrDefault(config, "dry_run_output_dir", common.Diode.DryRunOutputDir)

	// Precedence: explicit log_level > per-backend debug: true > the agent
	// itself running in debug mode. A non-string log_level (YAML
	// `log_level: 3`) falls through the type assertion and cannot panic.
	//
	// The third branch deliberately reads common.Debug rather than
	// logger.Enabled(ctx, slog.LevelDebug), which is what the other three
	// discovery backends currently do. logger.Enabled is not a reliable proxy
	// for debug mode here: when orb.backends.common.otlp.grpc is set,
	// agent.go:165-166 replaces the agent logger with a telemetry.multiHandler
	// wrapping both the console handler and the otelslog handler. multiHandler
	// ORs Enabled across its handlers (telemetry/logs.go:52-59) and the
	// otelslog handler applies no level filter, so Enabled(Debug) is true
	// whenever OTLP log export is enabled -- with or without -d. That would
	// silently start device-discovery at DEBUG and export the full traceback
	// plus napalm/netmiko/paramiko/ncclient chatter to the collector.
	//
	// common.Debug is the explicit state: agent.go:160 sets it from a.debug,
	// which cmd/main.go:95 derives as debugFlag || cfg.OrbAgent.Debug.Enable.
	// The same fix is owed to networkdiscovery, snmpdiscovery and
	// gnmidiscovery; tracked separately.
	if logLevel, prs := config["log_level"].(string); prs {
		d.diodeLogLevel = logLevel
	} else if debug, prs := config["debug"].(bool); prs && debug {
		d.diodeLogLevel = "debug"
	} else if common.Debug {
		d.diodeLogLevel = "debug"
	}

	if common.Otlp.Grpc != "" {
		d.diodeOtelEndpoint = common.Otlp.Grpc
		d.logger.Info("device-discovery using OTLP endpoint",
			"endpoint", d.diodeOtelEndpoint)
	}
	if d.diodeTarget == "" && d.diodeOtelEndpoint != "" {
		d.diodeTarget = d.diodeOtelEndpoint
		d.diodeTargetFromOtel = true
	}

	return nil
}

func (d *deviceDiscoveryBackend) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("device-discovery", d.proc, d.logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "detail")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

func (d *deviceDiscoveryBackend) buildArgs() []string {
	dOptions := []string{
		"--diode-app-name-prefix", d.diodeAppNamePrefix,
		"--host", d.apiHost,
		"--port", d.apiPort,
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
		d.logger.Info("device-discovery using log level",
			"log_level", d.diodeLogLevel)
	}

	if d.diodeOtelEndpoint != "" {
		dOptions = append(dOptions, "--otel-endpoint", d.diodeOtelEndpoint)
	}

	return dOptions
}

func (d *deviceDiscoveryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

	args := d.buildArgs()

	d.logger.Info("device-discovery startup", "arguments", redact.Args(args))

	return backend.StartProcess(backend.StartSpec{
		Logger:         d.logger,
		NameDisplay:    "device-discovery",
		NameUnderscore: "device_discovery",
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

// logLineAdapter routes a streamed stdout/stderr line to the device-discovery
// output normalizer with the level matching the source stream.
func (d *deviceDiscoveryBackend) logLineAdapter(line string, isStderr bool) {
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

	if parsedMsg, parsedAttrs, parsedLevel, ok := normalizeDeviceDiscoveryLine(trimmed, fallback); ok {
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

func (d *deviceDiscoveryBackend) Stop(ctx context.Context) error {
	d.logger.Info("routine call to stop device-discovery", "routine", ctx.Value(config.ContextKey("routine")))
	defer d.cancelFunc()
	backend.StopProcess(d.logger, d.proc, d.statusChan, backend.DefaultStopGracePeriod, "device_discovery")
	return nil
}

func (d *deviceDiscoveryBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(d.proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "device-discovery"))
	// start it
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.logger.Error("failed to start backend on restart procedure", "error", err)
		return err
	}
	return nil
}

func (d *deviceDiscoveryBackend) GetStartTime() time.Time {
	return d.startTime
}

func (d *deviceDiscoveryBackend) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("device-discovery", d.proc, d.logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

func (d *deviceDiscoveryBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
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

func (d *deviceDiscoveryBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

func (d *deviceDiscoveryBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := d.RemovePolicy(data); err != nil {
			d.logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	d.logger.Debug("device-discovery policy apply", "policy_id", data.ID, "data", data.Data)

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
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies", d.apiProtocol, d.apiHost, d.apiPort)
	err = backend.CommonRequest("device-discovery", d.proc, d.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.logger.Warn("policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

func (d *deviceDiscoveryBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("device-discovery policy remove", "policy_id", data.ID)
	var resp any
	var name string
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	} else {
		name = data.Name
	}
	segment, err := backend.PolicyPathSegment(name)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.apiProtocol, d.apiHost, d.apiPort, segment)
	err = backend.CommonRequest("device-discovery", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}

func (d *deviceDiscoveryBackend) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	var resp backend.StatusResponse
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("device-discovery", d.proc, d.logger, url, &resp, http.MethodGet,
		http.NoBody, "application/json", statusTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return resp.Policies, nil
}

func normalizeDeviceDiscoveryLine(line string, fallback slog.Level) (string, []slog.Attr, slog.Level, bool) {
	firstColon := strings.Index(line, ":")
	if firstColon <= 0 {
		return "", nil, fallback, false
	}

	levelCandidate := strings.TrimSpace(line[:firstColon])
	level, ok := parseDeviceDiscoveryLevel(levelCandidate)
	if !ok {
		return "", nil, fallback, false
	}

	remainder := strings.TrimSpace(line[firstColon+1:])
	if remainder == "" {
		return strings.TrimSpace(line), nil, level, true
	}

	var attrs []slog.Attr
	message := remainder

	if secondColon := strings.Index(remainder, ":"); secondColon >= 0 {
		moduleCandidate := strings.TrimSpace(remainder[:secondColon])
		rest := strings.TrimSpace(remainder[secondColon+1:])

		if moduleCandidate != "" && !strings.ContainsAny(moduleCandidate, " \t") {
			attrs = append(attrs, slog.String("module", moduleCandidate))
			if rest != "" {
				message = rest
			} else {
				message = remainder
			}
		}
	}

	if message == "" {
		message = strings.TrimSpace(line)
	}

	if message == "" {
		return "", nil, level, false
	}

	return message, attrs, level, true
}

func parseDeviceDiscoveryLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "trace":
		return slog.LevelDebug, true
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error", "err", "exception":
		return slog.LevelError, true
	case "critical", "fatal":
		return slog.LevelError, true
	default:
		return 0, false
	}
}
