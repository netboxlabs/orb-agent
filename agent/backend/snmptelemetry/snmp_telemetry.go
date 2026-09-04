package snmptelemetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
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

var _ backend.Backend = (*snmpTelemetryBackend)(nil)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	defaultExec         = "snmp-telemetry"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "8078"

	// maxExportPeriodSeconds is the binary's own cap on --otel-export-period,
	// one year. The binary exits on a larger value, which the agent would
	// then restart in a loop, so the agent refuses it at configuration.
	maxExportPeriodSeconds = 365 * 24 * 60 * 60
)

// stopProcess is backend.StopProcess behind a seam so a test can observe the
// grace Stop hands the process.
var stopProcess = backend.StopProcess

// snmpTelemetryBackend runs the snmp-telemetry binary, which polls SNMP
// devices and receives their traps under policies and exports metrics over
// OTLP. Every metric leaves over OTLP, so the backend refuses to configure
// without common.otlp.grpc rather than start a process with nowhere to export.
//
// It does not implement backend.PolicyStatusProvider. The agent uses that
// provider only to feed each policy's runs into the policy repo, and a
// telemetry policy is a continuous collector with no runs to report: its
// status carries a name, a state and a last error. Implementing the provider
// would poll the status endpoint every cycle to update nothing.
type snmpTelemetryBackend struct {
	logger     *slog.Logger
	policyRepo policies.PolicyRepo
	exec       string

	apiHost     string
	apiPort     string
	apiProtocol string

	otelEndpoint string

	// Optional flags, passed only when non-empty. Reset on every Configure
	// so a reconfiguration cannot carry a value over.
	otelExportPeriod string
	logLevel         string
	logFormat        string
	policyEnvVars    string
	profilesRoot     string
	profilesDir      string

	startTime  time.Time
	proc       backend.Commander
	statusChan <-chan backend.CmdStatus
	cancelFunc context.CancelFunc
	ctx        context.Context
}

type info struct {
	Version string `json:"version"`
}

// Register registers the snmp telemetry backend
func Register() bool {
	backend.Register("snmp_telemetry", &snmpTelemetryBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

func parseExportPeriod(v any) (int, error) {
	var n int

	switch val := v.(type) {
	case int:
		n = val
	case int64:
		n = int(val)
	case float64:
		if val != float64(int64(val)) {
			return 0, fmt.Errorf("otel_export_period must be a whole number, got %v", val)
		}
		n = int(val)
	case string:
		parsed, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("otel_export_period: invalid integer %q: %w", val, err)
		}
		n = parsed
	default:
		return 0, fmt.Errorf("otel_export_period must be an integer, got %T", v)
	}

	if n < 1 {
		return 0, fmt.Errorf("otel_export_period must be >= 1, got %d", n)
	}
	if n > maxExportPeriodSeconds {
		return 0, fmt.Errorf("otel_export_period must be <= %d, got %d", maxExportPeriodSeconds, n)
	}

	return n, nil
}

// parsePolicyEnvVars accepts the flag's own comma-separated string, or a YAML
// list of names so an operator does not have to write the comma form by hand.
func parsePolicyEnvVars(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case []string:
		return strings.Join(val, ","), nil
	case []any:
		names := make([]string, 0, len(val))
		for _, item := range val {
			name, ok := item.(string)
			if !ok {
				return "", fmt.Errorf("policy_env_vars entries must be strings, got %T", item)
			}
			names = append(names, name)
		}
		return strings.Join(names, ","), nil
	default:
		return "", fmt.Errorf("policy_env_vars must be a string or a list of strings, got %T", v)
	}
}

func (d *snmpTelemetryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	cfg map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.logger = logger.With("backend", "snmp_telemetry")
	d.policyRepo = repo

	if common.Otlp.Grpc == "" {
		return errors.New("snmp_telemetry: common.otlp.grpc is required, the backend exports its metrics over OTLP")
	}
	d.otelEndpoint = common.Otlp.Grpc

	d.apiHost = backend.ConfigValueOrDefault(cfg, "host", defaultAPIHost)
	d.apiPort = backend.ConfigValueOrDefault(cfg, "port", defaultAPIPort)

	d.otelExportPeriod = ""
	if v, prs := cfg["otel_export_period"]; prs {
		period, err := parseExportPeriod(v)
		if err != nil {
			return fmt.Errorf("snmp_telemetry: %w", err)
		}
		d.otelExportPeriod = strconv.Itoa(period)
	}

	d.logLevel = ""
	if level, prs := cfg["log_level"].(string); prs && level != "" {
		d.logLevel = level
	} else if debug, prs := cfg["debug"].(bool); prs && debug {
		d.logLevel = "DEBUG"
	} else if logger.Enabled(context.Background(), slog.LevelDebug) {
		d.logLevel = "DEBUG"
	}

	d.logFormat = backend.ConfigValueOrDefault(cfg, "log_format", "")

	d.policyEnvVars = ""
	if v, prs := cfg["policy_env_vars"]; prs {
		names, err := parsePolicyEnvVars(v)
		if err != nil {
			return fmt.Errorf("snmp_telemetry: %w", err)
		}
		d.policyEnvVars = names
	}

	d.profilesRoot = backend.ConfigValueOrDefault(cfg, "snmp_profiles_root", "")
	d.profilesDir = backend.ConfigValueOrDefault(cfg, "snmp_profiles_dir", "")

	d.logger.Info("snmp-telemetry using OTLP endpoint", "endpoint", d.otelEndpoint)

	return nil
}

func (d *snmpTelemetryBackend) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("snmp-telemetry", d.proc, d.logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "detail")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

// buildArgs lists the required flags first, then every optional flag that has
// a value. An optional flag left out leaves the binary on its own default.
func (d *snmpTelemetryBackend) buildArgs() []string {
	args := []string{
		"--host", d.apiHost,
		"--port", d.apiPort,
		"--otel-endpoint", d.otelEndpoint,
	}
	optional := []struct{ flag, value string }{
		{"--otel-export-period", d.otelExportPeriod},
		{"--log-level", d.logLevel},
		{"--log-format", d.logFormat},
		{"--policy-env-vars", d.policyEnvVars},
		{"--snmp-profiles-root", d.profilesRoot},
		{"--snmp-profiles-dir", d.profilesDir},
	}
	for _, opt := range optional {
		if opt.value != "" {
			args = append(args, opt.flag, opt.value)
		}
	}
	return args
}

func (d *snmpTelemetryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

	args := d.buildArgs()

	d.logger.Info("snmp-telemetry startup", "arguments", redact.Args(args))

	return backend.StartProcess(backend.StartSpec{
		Logger:         d.logger,
		NameDisplay:    "snmp-telemetry",
		NameUnderscore: "snmp_telemetry",
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

// logLineAdapter routes a streamed stdout/stderr line to the logfmt normalizer
// with the level matching the source stream.
func (d *snmpTelemetryBackend) logLineAdapter(line string, isStderr bool) {
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

// Stop hands the process the agent's default grace. The binary sizes its own
// shutdown, closing the trap sockets and then flushing the last OTLP export,
// to that five seconds; a shorter grace would SIGKILL it with traps in hand
// and the final export unsent.
func (d *snmpTelemetryBackend) Stop(ctx context.Context) error {
	d.logger.Info("routine call to stop snmp-telemetry", "routine", ctx.Value(config.ContextKey("routine")))
	defer d.cancelFunc()
	stopProcess(d.logger, d.proc, d.statusChan, backend.DefaultStopGracePeriod, "snmp_telemetry")
	return nil
}

func (d *snmpTelemetryBackend) FullReset(ctx context.Context) error {
	if state, _, _ := backend.GetRunningStatus(d.proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "snmp-telemetry"))
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.logger.Error("failed to start backend on restart procedure", "error", err)
		return err
	}
	return nil
}

func (d *snmpTelemetryBackend) GetStartTime() time.Time {
	return d.startTime
}

func (d *snmpTelemetryBackend) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("snmp-telemetry", d.proc, d.logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

func (d *snmpTelemetryBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	runningStatus, errMsg, err := backend.GetRunningStatus(d.proc)
	if runningStatus != backend.Running {
		return runningStatus, errMsg, err
	}
	if _, aiErr := d.Version(); aiErr != nil {
		return backend.BackendError, "process running, REST API unavailable", aiErr
	}
	return runningStatus, "", nil
}

func (d *snmpTelemetryBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

func (d *snmpTelemetryBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// The binary answers 409 for a name already running, so an update is a
		// remove followed by a fresh apply.
		if err := d.RemovePolicy(data); err != nil {
			d.logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	d.logger.Debug("snmp-telemetry policy apply", "policy_id", data.ID, "data", data.Data)

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
	err = backend.CommonRequest("snmp-telemetry", d.proc, d.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.logger.Warn("policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

func (d *snmpTelemetryBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("snmp-telemetry policy remove", "policy_id", data.ID)
	var resp any
	name := data.Name
	// Policies are removed by name, so a renamed policy is removed under the
	// name the binary knows it by.
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.apiProtocol, d.apiHost, d.apiPort, neturl.PathEscape(name))
	err := backend.CommonRequest("snmp-telemetry", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}
