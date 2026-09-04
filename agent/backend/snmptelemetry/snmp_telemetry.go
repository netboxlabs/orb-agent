package snmptelemetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
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
	// The binary's DELETE blocks on the policy's scheduler shutdown, which it
	// bounds at 24 seconds, and a POST for a name still stopping waits on that
	// same shutdown; both timeouts clear that bound.
	applyPolicyTimeout  = 30
	removePolicyTimeout = 30
	maxPort             = 65535
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

// envVarName is what --policy-env-vars accepts: variable names. A value that
// is not a name, such as a secrets-manager reference the agent has resolved
// into a secret, must not reach the command line.
var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// readHost reads the API host. Absent, null or empty keeps the loopback
// default: the binary joins an empty host with the port and binds every
// interface, and its API has no authentication.
func readHost(cfg map[string]any) (string, error) {
	v, prs := cfg["host"]
	if !prs || v == nil {
		return defaultAPIHost, nil
	}
	host, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("host must be a string, got %T", v)
	}
	if host == "" {
		return defaultAPIHost, nil
	}
	return host, nil
}

// readPort reads the API port as the binary's integer flag takes it. Absent,
// null or empty keeps the default; anything the flag would reject is refused
// here rather than at the binary's startup, which the agent would repeat.
func readPort(cfg map[string]any) (string, error) {
	v, prs := cfg["port"]
	if !prs || v == nil || v == "" {
		return defaultAPIPort, nil
	}
	var n int
	switch val := v.(type) {
	case int:
		n = val
	case int64:
		n = int(val)
	case float64:
		if val != float64(int64(val)) {
			return "", fmt.Errorf("port must be an integer from 1 to %d, got %v", maxPort, val)
		}
		n = int(val)
	case string:
		parsed, err := strconv.Atoi(val)
		if err != nil {
			return "", fmt.Errorf("port must be an integer from 1 to %d, got %q", maxPort, val)
		}
		n = parsed
	default:
		return "", fmt.Errorf("port must be an integer from 1 to %d, got %T", maxPort, v)
	}
	if n < 1 || n > maxPort {
		return "", fmt.Errorf("port must be an integer from 1 to %d, got %d", maxPort, n)
	}
	return strconv.Itoa(n), nil
}

// readChoice reads an optional key whose value the binary matches
// case-insensitively against a fixed set. An unrecognised value is refused
// here because the binary falls back silently: any other level runs at
// DEBUG and any other format is JSON.
func readChoice(cfg map[string]any, key string, choices ...string) (string, error) {
	value, err := optionalString(cfg, key)
	if err != nil || value == "" {
		return value, err
	}
	for _, choice := range choices {
		if strings.EqualFold(value, choice) {
			return value, nil
		}
	}
	return "", fmt.Errorf("%s must be one of %s, got %q", key, strings.Join(choices, ", "), value)
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

// optionalString reads a key that is either absent, or a string passed to the
// binary verbatim. Any other type is refused rather than coerced, so a stray
// YAML boolean does not reach a flag the binary would silently reinterpret.
func optionalString(cfg map[string]any, key string) (string, error) {
	v, prs := cfg[key]
	if !prs {
		return "", nil
	}
	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %T", key, v)
	}
	return str, nil
}

// parsePolicyEnvVars accepts the flag's own comma-separated string, or a YAML
// list of names so an operator does not have to write the comma form by hand.
func parsePolicyEnvVars(v any) (string, error) {
	var names []string
	switch val := v.(type) {
	case string:
		if val == "" {
			return "", nil
		}
		names = strings.Split(val, ",")
	case []string:
		names = val
	case []any:
		for _, item := range val {
			name, ok := item.(string)
			if !ok {
				return "", fmt.Errorf("policy_env_vars entries must be strings, got %T", item)
			}
			names = append(names, name)
		}
	default:
		return "", fmt.Errorf("policy_env_vars must be a string or a list of strings, got %T", v)
	}
	for i, name := range names {
		names[i] = strings.TrimSpace(name)
		if !envVarName.MatchString(names[i]) {
			return "", fmt.Errorf("policy_env_vars takes environment variable names, not %q", name)
		}
	}
	return strings.Join(names, ","), nil
}

// settings is what Configure derives from the backend map. It is applied to
// the backend only once every key has been read, so a refused reconfiguration
// leaves the running backend, and the address the agent polls it on, as they
// were.
type settings struct {
	apiHost, apiPort, otelEndpoint           string
	otelExportPeriod, logLevel, logFormat    string
	policyEnvVars, profilesRoot, profilesDir string
}

func (d *snmpTelemetryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	cfg map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	st, err := readSettings(cfg, common)
	if err != nil {
		return fmt.Errorf("snmp_telemetry: %w", err)
	}

	d.logger = logger.With("backend", "snmp_telemetry")
	d.policyRepo = repo
	d.apiHost = st.apiHost
	d.apiPort = st.apiPort
	d.otelEndpoint = st.otelEndpoint
	d.otelExportPeriod = st.otelExportPeriod
	d.logLevel = st.logLevel
	d.logFormat = st.logFormat
	d.policyEnvVars = st.policyEnvVars
	d.profilesRoot = st.profilesRoot
	d.profilesDir = st.profilesDir

	d.logger.Info("snmp-telemetry using OTLP endpoint", "endpoint", d.otelEndpoint)

	return nil
}

func readSettings(cfg map[string]any, common config.BackendCommons) (settings, error) {
	var st settings
	var err error

	if common.Otlp.Grpc == "" {
		return st, errors.New("common.otlp.grpc is required, the backend exports its metrics over OTLP")
	}
	st.otelEndpoint = common.Otlp.Grpc

	if st.apiHost, err = readHost(cfg); err != nil {
		return st, err
	}
	if st.apiPort, err = readPort(cfg); err != nil {
		return st, err
	}

	if v, prs := cfg["otel_export_period"]; prs {
		period, err := parseExportPeriod(v)
		if err != nil {
			return st, err
		}
		st.otelExportPeriod = strconv.Itoa(period)
	}

	if st.logLevel, err = readChoice(cfg, "log_level", "DEBUG", "INFO", "WARN", "ERROR"); err != nil {
		return st, err
	}
	// The agent's debug flag comes through the commons. The logger is not
	// consulted: when OTLP log export is on, the agent wraps it in a handler
	// that accepts debug records whatever the console level, so asking the
	// logger would put every OTLP-exporting agent's backend at DEBUG.
	if st.logLevel == "" {
		if debug, prs := cfg["debug"].(bool); prs && debug {
			st.logLevel = "DEBUG"
		} else if common.Debug {
			st.logLevel = "DEBUG"
		}
	}

	if st.logFormat, err = readChoice(cfg, "log_format", "TEXT", "JSON"); err != nil {
		return st, err
	}

	if v, prs := cfg["policy_env_vars"]; prs {
		if st.policyEnvVars, err = parsePolicyEnvVars(v); err != nil {
			return st, err
		}
	}

	if st.profilesRoot, err = optionalString(cfg, "snmp_profiles_root"); err != nil {
		return st, err
	}
	if st.profilesDir, err = optionalString(cfg, "snmp_profiles_dir"); err != nil {
		return st, err
	}

	return st, nil
}

// apiURL joins the API address the way the binary binds it, so an IPv6 host
// is bracketed.
func (d *snmpTelemetryBackend) apiURL(path string) string {
	return fmt.Sprintf("%s://%s/api/v1/%s", d.apiProtocol, net.JoinHostPort(d.apiHost, d.apiPort), path)
}

func (d *snmpTelemetryBackend) Version() (string, error) {
	var info info
	url := d.apiURL("status")
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
	// A registered backend the agent never configured has no logger and no
	// arguments; a fleet full reset walks the whole registry and would reach
	// it, so refuse rather than start a process on empty flags.
	if d.logger == nil {
		return errors.New("snmp_telemetry: started before it was configured")
	}
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

// logLineAdapter routes a streamed stdout/stderr line to the agent's logger
// with the level matching the source stream. The binary writes logfmt under
// its TEXT format and one JSON object per line under JSON; both are parsed,
// so a WARN or ERROR record keeps its severity and attributes either way.
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
	} else if parsedMsg, parsedAttrs, parsedLevel, ok := backend.NormalizeJSONLine(trimmed, fallback); ok {
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

// Stop hands the process the agent's default grace. The binary bounds the
// part of its shutdown that carries data, closing the trap sockets and then
// flushing the last OTLP export, to that same five seconds, and what follows
// (cancelling collections, stopping its API) normally takes milliseconds. A
// shorter grace would SIGKILL it with traps in hand and the final export
// unsent; a kill after the flush costs nothing but a warning in the log.
func (d *snmpTelemetryBackend) Stop(ctx context.Context) error {
	if d.cancelFunc != nil {
		defer d.cancelFunc()
	}
	if d.proc == nil {
		return nil
	}
	d.logger.Info("routine call to stop snmp-telemetry", "routine", ctx.Value(config.ContextKey("routine")))
	stopProcess(d.logger, d.proc, d.statusChan, backend.DefaultStopGracePeriod, "snmp_telemetry")
	return nil
}

func (d *snmpTelemetryBackend) FullReset(ctx context.Context) error {
	if d.logger == nil {
		return errors.New("snmp_telemetry: reset before it was configured")
	}
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
	url := d.apiURL("capabilities")
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

	// The body carries solved secrets (community, passphrases), and a debug
	// record reaches the OTLP log collector when export is on, so only the
	// policy's identity is logged.
	d.logger.Debug("snmp-telemetry policy apply", "policy_id", data.ID, "policy_name", data.Name)

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
	url := d.apiURL("policies")
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
	segment, err := backend.PolicyPathSegment(name)
	if err != nil {
		return err
	}
	url := d.apiURL("policies/" + segment)
	err = backend.CommonRequest("snmp-telemetry", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}
