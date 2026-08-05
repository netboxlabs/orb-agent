package opentelemetryinfinity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*openTelemetryBackend)(nil)

const (
	defaultExec         = "otlpinf"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "10222"
	versionTimeout      = 5
	capabilitiesTimeout = 5
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	statusTimeout       = 5
)

type openTelemetryBackend struct {
	logger     *slog.Logger
	policyRepo policies.PolicyRepo
	exec       string

	apiHost     string
	apiPort     string
	apiProtocol string

	startTime   time.Time
	proc        backend.Commander
	agentLabels map[string]string
	statusChan  <-chan backend.CmdStatus
	cancelFunc  context.CancelFunc
	ctx         context.Context
}

type info struct {
	StartTime string  `json:"start_time"`
	Version   string  `json:"version"`
	UpTime    float64 `json:"up_time"`
}

// Register registers otel backend
func Register() bool {
	backend.Register("opentelemetry_infinity", &openTelemetryBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

// Configure initializes the backend with the given configuration
func (o *openTelemetryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	o.logger = logger.With("backend", "opentelemetry_infinity")
	o.policyRepo = repo

	o.apiHost = backend.ConfigValueOrDefault(config, "host", defaultAPIHost)
	o.apiPort = backend.ConfigValueOrDefault(config, "port", defaultAPIPort)
	o.agentLabels = common.Otlp.AgentLabels

	return nil
}

func (o *openTelemetryBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

func (o *openTelemetryBackend) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", o.apiProtocol, o.apiHost, o.apiPort)
	err := backend.CommonRequest("opentelemetry-infinity", o.proc, o.logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "message")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

func (o *openTelemetryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	o.startTime = time.Now()
	o.cancelFunc = cancelFunc
	o.ctx = ctx

	pvOptions := []string{
		"run",
		"--server_host", o.apiHost,
		"--server_port", o.apiPort,
		"--log_timestamp=false",
	}

	o.logger.Info("opentelemetry infinity startup", "arguments", pvOptions)

	return backend.StartProcess(backend.StartSpec{
		Logger:         o.logger,
		NameDisplay:    "opentelemetry infinity",
		NameUnderscore: "opentelemetry_infinity",
		Exec:           o.exec,
		Args:           pvOptions,
		LogLine:        o.logLineAdapter,
		SetProc: func(p backend.Commander, ch <-chan backend.CmdStatus) {
			o.proc = p
			o.statusChan = ch
		},
		ReadinessCheck: o.Version,
	})
}

// logLineAdapter routes a streamed stdout/stderr line to the otel output
// normalizer with the level matching the source stream.
func (o *openTelemetryBackend) logLineAdapter(line string, isStderr bool) {
	level := slog.LevelInfo
	if isStderr {
		level = slog.LevelError
	}
	o.logOpenTelemetryInfinityOutput(line, level)
}

func (o *openTelemetryBackend) Stop(ctx context.Context) error {
	o.logger.Info("routine call to stop opentelemetry infinity",
		"routine", ctx.Value(config.ContextKey("routine")))
	defer o.cancelFunc()
	err := o.proc.Stop()
	finalStatus := <-o.statusChan
	if err != nil {
		o.logger.Error("opentelemetry infinity shutdown error", "error", err)
	}
	o.logger.Info("opentelemetry infinity process stopped", "pid", finalStatus.PID,
		"exit_code", finalStatus.Exit)
	return nil
}

func (o *openTelemetryBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(o.proc); state == backend.Running {
		if err := o.Stop(ctx); err != nil {
			o.logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "opentelemetry"))
	// start it
	if err := o.Start(backendCtx, cancelFunc); err != nil {
		o.logger.Error("failed to start backend on restart procedure", "error", err)
		return err
	}
	return nil
}

func (o *openTelemetryBackend) GetStartTime() time.Time {
	return o.startTime
}

// GetCapabilities this will only print a default backend config
func (o *openTelemetryBackend) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", o.apiProtocol, o.apiHost, o.apiPort)
	err := backend.CommonRequest("opentelemetry-infinity", o.proc, o.logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "message")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

// GetRunningStatus returns cross-reference the Processes using the os, with the policies and contexts
func (o *openTelemetryBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	// first check process status
	runningStatus, errMsg, err := backend.GetRunningStatus(o.proc)
	// if it's not running, we're done
	if runningStatus != backend.Running {
		return runningStatus, errMsg, err
	}
	// if it's running, check REST API availability too
	if _, aiErr := o.Version(); aiErr != nil {
		// process is running, but REST API is not accessible
		return backend.BackendError, "process running, REST API unavailable", aiErr
	}
	return runningStatus, "", nil
}

func (o *openTelemetryBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := o.RemovePolicy(data); err != nil {
			o.logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	o.logger.Debug("opentelemetry infinity policy apply", "policy_id", data.ID, "data", data.Data)

	fullPolicy := map[string]any{
		data.Name: data.Data,
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		o.logger.Warn("policy yaml marshal failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	var resp map[string]any
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies", o.apiProtocol, o.apiHost, o.apiPort)
	err = backend.CommonRequest("opentelemetry-infinity", o.proc, o.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "message")
	if err != nil {
		o.logger.Warn("policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

func (o *openTelemetryBackend) RemovePolicy(data policies.PolicyData) error {
	o.logger.Debug("opentelemetry policy remove", "policy_id", data.ID)
	var resp any
	var name string
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	} else {
		name = data.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", o.apiProtocol, o.apiHost, o.apiPort, name)
	err := backend.CommonRequest("opentelemetry-infinity", o.proc, o.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "message")
	if err != nil {
		return err
	}
	return nil
}

func (o *openTelemetryBackend) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	var resp backend.StatusResponse
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", o.apiProtocol, o.apiHost, o.apiPort)
	err := backend.CommonRequest("opentelemetry-infinity", o.proc, o.logger, url, &resp, http.MethodGet,
		http.NoBody, "application/json", statusTimeout, "message")
	if err != nil {
		return nil, err
	}
	return resp.Policies, nil
}

func (o *openTelemetryBackend) logOpenTelemetryInfinityOutput(line string, fallback slog.Level) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}

	msg := trimmed
	attrs := []slog.Attr(nil)
	level := fallback

	if parsedMsg, parsedAttrs, parsedLevel, ok := normalizeOpenTelemetryInfinityLine(trimmed, fallback); ok {
		msg = parsedMsg
		attrs = parsedAttrs
		level = parsedLevel
	}

	ctx := o.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	o.logger.LogAttrs(ctx, level, msg, attrs...)
}

func normalizeOpenTelemetryInfinityLine(line string, fallback slog.Level) (string, []slog.Attr, slog.Level, bool) {
	fields, ok := parseOpenTelemetryInfinityJSON(line)
	if !ok {
		return "", nil, fallback, false
	}

	msg, ok := extractMessage(fields)
	if !ok {
		return "", nil, fallback, false
	}

	level := fallback
	if lvl, exists := fields["level"]; exists {
		if parsed, ok := parseOpenTelemetryInfinityLevel(fmt.Sprint(lvl)); ok {
			level = parsed
		}
	}
	if severity, exists := fields["severity"]; exists {
		if parsed, ok := parseOpenTelemetryInfinityLevel(fmt.Sprint(severity)); ok {
			level = parsed
		}
	}

	delete(fields, "msg")
	delete(fields, "message")
	delete(fields, "level")
	delete(fields, "severity")
	delete(fields, "timestamp")
	delete(fields, "time")
	delete(fields, "ts")

	attrs := buildOpenTelemetryInfinityAttrs(fields)

	return msg, attrs, level, true
}

func extractMessage(fields map[string]any) (string, bool) {
	if raw, ok := fields["msg"]; ok {
		if msg, ok := raw.(string); ok && strings.TrimSpace(msg) != "" {
			return msg, true
		}
	}
	if raw, ok := fields["message"]; ok {
		if msg, ok := raw.(string); ok && strings.TrimSpace(msg) != "" {
			return msg, true
		}
	}
	return "", false
}

func parseOpenTelemetryInfinityJSON(line string) (map[string]any, bool) {
	var data map[string]any
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		return nil, false
	}
	if len(data) == 0 {
		return nil, false
	}
	return data, true
}

func parseOpenTelemetryInfinityLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "information":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error", "err":
		return slog.LevelError, true
	case "fatal":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

func buildOpenTelemetryInfinityAttrs(fields map[string]any) []slog.Attr {
	if len(fields) == 0 {
		return nil
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if strings.EqualFold(trimmed, "resource") {
			continue
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil
	}

	sort.Strings(keys)

	attrs := make([]slog.Attr, 0, len(keys))
	for _, key := range keys {
		attr, ok := convertOpenTelemetryInfinityAttr(key, fields[key])
		if !ok {
			continue
		}
		attrs = append(attrs, attr)
	}
	return attrs
}

func convertOpenTelemetryInfinityAttr(key string, value any) (slog.Attr, bool) {
	switch v := value.(type) {
	case map[string]any:
		nested := buildOpenTelemetryInfinityAttrs(v)
		if len(nested) == 0 {
			return slog.Attr{}, false
		}
		return openTelemetryInfinityGroupAttr(key, nested), true
	case []any:
		return slog.Any(key, normalizeOpenTelemetryInfinitySlice(v)), true
	case string:
		return slog.String(key, v), true
	case float64:
		if float64(int64(v)) == v {
			return slog.Int64(key, int64(v)), true
		}
		return slog.Float64(key, v), true
	case bool:
		return slog.Bool(key, v), true
	case nil:
		return slog.Any(key, nil), true
	default:
		return slog.Any(key, v), true
	}
}

func normalizeOpenTelemetryInfinitySlice(values []any) []any {
	if len(values) == 0 {
		return values
	}

	normalized := make([]any, len(values))
	for i, value := range values {
		normalized[i] = normalizeOpenTelemetryInfinityValue(value)
	}
	return normalized
}

func normalizeOpenTelemetryInfinityValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		nested := make(map[string]any, len(v))
		for key, val := range v {
			if strings.TrimSpace(key) == "" {
				continue
			}
			nested[key] = normalizeOpenTelemetryInfinityValue(val)
		}
		return nested
	case []any:
		return normalizeOpenTelemetryInfinitySlice(v)
	case float64:
		if float64(int64(v)) == v {
			return int64(v)
		}
		return v
	default:
		return v
	}
}

func openTelemetryInfinityGroupAttr(key string, attrs []slog.Attr) slog.Attr {
	if len(attrs) == 0 {
		return slog.Any(key, map[string]any{})
	}

	args := make([]any, len(attrs))
	for i, attr := range attrs {
		args[i] = attr
	}
	return slog.Group(key, args...)
}
