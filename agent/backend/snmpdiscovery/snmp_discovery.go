package snmpdiscovery

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/netboxlabs/orb-agent/agent/redact"
)

var _ backend.Backend = (*snmpDiscoveryBackend)(nil)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	readinessBackoff    = 10
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	statusTimeout       = 5
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
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.logger = logger.With("backend", "snmp_discovery")
	d.policyRepo = repo
	d.diodeTargetFromOtel = false

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

func (d *snmpDiscoveryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

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
		d.logger.Info("snmp-discovery using log level",
			"log_level", d.diodeLogLevel)
	}

	if d.diodeOtelEndpoint != "" {
		dOptions = append(dOptions, "--otel-endpoint", d.diodeOtelEndpoint)
		d.logger.Info("snmp-discovery using OTLP endpoint",
			"endpoint", d.diodeOtelEndpoint)
	}

	d.logger.Info("snmp-discovery startup", "arguments", redact.Args(dOptions))

	d.proc = backend.NewCmdOptions(backend.CmdOptions{
		Buffered:  false,
		Streaming: true,
	}, d.exec, dOptions...)
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
				d.logSnmpDiscoveryOutput(line, slog.LevelInfo)
			case line, open := <-stderr:
				if !open {
					stderr = nil
					continue
				}
				d.logSnmpDiscoveryOutput(line, slog.LevelError)
			}
		}
	}()

	// wait for simple startup errors
	time.Sleep(time.Second)

	status := d.proc.Status()

	if status.Error != nil {
		d.logger.Error("snmp-discovery startup error", "error", status.Error)
		return status.Error
	}

	if status.Complete {
		err := d.proc.Stop()
		if err != nil {
			d.logger.Error("proc.Stop error", "error", err)
		}
		return errors.New("snmp-discovery startup error, check log")
	}

	d.logger.Info("snmp-discovery process started", "pid", status.PID)

	var version string
	var readinessErr error
	for backoff := 1; backoff <= readinessBackoff; backoff++ {
		if status := d.proc.Status(); status.Complete {
			err := d.proc.Stop()
			if err != nil {
				d.logger.Error("proc.Stop error", "error", err)
			}
			return errors.New("snmp-discovery process ended unexpectedly, check log")
		}
		version, readinessErr = d.Version()
		if readinessErr == nil {
			d.logger.Info("snmp-discovery readiness ok, got version", "version", version)
			break
		}
		backoffDuration := time.Duration(backoff) * time.Second
		d.logger.Info("snmp-discovery is not ready, trying again with backoff",
			"backoff backoffDuration", backoffDuration.String())
		time.Sleep(backoffDuration)
	}

	if readinessErr != nil {
		d.logger.Error("snmp-discovery error on readiness", "error", readinessErr)
		err := d.proc.Stop()
		if err != nil {
			d.logger.Error("proc.Stop error", "error", err)
		}
		return readinessErr
	}

	return nil
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

func (d *snmpDiscoveryBackend) logSnmpDiscoveryOutput(line string, fallback slog.Level) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}

	msg := trimmed
	attrs := []slog.Attr(nil)
	level := fallback

	if parsedMsg, parsedAttrs, parsedLevel, ok := normalizeSnmpDiscoveryLine(trimmed, fallback); ok {
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

func normalizeSnmpDiscoveryLine(line string, fallback slog.Level) (string, []slog.Attr, slog.Level, bool) {
	fields, ok := parseSnmpDiscoveryLogfmt(line)
	if !ok {
		return "", nil, fallback, false
	}

	msg, ok := fields["msg"]
	if !ok || strings.TrimSpace(msg) == "" {
		return "", nil, fallback, false
	}

	level := fallback
	if lvlValue, exists := fields["level"]; exists {
		if parsedLevel, levelOK := parseSnmpDiscoveryLevel(lvlValue); levelOK {
			level = parsedLevel
		}
	}

	delete(fields, "msg")
	delete(fields, "level")
	delete(fields, "time")

	if len(fields) == 0 {
		return msg, nil, level, true
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return msg, nil, level, true
	}

	sort.Strings(keys)

	attrs := make([]slog.Attr, 0, len(keys))
	for _, key := range keys {
		attrs = append(attrs, slog.String(key, fields[key]))
	}

	return msg, attrs, level, true
}

func parseSnmpDiscoveryLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error", "err":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

func parseSnmpDiscoveryLogfmt(line string) (map[string]string, bool) {
	result := make(map[string]string)
	runes := []rune(line)
	length := len(runes)
	index := 0

	for index < length {
		for index < length && runes[index] == ' ' {
			index++
		}
		if index >= length {
			break
		}

		keyStart := index
		for index < length && runes[index] != '=' && runes[index] != ' ' {
			index++
		}
		if index >= length || runes[index] != '=' {
			return nil, false
		}

		key := strings.TrimSpace(string(runes[keyStart:index]))
		index++ // skip '='

		value, nextIndex, ok := readSnmpLogfmtValue(runes, index)
		if !ok {
			return nil, false
		}

		result[key] = value
		index = nextIndex
	}

	if len(result) == 0 {
		return nil, false
	}

	return result, true
}

func readSnmpLogfmtValue(runes []rune, start int) (string, int, bool) {
	length := len(runes)
	if start >= length {
		return "", start, true
	}

	switch runes[start] {
	case '"', '\'':
		return readSnmpQuotedValue(runes, start)
	default:
		return readSnmpUnquotedValue(runes, start)
	}
}

func readSnmpQuotedValue(runes []rune, start int) (string, int, bool) {
	length := len(runes)
	quote := runes[start]
	index := start + 1
	var builder strings.Builder

	for index < length {
		char := runes[index]
		if char == '\\' && index+1 < length {
			builder.WriteRune(runes[index+1])
			index += 2
			continue
		}
		if char == quote {
			index++
			for index < length && runes[index] == ' ' {
				index++
			}
			return builder.String(), index, true
		}
		builder.WriteRune(char)
		index++
	}

	return "", length, false
}

func readSnmpUnquotedValue(runes []rune, start int) (string, int, bool) {
	length := len(runes)
	index := start
	for index < length && runes[index] != ' ' {
		index++
	}
	value := string(runes[start:index])
	for index < length && runes[index] == ' ' {
		index++
	}
	return value, index, true
}

func (d *snmpDiscoveryBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("snmp-discovery policy remove", "policy_id", data.ID)
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
