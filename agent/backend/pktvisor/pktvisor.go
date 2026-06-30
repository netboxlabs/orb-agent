package pktvisor

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*pktvisorBackend)(nil)

const (
	defaultBinary       = "pktvisord"
	readinessTimeout    = 10
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	versionTimeout      = 2
	tapsTimeout         = 5
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "10853"
)

// AppInfo represents server application information
type AppInfo struct {
	App struct {
		Version   string  `json:"version"`
		UpTimeMin float64 `json:"up_time_min"`
	} `json:"app"`
}

type pktvisorBackend struct {
	logger          *slog.Logger
	binary          string
	configFile      string
	pktvisorVersion string
	proc            backend.Commander
	statusChan      <-chan backend.CmdStatus
	startTime       time.Time
	cancelFunc      context.CancelFunc
	ctx             context.Context
	policyRepo      policies.PolicyRepo

	adminAPIHost     string
	adminAPIPort     string
	adminAPIProtocol string

	// added for Strings
	agentLabels map[string]string

	// OpenTelemetry management
	otelReceiverHost string
	otelReceiverPort int
}

func (p *pktvisorBackend) GetStartTime() time.Time {
	return p.startTime
}

func (p *pktvisorBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

func (p *pktvisorBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	// first check process status
	runningStatus, errMsg, err := backend.GetRunningStatus(p.proc)
	// if it's not running, we're done
	if runningStatus != backend.Running {
		return runningStatus, errMsg, err
	}
	// if it's running, check REST API availability too
	_, aiErr := p.getAppInfo()
	if aiErr != nil {
		// process is running, but REST API is not accessible
		return backend.BackendError, "process running, REST API unavailable", aiErr
	}
	return runningStatus, "", nil
}

func (p *pktvisorBackend) Version() (string, error) {
	appInfo, err := p.getAppInfo()
	if err != nil {
		return "", err
	}
	p.pktvisorVersion = appInfo.App.Version
	return appInfo.App.Version, nil
}

func (p *pktvisorBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	// this should record the start time whether it's successful or not
	// because it is used by the automatic restart system for last attempt
	p.startTime = time.Now()
	p.cancelFunc = cancelFunc
	p.ctx = ctx

	_, err := exec.LookPath(p.binary)
	if err != nil {
		p.logger.Error("pktvisor startup error: binary not found", "error", err)
		return err
	}

	pvOptions := []string{"--admin-api"}
	if len(p.configFile) > 0 {
		pvOptions = append(pvOptions, "--config", p.configFile)
	}

	if p.otelReceiverHost != "" && p.otelReceiverPort != 0 {
		pvOptions = append(pvOptions, "--otel")
		pvOptions = append(pvOptions, "--otel-host", p.otelReceiverHost)
		pvOptions = append(pvOptions, "--otel-port", strconv.Itoa(p.otelReceiverPort))
	}

	p.logger.Info("pktvisor startup", "arguments", pvOptions)

	return backend.StartProcess(ctx, backend.StartSpec{
		Logger:         p.logger,
		NameDisplay:    "pktvisor",
		NameUnderscore: "pktvisor",
		Exec:           p.binary,
		Args:           pvOptions,
		LogLine:        p.logLineAdapter,
		SetProc: func(proc backend.Commander, ch <-chan backend.CmdStatus) {
			p.proc = proc
			p.statusChan = ch
		},
		// Readiness probes /api/v1/metrics/app with readinessTimeout (10s), NOT
		// getAppInfo (which uses versionTimeout=2). Returns the app version.
		ReadinessCheck: func() (string, error) {
			var appMetrics AppInfo
			url := fmt.Sprintf("%s://%s:%s/api/v1/metrics/app", p.adminAPIProtocol, p.adminAPIHost, p.adminAPIPort)
			err := backend.CommonRequest("pktvisor", p.proc, p.logger, url, &appMetrics, http.MethodGet,
				http.NoBody, "application/json", readinessTimeout, "error")
			return appMetrics.App.Version, err
		},
	})
}

// logLineAdapter routes a streamed stdout/stderr line to the pktvisor output
// normalizer with the level matching the source stream.
func (p *pktvisorBackend) logLineAdapter(line string, isStderr bool) {
	level := slog.LevelInfo
	if isStderr {
		level = slog.LevelError
	}
	p.logPktvisorOutput(line, level)
}

func (p *pktvisorBackend) logPktvisorOutput(line string, level slog.Level) {
	if strings.TrimSpace(line) == "" {
		return
	}

	msg, attrs := normalizePktvisorLine(line)
	if msg == "" {
		msg = line
	}

	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	p.logger.LogAttrs(ctx, level, msg, attrs...)
}

func normalizePktvisorLine(line string) (string, []slog.Attr) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", nil
	}

	cleaned := stripPktvisorPrefix(trimmed)
	if cleaned == "" {
		cleaned = trimmed
	}

	msg := cleaned
	attrs := make([]slog.Attr, 0, 2)

	if entity, name, rest, ok := parsePktvisorEntity(cleaned); ok {
		attrs = append(attrs, slog.String(entity, name))
		if rest != "" {
			msg = fmt.Sprintf("%s %s", entity, rest)
		} else {
			msg = entity
		}
	}

	return msg, attrs
}

func stripPktvisorPrefix(line string) string {
	trimmed := strings.TrimSpace(line)
	for strings.HasPrefix(trimmed, "[") {
		closeIdx := strings.Index(trimmed, "]")
		if closeIdx == -1 {
			break
		}
		trimmed = strings.TrimSpace(trimmed[closeIdx+1:])
	}
	return trimmed
}

func parsePktvisorEntity(line string) (entity, name, rest string, ok bool) {
	for _, candidate := range []string{"tap", "policy"} {
		prefix := candidate + " ["
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		remainder := line[len(prefix):]
		closeIdx := strings.Index(remainder, "]")
		if closeIdx == -1 {
			return "", "", "", false
		}

		name = remainder[:closeIdx]
		rest = strings.TrimSpace(remainder[closeIdx+1:])
		rest = strings.TrimPrefix(rest, ":")
		rest = strings.TrimSpace(rest)

		if name != "" {
			return candidate, name, rest, true
		}

		return "", "", "", false
	}

	return "", "", "", false
}

func (p *pktvisorBackend) Stop(ctx context.Context) error {
	p.logger.Info("routine call to stop pktvisor", "routine", ctx.Value(config.ContextKey("routine")))
	defer p.cancelFunc()

	err := p.proc.Stop()
	finalStatus := <-p.statusChan
	if err != nil {
		p.logger.Error("pktvisor shutdown error", "error", err)
	}

	p.logger.Info("pktvisor process stopped", "pid", finalStatus.PID,
		"exit_code", finalStatus.Exit)
	return nil
}

// Configure this will set configurations, but if not set, will use the following defaults
func (p *pktvisorBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	p.logger = logger.With("backend", "pktvisor")
	p.policyRepo = repo

	p.binary = defaultBinary
	p.adminAPIHost = defaultAPIHost
	p.adminAPIPort = defaultAPIPort
	p.agentLabels = common.Otlp.AgentLabels

	// Clean up old temp config file if it exists
	if p.configFile != "" {
		if err := os.Remove(p.configFile); err != nil && !os.IsNotExist(err) {
			p.logger.Warn("failed to remove old pktvisor temp config file",
				"file", p.configFile,
				"error", err)
		}
	}

	// Create temp config file
	tmpDir := os.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "pktvisor-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create pktvisor temp config file: %w", err)
	}

	// Prepare the visor configuration structure
	visorConfig := make(map[string]any)
	configSection := make(map[string]any)

	// Process all config entries
	for key, value := range config {
		switch key {
		case "host":
			if v, ok := value.(string); ok {
				p.adminAPIHost = v
			}
			configSection[key] = value
		case "port":
			p.adminAPIPort = fmt.Sprintf("%v", value)
			configSection[key] = value
		case "taps":
			visorConfig["taps"] = value
		default:
			configSection[key] = value
		}
	}

	if len(configSection) > 0 {
		visorConfig["config"] = configSection
	}

	fullConfig := map[string]any{
		"visor": visorConfig,
	}

	yamlData, err := yaml.Marshal(fullConfig)
	if err != nil {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			p.logger.Error("failed to remove temp config file", "file", tmpFile.Name(),
				"error", rerr)
		}
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(tmpFile.Name(), yamlData, 0o644); err != nil {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			p.logger.Error("failed to remove temp config file", "file", tmpFile.Name(),
				"error", rerr)
		}
		return fmt.Errorf("failed to write config file: %w", err)
	}

	p.configFile = tmpFile.Name()

	if common.Otlp.HTTP != "" {
		uri, err := url.Parse(common.Otlp.HTTP)
		if err != nil {
			return fmt.Errorf("failed to parse otlp receiver http url: %w", err)
		}
		p.otelReceiverHost = uri.Hostname()
		port, err := strconv.Atoi(uri.Port())
		if err != nil {
			return fmt.Errorf("failed to parse otlp receiver port: %w", err)
		}
		p.otelReceiverPort = port
		p.logger.Info("configured otlp receiver host", "host", p.otelReceiverHost,
			"port", p.otelReceiverPort)
	}

	return nil
}

func (p *pktvisorBackend) GetCapabilities() (map[string]any, error) {
	var taps any
	url := fmt.Sprintf("%s://%s:%s/api/v1/taps", p.adminAPIProtocol, p.adminAPIHost, p.adminAPIPort)
	err := backend.CommonRequest("pktvisor", p.proc, p.logger, url, &taps, http.MethodGet,
		http.NoBody, "application/json", tapsTimeout, "error")
	if err != nil {
		return nil, err
	}
	jsonBody := make(map[string]any)
	jsonBody["taps"] = taps
	return jsonBody, nil
}

func (p *pktvisorBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(p.proc); state == backend.Running {
		if err := p.Stop(ctx); err != nil {
			p.logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	// create a new context for the backend
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "pktvisor"))

	// start it
	if err := p.Start(backendCtx, cancelFunc); err != nil {
		p.logger.Error("failed to start backend on restart procedure", "error", err)
		return err
	}

	return nil
}

// Register registers pktvisor backend
func Register() bool {
	backend.Register("pktvisor", &pktvisorBackend{
		adminAPIProtocol: "http",
	})
	return true
}

func (p *pktvisorBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := p.RemovePolicy(data); err != nil {
			p.logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	p.logger.Debug("pktvisor policy apply", "policy_id", data.ID, "data", data.Data)

	fullPolicy := map[string]any{
		"version": "1.0",
		"visor": map[string]any{
			"policies": map[string]any{
				data.Name: data.Data,
			},
		},
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		p.logger.Warn("yaml policy marshal failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	var resp map[string]any
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies", p.adminAPIProtocol, p.adminAPIHost, p.adminAPIPort)
	err = backend.CommonRequest("pktvisor", p.proc, p.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "error")
	if err != nil {
		p.logger.Warn("yaml policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

func (p *pktvisorBackend) RemovePolicy(data policies.PolicyData) error {
	p.logger.Debug("pktvisor policy remove", "policy_id", data.ID)
	var resp any
	var name string
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	} else {
		name = data.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", p.adminAPIProtocol, p.adminAPIHost, p.adminAPIPort, name)
	err := backend.CommonRequest("pktvisor", p.proc, p.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "error")
	if err != nil {
		return err
	}
	return nil
}

func (p *pktvisorBackend) getAppInfo() (AppInfo, error) {
	var appInfo AppInfo
	url := fmt.Sprintf("%s://%s:%s/api/v1/metrics/app", p.adminAPIProtocol, p.adminAPIHost, p.adminAPIPort)
	err := backend.CommonRequest("pktvisor", p.proc, p.logger, url, &appInfo, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "error")
	return appInfo, err
}
