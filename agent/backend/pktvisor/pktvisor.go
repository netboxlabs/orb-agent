package pktvisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

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
	visorSettings   map[string]any // visor.config as Configure read it, without the port
	visorTaps       any            // visor.taps as Configure read it
	configFile      string
	pktvisorVersion string
	proc            backend.Commander
	statusChan      <-chan backend.CmdStatus
	startTime       time.Time
	cancelFunc      context.CancelFunc
	policyRepo      policies.PolicyRepo

	adminAPIHost     string
	adminAPIPort     backend.APIPort
	adminAPIProtocol string

	// added for Strings
	agentLabels map[string]string

	// OpenTelemetry management
	otelReceiverHost string
	otelReceiverPort int

	// keptTaps marks managed taps that cleanup must leave alone. It has its
	// own lock: a health restart runs Configure and Start without the policy
	// manager's apply lock while a removal can run.
	keptMu   sync.Mutex
	keptTaps map[string]bool
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

	_, err := exec.LookPath(p.binary)
	if err != nil {
		p.logger.Error("pktvisor startup error: binary not found", "error", err)
		return err
	}

	port, err := p.adminAPIPort.ForStart(ctx, p.adminAPIHost)
	if err != nil {
		return fmt.Errorf("pktvisor: %w", err)
	}

	if err := p.writeConfigFile(port); err != nil {
		return err
	}

	// The port goes in the config file and in -p, which wins over it, so
	// pktvisord binds it whichever it reads.
	pvOptions := []string{"--admin-api", "-p", port, "--config", p.configFile}

	if p.otelReceiverHost != "" && p.otelReceiverPort != 0 {
		pvOptions = append(pvOptions, "--otel")
		pvOptions = append(pvOptions, "--otel-host", p.otelReceiverHost)
		pvOptions = append(pvOptions, "--otel-port", strconv.Itoa(p.otelReceiverPort))
	}

	p.logger.Info("pktvisor startup", "arguments", pvOptions)

	// A fresh pktvisor is loading nothing, so no tap needs protecting.
	p.clearKeptTaps()

	return backend.StartProcess(backend.StartSpec{
		Logger:         p.logger,
		Ctx:            ctx,
		NameDisplay:    "pktvisor",
		NameUnderscore: "pktvisor",
		Exec:           p.binary,
		Args:           pvOptions,
		ListenAddr:     net.JoinHostPort(p.adminAPIHost, p.adminAPIPort.Get()),
		// The closure holds this start's ctx, so a restart cannot change what
		// the previous process's log goroutine reads.
		LogLine: func(line string, isStderr bool) {
			p.logLineAdapter(ctx, line, isStderr)
		},
		SetProc: func(proc backend.Commander, ch <-chan backend.CmdStatus) {
			p.proc = proc
			p.statusChan = ch
		},
		// Readiness probes /api/v1/metrics/app with readinessTimeout (10s), NOT
		// getAppInfo (which uses versionTimeout=2). Returns the app version.
		ReadinessCheck: func() (string, error) {
			var appMetrics AppInfo
			url := fmt.Sprintf("%s://%s/api/v1/metrics/app", p.adminAPIProtocol, net.JoinHostPort(p.adminAPIHost, p.adminAPIPort.Get()))
			err := backend.CommonRequest("pktvisor", p.proc, p.logger, url, &appMetrics, http.MethodGet,
				http.NoBody, "application/json", readinessTimeout, "error")
			return appMetrics.App.Version, err
		},
	})
}

// renderConfigFile is the config file for a process told port, from what
// Configure read; an empty port leaves visor.config.port out.
func (p *pktvisorBackend) renderConfigFile(port string) ([]byte, error) {
	settings := make(map[string]any, len(p.visorSettings)+1)
	maps.Copy(settings, p.visorSettings)
	if port != "" {
		if n, err := strconv.Atoi(port); err == nil {
			settings["port"] = n
		} else {
			settings["port"] = port
		}
	}
	visor := map[string]any{}
	if len(settings) > 0 {
		visor["config"] = settings
	}
	if p.visorTaps != nil {
		visor["taps"] = p.visorTaps
	}
	data, err := yaml.Marshal(map[string]any{"visor": visor})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	return data, nil
}

// writeConfigFile writes the config file for a process told port to a new
// temp file, and removes the previous start's. It runs at start rather than
// at configure time, so a backend declared on demand and never started
// writes nothing.
func (p *pktvisorBackend) writeConfigFile(port string) error {
	data, err := p.renderConfigFile(port)
	if err != nil {
		return err
	}
	if p.configFile != "" {
		if err := os.Remove(p.configFile); err != nil && !os.IsNotExist(err) {
			p.logger.Warn("failed to remove old pktvisor temp config file",
				"file", p.configFile,
				"error", err)
		}
		p.configFile = ""
	}

	tmpFile, err := os.CreateTemp(os.TempDir(), "pktvisor-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create pktvisor temp config file: %w", err)
	}
	_, werr := tmpFile.Write(data)
	if err := errors.Join(werr, tmpFile.Close()); err != nil {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			p.logger.Error("failed to remove temp config file", "file", tmpFile.Name(),
				"error", rerr)
		}
		return fmt.Errorf("failed to write config file: %w", err)
	}
	p.configFile = tmpFile.Name()
	return nil
}

// logLineAdapter routes a streamed stdout/stderr line to the pktvisor output
// normalizer with the level matching the source stream.
func (p *pktvisorBackend) logLineAdapter(ctx context.Context, line string, isStderr bool) {
	level := slog.LevelInfo
	if isStderr {
		level = slog.LevelError
	}
	p.logPktvisorOutput(ctx, line, level)
}

func (p *pktvisorBackend) logPktvisorOutput(ctx context.Context, line string, level slog.Level) {
	if strings.TrimSpace(line) == "" {
		return
	}

	msg, attrs := normalizePktvisorLine(line)
	if msg == "" {
		msg = line
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
	p.agentLabels = common.Otlp.AgentLabels

	// Prepare the visor configuration structure. The port is left out: each
	// start writes the one it settles, so the file and -p always agree.
	configSection := make(map[string]any)
	var taps any

	// Process all config entries
	for key, value := range config {
		switch key {
		case "host":
			if v, ok := value.(string); ok {
				p.adminAPIHost = v
			}
			configSection[key] = value
		case "port":
		case "taps":
			taps = value
		default:
			configSection[key] = value
		}
	}

	p.adminAPIPort.Configure(backend.ConfiguredPort(config), p.adminAPIHost, defaultAPIPort)

	p.visorSettings = configSection
	p.visorTaps = taps
	if _, err := p.renderConfigFile(""); err != nil {
		return err
	}

	if common.Otlp.HTTP != "" {
		uri, err := neturl.Parse(common.Otlp.HTTP)
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
	url := fmt.Sprintf("%s://%s/api/v1/taps", p.adminAPIProtocol, net.JoinHostPort(p.adminAPIHost, p.adminAPIPort.Get()))
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
	url := fmt.Sprintf("%s://%s/api/v1/policies", p.adminAPIProtocol, net.JoinHostPort(p.adminAPIHost, p.adminAPIPort.Get()))
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
	segment, err := backend.PolicyPathSegment(name)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s://%s/api/v1/policies/%s", p.adminAPIProtocol, net.JoinHostPort(p.adminAPIHost, p.adminAPIPort.Get()), segment)
	err = backend.CommonRequest("pktvisor", p.proc, p.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "error")
	// pktvisor answered, so the policy no longer holds a tap even when the
	// answer was an error such as 404: look for taps nothing uses.
	var httpErr *backend.HTTPError
	if err == nil || errors.As(err, &httpErr) {
		p.removeUnusedTaps()
	}
	return err
}

func (p *pktvisorBackend) getAppInfo() (AppInfo, error) {
	var appInfo AppInfo
	url := fmt.Sprintf("%s://%s/api/v1/metrics/app", p.adminAPIProtocol, net.JoinHostPort(p.adminAPIHost, p.adminAPIPort.Get()))
	err := backend.CommonRequest("pktvisor", p.proc, p.logger, url, &appInfo, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "error")
	return appInfo, err
}
