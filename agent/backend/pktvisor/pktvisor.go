package pktvisor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/go-cmd/cmd"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*pktvisorBackend)(nil)

const (
	defaultBinary       = "pktvisord"
	readinessBackoff    = 10
	readinessTimeout    = 10
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	versionTimeout      = 2
	scrapeTimeout       = 5
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
	logger          *zap.Logger
	binary          string
	configFile      string
	pktvisorVersion string
	proc            *cmd.Cmd
	statusChan      <-chan cmd.Status
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
	runningStatus, errMsg, err := p.getProcRunningStatus()
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
		p.logger.Error("pktvisor startup error: binary not found", zap.Error(err))
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

	// the macros should be properly configured to enable crashpad
	// pvOptions = append(pvOptions, "--cp-token", PKTVISOR_CP_TOKEN)
	// pvOptions = append(pvOptions, "--cp-url", PKTVISOR_CP_URL)
	// pvOptions = append(pvOptions, "--cp-path", PKTVISOR_CP_PATH)
	// pvOptions = append(pvOptions, "--default-geo-city", "/geo-db/city.mmdb")
	// pvOptions = append(pvOptions, "--default-geo-asn", "/geo-db/asn.mmdb")
	// pvOptions = append(pvOptions, "--default-service-registry", "/iana/custom-iana.csv")
	if ctx.Value("agent_id") != nil {
		pvOptions = append(pvOptions, "--cp-custom", ctx.Value("agent_id").(string))
	}

	p.logger.Info("pktvisor startup", zap.Strings("arguments", pvOptions))

	p.proc = cmd.NewCmdOptions(cmd.Options{
		Buffered:  false,
		Streaming: true,
	}, p.binary, pvOptions...)
	p.statusChan = p.proc.Start()

	// log STDOUT and STDERR lines streaming from Cmd
	doneChan := make(chan struct{})
	go func() {
		defer func() {
			if doneChan != nil {
				close(doneChan)
			}
		}()
		for p.proc.Stdout != nil || p.proc.Stderr != nil {
			select {
			case line, open := <-p.proc.Stdout:
				if !open {
					p.proc.Stdout = nil
					continue
				}
				p.logger.Info("pktvisor stdout", zap.String("log", line))
			case line, open := <-p.proc.Stderr:
				if !open {
					p.proc.Stderr = nil
					continue
				}
				p.logger.Info("pktvisor stderr", zap.String("log", line))
			}
		}
	}()

	// wait for simple startup errors
	time.Sleep(time.Second)

	status := p.proc.Status()

	if status.Error != nil {
		p.logger.Error("pktvisor startup error", zap.Error(status.Error))
		return status.Error
	}

	if status.Complete {
		err = p.proc.Stop()
		if err != nil {
			p.logger.Error("proc.Stop error", zap.Error(err))
		}
		return errors.New("pktvisor startup error, check log")
	}

	p.logger.Info("pktvisor process started", zap.Int("pid", status.PID))

	var readinessError error
	for backoff := 0; backoff < readinessBackoff; backoff++ {
		var appMetrics AppInfo
		readinessError = p.request("metrics/app", &appMetrics, http.MethodGet, http.NoBody, "application/json", readinessTimeout)
		if readinessError == nil {
			p.logger.Info("pktvisor readiness ok, got version ", zap.String("pktvisor_version", appMetrics.App.Version))
			break
		}
		backoffDuration := time.Duration(backoff) * time.Second
		p.logger.Info("pktvisor is not ready, trying again with backoff", zap.String("backoff backoffDuration", backoffDuration.String()))
		time.Sleep(backoffDuration)
	}

	if readinessError != nil {
		p.logger.Error("pktvisor error on readiness", zap.Error(readinessError))
		err = p.proc.Stop()
		if err != nil {
			p.logger.Error("proc.Stop error", zap.Error(err))
		}
		return readinessError
	}

	return nil
}

func (p *pktvisorBackend) Stop(ctx context.Context) error {
	p.logger.Info("routine call to stop pktvisor", zap.Any("routine", ctx.Value(config.ContextKey("routine"))))
	defer p.cancelFunc()
	err := p.proc.Stop()
	finalStatus := <-p.statusChan
	if err != nil {
		p.logger.Error("pktvisor shutdown error", zap.Error(err))
	}

	p.logger.Info("pktvisor process stopped", zap.Int("pid", finalStatus.PID), zap.Int("exit_code", finalStatus.Exit))
	return nil
}

// Configure this will set configurations, but if not set, will use the following defaults
func (p *pktvisorBackend) Configure(logger *zap.Logger, repo policies.PolicyRepo, config map[string]interface{}, common config.BackendCommons) error {
	p.logger = logger
	p.policyRepo = repo

	p.binary = defaultBinary
	p.adminAPIHost = defaultAPIHost
	p.adminAPIPort = defaultAPIPort
	p.agentLabels = common.Otel.AgentLabels

	// Create temp config file
	tmpDir := os.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "pktvisor-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create pktvisor temp config file: %w", err)
	}

	// Prepare the visor configuration structure
	visorConfig := make(map[string]interface{})
	configSection := make(map[string]interface{})

	// Process all config entries
	for key, value := range config {
		switch key {
		case "host":
			if v, ok := value.(string); ok {
				p.adminAPIHost = v
			}
			configSection[key] = value
		case "port":
			if v, ok := value.(string); ok {
				p.adminAPIPort = v
			}
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
			p.logger.Error("failed to remove temp config file", zap.String("file", tmpFile.Name()), zap.Error(rerr))
		}
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(tmpFile.Name(), yamlData, 0o644); err != nil {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			p.logger.Error("failed to remove temp config file", zap.String("file", tmpFile.Name()), zap.Error(rerr))
		}
		return fmt.Errorf("failed to write config file: %w", err)
	}

	p.configFile = tmpFile.Name()

	if common.Otel.Host != "" && common.Otel.Port != 0 {
		p.otelReceiverHost = common.Otel.Host
		p.otelReceiverPort = common.Otel.Port
		p.logger.Info("configured otel receiver host", zap.String("host", p.otelReceiverHost), zap.Int("port", p.otelReceiverPort))
	}

	return nil
}

func (p *pktvisorBackend) GetCapabilities() (map[string]interface{}, error) {
	var taps interface{}
	err := p.request("taps", &taps, http.MethodGet, http.NoBody, "application/json", tapsTimeout)
	if err != nil {
		return nil, err
	}
	jsonBody := make(map[string]interface{})
	jsonBody["taps"] = taps
	return jsonBody, nil
}

func (p *pktvisorBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := p.getProcRunningStatus(); state == backend.Running {
		if err := p.Stop(ctx); err != nil {
			p.logger.Error("failed to stop backend on restart procedure", zap.Error(err))
			return err
		}
	}

	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "pktvisor"))

	// start it
	if err := p.Start(backendCtx, cancelFunc); err != nil {
		p.logger.Error("failed to start backend on restart procedure", zap.Error(err))
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
