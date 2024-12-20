package otel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/go-cmd/cmd"
	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*openTelemetryBackend)(nil)

const (
	defaultPath = "otelcol-contrib"
	defaultHost = "localhost"
	defaultPort = 4317
)

type openTelemetryBackend struct {
	logger    *zap.Logger
	startTime time.Time

	// policies
	policyRepo            policies.PolicyRepo
	policyConfigDirectory string
	agentTags             map[string]string

	// Context for controlling the context cancellation
	mainContext        context.Context
	runningCollectors  map[string]runningPolicy
	mainCancelFunction context.CancelFunc

	mqttClient *mqtt.Client

	otlpMetricsTopic string
	otlpTracesTopic  string
	otlpLogsTopic    string
	otelReceiverTaps []string
	otelCurrVersion  string

	otelReceiverHost   string
	otelReceiverPort   int
	otelExecutablePath string
}

// Configure initializes the backend with the given configuration
func (o *openTelemetryBackend) Configure(logger *zap.Logger, repo policies.PolicyRepo,
	config map[string]interface{}, common config.BackendCommons,
) error {
	o.logger = logger
	o.logger.Info("configuring OpenTelemetry backend")
	o.policyRepo = repo
	var err error
	o.otelReceiverTaps = []string{"otelcol-contrib", "receivers", "processors", "extensions"}
	o.policyConfigDirectory, err = os.MkdirTemp("", "otel-policies")
	if err != nil {
		o.logger.Error("failed to create temporary directory for policy configs", zap.Error(err))
		return err
	}
	if path, ok := config["binary"].(string); ok {
		o.otelExecutablePath = path
	} else {
		o.otelExecutablePath = defaultPath
	}
	_, err = exec.LookPath(o.otelExecutablePath)
	if err != nil {
		o.logger.Error("otelcol-contrib: binary not found", zap.Error(err))
		return err
	}
	if err != nil {
		o.logger.Error("failed to create temporary directory for policy configs", zap.Error(err))
		return err
	}
	o.agentTags = common.Otel.AgentTags

	if otelPort, ok := config["otlp_port"]; ok {
		o.otelReceiverPort, err = strconv.Atoi(otelPort.(string))
		if err != nil {
			o.logger.Error("failed to parse otlp port using default", zap.Error(err))
			o.otelReceiverPort = defaultPort
		}
	} else {
		o.otelReceiverPort = defaultPort
	}
	if otelHost, ok := config["otlp_host"].(string); ok {
		o.otelReceiverHost = otelHost
	} else {
		o.otelReceiverHost = defaultHost
	}

	return nil
}

func (o *openTelemetryBackend) GetInitialState() backend.RunningStatus {
	return backend.Waiting
}

func (o *openTelemetryBackend) Version() (string, error) {
	if o.otelCurrVersion != "" {
		return o.otelCurrVersion, nil
	}
	ctx, cancel := context.WithTimeout(o.mainContext, 60*time.Second)
	var versionOutput string
	command := cmd.NewCmd(o.otelExecutablePath, "--version")
	status := command.Start()
	select {
	case finalStatus := <-status:
		if finalStatus.Error != nil {
			o.logger.Error("error during call of otelcol-contrib version", zap.Error(finalStatus.Error))
			cancel()
			return "", finalStatus.Error
		} else {
			output := finalStatus.Stdout
			o.otelCurrVersion = output[0]
			versionOutput = output[0]
		}
	case <-ctx.Done():
		o.logger.Error("timeout during getting version", zap.Error(ctx.Err()))
	}

	cancel()
	o.logger.Info("running opentelemetry-contrib version", zap.String("version", versionOutput))

	return versionOutput, nil
}

func (o *openTelemetryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) (err error) {
	o.runningCollectors = make(map[string]runningPolicy)
	o.mainCancelFunction = cancelFunc
	o.mainContext = ctx
	o.startTime = time.Now()
	currentWd, err := os.Getwd()
	if err != nil {
		o.otelExecutablePath = currentWd + "/otelcol-contrib"
	}
	currentVersion, err := o.Version()
	if err != nil {
		cancelFunc()
		o.logger.Error("error during getting current version", zap.Error(err))
		return err
	}
	o.logger.Info("starting open-telemetry backend using version", zap.String("version", currentVersion))
	policiesData, err := o.policyRepo.GetAll()
	if err != nil {
		cancelFunc()
		o.logger.Error("failed to start otel backend, policies are absent")
		return err
	}
	for _, policyData := range policiesData {
		if err := o.ApplyPolicy(policyData, true); err != nil {
			o.logger.Error("failed to start otel backend, failed to apply policy", zap.Error(err))
			cancelFunc()
			return err
		}
		o.logger.Info("policy applied successfully", zap.String("policy_id", policyData.ID))
	}

	return nil
}

func (o *openTelemetryBackend) Stop(_ context.Context) error {
	o.logger.Info("stopping all running policies")
	o.mainCancelFunction()
	for policyID, policyEntry := range o.runningCollectors {
		o.logger.Debug("stopping policy context", zap.String("policy_id", policyID))
		policyEntry.ctx.Done()
	}
	return nil
}

func (o *openTelemetryBackend) FullReset(ctx context.Context) error {
	o.logger.Info("restarting otel backend", zap.Int("running policies", len(o.runningCollectors)))
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "otel"))
	if err := o.Start(backendCtx, cancelFunc); err != nil {
		return err
	}
	return nil
}

// Register registers otel backend
func Register() bool {
	backend.Register("otel", &openTelemetryBackend{})
	return true
}

func (o *openTelemetryBackend) GetStartTime() time.Time {
	return o.startTime
}

// GetCapabilities this will only print a default backend config
func (o *openTelemetryBackend) GetCapabilities() (capabilities map[string]interface{}, err error) {
	capabilities = make(map[string]interface{})
	capabilities["taps"] = o.otelReceiverTaps
	return
}

// GetRunningStatus returns cross-reference the Processes using the os, with the policies and contexts
func (o *openTelemetryBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	amountCollectors := len(o.runningCollectors)
	if amountCollectors > 0 {
		return backend.Running, fmt.Sprintf("opentelemetry backend running with %d policies", amountCollectors), nil
	}
	return backend.Waiting, "opentelemetry backend is waiting for policy to come to start running", nil
}
