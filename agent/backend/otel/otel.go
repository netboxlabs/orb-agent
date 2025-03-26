package otel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-cmd/cmd"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*openTelemetryBackend)(nil)

const (
	defaultExec         = "otlpinf"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "10222"
	versionTimeout      = 5
	capabilitiesTimeout = 5
	readinessBackoff    = 10
	readinessTimeout    = 10
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
)

type openTelemetryBackend struct {
	logger     *zap.Logger
	policyRepo policies.PolicyRepo
	exec       string

	apiHost     string
	apiPort     string
	apiProtocol string

	startTime   time.Time
	proc        *cmd.Cmd
	agentLabels map[string]string
	statusChan  <-chan cmd.Status
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
	backend.Register("otel", &openTelemetryBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

// Configure initializes the backend with the given configuration
func (o *openTelemetryBackend) Configure(logger *zap.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons,
) error {
	o.logger = logger
	o.policyRepo = repo

	var prs bool
	if o.apiHost, prs = config["host"].(string); !prs {
		o.apiHost = defaultAPIHost
	}
	if o.apiPort, prs = config["port"].(string); !prs {
		o.apiPort = defaultAPIPort
	}

	o.agentLabels = common.Otel.AgentLabels

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

func (o *openTelemetryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) (err error) {
	o.startTime = time.Now()
	o.cancelFunc = cancelFunc
	o.ctx = ctx

	pvOptions := []string{
		"run",
		"--server_host", o.apiHost,
		"--server_port", o.apiPort,
	}

	o.logger.Info("opentelemetry infinity startup", zap.Strings("arguments", pvOptions))

	o.proc = cmd.NewCmdOptions(cmd.Options{
		Buffered:  false,
		Streaming: true,
	}, o.exec, pvOptions...)
	o.statusChan = o.proc.Start()

	// log STDOUT and STDERR lines streaming from Cmd
	doneChan := make(chan struct{})
	go func() {
		defer func() {
			if doneChan != nil {
				close(doneChan)
			}
		}()
		for o.proc.Stdout != nil || o.proc.Stderr != nil {
			select {
			case line, open := <-o.proc.Stdout:
				if !open {
					o.proc.Stdout = nil
					continue
				}
				o.logger.Info("opentelemetry infinity stdout", zap.String("log", line))
			case line, open := <-o.proc.Stderr:
				if !open {
					o.proc.Stderr = nil
					continue
				}
				o.logger.Info("opentelemetry infinity stderr", zap.String("log", line))
			}
		}
	}()

	// wait for simple startup errors
	time.Sleep(time.Second)

	status := o.proc.Status()

	if status.Error != nil {
		o.logger.Error("opentelemetry infinity startup error", zap.Error(status.Error))
		return status.Error
	}

	if status.Complete {
		err := o.proc.Stop()
		if err != nil {
			o.logger.Error("proc.Stop error", zap.Error(err))
		}
		return errors.New("opentelemetry infinity startup error, check log")
	}

	o.logger.Info("opentelemetry infinity process started", zap.Int("pid", status.PID))

	var readinessErr error
	for backoff := 0; backoff < readinessBackoff; backoff++ {
		version, readinessErr := o.Version()
		if readinessErr == nil {
			o.logger.Info("opentelemetry infinity readiness ok, got version ", zap.String("device_discovery_version", version))
			break
		}
		backoffDuration := time.Duration(backoff) * time.Second
		o.logger.Info("opentelemetry infinity is not ready, trying again with backoff", zap.String("backoff backoffDuration", backoffDuration.String()))
		time.Sleep(backoffDuration)
	}

	if readinessErr != nil {
		o.logger.Error("opentelemetry infinity error on readiness", zap.Error(readinessErr))
		err := o.proc.Stop()
		if err != nil {
			o.logger.Error("proc.Stop error", zap.Error(err))
		}
		return readinessErr
	}

	return nil
}

func (o *openTelemetryBackend) Stop(ctx context.Context) error {
	o.logger.Info("routine call to stop opentelemetry infinity", zap.Any("routine", ctx.Value(config.ContextKey("routine"))))
	defer o.cancelFunc()
	err := o.proc.Stop()
	finalStatus := <-o.statusChan
	if err != nil {
		o.logger.Error("opentelemetry infinity shutdown error", zap.Error(err))
	}
	o.logger.Info("opentelemetry infinity process stopped", zap.Int("pid", finalStatus.PID), zap.Int("exit_code", finalStatus.Exit))
	return nil
}

func (o *openTelemetryBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(o.proc); state == backend.Running {
		if err := o.Stop(ctx); err != nil {
			o.logger.Error("failed to stop backend on restart procedure", zap.Error(err))
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "opentelemetry"))
	// start it
	if err := o.Start(backendCtx, cancelFunc); err != nil {
		o.logger.Error("failed to start backend on restart procedure", zap.Error(err))
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
			o.logger.Warn("policy failed to remove", zap.String("policy_id", data.ID), zap.String("policy_name", data.Name), zap.Error(err))
		}
	}

	o.logger.Debug("opentelemetry infinity policy apply", zap.String("policy_id", data.ID), zap.Any("data", data.Data))

	fullPolicy := map[string]any{
		data.Name: data.Data,
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		o.logger.Warn("policy yaml marshal failure", zap.String("policy_id", data.ID), zap.Any("policy", fullPolicy))
		return err
	}

	var resp map[string]any
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies", o.apiProtocol, o.apiHost, o.apiPort)
	err = backend.CommonRequest("opentelemetry-infinity", o.proc, o.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "message")
	if err != nil {
		o.logger.Warn("policy application failure", zap.String("policy_id", data.ID), zap.ByteString("policy", policyYaml))
		return err
	}

	return nil
}

func (o *openTelemetryBackend) RemovePolicy(data policies.PolicyData) error {
	o.logger.Debug("opentelemetry policy remove", zap.String("policy_id", data.ID))
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
