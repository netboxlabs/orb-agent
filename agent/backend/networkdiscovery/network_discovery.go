package networkdiscovery

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

var _ backend.Backend = (*networkDiscoveryBackend)(nil)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	readinessBackoff    = 10
	readinessTimeout    = 10
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	defaultExec         = "network-discovery"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "8073"
)

type networkDiscoveryBackend struct {
	logger     *zap.Logger
	policyRepo policies.PolicyRepo
	exec       string

	apiHost     string
	apiPort     string
	apiProtocol string

	diodeTarget        string
	diodeAPIKey        string
	diodeAppNamePrefix string

	startTime  time.Time
	proc       *cmd.Cmd
	statusChan <-chan cmd.Status
	cancelFunc context.CancelFunc
	ctx        context.Context
}

type info struct {
	Version   string  `json:"version"`
	UpTimeMin float64 `json:"up_time_seconds"`
}

// Register registers the network discovery backend
func Register() bool {
	backend.Register("network_discovery", &networkDiscoveryBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

func (d *networkDiscoveryBackend) Configure(logger *zap.Logger, repo policies.PolicyRepo, config map[string]any, common config.BackendCommons) error {
	d.logger = logger
	d.policyRepo = repo

	var prs bool
	if d.apiHost, prs = config["host"].(string); !prs {
		d.apiHost = defaultAPIHost
	}
	if d.apiPort, prs = config["port"].(string); !prs {
		d.apiPort = defaultAPIPort
	}

	d.diodeTarget = common.Diode.Target
	d.diodeAPIKey = common.Diode.APIKey
	d.diodeAppNamePrefix = common.Diode.AgentName

	return nil
}

func (d *networkDiscoveryBackend) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("network-discovery", d.proc, d.logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "detail")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

func (d *networkDiscoveryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

	pvOptions := []string{
		"--host", d.apiHost,
		"--port", d.apiPort,
		"--diode-target", d.diodeTarget,
		"--diode-api-key", "********",
		"--diode-app-name-prefix", d.diodeAppNamePrefix,
	}

	d.logger.Info("network-discovery startup", zap.Strings("arguments", pvOptions))

	pvOptions[7] = d.diodeAPIKey

	d.proc = cmd.NewCmdOptions(cmd.Options{
		Buffered:  false,
		Streaming: true,
	}, d.exec, pvOptions...)
	d.statusChan = d.proc.Start()

	// log STDOUT and STDERR lines streaming from Cmd
	doneChan := make(chan struct{})
	go func() {
		defer func() {
			if doneChan != nil {
				close(doneChan)
			}
		}()
		for d.proc.Stdout != nil || d.proc.Stderr != nil {
			select {
			case line, open := <-d.proc.Stdout:
				if !open {
					d.proc.Stdout = nil
					continue
				}
				d.logger.Info("network-discovery stdout", zap.String("log", line))
			case line, open := <-d.proc.Stderr:
				if !open {
					d.proc.Stderr = nil
					continue
				}
				d.logger.Info("network-discovery stderr", zap.String("log", line))
			}
		}
	}()

	// wait for simple startup errors
	time.Sleep(time.Second)

	status := d.proc.Status()

	if status.Error != nil {
		d.logger.Error("network-discovery startup error", zap.Error(status.Error))
		return status.Error
	}

	if status.Complete {
		err := d.proc.Stop()
		if err != nil {
			d.logger.Error("proc.Stop error", zap.Error(err))
		}
		return errors.New("network-discovery startup error, check log")
	}

	d.logger.Info("network-discovery process started", zap.Int("pid", status.PID))

	var readinessErr error
	for backoff := 0; backoff < readinessBackoff; backoff++ {
		version, readinessErr := d.Version()
		if readinessErr == nil {
			d.logger.Info("network-discovery readiness ok, got version ", zap.String("network_discovery_version", version))
			break
		}
		backoffDuration := time.Duration(backoff) * time.Second
		d.logger.Info("network-discovery is not ready, trying again with backoff", zap.String("backoff backoffDuration", backoffDuration.String()))
		time.Sleep(backoffDuration)
	}

	if readinessErr != nil {
		d.logger.Error("network-discovery error on readiness", zap.Error(readinessErr))
		err := d.proc.Stop()
		if err != nil {
			d.logger.Error("proc.Stop error", zap.Error(err))
		}
		return readinessErr
	}

	return nil
}

func (d *networkDiscoveryBackend) Stop(ctx context.Context) error {
	d.logger.Info("routine call to stop network-discovery", zap.Any("routine", ctx.Value(config.ContextKey("routine"))))
	defer d.cancelFunc()
	err := d.proc.Stop()
	finalStatus := <-d.statusChan
	if err != nil {
		d.logger.Error("network-discovery shutdown error", zap.Error(err))
	}
	d.logger.Info("network-discovery process stopped", zap.Int("pid", finalStatus.PID), zap.Int("exit_code", finalStatus.Exit))
	return nil
}

func (d *networkDiscoveryBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(d.proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.logger.Error("failed to stop backend on restart procedure", zap.Error(err))
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "network-discovery"))
	// start it
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.logger.Error("failed to start backend on restart procedure", zap.Error(err))
		return err
	}
	return nil
}

func (d *networkDiscoveryBackend) GetStartTime() time.Time {
	return d.startTime
}

func (d *networkDiscoveryBackend) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("network-discovery", d.proc, d.logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

func (d *networkDiscoveryBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
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

func (d *networkDiscoveryBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

func (d *networkDiscoveryBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := d.RemovePolicy(data); err != nil {
			d.logger.Warn("policy failed to remove", zap.String("policy_id", data.ID), zap.String("policy_name", data.Name), zap.Error(err))
		}
	}

	d.logger.Debug("network-discovery policy apply", zap.String("policy_id", data.ID), zap.Any("data", data.Data))

	fullPolicy := map[string]any{
		"policies": map[string]any{
			data.Name: data.Data,
		},
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		d.logger.Warn("policy yaml marshal failure", zap.String("policy_id", data.ID), zap.Any("policy", fullPolicy))
		return err
	}

	var resp map[string]any
	url := fmt.Sprintf("%s://%s:%s/api/v1/%s", d.apiProtocol, d.apiHost, d.apiPort, "policies")
	err = backend.CommonRequest("network-discovery", d.proc, d.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.logger.Warn("policy application failure", zap.String("policy_id", data.ID), zap.ByteString("policy", policyYaml))
		return err
	}

	return nil
}

func (d *networkDiscoveryBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("network-discovery policy remove", zap.String("policy_id", data.ID))
	var resp any
	name := data.Name
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.apiProtocol, d.apiHost, d.apiPort, name)
	err := backend.CommonRequest("network-discovery", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}
