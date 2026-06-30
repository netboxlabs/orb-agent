// Package discovery provides DiscoveryBase, the shared state and lifecycle/REST
// machinery embedded by the diode discovery backends (network/snmp/device/gnmi).
//
// DiscoveryBase owns the behavior that is identical across those backends —
// Configure, Start, Stop, FullReset, the REST helpers (Version, GetCapabilities,
// GetRunningStatus, ApplyPolicy, RemovePolicy, GetPolicyStatus) and lifecycle
// bookkeeping — while three exported func-field hooks (BuildArgs, LogLine,
// ConfigureExtra) absorb the per-backend divergences. Because DiscoveryBase lives
// in its own package and the hook bodies stay in the embedder packages, every
// field or hook those packages read or write is exported (Go does not promote
// unexported fields across packages).
package discovery

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	// StatusTimeout is exported because gnmi's retained GetPolicyStatus override
	// (in its own package) passes it to backend.CommonRequest.
	StatusTimeout       = 5
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20

	defaultAPIHost = "localhost"
)

// DiscoveryBase holds the shared state and lifecycle/REST methods embedded by the
// diode discovery backends. Fields and hooks the embedder packages touch are
// exported; statusChan/cancelFunc/startTime stay unexported (only base methods
// use them).
type DiscoveryBase struct {
	Logger *slog.Logger
	// PolicyRepo is set by each embedder's Configure (mirroring the canonical
	// backends). It is exported so the embedder packages can write it; no base
	// method reads it today.
	PolicyRepo policies.PolicyRepo
	Exec       string

	ApiHost     string
	ApiPort     string
	ApiProtocol string

	DiodeTarget          string
	DiodeClientID        string
	DiodeClientSecret    string
	DiodeAppNamePrefix   string
	DiodeOtelEndpoint    string
	DiodeTargetFromOtel  bool
	DiodeDryRun          bool
	DiodeDryRunOutputDir string
	DiodeLogLevel        string

	// NameHyphen is the hyphen form (e.g. "network-discovery"): the CommonRequest
	// client id, every lifecycle log, and every error string. NameUnderscore is
	// the underscore form (e.g. "network_discovery") passed only to StopProcess.
	NameHyphen     string
	NameUnderscore string

	startTime  time.Time
	Proc       backend.Commander
	statusChan <-chan backend.CmdStatus
	cancelFunc context.CancelFunc
	Ctx        context.Context

	// BuildArgs assembles the process arguments. The base never builds the flag
	// list itself; each backend wires its own buildArgs (core flags diverge:
	// device omits --log-level, gnmi appends gNMI extras, etc.).
	BuildArgs func() []string
	// LogLine streams one line of process output to the agent logger; each
	// backend wraps its own normalizer + Logger.LogAttrs, reading d.Ctx.
	LogLine func(line string, isStderr bool)
	// ConfigureExtra runs early in Configure (after host/port, before the diode
	// reads) so per-backend validation aborts before the OTLP log. May be nil.
	ConfigureExtra func(config map[string]any) error
}

// Configure stores the backend configuration, merging the per-backend config map
// with the shared Diode/OTLP commons (per-backend keys take precedence). The
// ConfigureExtra hook runs early so per-backend validation aborts before the OTLP
// log; the OTLP-endpoint/target-from-otel block is shared base logic.
func (d *DiscoveryBase) Configure(config map[string]any, common config.BackendCommons) error {
	d.DiodeTargetFromOtel = false

	d.ApiHost = backend.ConfigStringOrDefault(config, "host", defaultAPIHost)
	// The default port differs per backend (network 8073 / snmp 8070 / device
	// 8072 / gnmi 8075), so the embedder pre-seeds ApiPort with its default in
	// Register(); the base only overrides it when an explicit port is configured.
	// A configured port may be a YAML number, so stringify whatever is present.
	if port, prs := config["port"]; prs {
		d.ApiPort = fmt.Sprintf("%v", port)
	}

	if d.ConfigureExtra != nil {
		if err := d.ConfigureExtra(config); err != nil {
			return err
		}
	}

	d.DiodeTarget = backend.ConfigStringOrDefault(config, "target", common.Diode.Target)
	d.DiodeClientID = backend.ConfigStringOrDefault(config, "client_id", common.Diode.ClientID)
	d.DiodeClientSecret = backend.ConfigStringOrDefault(config, "client_secret", common.Diode.ClientSecret)
	d.DiodeAppNamePrefix = backend.ConfigStringOrDefault(config, "agent_name", common.Diode.AgentName)
	d.DiodeDryRun = backend.ConfigBoolOrDefault(config, "dry_run", common.Diode.DryRun)
	d.DiodeDryRunOutputDir = backend.ConfigStringOrDefault(config, "dry_run_output_dir", common.Diode.DryRunOutputDir)

	if logLevel, prs := config["log_level"].(string); prs {
		d.DiodeLogLevel = logLevel
	} else if debug, prs := config["debug"].(bool); prs && debug {
		d.DiodeLogLevel = "debug"
	} else if d.Logger.Enabled(context.Background(), slog.LevelDebug) {
		d.DiodeLogLevel = "debug"
	}

	if common.Otlp.Grpc != "" {
		d.DiodeOtelEndpoint = common.Otlp.Grpc
		d.Logger.Info(d.NameHyphen+" using OTLP endpoint",
			"endpoint", d.DiodeOtelEndpoint)
	}
	if d.DiodeTarget == "" && d.DiodeOtelEndpoint != "" {
		d.DiodeTarget = d.DiodeOtelEndpoint
		d.DiodeTargetFromOtel = true
	}

	return nil
}

// Version returns the running backend version from its REST status endpoint.
func (d *DiscoveryBase) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.ApiProtocol, d.ApiHost, d.ApiPort)
	err := backend.CommonRequest(d.NameHyphen, d.Proc, d.Logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "detail")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

// Start launches the backend process via backend.StartProcess, streaming its logs
// through the LogLine hook and blocking until its REST API is ready.
func (d *DiscoveryBase) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.Ctx = ctx

	args := d.BuildArgs()
	d.Logger.Info(d.NameHyphen+" startup", "arguments", redact.Args(args))

	return backend.StartProcess(ctx, backend.StartSpec{
		Logger:         d.Logger,
		NameDisplay:    d.NameHyphen,
		NameUnderscore: d.NameUnderscore,
		Exec:           d.Exec,
		Args:           args,
		LogLine:        d.LogLine,
		SetProc: func(p backend.Commander, ch <-chan backend.CmdStatus) {
			d.Proc = p
			d.statusChan = ch
		},
		ReadinessCheck: d.Version,
	})
}

// Stop gracefully stops the backend process and cancels the backend context.
func (d *DiscoveryBase) Stop(ctx context.Context) error {
	d.Logger.Info("routine call to stop "+d.NameHyphen, "routine", ctx.Value(config.ContextKey("routine")))
	if d.cancelFunc != nil {
		defer d.cancelFunc()
	}
	backend.StopProcess(d.Logger, d.Proc, d.statusChan, backend.DefaultStopGracePeriod, d.NameUnderscore)
	return nil
}

// FullReset stops the backend process (if running) and starts it again.
func (d *DiscoveryBase) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(d.Proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.Logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), d.NameHyphen))
	// start it
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.Logger.Error("failed to start backend on restart procedure", "error", err)
		return err
	}
	return nil
}

// GetStartTime returns the time the backend process was last started.
func (d *DiscoveryBase) GetStartTime() time.Time {
	return d.startTime
}

// GetCapabilities returns the backend's capabilities from its REST endpoint.
func (d *DiscoveryBase) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", d.ApiProtocol, d.ApiHost, d.ApiPort)
	err := backend.CommonRequest(d.NameHyphen, d.Proc, d.Logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

// GetRunningStatus reports the process state, also verifying the REST API is
// reachable when the process is running.
func (d *DiscoveryBase) GetRunningStatus() (backend.RunningStatus, string, error) {
	// first check process status
	runningStatus, errMsg, err := backend.GetRunningStatus(d.Proc)
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

// GetInitialState returns the backend's initial running state (Unknown).
func (d *DiscoveryBase) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

// ApplyPolicy applies a policy via the REST API, removing the prior version first
// when this is an update.
func (d *DiscoveryBase) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := d.RemovePolicy(data); err != nil {
			d.Logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	d.Logger.Debug(d.NameHyphen+" policy apply", "policy_id", data.ID, "data", data.Data)

	fullPolicy := map[string]any{
		"policies": map[string]any{
			data.Name: data.Data,
		},
	}

	policyYaml, err := yaml.Marshal(fullPolicy)
	if err != nil {
		d.Logger.Warn("policy yaml marshal failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	var resp map[string]any
	url := fmt.Sprintf("%s://%s:%s/api/v1/%s", d.ApiProtocol, d.ApiHost, d.ApiPort, "policies")
	err = backend.CommonRequest(d.NameHyphen, d.Proc, d.Logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.Logger.Warn("policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

// RemovePolicy deletes a policy by name via the REST API (using the previous name
// when a policy was renamed). The name is path-escaped before being placed in the
// request URL.
func (d *DiscoveryBase) RemovePolicy(data policies.PolicyData) error {
	d.Logger.Debug(d.NameHyphen+" policy remove", "policy_id", data.ID)
	var resp any
	name := data.Name
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.ApiProtocol, d.ApiHost, d.ApiPort, neturl.PathEscape(name))
	err := backend.CommonRequest(d.NameHyphen, d.Proc, d.Logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}

// GetPolicyStatus returns per-policy run status from the REST status endpoint.
func (d *DiscoveryBase) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	var resp backend.StatusResponse
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.ApiProtocol, d.ApiHost, d.ApiPort)
	err := backend.CommonRequest(d.NameHyphen, d.Proc, d.Logger, url, &resp, http.MethodGet,
		http.NoBody, "application/json", StatusTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return resp.Policies, nil
}

// info mirrors the version payload of each backend's /api/v1/status endpoint.
type info struct {
	Version   string  `json:"version"`
	UpTimeMin float64 `json:"up_time_seconds"`
}
