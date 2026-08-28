package gnmidiscovery

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

var _ backend.Backend = (*gnmiDiscoveryBackend)(nil)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	statusTimeout       = 5
	defaultExec         = "gnmi-discovery"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "8075"
)

type gnmiDiscoveryBackend struct {
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

	// gNMI-specific options
	profilesDir      string
	otelExportPeriod string
	logFormat        string

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

// Register registers the gNMI discovery backend with the agent's backend
// registry under the name "gnmi_discovery".
func Register() bool {
	backend.Register("gnmi_discovery", &gnmiDiscoveryBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

// Configure stores the backend configuration, merging the per-backend config
// map with the shared Diode/OTLP commons (per-backend keys take precedence).
func (d *gnmiDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.logger = logger.With("backend", "gnmi_discovery")
	d.policyRepo = repo
	d.diodeTargetFromOtel = false

	d.apiHost = backend.ConfigValueOrDefault(config, "host", defaultAPIHost)
	d.apiPort = backend.ConfigValueOrDefault(config, "port", defaultAPIPort)

	// String options fall back to the shared Diode commons when unset.
	d.diodeTarget = backend.ConfigValueOrDefault(config, "target", common.Diode.Target)
	d.diodeClientID = backend.ConfigValueOrDefault(config, "client_id", common.Diode.ClientID)
	d.diodeClientSecret = backend.ConfigValueOrDefault(config, "client_secret", common.Diode.ClientSecret)
	d.diodeAppNamePrefix = backend.ConfigValueOrDefault(config, "agent_name", common.Diode.AgentName)
	d.diodeDryRunOutputDir = backend.ConfigValueOrDefault(config, "dry_run_output_dir", common.Diode.DryRunOutputDir)

	d.diodeDryRun = backend.ConfigValueOrDefault(config, "dry_run", common.Diode.DryRun)

	if logLevel, prs := config["log_level"].(string); prs {
		d.diodeLogLevel = logLevel
	} else if debug, prs := config["debug"].(bool); prs && debug {
		d.diodeLogLevel = "debug"
	} else if logger.Enabled(context.Background(), slog.LevelDebug) {
		d.diodeLogLevel = "debug"
	}

	// gNMI-specific options
	d.profilesDir = backend.ConfigValueOrDefault(config, "profiles_dir", "")
	d.logFormat = backend.ConfigValueOrDefault(config, "log_format", "")
	d.otelExportPeriod = backend.ConfigValueOrDefault(config, "otel_export_period", "")

	if common.Otlp.Grpc != "" {
		d.diodeOtelEndpoint = common.Otlp.Grpc
		d.logger.Info("gnmi-discovery using OTLP endpoint",
			"endpoint", d.diodeOtelEndpoint)
	}
	if d.diodeTarget == "" && d.diodeOtelEndpoint != "" {
		d.diodeTarget = d.diodeOtelEndpoint
		d.diodeTargetFromOtel = true
	}

	return nil
}

// Version returns the running gnmi-discovery version from its REST status endpoint.
func (d *gnmiDiscoveryBackend) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("gnmi-discovery", d.proc, d.logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "detail")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

// buildArgs assembles the gnmi-discovery process arguments from the configured
// options. Flags are order-independent, so they are appended in a single pass.
func (d *gnmiDiscoveryBackend) buildArgs() []string {
	args := []string{
		"--diode-app-name-prefix", d.diodeAppNamePrefix,
		"--host", d.apiHost,
		"--port", d.apiPort,
	}

	if d.diodeDryRun {
		args = append(args, "--dry-run")
		if d.diodeDryRunOutputDir != "" {
			args = append(args, "--dry-run-output-dir", d.diodeDryRunOutputDir)
		}
	} else {
		args = append(args, "--diode-target", d.diodeTarget)
		if !d.diodeTargetFromOtel {
			args = append(args,
				"--diode-client-id", d.diodeClientID,
				"--diode-client-secret", d.diodeClientSecret,
			)
		}
	}

	if d.diodeLogLevel != "" {
		args = append(args, "--log-level", d.diodeLogLevel)
		d.logger.Info("gnmi-discovery using log level", "log_level", d.diodeLogLevel)
	}
	if d.diodeOtelEndpoint != "" {
		args = append(args, "--otel-endpoint", d.diodeOtelEndpoint)
		d.logger.Info("gnmi-discovery using OTLP metrics endpoint", "endpoint", d.diodeOtelEndpoint)
	}

	// gNMI-specific options
	if d.profilesDir != "" {
		args = append(args, "--profiles-dir", d.profilesDir)
		d.logger.Info("gnmi-discovery using profiles dir", "profiles_dir", d.profilesDir)
	}
	if d.otelExportPeriod != "" {
		args = append(args, "--otel-export-period", d.otelExportPeriod)
	}
	if d.logFormat != "" {
		args = append(args, "--log-format", d.logFormat)
	}

	return args
}

// Start launches the gnmi-discovery process, streams its logs to the agent
// logger, and blocks until the process's REST API is ready — returning an error
// if it exits early or never becomes ready.
func (d *gnmiDiscoveryBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

	args := d.buildArgs()

	d.logger.Info("gnmi-discovery startup", "arguments", redact.Args(args))

	return backend.StartProcess(backend.StartSpec{
		Logger:         d.logger,
		NameDisplay:    "gnmi-discovery",
		NameUnderscore: "gnmi_discovery",
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

// logLineAdapter routes a streamed stdout/stderr line to the gnmi-discovery
// output normalizer with the level matching the source stream.
func (d *gnmiDiscoveryBackend) logLineAdapter(line string, isStderr bool) {
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
	}

	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	d.logger.LogAttrs(ctx, level, msg, attrs...)
}

// Stop gracefully stops the gnmi-discovery process and cancels the backend context.
func (d *gnmiDiscoveryBackend) Stop(ctx context.Context) error {
	d.logger.Info("routine call to stop gnmi-discovery", "routine", ctx.Value(config.ContextKey("routine")))
	if d.cancelFunc != nil {
		defer d.cancelFunc()
	}
	backend.StopProcess(d.logger, d.proc, d.statusChan, backend.DefaultStopGracePeriod, "gnmi_discovery")
	return nil
}

// FullReset stops the gnmi-discovery process (if running) and starts it again.
func (d *gnmiDiscoveryBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(d.proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "gnmi-discovery"))
	// start it
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.logger.Error("failed to start backend on restart procedure", "error", err)
		return err
	}
	return nil
}

// GetStartTime returns the time the gnmi-discovery process was last started.
func (d *gnmiDiscoveryBackend) GetStartTime() time.Time {
	return d.startTime
}

// GetCapabilities returns the backend's capabilities from its REST endpoint.
func (d *gnmiDiscoveryBackend) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("gnmi-discovery", d.proc, d.logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

// GetRunningStatus reports the process state, also verifying the REST API is
// reachable when the process is running.
func (d *gnmiDiscoveryBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
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

// GetInitialState returns the backend's initial running state (Unknown).
func (d *gnmiDiscoveryBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

// ApplyPolicy applies a policy via the REST API, removing the prior version
// first when this is an update.
func (d *gnmiDiscoveryBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := d.RemovePolicy(data); err != nil {
			d.logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	// The body is deliberately not logged. A gnmi policy may carry a literal
	// password, and a scope-level credential now covers a whole subnet rather
	// than one device, so a debug-level agent would put the campus password in
	// the log stream. The id and name identify the policy for troubleshooting.
	d.logger.Debug("gnmi-discovery policy apply", "policy_id", data.ID, "policy_name", data.Name)

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
	err = backend.CommonRequest("gnmi-discovery", d.proc, d.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.logger.Warn("policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

// RemovePolicy deletes a policy by name via the REST API (using the previous
// name when a policy was renamed).
func (d *gnmiDiscoveryBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("gnmi-discovery policy remove", "policy_id", data.ID)
	var resp any
	name := data.Name
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.apiProtocol, d.apiHost, d.apiPort, neturl.PathEscape(name))
	err := backend.CommonRequest("gnmi-discovery", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}

// gnmiStatusResponse mirrors gnmi-discovery's /api/v1/status. A run carries both
// a `targets` array and a single `target`, while the shared
// backend.PolicyStatusRun has only the array — so decoding straight into
// backend.StatusResponse would drop a run's target entirely. We decode into this
// shape and normalize below.
type gnmiStatusResponse struct {
	Policies []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Runs   []struct {
			ID          string   `json:"id"`
			Target      string   `json:"target"`
			Targets     []string `json:"targets"`
			Kind        string   `json:"kind"`
			Status      string   `json:"status"`
			Reason      string   `json:"reason"`
			EntityCount int64    `json:"entity_count"`
			CreatedAt   int64    `json:"created_at"`
			UpdatedAt   int64    `json:"updated_at"`
		} `json:"runs"`
	} `json:"policies"`
}

// runTargets picks the target list to report for one run.
//
// The array wins. A sweep run covering several scope entries carries each
// original host string in `targets` and a comma-joined compatibility value in
// `target`, so reading the singular field would deliver
// "10.0.0.0/24,10.1.0.0/24" to the fleet as one target instead of two. The
// singular field remains the fallback for a payload that predates the array.
func runTargets(targets []string, target string) []string {
	if len(targets) > 0 {
		return targets
	}
	if target == "" {
		return nil
	}
	return []string{target}
}

// GetPolicyStatus returns per-policy run status from the REST status endpoint,
// normalizing each run's singular target into the shared Targets slice.
func (d *gnmiDiscoveryBackend) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	var resp gnmiStatusResponse
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("gnmi-discovery", d.proc, d.logger, url, &resp, http.MethodGet,
		http.NoBody, "application/json", statusTimeout, "detail")
	if err != nil {
		return nil, err
	}

	policies := make([]backend.PolicyStatus, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		runs := make([]backend.PolicyStatusRun, 0, len(p.Runs))
		for _, r := range p.Runs {
			targets := runTargets(r.Targets, r.Target)
			runs = append(runs, backend.PolicyStatusRun{
				ID:          r.ID,
				Status:      r.Status,
				Reason:      r.Reason,
				EntityCount: r.EntityCount,
				CreatedAt:   r.CreatedAt,
				UpdatedAt:   r.UpdatedAt,
				Targets:     targets,
				// A sweep run and a flush run describe different things and
				// complete at different times, and can carry the same target
				// list, so nothing else in the payload tells them apart.
				Kind: r.Kind,
			})
		}
		policies = append(policies, backend.PolicyStatus{
			Name:   p.Name,
			Status: p.Status,
			Runs:   runs,
		})
	}
	return policies, nil
}
