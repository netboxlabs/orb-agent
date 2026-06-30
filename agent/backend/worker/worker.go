package worker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

var _ backend.Backend = (*workerBackend)(nil)

const (
	versionTimeout      = 2
	capabilitiesTimeout = 5
	applyPolicyTimeout  = 10
	removePolicyTimeout = 20
	statusTimeout       = 5
	defaultExec         = "orb-worker"
	defaultAPIHost      = "localhost"
	defaultAPIPort      = "8071"
)

type workerBackend struct {
	logger       *slog.Logger
	policyRepo   policies.PolicyRepo
	exec         string
	filesManager filesmgr.Manager

	// lastResolveExecWarning records the last bad path that triggered a fallback
	// warning, so the warning isn't re-emitted on every resolveExecPath call for
	// the same misconfiguration. Concurrent Stop/Start sequences against the
	// same backend are serialized by orbAgent.backendRestartLock (defined in
	// agent.go), so this field is accessed under that effective lock — no
	// additional synchronization needed here.
	lastResolveExecWarning string

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
	debug                bool // Debug flag from CLI

	startTime  time.Time
	proc       backend.Commander
	statusChan <-chan backend.CmdStatus
	cancelFunc context.CancelFunc
	ctx        context.Context
}

type info struct {
	Version   string  `json:"version"`
	UpTimeMin float64 `json:"up_time_min"`
}

// Register registers the backend
func Register() bool {
	backend.Register("worker", &workerBackend{
		apiProtocol: "http",
		exec:        defaultExec,
	})
	return true
}

func (d *workerBackend) checkWorkerSupportsDebug() bool {
	cmd := exec.Command(d.resolveExecPath(), "--help")
	output, err := cmd.Output()
	if err != nil {
		d.logger.Warn("unable to check orb-worker help, skipping --debug flag",
			"error", err)
		return false
	}

	supportsDebug := strings.Contains(string(output), "--debug")

	if !supportsDebug {
		d.logger.Debug("orb-worker does not support --debug flag")
	} else {
		d.logger.Debug("orb-worker supports --debug flag")
	}

	return supportsDebug
}

func (d *workerBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, fm filesmgr.Manager,
) error {
	d.logger = logger.With("backend", "worker")
	d.policyRepo = repo
	d.filesManager = fm
	d.diodeTargetFromOtel = false
	d.debug = common.Debug

	d.apiHost = backend.ConfigStringOrDefault(config, "host", defaultAPIHost)
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

	if common.Otlp.Grpc != "" {
		d.diodeOtelEndpoint = common.Otlp.Grpc
		d.logger.Info("orb-worker using OTLP endpoint",
			"endpoint", d.diodeOtelEndpoint)
	}
	if d.diodeTarget == "" && d.diodeOtelEndpoint != "" {
		d.diodeTarget = d.diodeOtelEndpoint
		d.diodeTargetFromOtel = true
	}

	return nil
}

func (d *workerBackend) Version() (string, error) {
	var info info
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("worker", d.proc, d.logger, url, &info, http.MethodGet,
		http.NoBody, "application/json", versionTimeout, "detail")
	if err != nil {
		return "", err
	}
	return info.Version, nil
}

func (d *workerBackend) Start(ctx context.Context, cancelFunc context.CancelFunc) error {
	d.startTime = time.Now()
	d.cancelFunc = cancelFunc
	d.ctx = ctx

	dOptions := []string{
		"--diode-app-name-prefix", d.diodeAppNamePrefix,
		"--host", d.apiHost,
		"--port", d.apiPort,
	}

	// Add debug flag if enabled and worker supports it
	if d.debug && d.checkWorkerSupportsDebug() {
		dOptions = append(dOptions, "--debug")
	} else if d.debug {
		d.logger.Warn("Debug flag requested but not supported by orb-worker, skipping --debug flag")
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

	if d.diodeOtelEndpoint != "" {
		dOptions = append(dOptions, "--otel-endpoint", d.diodeOtelEndpoint)
	}

	d.logger.Info("worker startup", "arguments", redact.Args(dOptions))

	return backend.StartProcess(ctx, backend.StartSpec{
		Logger:         d.logger,
		NameDisplay:    "worker",
		NameUnderscore: "worker",
		Exec:           d.resolveExecPath(),
		Args:           dOptions,
		LogLine:        d.logLineAdapter,
		SetProc: func(p backend.Commander, ch <-chan backend.CmdStatus) {
			d.proc = p
			d.statusChan = ch
		},
		ReadinessCheck: d.Version,
	})
}

// logLineAdapter routes a streamed stdout/stderr line to the worker output
// normalizer with the level matching the source stream.
func (d *workerBackend) logLineAdapter(line string, isStderr bool) {
	level := slog.LevelInfo
	if isStderr {
		level = slog.LevelError
	}
	d.logWorkerOutput(line, level)
}

func (d *workerBackend) Stop(ctx context.Context) error {
	d.logger.Info("routine call to stop worker", "routine", ctx.Value(config.ContextKey("routine")))
	defer d.cancelFunc()
	backend.StopProcess(d.logger, d.proc, d.statusChan, backend.DefaultStopGracePeriod, "worker")
	return nil
}

func (d *workerBackend) FullReset(ctx context.Context) error {
	// force a stop, which stops scrape as well. if proc is dead, it no ops.
	if state, _, _ := backend.GetRunningStatus(d.proc); state == backend.Running {
		if err := d.Stop(ctx); err != nil {
			d.logger.Error("failed to stop backend on restart procedure", "error", err)
			return err
		}
	}
	// for each policy, restart the scraper
	backendCtx, cancelFunc := context.WithCancel(context.WithValue(ctx, config.ContextKey("routine"), "worker"))
	// start it
	if err := d.Start(backendCtx, cancelFunc); err != nil {
		d.logger.Error("failed to start backend on restart procedure", "error", err)
		return err
	}
	return nil
}

func (d *workerBackend) GetStartTime() time.Time {
	return d.startTime
}

func (d *workerBackend) logWorkerOutput(line string, fallback slog.Level) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}

	msg := trimmed
	attrs := []slog.Attr(nil)
	level := fallback

	if parsedMsg, parsedAttrs, parsedLevel, ok := normalizeWorkerLine(trimmed, fallback); ok {
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

func (d *workerBackend) GetCapabilities() (map[string]any, error) {
	caps := make(map[string]any)
	url := fmt.Sprintf("%s://%s:%s/api/v1/capabilities", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("worker", d.proc, d.logger, url, &caps, http.MethodGet,
		http.NoBody, "application/json", capabilitiesTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return caps, nil
}

func (d *workerBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
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

func (d *workerBackend) GetInitialState() backend.RunningStatus {
	return backend.Unknown
}

func (d *workerBackend) ManagedBinaryName() string { return "orb-worker" }

// resolveExecPath returns the path to the orb-worker binary. If FilesManager
// tracks an entry under the name "orb-worker" and that entry points to a
// regular file, that path is used. If the entry path is a directory (e.g.
// when Ensure was called with Extract:true and no filename suffix) or the stat
// fails, a warning is logged and the baked-in binary path is used as fallback.
// The warning is emitted at most once per distinct bad path to avoid log spam
// when a persistent misconfiguration causes every exec.Command call to fall back.
func (d *workerBackend) resolveExecPath() string {
	if d.filesManager == nil {
		return d.exec
	}
	entry, ok := d.filesManager.Get("orb-worker")
	if !ok || entry.Path == "" {
		return d.exec
	}
	info, err := os.Stat(entry.Path)
	if err != nil || info.IsDir() {
		if d.lastResolveExecWarning != entry.Path {
			d.logger.Warn("filesmgr orb-worker entry is not a regular file; falling back to baked binary",
				"path", entry.Path, "error", err)
			d.lastResolveExecWarning = entry.Path
		}
		return d.exec
	}
	// Path is valid — clear warning state so a future regression re-logs.
	d.lastResolveExecWarning = ""
	return entry.Path
}

func (d *workerBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	if updatePolicy {
		// To update a policy it's necessary first remove it and then apply a new version
		if err := d.RemovePolicy(data); err != nil {
			d.logger.Warn("policy failed to remove", "policy_id", data.ID,
				"policy_name", data.Name, "error", err)
		}
	}

	d.logger.Debug("worker policy apply", "policy_id", data.ID, "data", data.Data)

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
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies", d.apiProtocol, d.apiHost, d.apiPort)
	err = backend.CommonRequest("worker", d.proc, d.logger, url, &resp, http.MethodPost,
		bytes.NewBuffer(policyYaml), "application/x-yaml", applyPolicyTimeout, "detail")
	if err != nil {
		d.logger.Warn("policy application failure", "policy_id", data.ID, "policy_name", data.Name)
		return err
	}

	return nil
}

func (d *workerBackend) RemovePolicy(data policies.PolicyData) error {
	d.logger.Debug("worker policy remove", "policy_id", data.ID)
	var resp any
	var name string
	// Since we use Name for removing policies not IDs, if there is a change, we need to remove the previous name of the policy
	if data.PreviousPolicyData != nil && data.PreviousPolicyData.Name != data.Name {
		name = data.PreviousPolicyData.Name
	} else {
		name = data.Name
	}
	url := fmt.Sprintf("%s://%s:%s/api/v1/policies/%s", d.apiProtocol, d.apiHost, d.apiPort, name)
	err := backend.CommonRequest("worker", d.proc, d.logger, url, &resp, http.MethodDelete,
		http.NoBody, "application/json", removePolicyTimeout, "detail")
	if err != nil {
		return err
	}
	return nil
}

func (d *workerBackend) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	var resp backend.StatusResponse
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.apiProtocol, d.apiHost, d.apiPort)
	err := backend.CommonRequest("worker", d.proc, d.logger, url, &resp, http.MethodGet,
		http.NoBody, "application/json", statusTimeout, "detail")
	if err != nil {
		return nil, err
	}
	return resp.Policies, nil
}

func normalizeWorkerLine(line string, fallback slog.Level) (string, []slog.Attr, slog.Level, bool) {
	firstColon := strings.Index(line, ":")
	if firstColon <= 0 {
		return "", nil, fallback, false
	}

	levelCandidate := strings.TrimSpace(line[:firstColon])
	level, ok := parseWorkerLevel(levelCandidate)
	if !ok {
		return "", nil, fallback, false
	}

	remainder := strings.TrimSpace(line[firstColon+1:])
	if remainder == "" {
		return strings.TrimSpace(line), nil, level, true
	}

	var attrs []slog.Attr
	message := remainder

	if secondColon := strings.Index(remainder, ":"); secondColon >= 0 {
		moduleCandidate := strings.TrimSpace(remainder[:secondColon])
		rest := strings.TrimSpace(remainder[secondColon+1:])

		if moduleCandidate != "" && !strings.ContainsAny(moduleCandidate, " \t") {
			attrs = append(attrs, slog.String("module", moduleCandidate))
			if rest != "" {
				message = rest
			} else {
				message = remainder
			}
		}
	}

	if message == "" {
		message = strings.TrimSpace(line)
	}

	if message == "" {
		return "", nil, level, false
	}

	return message, attrs, level, true
}

func parseWorkerLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "trace":
		return slog.LevelDebug, true
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error", "err", "exception":
		return slog.LevelError, true
	case "critical", "fatal":
		return slog.LevelError, true
	default:
		return 0, false
	}
}
