package gnmidiscovery

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/discovery"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*gnmiDiscoveryBackend)(nil)

const (
	defaultExec    = "gnmi-discovery"
	defaultAPIPort = "8075"
)

type gnmiDiscoveryBackend struct {
	discovery.Base

	// gNMI-specific options
	profilesDir      string
	otelExportPeriod string
	logFormat        string
}

// Register registers the gNMI discovery backend with the agent's backend
// registry under the name "gnmi_discovery".
func Register() bool {
	b := &gnmiDiscoveryBackend{
		Base: discovery.Base{
			Exec:           defaultExec,
			APIProtocol:    "http",
			APIPort:        defaultAPIPort,
			NameHyphen:     "gnmi-discovery",
			NameUnderscore: "gnmi_discovery",
		},
	}
	b.BuildArgs = b.buildArgs
	b.LogLine = b.logLineAdapter
	b.ConfigureExtra = b.configureExtra
	backend.Register("gnmi_discovery", b)
	return true
}

func (d *gnmiDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.Logger = logger.With("backend", "gnmi_discovery")
	d.PolicyRepo = repo
	return d.Base.Configure(config, common)
}

// configureExtra parses the gnmi-specific profiles_dir, log_format, and
// otel_export_period keys. It runs early in Configure (after host/port, before
// diode/OTLP reads) so the keys are populated before buildArgs consumes them.
func (d *gnmiDiscoveryBackend) configureExtra(config map[string]any) error {
	d.profilesDir = backend.ConfigStringOrDefault(config, "profiles_dir", "")
	d.logFormat = backend.ConfigStringOrDefault(config, "log_format", "")
	d.otelExportPeriod = backend.ConfigValueOrDefault(config, "otel_export_period", "")
	return nil
}

// buildArgs assembles the gnmi-discovery process arguments from the configured
// options. Flags are order-independent, so they are appended in a single pass.
func (d *gnmiDiscoveryBackend) buildArgs() []string {
	args := []string{
		"--diode-app-name-prefix", d.DiodeAppNamePrefix,
		"--host", d.APIHost,
		"--port", d.APIPort,
	}

	if d.DiodeDryRun {
		args = append(args, "--dry-run")
		if d.DiodeDryRunOutputDir != "" {
			args = append(args, "--dry-run-output-dir", d.DiodeDryRunOutputDir)
		}
	} else {
		args = append(args, "--diode-target", d.DiodeTarget)
		if !d.DiodeTargetFromOtel {
			args = append(args,
				"--diode-client-id", d.DiodeClientID,
				"--diode-client-secret", d.DiodeClientSecret,
			)
		}
	}

	if d.DiodeLogLevel != "" {
		args = append(args, "--log-level", d.DiodeLogLevel)
		d.Logger.Info("gnmi-discovery using log level", "log_level", d.DiodeLogLevel)
	}
	if d.DiodeOtelEndpoint != "" {
		args = append(args, "--otel-endpoint", d.DiodeOtelEndpoint)
		d.Logger.Info("gnmi-discovery using OTLP metrics endpoint", "endpoint", d.DiodeOtelEndpoint)
	}

	// gNMI-specific options
	if d.profilesDir != "" {
		args = append(args, "--profiles-dir", d.profilesDir)
		d.Logger.Info("gnmi-discovery using profiles dir", "profiles_dir", d.profilesDir)
	}
	if d.otelExportPeriod != "" {
		args = append(args, "--otel-export-period", d.otelExportPeriod)
	}
	if d.logFormat != "" {
		args = append(args, "--log-format", d.logFormat)
	}

	return args
}

// logLineAdapter logs one line of process output, parsing it as logfmt
// (structured attrs + level) when possible and falling back to the raw line.
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

	ctx := d.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	d.Logger.LogAttrs(ctx, level, msg, attrs...)
}

// gnmiStatusResponse mirrors gnmi-discovery's /api/v1/status. Each run carries a
// single `target` (string), unlike the shared backend.PolicyStatusRun which
// expects a `targets` array — so decoding straight into backend.StatusResponse
// would drop the per-run target. We decode into this shape and normalize
// `target` into Targets below.
type gnmiStatusResponse struct {
	Policies []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Runs   []struct {
			ID          string `json:"id"`
			Target      string `json:"target"`
			Status      string `json:"status"`
			Reason      string `json:"reason"`
			EntityCount int64  `json:"entity_count"`
			CreatedAt   int64  `json:"created_at"`
			UpdatedAt   int64  `json:"updated_at"`
		} `json:"runs"`
	} `json:"policies"`
}

// GetPolicyStatus returns per-policy run status from the REST status endpoint,
// normalizing each run's singular target into the shared Targets slice.
func (d *gnmiDiscoveryBackend) GetPolicyStatus() ([]backend.PolicyStatus, error) {
	var resp gnmiStatusResponse
	url := fmt.Sprintf("%s://%s:%s/api/v1/status", d.APIProtocol, d.APIHost, d.APIPort)
	err := backend.CommonRequest("gnmi-discovery", d.Proc, d.Logger, url, &resp, http.MethodGet,
		http.NoBody, "application/json", discovery.StatusTimeout, "detail")
	if err != nil {
		return nil, err
	}

	policies := make([]backend.PolicyStatus, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		runs := make([]backend.PolicyStatusRun, 0, len(p.Runs))
		for _, r := range p.Runs {
			var targets []string
			if r.Target != "" {
				targets = []string{r.Target}
			}
			runs = append(runs, backend.PolicyStatusRun{
				ID:          r.ID,
				Status:      r.Status,
				Reason:      r.Reason,
				EntityCount: r.EntityCount,
				CreatedAt:   r.CreatedAt,
				UpdatedAt:   r.UpdatedAt,
				Targets:     targets,
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
