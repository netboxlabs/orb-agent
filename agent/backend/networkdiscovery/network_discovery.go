package networkdiscovery

import (
	"context"
	"log/slog"
	"strings"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/discovery"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*networkDiscoveryBackend)(nil)

const (
	defaultExec    = "network-discovery"
	defaultAPIPort = "8073"
)

type networkDiscoveryBackend struct {
	discovery.DiscoveryBase
}

// Register registers the network discovery backend
func Register() bool {
	b := &networkDiscoveryBackend{
		DiscoveryBase: discovery.DiscoveryBase{
			Exec:           defaultExec,
			ApiProtocol:    "http",
			ApiPort:        defaultAPIPort,
			NameHyphen:     "network-discovery",
			NameUnderscore: "network_discovery",
		},
	}
	b.BuildArgs = b.buildArgs
	b.LogLine = b.logLineAdapter
	backend.Register("network_discovery", b)
	return true
}

func (d *networkDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.Logger = logger.With("backend", "network_discovery")
	d.PolicyRepo = repo
	return d.DiscoveryBase.Configure(config, common)
}

func (d *networkDiscoveryBackend) buildArgs() []string {
	dOptions := []string{
		"--diode-app-name-prefix", d.DiodeAppNamePrefix,
		"--host", d.ApiHost,
		"--port", d.ApiPort,
	}
	if d.DiodeDryRun {
		dOptions = append([]string{
			"--dry-run",
			"--dry-run-output-dir", d.DiodeDryRunOutputDir,
		}, dOptions...)
	} else {
		opts := []string{
			"--diode-target", d.DiodeTarget,
		}
		if !d.DiodeTargetFromOtel {
			opts = append(opts,
				"--diode-client-id", d.DiodeClientID,
				"--diode-client-secret", d.DiodeClientSecret,
			)
		}
		dOptions = append(opts, dOptions...)
	}

	if d.DiodeLogLevel != "" {
		dOptions = append(dOptions, "--log-level", d.DiodeLogLevel)
		d.Logger.Info("network-discovery using log level",
			"log_level", d.DiodeLogLevel)
	}

	if d.DiodeOtelEndpoint != "" {
		dOptions = append(dOptions, "--otel-endpoint", d.DiodeOtelEndpoint)
		d.Logger.Info("network-discovery using OTLP metrics endpoint",
			"endpoint", d.DiodeOtelEndpoint)
	}

	return dOptions
}

func (d *networkDiscoveryBackend) logLineAdapter(line string, isStderr bool) {
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
