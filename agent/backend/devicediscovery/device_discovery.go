package devicediscovery

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

var _ backend.Backend = (*deviceDiscoveryBackend)(nil)

const (
	defaultExec    = "device-discovery"
	defaultAPIPort = "8072"
)

type deviceDiscoveryBackend struct {
	discovery.Base
}

// Register registers the device discovery backend.
func Register() bool {
	b := &deviceDiscoveryBackend{
		Base: discovery.Base{
			Exec:           defaultExec,
			APIProtocol:    "http",
			APIPort:        defaultAPIPort,
			NameHyphen:     "device-discovery",
			NameUnderscore: "device_discovery",
		},
	}
	b.BuildArgs = b.buildArgs
	b.LogLine = b.logLineAdapter
	// device has no extra config keys; ConfigureExtra intentionally left nil.
	backend.Register("device_discovery", b)
	return true
}

func (d *deviceDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.Logger = logger.With("backend", "device_discovery")
	d.PolicyRepo = repo
	return d.Base.Configure(config, common)
}

func (d *deviceDiscoveryBackend) buildArgs() []string {
	dOptions := []string{
		"--diode-app-name-prefix", d.DiodeAppNamePrefix,
		"--host", d.APIHost,
		"--port", d.APIPort,
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

	if d.DiodeOtelEndpoint != "" {
		dOptions = append(dOptions, "--otel-endpoint", d.DiodeOtelEndpoint)
	}

	return dOptions
}

func (d *deviceDiscoveryBackend) logLineAdapter(line string, isStderr bool) {
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

	if parsedMsg, parsedAttrs, parsedLevel, ok := normalizeDeviceDiscoveryLine(trimmed, fallback); ok {
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

func normalizeDeviceDiscoveryLine(line string, fallback slog.Level) (string, []slog.Attr, slog.Level, bool) {
	firstColon := strings.Index(line, ":")
	if firstColon <= 0 {
		return "", nil, fallback, false
	}

	levelCandidate := strings.TrimSpace(line[:firstColon])
	level, ok := parseDeviceDiscoveryLevel(levelCandidate)
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

func parseDeviceDiscoveryLevel(value string) (slog.Level, bool) {
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
