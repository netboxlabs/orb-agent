package snmpdiscovery

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/discovery"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

var _ backend.Backend = (*snmpDiscoveryBackend)(nil)

const (
	defaultExec             = "snmp-discovery"
	defaultAPIPort          = "8070"
	defaultIngestBufferSize = 512
)

type snmpDiscoveryBackend struct {
	discovery.Base
	ingestBufferSize int
}

// Register registers the snmp discovery backend
func Register() bool {
	b := &snmpDiscoveryBackend{
		Base: discovery.Base{
			Exec:           defaultExec,
			APIProtocol:    "http",
			APIPort:        defaultAPIPort,
			NameHyphen:     "snmp-discovery",
			NameUnderscore: "snmp_discovery",
		},
	}
	b.BuildArgs = b.buildArgs
	b.LogLine = b.logLineAdapter
	b.ConfigureExtra = b.configureExtra
	backend.Register("snmp_discovery", b)
	return true
}

func (d *snmpDiscoveryBackend) Configure(logger *slog.Logger, repo policies.PolicyRepo,
	config map[string]any, common config.BackendCommons, _ filesmgr.Manager,
) error {
	d.Logger = logger.With("backend", "snmp_discovery")
	d.PolicyRepo = repo
	return d.Base.Configure(config, common)
}

// configureExtra parses and validates the snmp-specific ingest_buffer_size key.
// It runs early in Configure (after host/port, before diode/OTLP reads) so a
// validation error aborts before the OTLP log — ordering preserved from the
// original inline implementation.
func (d *snmpDiscoveryBackend) configureExtra(config map[string]any) error {
	d.ingestBufferSize = defaultIngestBufferSize
	if v, prs := config["ingest_buffer_size"]; prs {
		size, err := parseIngestBufferSize(v)
		if err != nil {
			return fmt.Errorf("snmp_discovery: %w", err)
		}
		d.ingestBufferSize = size
	}
	return nil
}

func parseIngestBufferSize(v any) (int, error) {
	var n int

	switch val := v.(type) {
	case int:
		n = val
	case int64:
		n = int(val)
	case float64:
		if val != float64(int64(val)) {
			return 0, fmt.Errorf("ingest_buffer_size must be a whole number, got %v", val)
		}
		n = int(val)
	case string:
		parsed, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("ingest_buffer_size: invalid integer %q: %w", val, err)
		}
		n = parsed
	default:
		return 0, fmt.Errorf("ingest_buffer_size must be an integer, got %T", v)
	}

	if n < 1 {
		return 0, fmt.Errorf("ingest_buffer_size must be >= 1, got %d", n)
	}

	return n, nil
}

func (d *snmpDiscoveryBackend) buildArgs() []string {
	dOptions := []string{
		"--diode-app-name-prefix", d.DiodeAppNamePrefix,
		"--host", d.APIHost,
		"--port", d.APIPort,
		"--ingest-buffer-size", fmt.Sprintf("%d", d.ingestBufferSize),
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
		d.Logger.Info("snmp-discovery using log level",
			"log_level", d.DiodeLogLevel)
	}

	if d.DiodeOtelEndpoint != "" {
		dOptions = append(dOptions, "--otel-endpoint", d.DiodeOtelEndpoint)
		d.Logger.Info("snmp-discovery using OTLP endpoint",
			"endpoint", d.DiodeOtelEndpoint)
	}

	return dOptions
}

func (d *snmpDiscoveryBackend) logLineAdapter(line string, isStderr bool) {
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
