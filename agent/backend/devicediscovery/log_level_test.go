package devicediscovery

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// discardLogger is a plain Info-level logger; the level is irrelevant to the
// precedence chain now that it keys off common.Debug rather than the handler.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// otlpLikeHandler mimics the otelslog handler that
// telemetry.BuildOTLPLogExporter merges into the agent logger: no level filter,
// so Enabled always reports true. telemetry.multiHandler ORs Enabled across its
// handlers, which is why an OTLP-wrapped agent logger claims Debug is enabled
// even when the agent was never started with -d.
type otlpLikeHandler struct {
	slog.Handler
}

func (otlpLikeHandler) Enabled(context.Context, slog.Level) bool { return true }

func otlpWrappedLogger() *slog.Logger {
	return slog.New(otlpLikeHandler{Handler: slog.NewTextHandler(io.Discard, nil)})
}

// flagValue returns the argument immediately following flag. Asserting on
// adjacency is strictly stronger than two separate assert.Contains calls, which
// would pass even if the flag and its value were separated by another option.
func flagValue(t *testing.T, args []string, flag string) (string, bool) {
	t.Helper()
	for i, arg := range args {
		if arg == flag {
			require.Less(t, i+1, len(args), "flag %s has no value following it", flag)
			return args[i+1], true
		}
	}
	return "", false
}

func TestConfigureLogLevelPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]any
		agentDebug bool
		expected   string
	}{
		{
			name:     "explicit log_level wins",
			config:   map[string]any{"log_level": "error"},
			expected: "error",
		},
		{
			name:     "explicit log_level beats per-backend debug",
			config:   map[string]any{"log_level": "error", "debug": true},
			expected: "error",
		},
		{
			name:       "explicit log_level beats agent debug",
			config:     map[string]any{"log_level": "error"},
			agentDebug: true,
			expected:   "error",
		},
		{
			name:     "per-backend debug implies debug",
			config:   map[string]any{"debug": true},
			expected: "debug",
		},
		{
			name:     "per-backend debug false does not imply debug",
			config:   map[string]any{"debug": false},
			expected: "",
		},
		{
			name:       "agent debug implies debug",
			config:     map[string]any{},
			agentDebug: true,
			expected:   "debug",
		},
		{
			name:     "nothing set leaves it empty",
			config:   map[string]any{},
			expected: "",
		},
		{
			// YAML `log_level: 3` must fall through the type assertion.
			name:     "non-string log_level does not panic",
			config:   map[string]any{"log_level": 3},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commons := config.BackendCommons{}
			commons.Debug = tt.agentDebug

			d := &deviceDiscoveryBackend{apiProtocol: "http"}
			require.NotPanics(t, func() {
				require.NoError(t, d.Configure(discardLogger(), nil, tt.config, commons, nil))
			})
			assert.Equal(t, tt.expected, d.diodeLogLevel)
		})
	}
}

// TestConfigureDoesNotTreatOtlpExportAsDebug is the regression guard for the
// review finding on PR #510. Enabling OTLP log export must not, by itself, put
// the backend into debug.
func TestConfigureDoesNotTreatOtlpExportAsDebug(t *testing.T) {
	logger := otlpWrappedLogger()
	require.True(t, logger.Enabled(context.Background(), slog.LevelDebug),
		"precondition: an OTLP-wrapped agent logger reports Debug as enabled")

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "collector:4317"
	commons.Debug = false // no -d, no orb.debug.enable

	d := &deviceDiscoveryBackend{apiProtocol: "http"}
	require.NoError(t, d.Configure(logger, nil, map[string]any{}, commons, nil))

	assert.Empty(t, d.diodeLogLevel,
		"OTLP log export alone must not enable debug — see telemetry/logs.go:52-59")

	_, found := flagValue(t, d.buildArgs(), "--log-level")
	assert.False(t, found, "expected no --log-level when only OTLP export is configured")
}

// TestConfigureOtlpPlusAgentDebugStillEnablesDebug is the other half: the fix
// must not have broken the legitimate case.
func TestConfigureOtlpPlusAgentDebugStillEnablesDebug(t *testing.T) {
	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "collector:4317"
	commons.Debug = true

	d := &deviceDiscoveryBackend{apiProtocol: "http"}
	require.NoError(t, d.Configure(otlpWrappedLogger(), nil, map[string]any{}, commons, nil))

	assert.Equal(t, "debug", d.diodeLogLevel)
}

func TestBuildArgsIncludesLogLevel(t *testing.T) {
	d := &deviceDiscoveryBackend{apiProtocol: "http"}
	require.NoError(t, d.Configure(discardLogger(), nil,
		map[string]any{"log_level": "debug"}, config.BackendCommons{}, nil))

	args := d.buildArgs()

	value, found := flagValue(t, args, "--log-level")
	require.True(t, found, "expected --log-level in %v", args)
	assert.Equal(t, "debug", value, "--log-level must be immediately followed by its value")
}

func TestBuildArgsOmitsLogLevelWhenUnset(t *testing.T) {
	// Pins the byte-identical default command line: with no log_level and no
	// debug anywhere, the arguments must be exactly what they were before this
	// change. That is what bounds the blast radius.
	d := &deviceDiscoveryBackend{apiProtocol: "http"}
	require.NoError(t, d.Configure(discardLogger(), nil,
		map[string]any{}, config.BackendCommons{}, nil))

	args := d.buildArgs()

	_, found := flagValue(t, args, "--log-level")
	assert.False(t, found, "expected no --log-level in %v", args)
}

func TestBuildArgsLogLevelPrecedesOtelEndpoint(t *testing.T) {
	// Order matters only in that both must survive; this catches an append that
	// accidentally replaces rather than extends.
	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "collector:4317"

	d := &deviceDiscoveryBackend{apiProtocol: "http"}
	require.NoError(t, d.Configure(discardLogger(), nil,
		map[string]any{"log_level": "warn"}, commons, nil))

	args := d.buildArgs()

	logLevel, foundLevel := flagValue(t, args, "--log-level")
	require.True(t, foundLevel)
	assert.Equal(t, "warn", logLevel)

	endpoint, foundEndpoint := flagValue(t, args, "--otel-endpoint")
	require.True(t, foundEndpoint)
	assert.Equal(t, "collector:4317", endpoint)
}
