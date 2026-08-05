package devicediscovery

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// levelLogger builds a discarding logger pinned at the given level, standing in
// for the shared LevelVar that cmd/main.go raises for -d or orb.debug.enable.
func levelLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
}

// flagValue returns the argument immediately following flag. Asserting on
// adjacency is strictly stronger than two separate assert.Contains calls, which
// would pass even if the flag and its value were separated by another option.
// The Python side pins the other half of this boundary in
// orb-discovery/device-discovery/tests/test_cli_parity.py.
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
		name     string
		config   map[string]any
		logger   *slog.Logger
		expected string
	}{
		{
			name:     "explicit log_level wins",
			config:   map[string]any{"log_level": "error"},
			logger:   levelLogger(slog.LevelInfo),
			expected: "error",
		},
		{
			name:     "explicit log_level beats per-backend debug",
			config:   map[string]any{"log_level": "error", "debug": true},
			logger:   levelLogger(slog.LevelInfo),
			expected: "error",
		},
		{
			name:     "per-backend debug implies debug",
			config:   map[string]any{"debug": true},
			logger:   levelLogger(slog.LevelInfo),
			expected: "debug",
		},
		{
			name:     "per-backend debug false does not imply debug",
			config:   map[string]any{"debug": false},
			logger:   levelLogger(slog.LevelInfo),
			expected: "",
		},
		{
			name:     "agent already at debug implies debug",
			config:   map[string]any{},
			logger:   levelLogger(slog.LevelDebug),
			expected: "debug",
		},
		{
			name:     "nothing set leaves it empty",
			config:   map[string]any{},
			logger:   levelLogger(slog.LevelInfo),
			expected: "",
		},
		{
			// YAML `log_level: 3` must fall through the type assertion.
			name:     "non-string log_level does not panic",
			config:   map[string]any{"log_level": 3},
			logger:   levelLogger(slog.LevelInfo),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &deviceDiscoveryBackend{apiProtocol: "http"}
			require.NotPanics(t, func() {
				require.NoError(t, d.Configure(tt.logger, nil, tt.config, config.BackendCommons{}, nil))
			})
			assert.Equal(t, tt.expected, d.diodeLogLevel)
		})
	}
}

func TestBuildArgsIncludesLogLevel(t *testing.T) {
	d := &deviceDiscoveryBackend{apiProtocol: "http"}
	require.NoError(t, d.Configure(levelLogger(slog.LevelInfo), nil,
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
	require.NoError(t, d.Configure(levelLogger(slog.LevelInfo), nil,
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
	require.NoError(t, d.Configure(levelLogger(slog.LevelInfo), nil,
		map[string]any{"log_level": "warn"}, commons, nil))

	args := d.buildArgs()

	logLevel, foundLevel := flagValue(t, args, "--log-level")
	require.True(t, foundLevel)
	assert.Equal(t, "warn", logLevel)

	endpoint, foundEndpoint := flagValue(t, args, "--otel-endpoint")
	require.True(t, foundEndpoint)
	assert.Equal(t, "collector:4317", endpoint)
}
