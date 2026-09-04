package snmptelemetry

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
)

func quietLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level}))
}

func commonsWithOTLP(endpoint string) config.BackendCommons {
	var c config.BackendCommons
	c.Otlp.Grpc = endpoint
	return c
}

func TestConfigureBuildsArgs(t *testing.T) {
	cases := []struct {
		name    string
		cfg     map[string]any
		commons config.BackendCommons
		logger  *slog.Logger
		want    []string
		wantErr string
	}{
		{
			name:    "defaults pass only host, port and the endpoint",
			cfg:     map[string]any{},
			commons: commonsWithOTLP("grpc://collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "grpc://collector:4317"},
		},
		{
			name: "every key is forwarded as its flag",
			cfg: map[string]any{
				"host":               "127.0.0.1",
				"port":               9078,
				"otel_export_period": 30,
				"log_level":          "warn",
				"log_format":         "JSON",
				"policy_env_vars":    "SNMP_COMMUNITY,SNMP_PASS",
				"snmp_profiles_root": "/opt/orb/profiles",
				"snmp_profiles_dir":  "/opt/orb/overrides",
			},
			commons: commonsWithOTLP("collector:4317"),
			want: []string{
				"--host", "127.0.0.1", "--port", "9078", "--otel-endpoint", "collector:4317",
				"--otel-export-period", "30", "--log-level", "warn", "--log-format", "JSON",
				"--policy-env-vars", "SNMP_COMMUNITY,SNMP_PASS",
				"--snmp-profiles-root", "/opt/orb/profiles", "--snmp-profiles-dir", "/opt/orb/overrides",
			},
		},
		{
			name:    "policy_env_vars as a list is joined with commas",
			cfg:     map[string]any{"policy_env_vars": []any{"A", "B"}},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--policy-env-vars", "A,B"},
		},
		{
			name:    "empty strings are unset",
			cfg:     map[string]any{"log_format": "", "policy_env_vars": "", "snmp_profiles_root": "", "snmp_profiles_dir": ""},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317"},
		},
		{
			name:    "debug true selects DEBUG",
			cfg:     map[string]any{"debug": true},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--log-level", "DEBUG"},
		},
		{
			name:    "a debug-enabled agent logger selects DEBUG",
			cfg:     map[string]any{},
			commons: commonsWithOTLP("collector:4317"),
			logger:  quietLogger(slog.LevelDebug),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--log-level", "DEBUG"},
		},
		{
			name:    "an explicit log_level wins over debug",
			cfg:     map[string]any{"debug": true, "log_level": "ERROR"},
			commons: commonsWithOTLP("collector:4317"),
			logger:  quietLogger(slog.LevelDebug),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--log-level", "ERROR"},
		},
		{
			name:    "export period accepts a whole float",
			cfg:     map[string]any{"otel_export_period": 15.0},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--otel-export-period", "15"},
		},
		{
			name:    "export period accepts a numeric string",
			cfg:     map[string]any{"otel_export_period": "20"},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--otel-export-period", "20"},
		},
		{
			name:    "missing OTLP endpoint is refused",
			cfg:     map[string]any{},
			commons: config.BackendCommons{},
			wantErr: "snmp_telemetry: common.otlp.grpc is required, the backend exports its metrics over OTLP",
		},
		{
			name:    "export period zero is refused",
			cfg:     map[string]any{"otel_export_period": 0},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: otel_export_period must be >= 1, got 0",
		},
		{
			name:    "export period above one year is refused",
			cfg:     map[string]any{"otel_export_period": 31536001},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: otel_export_period must be <= 31536000, got 31536001",
		},
		{
			name:    "export period fractional is refused",
			cfg:     map[string]any{"otel_export_period": 1.5},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: otel_export_period must be a whole number, got 1.5",
		},
		{
			name:    "export period text is refused",
			cfg:     map[string]any{"otel_export_period": "soon"},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: `snmp_telemetry: otel_export_period: invalid integer "soon"`,
		},
		{
			name:    "export period bool is refused",
			cfg:     map[string]any{"otel_export_period": true},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: otel_export_period must be an integer, got bool",
		},
		{
			name:    "policy_env_vars with a non-string entry is refused",
			cfg:     map[string]any{"policy_env_vars": []any{"A", 2}},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: policy_env_vars entries must be strings, got int",
		},
		{
			name:    "policy_env_vars of another type is refused",
			cfg:     map[string]any{"policy_env_vars": 7},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: policy_env_vars must be a string or a list of strings, got int",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := tc.logger
			if logger == nil {
				logger = quietLogger(slog.LevelInfo)
			}
			b := &snmpTelemetryBackend{apiProtocol: "http", exec: defaultExec}
			err := b.Configure(logger, nil, tc.cfg, tc.commons, nil)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, b.buildArgs())
		})
	}
}

// A second Configure on the same backend must not carry an optional flag over
// from the first: the agent reconfigures a registered backend in place.
func TestConfigureResetsOptionalFlags(t *testing.T) {
	b := &snmpTelemetryBackend{apiProtocol: "http", exec: defaultExec}
	logger := quietLogger(slog.LevelInfo)
	require.NoError(t, b.Configure(logger, nil, map[string]any{
		"otel_export_period": 5, "log_level": "ERROR", "log_format": "JSON",
		"policy_env_vars": "A", "snmp_profiles_root": "/r", "snmp_profiles_dir": "/d",
	}, commonsWithOTLP("collector:4317"), nil))
	require.NoError(t, b.Configure(logger, nil, map[string]any{}, commonsWithOTLP("collector:4317"), nil))
	assert.Equal(t, []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317"}, b.buildArgs())
}

// The binary sizes its shutdown, trap sockets closed and then the final
// OTLP flush, to the agent's default stop grace. Stop must hand it exactly
// that grace; a shorter one would SIGKILL it with the last export unsent.
func TestStopPassesTheAgentGrace(t *testing.T) {
	var gotGrace time.Duration
	var gotName string
	original := stopProcess
	stopProcess = func(_ *slog.Logger, _ backend.Commander, _ <-chan backend.CmdStatus, grace time.Duration, name string) {
		gotGrace = grace
		gotName = name
	}
	t.Cleanup(func() { stopProcess = original })

	b := &snmpTelemetryBackend{apiProtocol: "http", exec: defaultExec}
	require.NoError(t, b.Configure(quietLogger(slog.LevelInfo), nil, map[string]any{}, commonsWithOTLP("collector:4317"), nil))
	_, cancel := context.WithCancel(context.Background())
	b.cancelFunc = cancel

	require.NoError(t, b.Stop(context.Background()))

	assert.Equal(t, backend.DefaultStopGracePeriod, gotGrace)
	assert.Equal(t, "snmp_telemetry", gotName)
}
