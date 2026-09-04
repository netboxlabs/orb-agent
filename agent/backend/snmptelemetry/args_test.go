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
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
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

// debugCommons is what the agent hands a backend when run with its debug
// flag; the flag arrives through the commons, not the config map.
func debugCommons(endpoint string) config.BackendCommons {
	c := commonsWithOTLP(endpoint)
	c.Debug = true
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
			name:    "the agent's debug flag selects DEBUG",
			cfg:     map[string]any{},
			commons: debugCommons("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--log-level", "DEBUG"},
		},
		{
			name:    "a debug-enabled logger alone does not select DEBUG",
			cfg:     map[string]any{},
			commons: commonsWithOTLP("collector:4317"),
			logger:  quietLogger(slog.LevelDebug),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317"},
		},
		{
			name:    "an explicit log_level wins over debug",
			cfg:     map[string]any{"debug": true, "log_level": "ERROR"},
			commons: debugCommons("collector:4317"),
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
			name:    "a nil map, the documented bare snmp_telemetry key, uses the defaults",
			cfg:     nil,
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317"},
		},
		{
			name:    "an empty host or port stays on the default rather than binding everywhere",
			cfg:     map[string]any{"host": "", "port": ""},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317"},
		},
		{
			name:    "a null host or port, a key left blank in YAML, keeps the default",
			cfg:     map[string]any{"host": nil, "port": nil},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317"},
		},
		{
			name:    "port accepts a whole float and a numeric string",
			cfg:     map[string]any{"port": 9078.0},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "9078", "--otel-endpoint", "collector:4317"},
		},
		{
			name:    "a non-string host is refused",
			cfg:     map[string]any{"host": 7},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: host must be a string, got int",
		},
		{
			name:    "a fractional port is refused",
			cfg:     map[string]any{"port": 8078.5},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: port must be an integer from 1 to 65535, got 8078.5",
		},
		{
			name:    "a port out of range is refused",
			cfg:     map[string]any{"port": 70000},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: port must be an integer from 1 to 65535, got 70000",
		},
		{
			name:    "a port that is not a number is refused",
			cfg:     map[string]any{"port": "eight"},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: `snmp_telemetry: port must be an integer from 1 to 65535, got "eight"`,
		},
		{
			name:    "an unrecognised log_level is refused rather than run at DEBUG",
			cfg:     map[string]any{"log_level": "verbose"},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: `snmp_telemetry: log_level must be one of DEBUG, INFO, WARN, ERROR, got "verbose"`,
		},
		{
			name:    "an unrecognised log_format is refused rather than fall to JSON",
			cfg:     map[string]any{"log_format": "yaml"},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: `snmp_telemetry: log_format must be one of TEXT, JSON, got "yaml"`,
		},
		{
			name:    "policy_env_vars entries are trimmed and joined",
			cfg:     map[string]any{"policy_env_vars": "A, B"},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--policy-env-vars", "A,B"},
		},
		{
			name:    "a resolved secret in policy_env_vars is refused",
			cfg:     map[string]any{"policy_env_vars": []any{"SNMP_COMMUNITY", "s3cr3t-value"}},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: `snmp_telemetry: policy_env_vars takes environment variable names, not "s3cr3t-value"`,
		},
		{
			name:    "an empty log_level still follows the debug rule",
			cfg:     map[string]any{"log_level": "", "debug": true},
			commons: commonsWithOTLP("collector:4317"),
			want:    []string{"--host", "localhost", "--port", "8078", "--otel-endpoint", "collector:4317", "--log-level", "DEBUG"},
		},
		{
			name:    "a non-string log_level is refused",
			cfg:     map[string]any{"log_level": false},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: log_level must be a string, got bool",
		},
		{
			name:    "a non-string log_format is refused",
			cfg:     map[string]any{"log_format": 7},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: log_format must be a string, got int",
		},
		{
			name:    "a non-string profiles path is refused",
			cfg:     map[string]any{"snmp_profiles_root": true},
			commons: commonsWithOTLP("collector:4317"),
			wantErr: "snmp_telemetry: snmp_profiles_root must be a string, got bool",
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
	b.proc = &mocks.MockCmd{}

	require.NoError(t, b.Stop(context.Background()))

	assert.Equal(t, backend.DefaultStopGracePeriod, gotGrace)
	assert.Equal(t, "snmp_telemetry", gotName)
}

// A backend that never started has no process to stop; Stop is a no-op
// rather than a nil dereference.
func TestStopBeforeStartIsANoOp(t *testing.T) {
	calls := 0
	original := stopProcess
	stopProcess = func(*slog.Logger, backend.Commander, <-chan backend.CmdStatus, time.Duration, string) { calls++ }
	t.Cleanup(func() { stopProcess = original })

	b := &snmpTelemetryBackend{apiProtocol: "http", exec: defaultExec}
	require.NoError(t, b.Stop(context.Background()))
	assert.Equal(t, 0, calls)
}

// A fleet full reset walks the whole registry, reaching a backend the agent
// never configured. It must refuse rather than start a process on empty
// arguments through a nil logger.
func TestStartAndResetBeforeConfigureAreRefused(t *testing.T) {
	b := &snmpTelemetryBackend{apiProtocol: "http", exec: defaultExec}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	assert.EqualError(t, b.Start(ctx, cancel), "snmp_telemetry: started before it was configured")
	assert.EqualError(t, b.FullReset(ctx), "snmp_telemetry: reset before it was configured")
}

// A refused reconfiguration must not move the address the agent polls the
// running process on, or every status check would miss it until a restart.
func TestConfigureFailureLeavesTheBackendUnchanged(t *testing.T) {
	b := &snmpTelemetryBackend{apiProtocol: "http", exec: defaultExec}
	logger := quietLogger(slog.LevelInfo)
	require.NoError(t, b.Configure(logger, nil, map[string]any{"port": 9078, "log_format": "JSON"}, commonsWithOTLP("collector:4317"), nil))
	before := b.buildArgs()

	err := b.Configure(logger, nil, map[string]any{"port": 9079, "otel_export_period": 0}, commonsWithOTLP("other:4317"), nil)
	require.Error(t, err)

	assert.Equal(t, before, b.buildArgs())
	assert.Equal(t, "http://localhost:9078/api/v1/status", b.apiURL("status"))
}

// The binary brackets an IPv6 host when it binds; the agent must do the same
// when it dials, or readiness never passes.
func TestAPIURLBracketsAnIPv6Host(t *testing.T) {
	b := &snmpTelemetryBackend{apiProtocol: "http", exec: defaultExec}
	require.NoError(t, b.Configure(quietLogger(slog.LevelInfo), nil, map[string]any{"host": "::1"}, commonsWithOTLP("collector:4317"), nil))
	assert.Equal(t, "http://[::1]:8078/api/v1/status", b.apiURL("status"))
	assert.Equal(t, "http://[::1]:8078/api/v1/policies/a%20b", b.apiURL("policies/a%20b"))
}
