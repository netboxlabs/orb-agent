package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/snmptelemetry"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// mockConfigManager implements configmgr.Manager for testing Stop delegation
type mockConfigManager struct {
	stopCalled bool
	// onStop runs at the start of Stop (before stopCalled is set). Use it to
	// assert ordering relative to other shutdown side effects.
	onStop func()
}

func (m *mockConfigManager) Start(_ context.Context, _ config.Config, _ map[string]backend.Backend) error {
	return nil
}
func (m *mockConfigManager) GetContext(ctx context.Context) context.Context { return ctx }
func (m *mockConfigManager) Stop(_ context.Context) error {
	if m.onStop != nil {
		m.onStop()
	}
	m.stopCalled = true
	return nil
}

// Every bundled backend is registered; only the ones this agent started are
// in its backends map. A restart asked for a registered backend the agent
// never started, which has no process, logger or arguments, is refused
// rather than reached for.
func TestRestartBackendRefusesABackendTheAgentDidNotStart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	snmptelemetry.Register()
	require.True(t, backend.HaveBackend("snmp_telemetry"))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{},
		policyManager:       &mockPolicyManager{repo: repo},
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), repo),
	}

	var restartErr error
	require.NotPanics(t, func() { restartErr = a.RestartBackend(context.Background(), "snmp_telemetry", "test") })
	require.Error(t, restartErr)
	assert.Contains(t, restartErr.Error(), "not started by this agent")
}

func TestAgentStop_DelegatesToConfigManagerStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a := &orbAgent{logger: logger}

	mockMgr := &mockConfigManager{}
	// type assertion to satisfy compile-time check for interface
	var _ configmgr.Manager = mockMgr
	a.configManager = mockMgr

	// no backends running
	a.backends = map[string]backend.Backend{}

	a.Stop(context.Background())

	assert.True(t, mockMgr.stopCalled, "expected configManager.Stop to be called")
}

func TestAgentStop_FailNonTerminalRunsBeforeConfigManagerStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, repo.Update(policies.PolicyData{
		ID:       "p1",
		Name:     "policy-one",
		Datasets: map[string]bool{"d1": true},
		Runs: []policies.RunData{
			{ID: "run-1", Status: "running", CreatedAt: now, UpdatedAt: now},
		},
	}))

	cm := &mockConfigManager{
		onStop: func() {
			pd, err := repo.Get("p1")
			require.NoError(t, err)
			require.Len(t, pd.Runs, 1)
			assert.Equal(t, "failed", pd.Runs[0].Status,
				"run must already be finalized when configManager.Stop is invoked (FailNonTerminalRuns before Stop)")
			assert.Equal(t, policies.RunFailureReasonAgentStopped, pd.Runs[0].Reason)
		},
	}
	a := &orbAgent{
		logger:        logger,
		backends:      map[string]backend.Backend{},
		policyManager: &mockPolicyManager{repo: repo},
		configManager: cm,
	}
	a.Stop(context.Background())

	assert.True(t, cm.stopCalled, "expected configManager.Stop to complete")
	pd, err := repo.Get("p1")
	require.NoError(t, err)
	require.Len(t, pd.Runs, 1)
	assert.Equal(t, "failed", pd.Runs[0].Status)
	assert.Equal(t, policies.RunFailureReasonAgentStopped, pd.Runs[0].Reason)
}

// mockPolicyManager implements policymgr.PolicyManager for testing
type mockPolicyManager struct {
	repo policies.PolicyRepo
}

func (m *mockPolicyManager) ManagePolicy(_ config.PolicyPayload)                       {}
func (m *mockPolicyManager) RemovePolicyDataset(_ string, _ string, _ backend.Backend) {}
func (m *mockPolicyManager) GetPolicyState() ([]policies.PolicyData, error) {
	return nil, nil
}

func (m *mockPolicyManager) GetRepo() policies.PolicyRepo {
	return m.repo
}

func (m *mockPolicyManager) ApplyBackendPolicies(_ backend.Backend) error {
	return nil
}

func (m *mockPolicyManager) RemoveBackendPolicies(_ string, _ backend.Backend, _ bool) error {
	return nil
}

func (m *mockPolicyManager) RemovePolicy(_ string, _ string, _ string) error {
	return nil
}

// mockFilesManager implements filesmgr.Manager for testing (no-op), and
// records every Rollback call so a test can assert one was, or was not, made.
type mockFilesManager struct {
	rollbackCalls int
	rollbackNames []string
}

func (m *mockFilesManager) Start(_ context.Context) error { return nil }
func (m *mockFilesManager) Stop(_ context.Context) error  { return nil }
func (m *mockFilesManager) Ensure(_ context.Context, _ filesmgr.FileSpec) (string, error) {
	return "", nil
}

func (m *mockFilesManager) Get(_ string) (filesmgr.FileEntry, bool) {
	return filesmgr.FileEntry{}, false
}

func (m *mockFilesManager) List() []filesmgr.FileEntry               { return nil }
func (m *mockFilesManager) ListPending() []filesmgr.FileEntry        { return nil }
func (m *mockFilesManager) Remove(_ context.Context, _ string) error { return nil }
func (m *mockFilesManager) Rollback(_ context.Context, name string) error {
	m.rollbackCalls++
	m.rollbackNames = append(m.rollbackNames, name)
	return nil
}
func (m *mockFilesManager) Subscribe(_ func(filesmgr.FileEvent)) func() { return func() {} }

// mockSecretsManager implements secretsmgr.Manager for testing
type mockSecretsManager struct{}

func (m *mockSecretsManager) Start(_ context.Context) error {
	return nil
}
func (m *mockSecretsManager) RegisterUpdatePoliciesCallback(_ func(map[string]bool)) {}
func (m *mockSecretsManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, nil
}

func (m *mockSecretsManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	return backends, configManager, nil
}

func TestStart_FleetConfig_OverridesExistingOTLPGrpcURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{
				"common": map[string]any{
					"otlp": map[string]any{
						"grpc": "original:4317",
					},
				},
			},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}
	orbAgent.configManager = &mockConfigManager{} // avoid real fleet startup
	orbAgent.filesManager = &mockFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.NoError(t, err)

	// Verify the OTLP URLs were overridden before backends started
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
	assert.Equal(t, "http://localhost:4318", orbAgent.backendsCommon.Otlp.HTTP)
}

func TestStart_FleetConfig_CreatesOTLPSectionWhenMissing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{
				"common": map[string]any{
					"other": "value",
				},
			},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}
	orbAgent.configManager = &mockConfigManager{} // avoid real fleet startup
	orbAgent.filesManager = &mockFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.NoError(t, err)

	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
	assert.Equal(t, "http://localhost:4318", orbAgent.backendsCommon.Otlp.HTTP)
}

func TestStart_FleetConfig_CreatesCommonBackendWhenMissing(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}
	orbAgent.configManager = &mockConfigManager{} // avoid real fleet startup
	orbAgent.filesManager = &mockFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.NoError(t, err)

	// The OTLP override creates the "common" backend with the grpc and http
	// URLs before startBackends extracts it into backendsCommon (and deletes the key).
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
	assert.Equal(t, "http://localhost:4318", orbAgent.backendsCommon.Otlp.HTTP)
}

// fleetRewriteCase starts an agent in fleet mode with the given backends map and
// returns the extracted common config, so table cases can assert the rewrite.
func fleetRewriteCase(t *testing.T, backends map[string]any) config.BackendCommons {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends:       backends,
			ConfigManager:  config.ManagerConfig{Active: "fleet"},
			SecretsManager: config.ManagerSecrets{Active: ""},
		},
	}
	agent, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}
	orbAgent.configManager = &mockConfigManager{} // avoid real fleet startup
	orbAgent.filesManager = &mockFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, orbAgent.Start(ctx, cancel))
	return orbAgent.backendsCommon
}

func TestStart_FleetConfig_RewritesOTLPForDegenerateCommonBlocks(t *testing.T) {
	// `common:` with no value is stored as nil by yaml.v3; `otlp:` with no
	// value likewise. Neither may stop the bridge endpoints from being set,
	// otherwise pktvisor starts without --otel and silently sends nothing.
	cases := map[string]map[string]any{
		"empty common block":     {"common": nil},
		"non-map common value":   {"common": "oops"},
		"empty otlp key":         {"common": map[string]any{"otlp": nil}},
		"non-map otlp value":     {"common": map[string]any{"otlp": []any{"x"}}},
		"nil backends map":       nil,
		"common with other keys": {"common": map[string]any{"diode": map[string]any{"target": "t"}}},
	}
	for name, backends := range cases {
		t.Run(name, func(t *testing.T) {
			common := fleetRewriteCase(t, backends)
			assert.Equal(t, "grpc://localhost:4317", common.Otlp.Grpc)
			assert.Equal(t, "http://localhost:4318", common.Otlp.HTTP)
		})
	}
}

func TestStart_FleetConfig_RejectsUnusablePorts(t *testing.T) {
	// Backends dial the configured port on localhost, so an ephemeral (0) or
	// out-of-range port must fail start-up loudly instead of leaving pktvisor
	// without --otel.
	zero, tooBig, negative := 0, 70000, -1
	cases := map[string]struct {
		fleet   config.FleetManager
		mention string
	}{
		"http port zero":     {config.FleetManager{OTLPBridgeHTTPPort: &zero}, "otlp_bridge_http_port"},
		"http port too big":  {config.FleetManager{OTLPBridgeHTTPPort: &tooBig}, "otlp_bridge_http_port"},
		"grpc port zero":     {config.FleetManager{OTLPBridgeGRPCPort: &zero}, "otlp_bridge_grpc_port"},
		"grpc port negative": {config.FleetManager{OTLPBridgeGRPCPort: &negative}, "otlp_bridge_grpc_port"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			repo, err := policies.NewMemRepo()
			require.NoError(t, err)
			cfg := config.Config{
				OrbAgent: config.OrbAgent{
					Backends:       map[string]any{},
					ConfigManager:  config.ManagerConfig{Active: "fleet", Sources: config.Sources{Fleet: tc.fleet}},
					SecretsManager: config.ManagerSecrets{Active: ""},
				},
			}
			agent, err := New(logger, cfg, false)
			require.NoError(t, err)
			orbAgent := agent.(*orbAgent)
			orbAgent.secretsManager = &mockSecretsManager{}
			orbAgent.policyManager = &mockPolicyManager{repo: repo}
			orbAgent.configManager = &mockConfigManager{}
			orbAgent.filesManager = &mockFilesManager{}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err = orbAgent.Start(ctx, cancel)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.mention)
			assert.Contains(t, err.Error(), "between 1 and 65535")
		})
	}
}

func TestStart_NonFleetConfig_DoesNotModifyConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	originalGrpcURL := "original:4317"
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{
				"common": map[string]any{
					"otlp": map[string]any{
						"grpc": originalGrpcURL,
					},
				},
			},
			ConfigManager: config.ManagerConfig{
				Active: "local", // Not fleet
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}
	orbAgent.filesManager = &mockFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.Error(t, err) // Expected to fail when starting backends

	// Verify the config was NOT modified by checking backendsCommon which is set in startBackends
	// For non-fleet config, the original value should remain
	assert.Equal(t, originalGrpcURL, orbAgent.backendsCommon.Otlp.Grpc, "grpc URL should remain unchanged for non-fleet config")
	assert.Empty(t, orbAgent.backendsCommon.Otlp.HTTP, "http URL should not be injected for non-fleet config")
}

func TestStart_FleetConfig_UsesConfiguredGRPCPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	customPort := 9999
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
				Sources: config.Sources{
					Fleet: config.FleetManager{
						OTLPBridgeGRPCPort: &customPort,
					},
				},
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}
	orbAgent.configManager = &mockConfigManager{} // avoid real fleet startup
	orbAgent.filesManager = &mockFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.NoError(t, err)

	// The OTLP override runs before startBackends, which extracts common config
	// into backendsCommon and then deletes the "common" key from the map.
	// Verify the extracted config has the custom port.
	assert.Equal(t, "grpc://localhost:9999", orbAgent.backendsCommon.Otlp.Grpc, "grpc URL should use configured port")
	assert.Equal(t, "http://localhost:4318", orbAgent.backendsCommon.Otlp.HTTP, "http URL keeps its default when only the grpc port is set")
}

func TestStart_FleetConfig_UsesConfiguredHTTPPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	httpPort := 4338
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			Backends: map[string]any{
				"common": map[string]any{
					"otlp": map[string]any{
						"http": "http://otel-collector:4318",
					},
				},
			},
			ConfigManager: config.ManagerConfig{
				Active: "fleet",
				Sources: config.Sources{
					Fleet: config.FleetManager{
						OTLPBridgeHTTPPort: &httpPort,
					},
				},
			},
			SecretsManager: config.ManagerSecrets{
				Active: "",
			},
		},
	}

	agent, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := agent.(*orbAgent)
	orbAgent.secretsManager = &mockSecretsManager{}
	orbAgent.policyManager = &mockPolicyManager{repo: repo}
	orbAgent.configManager = &mockConfigManager{} // avoid real fleet startup
	orbAgent.filesManager = &mockFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = orbAgent.Start(ctx, cancel)
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:4338", orbAgent.backendsCommon.Otlp.HTTP, "a user-supplied http URL is replaced by the bridge listener in fleet mode")
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
}

// stubCancelledStartBackend is a minimal backend.Backend and backend.ManagedBinary
// whose Start always fails as if the agent's own shutdown had already cancelled
// the context it was given, for testing that filesmgr's rollback gate treats
// that as distinct from a bad binary.
type stubCancelledStartBackend struct {
	startCalls int
}

func (s *stubCancelledStartBackend) Configure(*slog.Logger, policies.PolicyRepo, map[string]any, config.BackendCommons, filesmgr.Manager) error {
	return nil
}
func (s *stubCancelledStartBackend) Version() (string, error) { return "", nil }
func (s *stubCancelledStartBackend) Start(context.Context, context.CancelFunc) error {
	s.startCalls++
	return fmt.Errorf("stub start cancelled: %w", context.Canceled)
}
func (s *stubCancelledStartBackend) Stop(context.Context) error      { return nil }
func (s *stubCancelledStartBackend) FullReset(context.Context) error { return nil }
func (s *stubCancelledStartBackend) GetStartTime() time.Time         { return time.Time{} }
func (s *stubCancelledStartBackend) GetCapabilities() (map[string]any, error) {
	return nil, nil
}

func (s *stubCancelledStartBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	return backend.Unknown, "", nil
}
func (s *stubCancelledStartBackend) GetInitialState() backend.RunningStatus      { return backend.Unknown }
func (s *stubCancelledStartBackend) ApplyPolicy(policies.PolicyData, bool) error { return nil }
func (s *stubCancelledStartBackend) RemovePolicy(policies.PolicyData) error      { return nil }
func (s *stubCancelledStartBackend) ManagedBinaryName() string                   { return "stub-binary" }

// A start the agent itself gave up on (its context was already cancelled,
// typically by shutdown) is not evidence the managed binary is bad, so it
// must not trigger a rollback to the previous version.
func TestFilesmgrRestartDoesNotRollBackACancelledStart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	be := &stubCancelledStartBackend{}
	fm := &mockFilesManager{}

	a := &orbAgent{
		logger:       logger,
		backends:     map[string]backend.Backend{"stub": be},
		filesManager: fm,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a.restartBackendWithFilesmgrRollback(ctx, "stub")

	assert.Equal(t, 1, be.startCalls, "Start should be attempted exactly once")
	assert.Equal(t, 0, fm.rollbackCalls, "a cancelled start must not trigger a rollback")
}
