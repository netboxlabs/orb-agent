package agent

import (
	"context"
	"errors"
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
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
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
	repo   policies.PolicyRepo
	events *[]string // shared with the backend stub so one slice records the order
}

func (m *mockPolicyManager) record(event string) {
	if m.events != nil {
		*m.events = append(*m.events, event)
	}
}

func (m *mockPolicyManager) ManagePolicy(_ config.PolicyPayload)                                 {}
func (m *mockPolicyManager) RemovePolicyDataset(_ string, _ string, _ string, _ backend.Backend) {}
func (m *mockPolicyManager) GetPolicyState() ([]policies.PolicyData, error) {
	return nil, nil
}

func (m *mockPolicyManager) GetRepo() policies.PolicyRepo {
	return m.repo
}

func (m *mockPolicyManager) ApplyBackendPolicies(name string, _ backend.Backend) error {
	m.record("apply:" + name)
	return nil
}

func (m *mockPolicyManager) RemoveBackendPolicies(name string, _ backend.Backend, permanently bool) error {
	m.record(fmt.Sprintf("remove:%s:permanently=%t", name, permanently))
	return nil
}

func (m *mockPolicyManager) RemovePolicy(_ string, _ string, _ string) error {
	return nil
}

func (m *mockPolicyManager) SetStarter(_ policymgr.BackendStarter) {}

// restartableBackend records, into the shared slice, the calls a restart makes.
type restartableBackend struct {
	backend.Backend
	events  *[]string
	applied []policies.PolicyData
}

func (r *restartableBackend) Configure(*slog.Logger, policies.PolicyRepo, map[string]any, config.BackendCommons, filesmgr.Manager) error {
	*r.events = append(*r.events, "configure")
	return nil
}

func (r *restartableBackend) FullReset(context.Context) error {
	*r.events = append(*r.events, "reset")
	return nil
}

func (r *restartableBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	return backend.Running, "", nil
}

func (r *restartableBackend) ApplyPolicy(pd policies.PolicyData, updatePolicy bool) error {
	*r.events = append(*r.events, fmt.Sprintf("apply-policy:%s:update=%t", pd.ID, updatePolicy))
	r.applied = append(r.applied, pd)
	return nil
}

func (r *restartableBackend) RemovePolicy(pd policies.PolicyData) error {
	*r.events = append(*r.events, "remove-policy:"+pd.ID)
	return nil
}

type failingResetBackend struct{ restartableBackend }

func (f *failingResetBackend) FullReset(context.Context) error {
	*f.events = append(*f.events, "reset")
	return errors.New("reset failed")
}

type failingConfigureBackend struct{ restartableBackend }

func (f *failingConfigureBackend) Configure(*slog.Logger, policies.PolicyRepo, map[string]any, config.BackendCommons, filesmgr.Manager) error {
	*f.events = append(*f.events, "configure")
	return errors.New("configure failed")
}

// A restart keeps the backend's policies and re-applies them once the
// backend is back: they are marked unknown for the restart, not deleted,
// and applied after the reset.
func TestRestartBackendReappliesItsOwnPolicies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	events := []string{}
	pm := &mockPolicyManager{repo: repo, events: &events}
	be := &restartableBackend{events: &events}
	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), repo),
		config:              config.Config{},
	}

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	assert.Equal(t, []string{
		"remove:snmp_discovery:permanently=false",
		"configure",
		"reset",
		"apply:snmp_discovery",
	}, events, "policies kept, removed before the reset and applied after it")
}

// A reset that fails leaves the policies marked for the next restart and
// does not apply them to a backend that is not back.
func TestRestartBackendDoesNotReapplyWhenTheResetFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	events := []string{}
	pm := &mockPolicyManager{repo: repo, events: &events}
	be := &failingResetBackend{restartableBackend: restartableBackend{events: &events}}
	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), repo),
		config:              config.Config{},
	}

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	assert.Equal(t, []string{
		"remove:snmp_discovery:permanently=false",
		"configure",
		"reset",
	}, events, "the removal still runs and nothing past the failed reset does")
}

// A Configure failure never stops the backend: it is still running its
// previous configuration, so the policies removed for the restart are handed
// back immediately rather than left marked unknown for a restart that may
// not come again soon.
func TestRestartBackendReappliesPoliciesWhenConfigureFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	events := []string{}
	pm := &mockPolicyManager{repo: repo, events: &events}
	be := &failingConfigureBackend{restartableBackend: restartableBackend{events: &events}}
	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), repo),
		config:              config.Config{},
	}

	restartErr := a.RestartBackend(context.Background(), "snmp_discovery", "test")

	require.Error(t, restartErr)
	assert.Equal(t, []string{
		"remove:snmp_discovery:permanently=false",
		"configure",
		"apply:snmp_discovery",
	}, events, "the backend never stopped, so the removed policies are reapplied immediately")
}

// End to end with the real policy manager: a policy the backend ran before
// the restart is still in the repo afterwards, running, and was handed to
// the backend once more in the remove-then-apply form.
func TestRestartBackendReappliesPoliciesEndToEnd(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)
	events := []string{}
	be := &restartableBackend{events: &events}
	require.NoError(t, pm.GetRepo().Update(policies.PolicyData{ID: "kept", Name: "Kept", Backend: "snmp_discovery", Version: 3, Data: map[string]any{"k": "v"}, State: policies.Running}))
	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), pm.GetRepo()),
		config:              config.Config{},
	}

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	stored, err := pm.GetRepo().Get("kept")
	require.NoError(t, err, "the policy survives the restart")
	assert.Equal(t, policies.Running, stored.State)
	assert.Equal(t, int32(3), stored.Version)
	assert.Equal(t, []string{"remove-policy:kept", "configure", "reset", "apply-policy:kept:update=true"}, events,
		"the backend is asked to drop the policy before the reset and handed it again after")
	require.Len(t, be.applied, 1)
	assert.Equal(t, int32(3), be.applied[0].Version)
}

// filesmgrRestartBackend records, into the shared slice, the Stop/Start calls
// a filesmgr-driven restart makes. startFailures controls how many of the
// first calls to Start return an error before Start starts succeeding; a
// zero value never fails.
type filesmgrRestartBackend struct {
	restartableBackend
	binaryName    string
	startFailures int
	startCalls    int
}

func (r *filesmgrRestartBackend) ManagedBinaryName() string { return r.binaryName }

func (r *filesmgrRestartBackend) Stop(context.Context) error {
	*r.events = append(*r.events, "stop")
	return nil
}

func (r *filesmgrRestartBackend) Start(context.Context, context.CancelFunc) error {
	r.startCalls++
	*r.events = append(*r.events, "start")
	if r.startCalls <= r.startFailures {
		return errors.New("start failed")
	}
	return nil
}

// A filesmgr-driven restart brackets its Stop/Start sequence the same way
// RestartBackend does: policies are marked unknown before Stop and handed
// back to the backend once Start succeeds.
func TestRestartBackendWithFilesmgrRollback_ReappliesPoliciesAfterSuccessfulStart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	events := []string{}
	pm := &mockPolicyManager{events: &events}
	be := &filesmgrRestartBackend{restartableBackend: restartableBackend{events: &events}, binaryName: "orb-worker"}
	a := &orbAgent{
		logger:        logger,
		backends:      map[string]backend.Backend{"worker": be},
		policyManager: pm,
		filesManager:  &mockFilesManager{},
	}

	a.restartBackendWithFilesmgrRollback(context.Background(), "worker")

	assert.Equal(t, []string{
		"remove:worker:permanently=false",
		"stop",
		"start",
		"apply:worker",
	}, events)
}

// A Start that fails, then succeeds after a rollback, is re-applied exactly
// once, after the retry, not after the failed first attempt.
func TestRestartBackendWithFilesmgrRollback_ReappliesPoliciesAfterRollbackRetry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	events := []string{}
	pm := &mockPolicyManager{events: &events}
	be := &filesmgrRestartBackend{restartableBackend: restartableBackend{events: &events}, binaryName: "orb-worker", startFailures: 1}
	a := &orbAgent{
		logger:        logger,
		backends:      map[string]backend.Backend{"worker": be},
		policyManager: pm,
		filesManager:  &mockFilesManager{},
	}

	a.restartBackendWithFilesmgrRollback(context.Background(), "worker")

	assert.Equal(t, []string{
		"remove:worker:permanently=false",
		"stop",
		"start",
		"start",
		"apply:worker",
	}, events, "apply must run exactly once, after the successful retry")
}

// A Start that fails on a backend with no managed binary name cannot roll
// back, so the restart gives up without ever reapplying the policies it
// removed.
func TestRestartBackendWithFilesmgrRollback_DoesNotReapplyWithoutAManagedBinary(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	events := []string{}
	pm := &mockPolicyManager{events: &events}
	be := &filesmgrRestartBackend{restartableBackend: restartableBackend{events: &events}, startFailures: 1}
	a := &orbAgent{
		logger:        logger,
		backends:      map[string]backend.Backend{"worker": be},
		policyManager: pm,
		filesManager:  &mockFilesManager{},
	}

	a.restartBackendWithFilesmgrRollback(context.Background(), "worker")

	assert.Equal(t, []string{
		"remove:worker:permanently=false",
		"stop",
		"start",
	}, events)
}

// mockFilesManager implements filesmgr.Manager for testing (no-op)
type mockFilesManager struct{}

func (m *mockFilesManager) Start(_ context.Context) error { return nil }
func (m *mockFilesManager) Stop(_ context.Context) error  { return nil }
func (m *mockFilesManager) Ensure(_ context.Context, _ filesmgr.FileSpec) (string, error) {
	return "", nil
}

func (m *mockFilesManager) Get(_ string) (filesmgr.FileEntry, bool) {
	return filesmgr.FileEntry{}, false
}

func (m *mockFilesManager) List() []filesmgr.FileEntry                  { return nil }
func (m *mockFilesManager) ListPending() []filesmgr.FileEntry           { return nil }
func (m *mockFilesManager) Remove(_ context.Context, _ string) error    { return nil }
func (m *mockFilesManager) Rollback(_ context.Context, _ string) error  { return nil }
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

	// Verify the OTLP gRPC URL was overridden before backends started
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
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

	// The OTLP override creates the "common" backend with the grpc URL before
	// startBackends extracts it into backendsCommon (and deletes the key).
	assert.Equal(t, "grpc://localhost:4317", orbAgent.backendsCommon.Otlp.Grpc)
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
}
