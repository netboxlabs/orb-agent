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

	// agent, when set, makes ApplyBackendPolicies record whether the
	// backend's restart mutex is held at call time (see ApplyBackendPolicies
	// below), for tests asserting a restart's second re-apply pass runs only
	// after the mutex is released. Left nil, and so checked before use, by
	// tests that do not care.
	agent *orbAgent
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

// ApplyBackendPolicies records a plain "apply:<name>" event, unless agent is
// set: then it records whether the backend's restart mutex was held at call
// time, as "apply:<name>:locked" or "apply:<name>:unlocked", so a test can
// tell a restart's first (locked) re-apply pass from its second (unlocked,
// taken after the mutex is released) one.
func (m *mockPolicyManager) ApplyBackendPolicies(_ context.Context, name string, _ backend.Backend) error {
	if m.agent == nil {
		m.record("apply:" + name)
		return nil
	}
	mu := m.agent.backendRestartLock(name)
	held := !mu.TryLock()
	if !held {
		mu.Unlock()
	}
	state := "unlocked"
	if held {
		state = "locked"
	}
	m.record(fmt.Sprintf("apply:%s:%s", name, state))
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
// and applied after the reset, once while the restart mutex is still held
// and once more after it is released, to pick up anything that landed as
// "starting" in between.
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
	pm.agent = a

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	assert.Equal(t, []string{
		"remove:snmp_discovery:permanently=false",
		"configure",
		"reset",
		"apply:snmp_discovery:locked",
		"apply:snmp_discovery:unlocked",
	}, events, "policies kept, removed before the reset, applied once under the restart mutex and once more after it releases")
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
		"apply:snmp_discovery",
	}, events, "the backend never stopped, so the removed policies are reapplied immediately, then once more with the mutex released")
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

// failOnceApplyBackend fails the first ApplyPolicy call and succeeds on any
// call after, recording how many times it was called, so a test can prove a
// replay's second pass does not retry a policy its first pass already
// answered.
type failOnceApplyBackend struct {
	restartableBackend
	calls int
}

func (f *failOnceApplyBackend) ApplyPolicy(pd policies.PolicyData, updatePolicy bool) error {
	f.calls++
	if f.calls == 1 {
		return errors.New("apply timed out")
	}
	return f.restartableBackend.ApplyPolicy(pd, updatePolicy)
}

// End to end with the real policy manager: a policy the first replay pass
// fails to apply is stored failed to apply with the backend's own reason,
// and the second pass, taken after the restart mutex is released, must not
// hand it to the backend again.
func TestRestartBackendSecondPassDoesNotRetryAPolicyTheFirstPassFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)
	events := []string{}
	be := &failOnceApplyBackend{restartableBackend: restartableBackend{events: &events}}
	require.NoError(t, pm.GetRepo().Update(policies.PolicyData{ID: "flaky", Name: "Flaky", Backend: "snmp_discovery", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Running}))
	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), pm.GetRepo()),
		config:              config.Config{},
	}

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	stored, err := pm.GetRepo().Get("flaky")
	require.NoError(t, err)
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Equal(t, "apply timed out", stored.BackendErr)
	assert.Equal(t, 1, be.calls, "the second pass must not retry a policy the first pass already failed")
}

// A Start (file-driven or otherwise) that is already blocked on the restart
// mutex when Stop cancels the agent context can still succeed once the
// mutex is free, but by then the agent is shutting down: the reset succeeds
// and the policies stay marked unknown rather than being handed back to a
// backend about to be torn down.
func TestRestartBackendDoesNotReapplyAfterShutdownBegan(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, a.RestartBackend(ctx, "snmp_discovery", "test"))

	assert.Equal(t, []string{
		"remove:snmp_discovery:permanently=false",
		"configure",
		"reset",
	}, events, "shutdown already began, so the policies must stay unknown rather than be reapplied")
}

// Stop cancels the dispatcher and the file-driven restart contexts, then
// takes each backend's restart mutex to stop it, and only cancels the agent
// context at the end, after every backend is stopped. A health or fleet
// restart that already holds the restart mutex when Stop begins therefore
// still sees a live context when it reaches the re-apply: ctx.Err() alone
// would not catch it, so the stop context does.
func TestRestartBackendDoesNotReapplyOnceStopBegan(t *testing.T) {
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
	a.stopCtx, a.stopCancel = context.WithCancel(context.Background())
	a.stopCancel()

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	assert.Equal(t, []string{
		"remove:snmp_discovery:permanently=false",
		"configure",
		"reset",
	}, events, "Stop already began, so the policies must stay unknown rather than be reapplied")
}

// stopCancellingBackend calls the agent's stopCancel from every ApplyPolicy
// call, simulating Stop beginning while a restart's replay of more than one
// policy is mid-loop: once the first policy's apply triggers it, the loop's
// own per-iteration context check must stop the replay before the second.
type stopCancellingBackend struct {
	restartableBackend
	agent *orbAgent
}

func (s *stopCancellingBackend) ApplyPolicy(pd policies.PolicyData, updatePolicy bool) error {
	s.agent.stopCancel()
	return s.restartableBackend.ApplyPolicy(pd, updatePolicy)
}

// End to end with the real policy manager: Stop beginning mid-replay (through
// the stop context, not the ctx argument, which stays live throughout) must
// be observed between policies, the same way a cancelled ctx argument is.
// Only one of the two stored policies reaches the backend; the other is left
// as it was.
func TestRestartBackendStopsReplayingWhenStopBeginsMidLoop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)

	events := []string{}
	stopCtx, stopCancel := context.WithCancel(context.Background())
	a := &orbAgent{
		logger:              logger,
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), pm.GetRepo()),
		config:              config.Config{},
		stopCtx:             stopCtx,
		stopCancel:          stopCancel,
	}
	be := &stopCancellingBackend{restartableBackend: restartableBackend{events: &events}, agent: a}
	a.backends = map[string]backend.Backend{"snmp_discovery": be}
	backend.Register("snmp_discovery", be)

	require.NoError(t, pm.GetRepo().Update(policies.PolicyData{ID: "one", Name: "one", Backend: "snmp_discovery", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Unknown}))
	require.NoError(t, pm.GetRepo().Update(policies.PolicyData{ID: "two", Name: "two", Backend: "snmp_discovery", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Unknown}))

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	require.Len(t, be.applied, 1, "the second policy must never reach the backend once Stop begins")

	state, err := pm.GetPolicyState()
	require.NoError(t, err)
	var running, unknown int
	for _, pd := range state {
		switch pd.State {
		case policies.Running:
			running++
		case policies.Unknown:
			unknown++
		}
	}
	assert.Equal(t, 1, running, "the policy reached before Stop began was applied")
	assert.Equal(t, 1, unknown, "the policy the replay never reached stays as it was")
}

// A restart holds the restart mutex across the whole sequence, so the
// starter reports a backend as starting for as long as a restart of it is in
// flight, and running again the instant the mutex is free.
func TestRestartStarterReportsStartingWhileARestartHoldsTheMutex(t *testing.T) {
	a := &orbAgent{}
	starter := restartStarter{agent: a}

	mu := a.backendRestartLock("snmp_discovery")
	mu.Lock()

	state, err := starter.EnsureStarted("snmp_discovery")
	require.NoError(t, err)
	assert.Equal(t, policymgr.StartStarting, state, "a restart holds the mutex, so the starter must report starting")

	mu.Unlock()

	state, err = starter.EnsureStarted("snmp_discovery")
	require.NoError(t, err)
	assert.Equal(t, policymgr.StartRunning, state, "no restart is in flight, so the starter must report running")

	require.True(t, a.backendRestartLock("snmp_discovery").TryLock(), "the mutex must be free after EnsureStarted reports running")
	a.backendRestartLock("snmp_discovery").Unlock()
}

// blockingResetBackend signals entry into FullReset on a channel and waits on
// a release channel before returning, so a test can deliver a policy while a
// restart is blocked inside the reset.
type blockingResetBackend struct {
	restartableBackend
	entered chan struct{}
	release chan struct{}
}

func (b *blockingResetBackend) FullReset(context.Context) error {
	*b.events = append(*b.events, "reset")
	close(b.entered)
	<-b.release
	return nil
}

// A policy delivered while a restart is in flight for its backend is stored
// failed to apply with the reason the starter gives, is never handed to the
// backend, and is applied exactly once, by the restart's own re-apply, once
// the restart finishes. This is the window RestartBackend documents between
// FullReset returning and the re-apply taking the policy manager's mutex.
func TestManageDuringARestartIsAppliedExactlyOnce(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)

	events := []string{}
	be := &blockingResetBackend{
		restartableBackend: restartableBackend{events: &events},
		entered:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	backend.Register("snmp_discovery", be)

	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), pm.GetRepo()),
		config:              config.Config{},
	}
	// Installed the same way agent.New installs it: after the orbAgent is
	// built, before any goroutine can reach the policy manager.
	pm.SetStarter(restartStarter{agent: a})

	restartDone := make(chan error, 1)
	go func() {
		restartDone <- a.RestartBackend(context.Background(), "snmp_discovery", "test")
	}()

	select {
	case <-be.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the restart to enter FullReset")
	}

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "during-restart",
		Name:      "during-restart-policy",
		Backend:   "snmp_discovery",
		DatasetID: "dataset-1",
		Version:   1,
		Data:      map[string]any{"k": "v"},
	}
	pm.ManagePolicy(payload)

	stored, err := pm.GetRepo().Get("during-restart")
	require.NoError(t, err)
	assert.Equal(t, policies.FailedToApply, stored.State, "a manage during the restart must not apply")
	assert.Equal(t, "backend starting", stored.BackendErr)
	assert.Empty(t, be.applied, "the backend must not receive the policy while the restart is in flight")

	close(be.release)

	select {
	case restartErr := <-restartDone:
		require.NoError(t, restartErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RestartBackend to return")
	}

	stored, err = pm.GetRepo().Get("during-restart")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State, "the re-apply after the restart must apply the policy stored while it was in flight")
	require.Len(t, be.applied, 1, "the backend must receive the policy exactly once")
	assert.Equal(t, "during-restart", be.applied[0].ID)
	assert.Contains(t, events, "apply-policy:during-restart:update=true")
}

// windowStampingBackend writes a policy record directly to the repo from
// within FullReset, stamped the way the starter stamps a manage that lands
// while a restart holds the backend's restart mutex: failed to apply with
// the "backend starting" reason. This stands in for the window Finding B
// closes (a manage landing between the restart's first replay and the
// mutex unlock) without needing to choreograph the real race.
type windowStampingBackend struct {
	restartableBackend
	repo policies.PolicyRepo
}

func (w *windowStampingBackend) FullReset(ctx context.Context) error {
	if err := w.restartableBackend.FullReset(ctx); err != nil {
		return err
	}
	return w.repo.Update(policies.PolicyData{
		ID:         "during-window",
		Name:       "during-window",
		Backend:    "snmp_discovery",
		Version:    1,
		Data:       map[string]any{"k": "v"},
		State:      policies.FailedToApply,
		BackendErr: policymgr.ReasonBackendStarting,
	})
}

// End to end with the real policy manager: a policy stamped failed to apply
// with the starter's "backend starting" reason, the way one landing in the
// window RestartBackend documents (between the first replay and the restart
// mutex releasing) is stamped, is healed by the restart's own replay and
// ends Running, applied exactly once even though two replay passes run.
// TestManageDuringARestartIsAppliedExactlyOnce proves the same "exactly
// once" outcome through the real concurrent race; this test isolates the
// running-skip's role in it.
func TestRestartBackendHealsAPolicyStampedBackendStartingDuringTheRestart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)

	events := []string{}
	be := &windowStampingBackend{restartableBackend: restartableBackend{events: &events}, repo: pm.GetRepo()}
	backend.Register("snmp_discovery", be)

	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), pm.GetRepo()),
		config:              config.Config{},
	}
	pm.SetStarter(restartStarter{agent: a})

	require.NoError(t, a.RestartBackend(context.Background(), "snmp_discovery", "test"))

	stored, err := pm.GetRepo().Get("during-window")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State, "the record stamped starting during the restart is healed by the restart's own replay")

	var appliedCount int
	for _, applied := range be.applied {
		if applied.ID == "during-window" {
			appliedCount++
		}
	}
	assert.Equal(t, 1, appliedCount, "applied exactly once, even though two replay passes ran")
}

// Outside a restart, a manage applies the way it always has: the starter
// reports the backend running and the policy is applied once.
func TestManageOutsideARestartAppliesAsToday(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)

	events := []string{}
	be := &restartableBackend{events: &events}
	backend.Register("snmp_discovery", be)

	a := &orbAgent{
		logger:              logger,
		backends:            map[string]backend.Backend{"snmp_discovery": be},
		policyManager:       pm,
		backendStateManager: backend.NewStateManager("local", logger, make(chan string, 1), pm.GetRepo()),
		config:              config.Config{},
	}
	pm.SetStarter(restartStarter{agent: a})

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "outside-restart",
		Name:      "outside-restart-policy",
		Backend:   "snmp_discovery",
		DatasetID: "dataset-1",
		Version:   1,
		Data:      map[string]any{"k": "v"},
	}
	pm.ManagePolicy(payload)

	stored, err := pm.GetRepo().Get("outside-restart")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)
	require.Len(t, be.applied, 1)
	assert.Equal(t, "outside-restart", be.applied[0].ID)
	assert.Contains(t, events, "apply-policy:outside-restart:update=false")
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
// back to the backend once Start succeeds, once while the restart mutex is
// still held and once more after it is released.
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
	pm.agent = a

	a.restartBackendWithFilesmgrRollback(context.Background(), "worker")

	assert.Equal(t, []string{
		"remove:worker:permanently=false",
		"stop",
		"start",
		"apply:worker:locked",
		"apply:worker:unlocked",
	}, events)
}

// A Start that fails, then succeeds after a rollback, is re-applied exactly
// once under the restart mutex, after the retry rather than the failed first
// attempt, and once more after the mutex is released.
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
	pm.agent = a

	a.restartBackendWithFilesmgrRollback(context.Background(), "worker")

	assert.Equal(t, []string{
		"remove:worker:permanently=false",
		"stop",
		"start",
		"start",
		"apply:worker:locked",
		"apply:worker:unlocked",
	}, events, "apply runs exactly once under the mutex, after the successful retry, and once more after the mutex releases")
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

// A Start that succeeds after the agent context was already cancelled before
// the call (Stop ran while this restart was blocked on the restart mutex)
// must not hand the policies back: the agent is shutting down.
func TestRestartBackendWithFilesmgrRollbackDoesNotReapplyAfterShutdownBegan(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a.restartBackendWithFilesmgrRollback(ctx, "worker")

	assert.Equal(t, []string{
		"remove:worker:permanently=false",
		"stop",
		"start",
	}, events, "shutdown already began, so the policies must stay unknown rather than be reapplied")
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
