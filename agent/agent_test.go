package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
	"github.com/netboxlabs/orb-agent/agent/supervisor"
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

// testAgentOptions selects what newTestAgent wires; zero values mean none.
type testAgentOptions struct {
	name          string          // the registry name the stub is declared under (unique per test)
	be            backend.Backend // the stub; started by ConfigureAll
	files         filesmgr.Manager
	configManager configmgr.Manager
	supervisor    supervisor.Options // NotRunning is always set to policymgr.ErrBackendNotRunning
}

// newTestAgent builds an agent the way New does, over a real policy manager
// and a real supervisor with the stub backend registered under opts.name
// and started; the supervisor is handed back so a test can reach it
// (BeginStop for the stop-mid-loop test). Every delay defaults to a
// millisecond and the replay interval to an hour unless opts.supervisor
// sets them.
func newTestAgent(t *testing.T, opts testAgentOptions) (*orbAgent, *supervisor.Supervisor) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)
	backend.Register(opts.name, opts.be)
	restartChan := make(chan string, 1)
	state := backend.NewStateManager("local", logger, restartChan, pm.GetRepo())
	so := opts.supervisor
	so.NotRunning = policymgr.ErrBackendNotRunning
	if so.ReapplyRetryDelay == 0 {
		so.ReapplyRetryDelay = time.Millisecond
	}
	if so.ReplayRetryInterval == 0 {
		so.ReplayRetryInterval = time.Hour
	}
	sup := supervisor.New(logger, state, opts.files, pm, restartChan, so)
	require.NoError(t, sup.ConfigureAll(context.Background(), map[string]any{opts.name: nil}, config.BackendCommons{}, func(string) context.Context { return context.Background() }))
	a := &orbAgent{logger: logger, policyManager: pm, backendStateManager: state, filesManager: opts.files, configManager: opts.configManager, supervisor: sup, config: config.Config{}}
	t.Cleanup(func() { sup.StopAll(context.Background()) })
	return a, sup
}

// A supervisor whose stub backend records its own stop before Stop hands off
// to the config manager, so the ordering (the supervisor is stopped first)
// is observable, not just the config manager's own call.
func TestAgentStop_DelegatesToConfigManagerStop(t *testing.T) {
	events := []string{}
	be := &restartableBackend{events: &events}
	mockMgr := &mockConfigManager{
		onStop: func() {
			assert.Contains(t, events, "stop", "the supervisor must stop its backends before the config manager stops")
		},
	}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_stop_delegates", be: be, configManager: mockMgr})

	a.Stop(context.Background())

	assert.True(t, mockMgr.stopCalled, "expected configManager.Stop to be called")
	assert.Contains(t, events, "stop")
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

// New installs the supervisor as the fleet config manager's resetter, so a
// full agent reset restarts through it instead of being ignored.
func TestNewInstallsTheResetterOnTheFleetManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.Config{
		OrbAgent: config.OrbAgent{
			ConfigManager: config.ManagerConfig{Active: "fleet"},
		},
	}

	a, err := New(logger, cfg, false)
	require.NoError(t, err)

	orbAgent := a.(*orbAgent)
	fleetCM, ok := orbAgent.configManager.(*configmgr.FleetConfigManager)
	require.True(t, ok)
	assert.Same(t, orbAgent.supervisor, fleetCM.Resetter(), "New must install the supervisor as the fleet manager's resetter")
}

// mockPolicyManager implements policymgr.PolicyManager for testing
type mockPolicyManager struct {
	repo   policies.PolicyRepo
	events *[]string // shared with the backend stub so one slice records the order

	// mu guards events, applyErrs, and lastErr against a scheduled replay
	// goroutine calling ApplyBackendPolicies while a test concurrently reads
	// the recorded events through snapshotEvents.
	mu sync.Mutex

	// applyErrs queues the errors ApplyBackendPolicies returns, one per call,
	// popped in call order; once the queue is empty every further call
	// returns nil, unless repeatLastErr is set.
	applyErrs []error

	// repeatLastErr, when true, makes ApplyBackendPolicies keep returning the
	// last popped error forever once applyErrs is exhausted, instead of nil.
	repeatLastErr bool
	lastErr       error

	// onApply, when set, runs at the start of every ApplyBackendPolicies
	// call, before the queued error is popped.
	onApply func()
}

func (m *mockPolicyManager) record(event string) {
	m.mu.Lock()
	defer m.mu.Unlock()
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

// nextErr pops the next queued error for ApplyBackendPolicies, in call
// order; once the queue is empty it returns nil, unless repeatLastErr is
// set, in which case it keeps returning the last popped error.
func (m *mockPolicyManager) nextErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.applyErrs) > 0 {
		m.lastErr = m.applyErrs[0]
		m.applyErrs = m.applyErrs[1:]
		return m.lastErr
	}
	if m.repeatLastErr {
		return m.lastErr
	}
	return nil
}

// ApplyBackendPolicies records a plain "apply:<name>" event.
func (m *mockPolicyManager) ApplyBackendPolicies(_ context.Context, name string, _ backend.Backend) error {
	if m.onApply != nil {
		m.onApply()
	}
	m.record("apply:" + name)
	return m.nextErr()
}

func (m *mockPolicyManager) RemoveBackendPolicies(name string, _ backend.Backend, permanently bool) error {
	m.record(fmt.Sprintf("remove:%s:permanently=%t", name, permanently))
	return nil
}

func (m *mockPolicyManager) RemovePolicy(_ string, _ string, _ string) error {
	return nil
}

func (m *mockPolicyManager) SetStarter(_ policymgr.BackendStarter) {}

// restartableBackend records, into the shared slice, the calls a restart
// makes. It reports Running unconditionally and no-ops Start and Stop: the
// supervisor starts it through ConfigureAll and stops it through StopAll
// (a test's t.Cleanup), neither of which any of these tests assert on
// directly.
type restartableBackend struct {
	backend.Backend
	events  *[]string
	applied []policies.PolicyData
}

func (r *restartableBackend) Start(context.Context, context.CancelFunc) error {
	*r.events = append(*r.events, "start")
	return nil
}

func (r *restartableBackend) Stop(context.Context) error {
	*r.events = append(*r.events, "stop")
	return nil
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

// RestartBackend is a thin delegation to the supervisor: the agent adds
// nothing of its own, so the restart it drives shows the same remove,
// configure, reset, apply sequence the supervisor documents for a health or
// fleet-driven restart.
func TestRestartBackendDelegatesToTheSupervisor(t *testing.T) {
	events := []string{}
	be := &restartableBackend{events: &events}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_delegates", be: be})
	require.NoError(t, a.policyManager.GetRepo().Update(policies.PolicyData{
		ID: "p1", Name: "p1", Backend: "e2e_delegates", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Running,
	}))
	events = events[:0]

	require.NoError(t, a.RestartBackend(context.Background(), "e2e_delegates", "test"))

	assert.Equal(t, []string{"remove-policy:p1", "configure", "reset", "apply-policy:p1:update=true"}, events)
}

// failOnceApplyBackend fails the first ApplyPolicy call and succeeds on any
// call after, recording how many times it was called, so a test can prove a
// replay does not retry a policy it already failed to apply.
type failOnceApplyBackend struct {
	restartableBackend
	calls int
}

func (f *failOnceApplyBackend) ApplyPolicy(pd policies.PolicyData, updatePolicy bool) error {
	f.calls++
	if f.calls == 1 {
		return fmt.Errorf("apply timed out")
	}
	return f.restartableBackend.ApplyPolicy(pd, updatePolicy)
}

// End to end with the real policy manager: a policy the replay fails to
// apply is stored failed to apply with the backend's own reason, and is not
// retried within the same replay.
func TestRestartBackendDoesNotRetryAPolicyItFailed(t *testing.T) {
	events := []string{}
	be := &failOnceApplyBackend{restartableBackend: restartableBackend{events: &events}}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_no_retry", be: be})
	require.NoError(t, a.policyManager.GetRepo().Update(policies.PolicyData{ID: "flaky", Name: "Flaky", Backend: "e2e_no_retry", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Running}))
	events = events[:0]

	require.NoError(t, a.RestartBackend(context.Background(), "e2e_no_retry", "test"))

	stored, err := a.policyManager.GetRepo().Get("flaky")
	require.NoError(t, err)
	assert.Equal(t, policies.FailedToApply, stored.State)
	assert.Equal(t, "apply timed out", stored.BackendErr)
	assert.Equal(t, 1, be.calls, "the replay must not retry a policy it already failed to apply")
}

// End to end with the real policy manager: a policy the backend ran before
// the restart is still in the repo afterwards, running, and was handed to
// the backend once more in the remove-then-apply form.
func TestRestartBackendReappliesPoliciesEndToEnd(t *testing.T) {
	events := []string{}
	be := &restartableBackend{events: &events}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_reapplies", be: be})
	require.NoError(t, a.policyManager.GetRepo().Update(policies.PolicyData{ID: "kept", Name: "Kept", Backend: "e2e_reapplies", Version: 3, Data: map[string]any{"k": "v"}, State: policies.Running}))
	events = events[:0]

	require.NoError(t, a.RestartBackend(context.Background(), "e2e_reapplies", "test"))

	stored, err := a.policyManager.GetRepo().Get("kept")
	require.NoError(t, err, "the policy survives the restart")
	assert.Equal(t, policies.Running, stored.State)
	assert.Equal(t, int32(3), stored.Version)
	assert.Equal(t, []string{"remove-policy:kept", "configure", "reset", "apply-policy:kept:update=true"}, events,
		"the backend is asked to drop the policy before the reset and handed it again after")
	require.Len(t, be.applied, 1)
	assert.Equal(t, int32(3), be.applied[0].Version)
}

// stopCancellingBackend calls the supervisor's BeginStop from every
// ApplyPolicy call, simulating Stop beginning while a restart's replay of
// more than one policy is mid-loop: once the first policy's apply triggers
// it, the loop's own per-iteration context check must stop the replay
// before the second.
type stopCancellingBackend struct {
	restartableBackend
	sup *supervisor.Supervisor
}

func (s *stopCancellingBackend) ApplyPolicy(pd policies.PolicyData, updatePolicy bool) error {
	s.sup.BeginStop()
	return s.restartableBackend.ApplyPolicy(pd, updatePolicy)
}

// End to end with the real policy manager: Stop beginning mid-replay (through
// the supervisor's stop context, not the ctx argument, which stays live
// throughout) must be observed between policies, the same way a cancelled
// ctx argument is. Only one of the two stored policies reaches the backend;
// the other is left as it was.
func TestRestartBackendStopsReplayingWhenStopBeginsMidLoop(t *testing.T) {
	events := []string{}
	be := &stopCancellingBackend{restartableBackend: restartableBackend{events: &events}}
	a, sup := newTestAgent(t, testAgentOptions{name: "e2e_stop_mid_loop", be: be})
	be.sup = sup

	require.NoError(t, a.policyManager.GetRepo().Update(policies.PolicyData{ID: "one", Name: "one", Backend: "e2e_stop_mid_loop", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Unknown}))
	require.NoError(t, a.policyManager.GetRepo().Update(policies.PolicyData{ID: "two", Name: "two", Backend: "e2e_stop_mid_loop", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Unknown}))
	events = events[:0]

	require.NoError(t, a.RestartBackend(context.Background(), "e2e_stop_mid_loop", "test"))

	require.Len(t, be.applied, 1, "the second policy must never reach the backend once Stop begins")

	state, err := a.policyManager.GetPolicyState()
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
// the restart finishes. This is the window the supervisor documents between
// FullReset returning and the re-apply taking the policy manager's mutex.
func TestManageDuringARestartIsAppliedExactlyOnce(t *testing.T) {
	events := []string{}
	be := &blockingResetBackend{
		restartableBackend: restartableBackend{events: &events},
		entered:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_manage_during_restart", be: be})
	events = events[:0]

	restartDone := make(chan error, 1)
	go func() {
		restartDone <- a.RestartBackend(context.Background(), "e2e_manage_during_restart", "test")
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
		Backend:   "e2e_manage_during_restart",
		DatasetID: "dataset-1",
		Version:   1,
		Data:      map[string]any{"k": "v"},
	}
	a.policyManager.ManagePolicy(payload)

	stored, err := a.policyManager.GetRepo().Get("during-restart")
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

	stored, err = a.policyManager.GetRepo().Get("during-restart")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State, "the re-apply after the restart must apply the policy stored while it was in flight")
	require.Len(t, be.applied, 1, "the backend must receive the policy exactly once")
	assert.Equal(t, "during-restart", be.applied[0].ID)
	assert.Contains(t, events, "apply-policy:during-restart:update=true")
}

// windowStampingBackend writes a policy record directly to the repo from
// within FullReset, stamped the way the starter stamps a manage that lands
// while the restarting marker is set: failed to apply with the "backend
// starting" reason. This stands in for a manage landing during the restart
// without needing to choreograph the real race.
type windowStampingBackend struct {
	restartableBackend
	repo policies.PolicyRepo
	// backendName is the name the entry is declared under (set by
	// newTestAgent, so it is filled in after construction), used to stamp
	// the policy record with the backend the replay filters on.
	backendName string
}

func (w *windowStampingBackend) FullReset(ctx context.Context) error {
	if err := w.restartableBackend.FullReset(ctx); err != nil {
		return err
	}
	return w.repo.Update(policies.PolicyData{
		ID:         "during-window",
		Name:       "during-window",
		Backend:    w.backendName,
		Version:    1,
		Data:       map[string]any{"k": "v"},
		State:      policies.FailedToApply,
		BackendErr: policymgr.ReasonBackendStarting,
	})
}

// End to end with the real policy manager: a policy stamped failed to apply
// with the starter's "backend starting" reason, the way one landing while
// the restarting marker is set is stamped, is healed by the restart's own
// single replay and ends Running, applied exactly once.
// TestManageDuringARestartIsAppliedExactlyOnce proves the same "exactly
// once" outcome through the real concurrent race; this test isolates the
// running-skip's role in it.
func TestRestartBackendHealsAPolicyStampedBackendStartingDuringTheRestart(t *testing.T) {
	events := []string{}
	be := &windowStampingBackend{restartableBackend: restartableBackend{events: &events}, backendName: "e2e_heals_window"}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_heals_window", be: be})
	be.repo = a.policyManager.GetRepo()
	events = events[:0]

	require.NoError(t, a.RestartBackend(context.Background(), "e2e_heals_window", "test"))

	stored, err := a.policyManager.GetRepo().Get("during-window")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State, "the record stamped starting during the restart is healed by the restart's own replay")

	var appliedCount int
	for _, applied := range be.applied {
		if applied.ID == "during-window" {
			appliedCount++
		}
	}
	assert.Equal(t, 1, appliedCount, "applied exactly once by the replay")
}

// blockingApplyBackend blocks the first call to ApplyPolicy on a channel,
// signalling entry so a test can deliver a manage while that call is in
// flight, then waits for release before returning. Any later call (a manage
// applied directly once the backend is up) proceeds unblocked.
type blockingApplyBackend struct {
	restartableBackend
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingApplyBackend) ApplyPolicy(pd policies.PolicyData, updatePolicy bool) error {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.restartableBackend.ApplyPolicy(pd, updatePolicy)
}

// A manage delivered while the restart's replay is itself inside an apply
// call (the restarting marker has already cleared, since the replay only
// starts after the clear) waits on the apply mutex the replay holds and,
// once it is free, applies directly to the backend, which is up; it is
// never stored as starting and never replayed.
func TestManageArrivingDuringTheReplayAppliesDirectlyOnce(t *testing.T) {
	events := []string{}
	be := &blockingApplyBackend{
		restartableBackend: restartableBackend{events: &events},
		entered:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_manage_during_replay", be: be})
	require.NoError(t, a.policyManager.GetRepo().Update(policies.PolicyData{ID: "seeded", Name: "seeded", Backend: "e2e_manage_during_replay", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Running}))
	events = events[:0]

	restartDone := make(chan error, 1)
	go func() {
		restartDone <- a.RestartBackend(context.Background(), "e2e_manage_during_replay", "test")
	}()

	select {
	case <-be.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the replay to enter its apply call")
	}

	manageDone := make(chan struct{})
	go func() {
		defer close(manageDone)
		a.policyManager.ManagePolicy(config.PolicyPayload{
			Action:    "manage",
			ID:        "during-replay",
			Name:      "during-replay-policy",
			Backend:   "e2e_manage_during_replay",
			DatasetID: "dataset-1",
			Version:   1,
			Data:      map[string]any{"k": "v"},
		})
	}()

	close(be.release)

	select {
	case restartErr := <-restartDone:
		require.NoError(t, restartErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RestartBackend to return")
	}

	select {
	case <-manageDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the manage to finish")
	}

	stored, err := a.policyManager.GetRepo().Get("during-replay")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State, "a manage arriving during the replay must apply directly")

	var directApplies int
	for _, applied := range be.applied {
		if applied.ID == "during-replay" {
			directApplies++
		}
	}
	assert.Equal(t, 1, directApplies, "the manage must be applied exactly once")
	assert.Contains(t, events, "apply-policy:during-replay:update=false",
		"a direct manage uses the plain apply form, not the replay's remove-then-apply form")

	seededStored, err := a.policyManager.GetRepo().Get("seeded")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, seededStored.State)
	var seededApplies int
	for _, applied := range be.applied {
		if applied.ID == "seeded" {
			seededApplies++
		}
	}
	assert.Equal(t, 1, seededApplies, "the seeded policy was applied exactly once by the replay")
}

// yieldingResetBackend sleeps briefly inside FullReset, widening the window
// in which a second, concurrent restart of the same backend can attempt to
// take the restart mutex while the first is still inside it.
type yieldingResetBackend struct {
	restartableBackend
}

func (y *yieldingResetBackend) FullReset(ctx context.Context) error {
	time.Sleep(20 * time.Millisecond)
	return y.restartableBackend.FullReset(ctx)
}

// Two restarts of the same backend issued at once are serialized by the
// restart mutex: each removes the policy, resets, and replays it, so it
// ends Running and was handed to the backend exactly twice, once per
// restart, never lost to an interleaving between them.
func TestBackToBackRestartsDoNotLoseAPolicy(t *testing.T) {
	events := []string{}
	be := &yieldingResetBackend{restartableBackend: restartableBackend{events: &events}}
	a, _ := newTestAgent(t, testAgentOptions{name: "e2e_back_to_back", be: be})
	require.NoError(t, a.policyManager.GetRepo().Update(policies.PolicyData{ID: "seeded", Name: "seeded", Backend: "e2e_back_to_back", Version: 1, Data: map[string]any{"k": "v"}, State: policies.Running}))
	events = events[:0]

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- a.RestartBackend(context.Background(), "e2e_back_to_back", "test")
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for both restarts to finish")
	}
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	stored, err := a.policyManager.GetRepo().Get("seeded")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State)

	var applies int
	for _, applied := range be.applied {
		if applied.ID == "seeded" {
			applies++
		}
	}
	assert.Equal(t, 2, applies, "each restart replays the policy once")
}

// notRunningOnceBackend answers not running the first time GetRunningStatus
// is called after the reset, then running for every call after, closing
// notRunningSeen the moment it gives that first not-running answer so a test
// can deliver a manage while the retry delay that follows it is still
// running.
type notRunningOnceBackend struct {
	restartableBackend
	mu             sync.Mutex
	calls          int
	notRunningSeen chan struct{}
}

func (b *notRunningOnceBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	b.mu.Lock()
	b.calls++
	first := b.calls == 1
	b.mu.Unlock()
	if first {
		close(b.notRunningSeen)
		return backend.BackendError, "not ready yet", nil
	}
	return backend.Running, "", nil
}

// End to end with the real policy manager: a manage delivered while the
// replay's first attempt has already answered not running, but before its
// retry delay has elapsed, is stored as starting by the marker the removal
// set (the failed gate left it set). The retry's next attempt, once the
// backend answers, applies it exactly like every other record a restart
// deferred: through the replay's own remove-then-apply form, not a manage
// applying it directly.
func TestManageDuringTheReplayRetryDelayIsAppliedByTheRetry(t *testing.T) {
	events := []string{}
	be := &notRunningOnceBackend{restartableBackend: restartableBackend{events: &events}, notRunningSeen: make(chan struct{})}
	a, _ := newTestAgent(t, testAgentOptions{
		name:       "e2e_retry_delay",
		be:         be,
		supervisor: supervisor.Options{ReapplyRetryDelay: 50 * time.Millisecond},
	})
	events = events[:0]

	restartDone := make(chan error, 1)
	go func() {
		restartDone <- a.RestartBackend(context.Background(), "e2e_retry_delay", "test")
	}()

	select {
	case <-be.notRunningSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the replay's first not-running probe")
	}

	manageDone := make(chan struct{})
	go func() {
		defer close(manageDone)
		a.policyManager.ManagePolicy(config.PolicyPayload{
			Action:    "manage",
			ID:        "during-retry-delay",
			Name:      "during-retry-delay-policy",
			Backend:   "e2e_retry_delay",
			DatasetID: "dataset-1",
			Version:   1,
			Data:      map[string]any{"k": "v"},
		})
	}()

	select {
	case restartErr := <-restartDone:
		require.NoError(t, restartErr)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RestartBackend to return")
	}
	select {
	case <-manageDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the manage to finish")
	}

	stored, err := a.policyManager.GetRepo().Get("during-retry-delay")
	require.NoError(t, err)
	assert.Equal(t, policies.Running, stored.State, "the manage must be healed by the retry, not left failed")

	var applies int
	for _, applied := range be.applied {
		if applied.ID == "during-retry-delay" {
			applies++
		}
	}
	assert.Equal(t, 1, applies, "applied exactly once")
	assert.Contains(t, events, "apply-policy:during-retry-delay:update=true",
		"applied by the replay's remove-then-apply form, not a direct manage")
}

// Outside a restart, a manage applies the way it always has: no restart has
// set the backend's marker, so the policy is applied once, directly.
func TestManageOutsideARestartAppliesAsToday(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)

	events := []string{}
	be := &restartableBackend{events: &events}
	backend.Register("e2e_outside", be)

	payload := config.PolicyPayload{
		Action:    "manage",
		ID:        "outside-restart",
		Name:      "outside-restart-policy",
		Backend:   "e2e_outside",
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
