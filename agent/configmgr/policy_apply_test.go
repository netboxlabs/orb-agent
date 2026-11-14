package configmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
	"github.com/netboxlabs/orb-agent/agent/supervisor"
)

// backendCall is one thing the policy manager asked a recordingBackend to do.
type backendCall struct {
	Op      string // "apply" or "remove"
	Policy  string
	Version int32
	Data    any
}

// recordingBackend records what the policy manager asks of it. An apply
// with updatePolicy set first removes the policy, as every bundled backend
// does, so it records a "remove" before the "apply", the order pktvisor logs
// them in.
type recordingBackend struct {
	mu      sync.Mutex
	started bool
	calls   []backendCall
}

var _ backend.Backend = (*recordingBackend)(nil)

var recordingBackendSeq atomic.Int32

// registerRecordingBackend registers a recordingBackend under a name no
// other test uses and returns both. An eager backend is running from the
// start; an on-demand one runs once the supervisor starts it.
func registerRecordingBackend(t *testing.T, running bool) (string, *recordingBackend) {
	t.Helper()
	name := fmt.Sprintf("recorder_%d", recordingBackendSeq.Add(1))
	be := &recordingBackend{started: running}
	backend.Register(name, be)
	return name, be
}

func (b *recordingBackend) Configure(*slog.Logger, policies.PolicyRepo, map[string]any, config.BackendCommons, filesmgr.Manager) error {
	return nil
}

func (b *recordingBackend) Version() (string, error) { return "test", nil }

func (b *recordingBackend) Start(context.Context, context.CancelFunc) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = true
	return nil
}

func (b *recordingBackend) Stop(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = false
	return nil
}

func (b *recordingBackend) FullReset(context.Context) error { return nil }

func (b *recordingBackend) GetStartTime() time.Time { return time.Time{} }

func (b *recordingBackend) GetCapabilities() (map[string]any, error) { return map[string]any{}, nil }

// GetRunningStatus reports Unknown until the backend is started, the way a
// backend the agent never started does.
func (b *recordingBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started {
		return backend.Unknown, "", nil
	}
	return backend.Running, "", nil
}

func (b *recordingBackend) GetInitialState() backend.RunningStatus { return backend.Running }

func (b *recordingBackend) ApplyPolicy(data policies.PolicyData, updatePolicy bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if updatePolicy {
		b.calls = append(b.calls, backendCall{Op: "remove", Policy: data.Name, Version: data.Version})
	}
	b.calls = append(b.calls, backendCall{Op: "apply", Policy: data.Name, Version: data.Version, Data: data.Data})
	return nil
}

func (b *recordingBackend) RemovePolicy(data policies.PolicyData) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, backendCall{Op: "remove", Policy: data.Name, Version: data.Version})
	return nil
}

// callsFor returns what the backend was asked about one policy, in order.
func (b *recordingBackend) callsFor(policy string) []backendCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []backendCall
	for _, c := range b.calls {
		if c.Policy == policy {
			out = append(out, c)
		}
	}
	return out
}

// reset forgets the calls recorded so far.
func (b *recordingBackend) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = nil
}

// requireAppliedOnce asserts the backend was asked about policy exactly
// once, to apply it fresh, at version, without removing it first.
func requireAppliedOnce(t *testing.T, be *recordingBackend, policy string, version int32) {
	t.Helper()
	calls := be.callsFor(policy)
	require.Len(t, calls, 1, "policy %s must reach the backend once, as one apply: %+v", policy, calls)
	assert.Equal(t, "apply", calls[0].Op, "policy %s: a first apply must not remove it first: %+v", policy, calls)
	assert.Equal(t, version, calls[0].Version, "policy %s", policy)
}

// requireUpdatedOnce asserts the backend was asked about policy exactly once,
// to update it: a remove followed by an apply at version.
func requireUpdatedOnce(t *testing.T, be *recordingBackend, policy string, version int32) {
	t.Helper()
	calls := be.callsFor(policy)
	require.Len(t, calls, 2, "policy %s must be updated once, as one remove and one apply: %+v", policy, calls)
	assert.Equal(t, "remove", calls[0].Op, "policy %s: %+v", policy, calls)
	assert.Equal(t, "apply", calls[1].Op, "policy %s: %+v", policy, calls)
	assert.Equal(t, version, calls[1].Version, "policy %s", policy)
}

// newPolicyManager returns the agent's real policy manager, with no secrets
// manager, as the agent builds it when none is configured.
func newPolicyManager(t *testing.T, logger *slog.Logger) policymgr.PolicyManager {
	t.Helper()
	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{})
	require.NoError(t, err)
	pm, err := policymgr.New(logger, secrets, config.Config{})
	require.NoError(t, err)
	return pm
}

// superviseOnDemand declares beName on demand with a real supervisor, as the
// image declares pktvisor: its first policy starts it, and the policies
// stored while it starts are replayed once it runs.
func superviseOnDemand(t *testing.T, logger *slog.Logger, pm policymgr.PolicyManager, beName string) {
	t.Helper()
	sup := supervisor.New(logger, backend.NewStateManager("git", logger, make(chan string, 1), pm.GetRepo()),
		nil, pm, make(chan string), supervisor.Options{NotRunning: policymgr.ErrBackendNotRunning})
	pm.SetStarter(sup)
	require.NoError(t, sup.ConfigureAll(map[string]any{beName: map[string]any{"start_mode": "on_demand"}},
		config.BackendCommons{}, func(string) context.Context { return context.Background() }))
	t.Cleanup(func() { sup.StopAll(context.Background()) })
}

// awaitApplies waits until the backend has applied every one of policies.
func awaitApplies(t *testing.T, be *recordingBackend, policies ...string) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, p := range policies {
			applied := false
			for _, c := range be.callsFor(p) {
				applied = applied || c.Op == "apply"
			}
			if !applied {
				return false
			}
		}
		return true
	}, 5*time.Second, 5*time.Millisecond)
}

func testOutputLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(t.Output(), nil))
}

// sendAgentPolicies hands the Fleet message handler an agent_policy RPC, as
// Fleet sends it.
func sendAgentPolicies(t *testing.T, m *fleet.Messaging, fullList bool, payloads ...messages.AgentPolicyRPCPayload) {
	t.Helper()
	if payloads == nil {
		// An empty list is [], not null, which the handler refuses.
		payloads = []messages.AgentPolicyRPCPayload{}
	}
	rpc, err := json.Marshal(messages.AgentPolicyRPC{
		SchemaVersion: messages.CurrentRPCSchemaVersion,
		Func:          messages.AgentPolicyRPCFunc,
		Payload:       payloads,
		FullList:      fullList,
	})
	require.NoError(t, err)
	require.NoError(t, m.DispatchToHandlers(t.Context(), rpc, "org", "agent", fleet.TopicActions{}))
}

func fleetPolicy(beName, name string, version int32, value string) messages.AgentPolicyRPCPayload {
	return messages.AgentPolicyRPCPayload{
		Action: "manage", ID: "id-" + name, DatasetID: "dataset-1", AgentGroupID: "group-1",
		Name: name, Backend: beName, Version: version, Data: map[string]any{"key": value},
	}
}

// An edit from Fleet still removes the running policy and applies the new
// version, and a policy Fleet no longer lists is still removed: the first
// apply of a policy skipping the removal changes neither.
func TestFleetPolicyIsAppliedThenUpdatedThenRemoved(t *testing.T) {
	logger := testOutputLogger(t)
	beName, be := registerRecordingBackend(t, true)
	pm := newPolicyManager(t, logger)
	m := fleet.NewMessaging(logger, pm, make(chan struct{}, 1), nil, nil)

	sendAgentPolicies(t, m, false, fleetPolicy(beName, "edge_tcp", 1, "v1"))
	requireAppliedOnce(t, be, "edge_tcp", 1)

	be.reset()
	sendAgentPolicies(t, m, false, fleetPolicy(beName, "edge_tcp", 2, "v2"))
	requireUpdatedOnce(t, be, "edge_tcp", 2)

	be.reset()
	sendAgentPolicies(t, m, true)
	calls := be.callsFor("edge_tcp")
	require.Len(t, calls, 1, "%+v", calls)
	assert.Equal(t, "remove", calls[0].Op)
	assert.False(t, pm.GetRepo().Exists("id-edge_tcp"))
}

// A policy from Fleet for a backend that starts on demand is stored while
// the backend starts and replayed once it runs: that replay is its first
// apply, and does not remove it first. A later edit from Fleet still removes
// and re-applies it.
func TestFleetPolicyForABackendStartingOnDemandIsNotRemovedBeforeItsFirstApply(t *testing.T) {
	logger := testOutputLogger(t)
	beName, be := registerRecordingBackend(t, false)
	pm := newPolicyManager(t, logger)
	superviseOnDemand(t, logger, pm, beName)
	m := fleet.NewMessaging(logger, pm, make(chan struct{}, 1), nil, nil)

	sendAgentPolicies(t, m, false, fleetPolicy(beName, "edge_tcp", 1, "v1"))
	awaitApplies(t, be, "edge_tcp")
	requireAppliedOnce(t, be, "edge_tcp", 1)

	be.reset()
	sendAgentPolicies(t, m, false, fleetPolicy(beName, "edge_tcp", 2, "v2"))
	requireUpdatedOnce(t, be, "edge_tcp", 2)
}

// The local config manager applies its policies once, at start. For a
// backend that starts on demand that first apply is the replay after the
// start, which does not remove the policy first.
func TestLocalPolicyForABackendStartingOnDemandIsNotRemovedBeforeItsFirstApply(t *testing.T) {
	logger := testOutputLogger(t)
	beName, be := registerRecordingBackend(t, false)
	pm := newPolicyManager(t, logger)
	superviseOnDemand(t, logger, pm, beName)
	lc := &localConfigManager{logger: logger, pMgr: pm}

	require.NoError(t, lc.Start(t.Context(), config.Config{OrbAgent: config.OrbAgent{Policies: map[string]any{
		beName: map[string]any{"edge_tcp": map[string]any{"key": "v1"}, "edge_dns": map[string]any{"key": "v1"}},
	}}}, map[string]backend.Backend{beName: be}))

	awaitApplies(t, be, "edge_tcp", "edge_dns")
	requireAppliedOnce(t, be, "edge_tcp", 1)
	requireAppliedOnce(t, be, "edge_dns", 1)
}
