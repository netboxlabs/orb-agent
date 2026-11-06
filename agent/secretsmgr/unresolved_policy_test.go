package secretsmgr_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
)

// These tests run the polling secrets manager with the policy manager and a
// backend that keeps what it runs, through the orderings a unit test of
// either side cannot reach.

// vaultStub answers reads from values and errs; block makes the next read of
// a body wait until released.
type vaultStub struct {
	mu      sync.Mutex
	reads   map[string]int
	values  map[string]string
	errs    map[string]error
	gate    map[string]chan struct{}
	entered map[string]chan struct{}
}

func newVaultStub() *vaultStub {
	return &vaultStub{reads: map[string]int{}, values: map[string]string{}, errs: map[string]error{}, gate: map[string]chan struct{}{}, entered: map[string]chan struct{}{}}
}

func (v *vaultStub) set(body, val string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.values[body] = val
	delete(v.errs, body)
}

func (v *vaultStub) fail(body string, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.errs[body] = err
}

func (v *vaultStub) block(body string) (entered <-chan struct{}, release func()) {
	v.mu.Lock()
	defer v.mu.Unlock()
	g, e := make(chan struct{}), make(chan struct{})
	v.gate[body], v.entered[body] = g, e
	return e, func() { close(g) }
}

func (v *vaultStub) readsOf(body string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reads[body]
}

func (v *vaultStub) fetch(body string) (string, error) {
	v.mu.Lock()
	v.reads[body]++
	g, gated := v.gate[body]
	if gated {
		close(v.entered[body])
		delete(v.gate, body)
		delete(v.entered, body)
	}
	v.mu.Unlock()
	if gated {
		<-g
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err, ok := v.errs[body]; ok {
		return "", err
	}
	if val, ok := v.values[body]; ok {
		return val, nil
	}
	return "", fmt.Errorf("secret not found: %s", body)
}

// keepingBackend runs the policies applied to it, by name.
type keepingBackend struct {
	mu      sync.Mutex
	running map[string]any
}

func (f *keepingBackend) Configure(*slog.Logger, policies.PolicyRepo, map[string]any, config.BackendCommons, filesmgr.Manager) error {
	return nil
}
func (f *keepingBackend) Version() (string, error)                        { return "1", nil }
func (f *keepingBackend) Start(context.Context, context.CancelFunc) error { return nil }
func (f *keepingBackend) Stop(context.Context) error                      { return nil }
func (f *keepingBackend) FullReset(context.Context) error                 { return nil }
func (f *keepingBackend) GetStartTime() time.Time                         { return time.Time{} }
func (f *keepingBackend) GetCapabilities() (map[string]any, error)        { return nil, nil }
func (f *keepingBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	return backend.Running, "", nil
}
func (f *keepingBackend) GetInitialState() backend.RunningStatus { return backend.Running }

func (f *keepingBackend) ApplyPolicy(pd policies.PolicyData, update bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if update {
		delete(f.running, pd.Name)
	}
	f.running[pd.Name] = pd.Data
	return nil
}

func (f *keepingBackend) RemovePolicy(pd policies.PolicyData) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.running[pd.Name]; !ok {
		return &backend.HTTPError{StatusCode: http.StatusNotFound, Message: "404 not found"}
	}
	delete(f.running, pd.Name)
	return nil
}

func (f *keepingBackend) runs(name string) (any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.running[name]
	return d, ok
}

func newPollerAndManager(t *testing.T, beName string) (*vaultStub, *secretsmgr.TestPoller, *keepingBackend, policymgr.PolicyManager) {
	t.Helper()
	v := newVaultStub()
	p := secretsmgr.NewTestPoller(v.fetch)
	be := &keepingBackend{running: map[string]any{}}
	backend.Register(beName, be)
	mgr, err := policymgr.New(slog.New(slog.NewTextHandler(io.Discard, nil)), p, config.Config{})
	require.NoError(t, err)
	return v, p, be, mgr
}

func deliver(mgr policymgr.PolicyManager, id, beName string, version int32, ref, datasetID string) {
	mgr.ManagePolicy(config.PolicyPayload{
		Action: "manage", ID: id, Name: id, Backend: beName, Version: version, DatasetID: datasetID,
		Data: map[string]any{"community": "${vault://" + ref + "}"},
	})
}

func storedState(t *testing.T, mgr policymgr.PolicyManager, id string) policies.PolicyData {
	t.Helper()
	pd, err := mgr.GetRepo().Get(id)
	require.NoError(t, err)
	return pd
}

// A poll finds a reference failing and reports it only after reading the
// others, slowly. Meanwhile a delivery, or a backend restart's replay, reads
// the reference again, and it resolves. The late report leaves the policy
// running: stopping it would leave it stopped with nothing to re-apply it.
func TestAPolicyThatResolvedItsSecretAgainIsNotStoppedByALateReport(t *testing.T) {
	for _, meanwhile := range []string{"delivery", "replay"} {
		t.Run(meanwhile, func(t *testing.T) {
			beName := "late_report_" + meanwhile
			v, poller, be, mgr := newPollerAndManager(t, beName)
			v.set("a/community", "public")
			v.set("z/token", "tok")
			deliver(mgr, "policy-1", beName, 1, "a/community", "ds")
			deliver(mgr, "policy-2", beName, 1, "z/token", "ds")
			require.Equal(t, policies.Running, storedState(t, mgr, "policy-1").State)

			v.fail("a/community", errors.New("Code: 503. Vault is sealed"))
			entered, release := v.block("z/token")
			done := make(chan struct{})
			go func() { poller.Poll(); close(done) }()
			<-entered

			v.set("a/community", "public")
			if meanwhile == "delivery" {
				deliver(mgr, "policy-1", beName, 2, "a/community", "")
			} else {
				require.NoError(t, mgr.RemoveBackendPolicies(beName, be, false))
				require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), beName, be))
			}
			require.Equal(t, policies.Running, storedState(t, mgr, "policy-1").State)

			release()
			<-done
			pd := storedState(t, mgr, "policy-1")
			require.Equal(t, policies.Running, pd.State, pd.BackendErr)
			_, running := be.runs("policy-1")
			require.True(t, running)
		})
	}
}

// A policy edited onto another path keeps running when the path it used
// before is deleted, as when a credential is rotated to a new path and the
// old one is removed.
func TestAPolicyEditedOntoAnotherPathKeepsRunningWhenTheOldOneIsDeleted(t *testing.T) {
	const beName = "retired_reference"
	v, poller, be, mgr := newPollerAndManager(t, beName)
	v.set("old/community", "public")
	v.set("new/community", "public2")
	deliver(mgr, "policy-1", beName, 1, "old/community", "ds")
	deliver(mgr, "policy-1", beName, 2, "new/community", "")
	require.Equal(t, policies.Running, storedState(t, mgr, "policy-1").State)

	v.fail("old/community", errors.New("secret not found: old/community"))
	poller.Poll()

	pd := storedState(t, mgr, "policy-1")
	require.Equal(t, policies.Running, pd.State, pd.BackendErr)
	data, running := be.runs("policy-1")
	require.True(t, running)
	require.Equal(t, map[string]any{"community": "public2"}, data)
}

// The whole of MON-840: a running policy whose secret is deleted is stopped
// and kept failed with the reason, and runs again once the secret is back,
// with no delivery and no restart.
func TestAPolicyWhoseSecretIsDeletedRunsAgainOnceItIsBack(t *testing.T) {
	const beName = "deleted_and_back"
	v, poller, be, mgr := newPollerAndManager(t, beName)
	v.set("snmp/community", "public")
	deliver(mgr, "policy-1", beName, 1, "snmp/community", "ds")

	v.fail("snmp/community", errors.New("secret not found: snmp/community"))
	poller.Poll()
	pd := storedState(t, mgr, "policy-1")
	require.Equal(t, policies.FailedToApply, pd.State)
	require.Equal(t, "failed to resolve policy secrets: secret not found: snmp/community", pd.BackendErr)
	_, running := be.runs("policy-1")
	require.False(t, running)

	poller.Poll() // still gone: nothing changes
	require.Equal(t, policies.FailedToApply, storedState(t, mgr, "policy-1").State)

	v.set("snmp/community", "public")
	poller.Poll()
	pd = storedState(t, mgr, "policy-1")
	require.Equal(t, policies.Running, pd.State)
	require.Empty(t, pd.BackendErr)
	_, running = be.runs("policy-1")
	require.True(t, running)
}

// An update that lands while its backend restarts is stored unapplied, so the
// secrets manager still counts the policy among the users of the path it used
// before. Deleting that path then fails a poll's read before the replay: the
// report leaves the deferred record to the replay, which applies the update.
func TestAnUpdateDeferredByARestartIsAppliedWhenItsOldPathIsDeleted(t *testing.T) {
	const beName = "deferred_update"
	v, poller, be, mgr := newPollerAndManager(t, beName)
	v.set("old/community", "public")
	v.set("new/community", "public2")
	deliver(mgr, "policy-1", beName, 1, "old/community", "ds")
	require.NoError(t, mgr.RemoveBackendPolicies(beName, be, false))
	deliver(mgr, "policy-1", beName, 2, "new/community", "")

	v.fail("old/community", errors.New("secret not found: old/community"))
	poller.Poll()
	require.NoError(t, mgr.ApplyBackendPolicies(context.Background(), beName, be))

	pd := storedState(t, mgr, "policy-1")
	require.Equal(t, policies.Running, pd.State, pd.BackendErr)
	data, running := be.runs("policy-1")
	require.True(t, running)
	require.Equal(t, map[string]any{"community": "public2"}, data)
}

// A policy unapplied by removing its last dataset, as the Telemetry Service
// unapplies one, or removed outright, is forgotten: the path only it used is
// no longer read.
func TestARemovedPolicysPathIsNoLongerRead(t *testing.T) {
	for _, how := range []string{"remove", "last dataset removed"} {
		t.Run(how, func(t *testing.T) {
			beName := "forgotten_" + strings.ReplaceAll(how, " ", "_")
			v, poller, be, mgr := newPollerAndManager(t, beName)
			v.set("snmp/community", "public")
			deliver(mgr, "policy-1", beName, 1, "snmp/community", "ds-1")
			if how == "remove" {
				require.NoError(t, mgr.RemovePolicy("policy-1", "policy-1", beName))
			} else {
				mgr.RemovePolicyDataset("policy-1", "ds-1", beName, be)
			}
			_, err := mgr.GetRepo().Get("policy-1")
			require.Error(t, err)

			before := v.readsOf("snmp/community")
			poller.Poll()
			require.Equal(t, before, v.readsOf("snmp/community"))
		})
	}
}

// An update whose secret does not resolve leaves the version before it
// running, and that version's secret still counts: revoking it stops the
// policy.
func TestTheRunningVersionsSecretStillCountsWhileItsUpdateFails(t *testing.T) {
	const beName = "failed_update"
	v, poller, be, mgr := newPollerAndManager(t, beName)
	v.set("old/community", "public")
	deliver(mgr, "policy-1", beName, 1, "old/community", "ds")
	deliver(mgr, "policy-1", beName, 2, "new/community", "")
	require.Equal(t, policies.FailedToApply, storedState(t, mgr, "policy-1").State)
	_, running := be.runs("policy-1")
	require.True(t, running, "the version before the update still runs")

	v.fail("old/community", errors.New("permission denied: old/community revoked"))
	poller.Poll()
	_, running = be.runs("policy-1")
	require.False(t, running, "revoking the running version's secret stops it")
}
