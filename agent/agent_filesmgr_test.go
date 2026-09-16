package agent

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/supervisor"
)

// filesmgrTestBackend is a minimal Backend stub that returns a configurable
// ManagedBinaryName and no-ops everything else.
type filesmgrTestBackend struct {
	managedBinary string
}

func (b *filesmgrTestBackend) ManagedBinaryName() string { return b.managedBinary }

func (b *filesmgrTestBackend) Configure(_ *slog.Logger, _ policies.PolicyRepo, _ map[string]any, _ config.BackendCommons, _ filesmgr.Manager) error {
	return nil
}
func (b *filesmgrTestBackend) Version() (string, error)                            { return "", nil }
func (b *filesmgrTestBackend) Start(_ context.Context, _ context.CancelFunc) error { return nil }
func (b *filesmgrTestBackend) Stop(_ context.Context) error                        { return nil }
func (b *filesmgrTestBackend) FullReset(_ context.Context) error                   { return nil }
func (b *filesmgrTestBackend) GetStartTime() time.Time                             { return time.Time{} }
func (b *filesmgrTestBackend) GetCapabilities() (map[string]any, error)            { return nil, nil }
func (b *filesmgrTestBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	return backend.Unknown, "", nil
}
func (b *filesmgrTestBackend) GetInitialState() backend.RunningStatus          { return backend.Unknown }
func (b *filesmgrTestBackend) ApplyPolicy(_ policies.PolicyData, _ bool) error { return nil }
func (b *filesmgrTestBackend) RemovePolicy(_ policies.PolicyData) error        { return nil }

// makeBridge models the subscribeFilesmgr logic: iterate registered backends,
// check ManagedBinaryName(), and enqueue the backend name (NOT the file name)
// when a match is found. Both EventInstalled and EventUpgraded trigger restarts.
func makeBridge(backends map[string]*filesmgrTestBackend, restartCh chan string) func(filesmgr.FileEvent) {
	return func(ev filesmgr.FileEvent) {
		switch ev.Type {
		case filesmgr.EventInstalled, filesmgr.EventUpgraded:
			// continue
		default:
			return
		}
		for name, be := range backends {
			if be.ManagedBinaryName() == ev.Entry.Name {
				restartCh <- name
			}
		}
	}
}

func TestSubscribeToFilesmgr_TriggersRestartOnUpgrade(t *testing.T) {
	restartCh := make(chan string, 1)
	backends := map[string]*filesmgrTestBackend{
		"worker": {managedBinary: "orb-worker"},
	}

	bridge := makeBridge(backends, restartCh)

	bridge(filesmgr.FileEvent{
		Type:     filesmgr.EventUpgraded,
		Entry:    filesmgr.FileEntry{Name: "orb-worker"},
		Previous: &filesmgr.FileEntry{Name: "orb-worker"},
	})

	select {
	case got := <-restartCh:
		// Expect the backend name ("worker"), NOT the file name ("orb-worker").
		assert.Equal(t, "worker", got)
	case <-time.After(time.Second):
		t.Fatal("expected restart signal")
	}
}

func TestSubscribeToFilesmgr_IgnoresUnknownBackend(t *testing.T) {
	restartCh := make(chan string, 1)
	backends := map[string]*filesmgrTestBackend{
		"worker": {managedBinary: "orb-worker"},
	}

	bridge := makeBridge(backends, restartCh)

	bridge(filesmgr.FileEvent{
		Type:  filesmgr.EventUpgraded,
		Entry: filesmgr.FileEntry{Name: "not-a-known-binary"},
	})

	select {
	case got := <-restartCh:
		t.Fatalf("unexpected restart for %q", got)
	case <-time.After(50 * time.Millisecond):
		// ok — no match expected
	}
}

// TestSubscribeToFilesmgr_DecouplesBackendNameFromBinaryName asserts that the
// file name ("orb-worker") is mapped to the backend name ("worker") — the
// restart channel receives the backend name, not the file name.
func TestSubscribeToFilesmgr_DecouplesBackendNameFromBinaryName(t *testing.T) {
	restartCh := make(chan string, 1)
	backends := map[string]*filesmgrTestBackend{
		"worker": {managedBinary: "orb-worker"},
	}

	bridge := makeBridge(backends, restartCh)

	bridge(filesmgr.FileEvent{
		Type:  filesmgr.EventUpgraded,
		Entry: filesmgr.FileEntry{Name: "orb-worker", Version: "v2"},
	})

	select {
	case got := <-restartCh:
		assert.Equal(t, "worker", got, "restart channel must receive backend name, not file name")
	case <-time.After(time.Second):
		t.Fatal("expected restart signal")
	}
}

// TestSubscribeToFilesmgr_TriggersRestartOnInstall verifies that EventInstalled
// (first-time file arrival) also triggers a backend restart.
func TestSubscribeToFilesmgr_TriggersRestartOnInstall(t *testing.T) {
	restartCh := make(chan string, 1)
	backends := map[string]*filesmgrTestBackend{
		"worker": {managedBinary: "orb-worker"},
	}

	bridge := makeBridge(backends, restartCh)

	bridge(filesmgr.FileEvent{
		Type:  filesmgr.EventInstalled,
		Entry: filesmgr.FileEntry{Name: "orb-worker", Version: "v1.0.0"},
	})

	select {
	case got := <-restartCh:
		assert.Equal(t, "worker", got, "restart channel must receive backend name on EventInstalled")
	case <-time.After(time.Second):
		t.Fatal("expected restart signal on EventInstalled")
	}
}

// TestSubscribeToFilesmgr_IgnoresRolledBackAndRemoved verifies that
// EventRolledBack and EventRemoved do NOT trigger a restart — these are
// handled by the auto-rollback flow itself and triggering here would cause
// duplicate restart cycles.
func TestSubscribeToFilesmgr_IgnoresRolledBackAndRemoved(t *testing.T) {
	restartCh := make(chan string, 1)
	backends := map[string]*filesmgrTestBackend{
		"worker": {managedBinary: "orb-worker"},
	}

	bridge := makeBridge(backends, restartCh)

	for _, evType := range []filesmgr.FileEventType{filesmgr.EventRolledBack, filesmgr.EventRemoved} {
		bridge(filesmgr.FileEvent{
			Type:  evType,
			Entry: filesmgr.FileEntry{Name: "orb-worker"},
		})
	}

	select {
	case got := <-restartCh:
		t.Fatalf("unexpected restart for event: %q", got)
	case <-time.After(50 * time.Millisecond):
		// ok — neither event type should trigger a restart
	}
}

// countingUpgradeBackend is a managed-binary Backend that reports Running
// (so the supervisor's gated stop actually stops it) and counts its Stop and
// Start calls under a mutex, since the supervisor's own dispatch goroutine
// makes them concurrently with a test's polling.
type countingUpgradeBackend struct {
	filesmgrTestBackend
	mu         sync.Mutex
	stopCalls  int
	startCalls int
}

func (b *countingUpgradeBackend) GetRunningStatus() (backend.RunningStatus, string, error) {
	return backend.Running, "", nil
}

func (b *countingUpgradeBackend) Start(_ context.Context, _ context.CancelFunc) error {
	b.mu.Lock()
	b.startCalls++
	b.mu.Unlock()
	return nil
}

func (b *countingUpgradeBackend) Stop(_ context.Context) error {
	b.mu.Lock()
	b.stopCalls++
	b.mu.Unlock()
	return nil
}

func (b *countingUpgradeBackend) counts() (stop, start int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopCalls, b.startCalls
}

// stubSubscribeFilesManager is a filesmgr.Manager whose Subscribe stores the
// callback instead of watching real files, so a test can deliver a
// FileEvent to it directly.
type stubSubscribeFilesManager struct {
	mockFilesManager
	cb func(filesmgr.FileEvent)
}

func (m *stubSubscribeFilesManager) Subscribe(cb func(filesmgr.FileEvent)) func() {
	m.cb = cb
	return func() {}
}

// A FilesManager upgrade event for a backend's managed binary, delivered
// through subscribeFilesmgr, queues an upgrade restart that the supervisor's
// dispatcher picks up and runs: the backend is stopped, then started again.
func TestSubscribeFilesmgrQueuesAnUpgradeRestart(t *testing.T) {
	be := &countingUpgradeBackend{filesmgrTestBackend: filesmgrTestBackend{managedBinary: "orb-worker"}}
	fm := &stubSubscribeFilesManager{}
	a, _ := newTestAgent(t, testAgentOptions{
		name:       "e2e_upgrade_queue",
		be:         be,
		files:      fm,
		supervisor: supervisor.Options{DispatchInterval: 5 * time.Millisecond},
	})

	a.subscribeFilesmgr()
	fm.cb(filesmgr.FileEvent{Type: filesmgr.EventUpgraded, Entry: filesmgr.FileEntry{Name: "orb-worker"}})

	require.Eventually(t, func() bool {
		// start >= 2: ConfigureAll already started the backend once before
		// the upgrade event was ever delivered, so start >= 1 alone would be
		// true before the restart under test runs at all.
		stop, start := be.counts()
		return stop >= 1 && start >= 2
	}, time.Second, 5*time.Millisecond, "the queued upgrade restart must stop then start the backend again")
}
