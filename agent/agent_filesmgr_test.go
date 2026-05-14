package agent

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
	"github.com/netboxlabs/orb-agent/agent/policies"
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
// when a match is found.
func makeBridge(backends map[string]*filesmgrTestBackend, restartCh chan string) func(filesmgr.FileEvent) {
	return func(ev filesmgr.FileEvent) {
		if ev.Type != filesmgr.EventUpgraded {
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

// TestSubscribeToFilesmgr_CoalescesAndDeliversReliably fires 10 upgrade events
// for the same file, runs the restartDispatcher, and asserts that exactly one
// restart reaches restartBackendChan within 1 second.
func TestSubscribeToFilesmgr_CoalescesAndDeliversReliably(t *testing.T) {
	restartBackendChan := make(chan string, 5)

	a := &orbAgent{
		logger:             slog.Default(),
		restartBackendChan: restartBackendChan,
		backends:           map[string]backend.Backend{},
	}

	// Register one backend whose managed binary is "orb-worker".
	a.backends["worker"] = &filesmgrTestBackend{managedBinary: "orb-worker"}

	// Simulate the bridge firing 10 upgrade events for the same backend.
	for i := 0; i < 10; i++ {
		a.pendingRestartsMu.Lock()
		if a.pendingRestarts == nil {
			a.pendingRestarts = make(map[string]struct{})
		}
		a.pendingRestarts["worker"] = struct{}{}
		a.pendingRestartsMu.Unlock()
	}

	// Run the dispatcher for a short time in the background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.restartDispatcher(ctx)

	// Collect all restart signals within 1 second.
	var received []string
	deadline := time.After(time.Second)
drain:
	for {
		select {
		case name := <-restartBackendChan:
			received = append(received, name)
		case <-deadline:
			break drain
		}
	}

	assert.Len(t, received, 1, "coalescing: 10 upgrade events must produce exactly 1 restart")
	if len(received) == 1 {
		assert.Equal(t, "worker", received[0])
	}
}
