package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// failOnceThenSucceedBackend fails Start on the first call and succeeds thereafter.
type failOnceThenSucceedBackend struct {
	filesmgrTestBackend
	mu         sync.Mutex
	startCalls int
}

func (b *failOnceThenSucceedBackend) Start(_ context.Context, _ context.CancelFunc) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.startCalls++
	if b.startCalls == 1 {
		return fmt.Errorf("simulated start failure")
	}
	return nil
}

// rollbackRecordingFilesManager is a mockFilesManager that records Rollback calls.
type rollbackRecordingFilesManager struct {
	mockFilesManager
	mu            sync.Mutex
	rollbackCalls []string
}

func (m *rollbackRecordingFilesManager) Rollback(_ context.Context, name string) error {
	m.mu.Lock()
	m.rollbackCalls = append(m.rollbackCalls, name)
	m.mu.Unlock()
	return nil
}

func TestRestartBackendWithFilesmgrRollback_RetriesAfterFailure(t *testing.T) {
	be := &failOnceThenSucceedBackend{
		filesmgrTestBackend: filesmgrTestBackend{managedBinary: "orb-worker"},
	}
	fm := &rollbackRecordingFilesManager{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &orbAgent{
		logger:         slog.Default(),
		backends:       map[string]backend.Backend{"worker": be},
		filesManager:   fm,
		cancelFunction: cancel,
		ctx:            ctx,
	}

	a.restartBackendWithFilesmgrRollback(ctx, "worker")

	// Start must have been called twice: once (fails) + once after rollback.
	be.mu.Lock()
	starts := be.startCalls
	be.mu.Unlock()
	assert.Equal(t, 2, starts, "Start must be called twice: initial attempt + post-rollback retry")

	// Rollback must have been called exactly once with the binary name.
	fm.mu.Lock()
	calls := fm.rollbackCalls
	fm.mu.Unlock()
	require.Len(t, calls, 1, "Rollback must be called exactly once")
	assert.Equal(t, "orb-worker", calls[0])
}

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

// slowStartBackend is a Backend whose Start blocks for a configurable duration
// and tracks the peak number of concurrent in-flight Start calls via a shared
// counter. Used by TestRestartDispatcher_ProcessesRestartsSequentially.
type slowStartBackend struct {
	filesmgrTestBackend
	delay       time.Duration
	globalMu    *sync.Mutex
	inFlight    *int
	maxInFlight *int
}

func (b *slowStartBackend) Start(_ context.Context, _ context.CancelFunc) error {
	b.globalMu.Lock()
	*b.inFlight++
	if *b.inFlight > *b.maxInFlight {
		*b.maxInFlight = *b.inFlight
	}
	b.globalMu.Unlock()

	time.Sleep(b.delay)

	b.globalMu.Lock()
	*b.inFlight--
	b.globalMu.Unlock()
	return nil
}

// TestRestartDispatcher_ProcessesRestartsSequentially verifies that the
// dispatcher does not run concurrent Stop+Start sequences for different
// backends within the same tick (F9). It uses slowStartBackend to track the
// peak number of concurrent in-flight Start calls.
func TestRestartDispatcher_ProcessesRestartsSequentially(t *testing.T) {
	const delay = 50 * time.Millisecond
	const nBackends = 3

	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0

	backends := make(map[string]backend.Backend, nBackends)
	for i := range nBackends {
		name := fmt.Sprintf("backend-%d", i)
		backends[name] = &slowStartBackend{
			filesmgrTestBackend: filesmgrTestBackend{managedBinary: name},
			delay:               delay,
			globalMu:            &mu,
			inFlight:            &inFlight,
			maxInFlight:         &maxInFlight,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &orbAgent{
		logger:         slog.Default(),
		backends:       backends,
		filesManager:   &mockFilesManager{},
		cancelFunction: cancel,
		ctx:            ctx,
	}

	// Enqueue all backends at once.
	a.pendingRestartsMu.Lock()
	a.pendingRestarts = make(map[string]struct{})
	for name := range backends {
		a.pendingRestarts[name] = struct{}{}
	}
	a.pendingRestartsMu.Unlock()

	go a.restartDispatcher(ctx)

	// Wait long enough for one tick + nBackends sequential restarts.
	time.Sleep(time.Duration(nBackends+2)*delay + 300*time.Millisecond)
	cancel()

	// Max concurrent in-flight Start calls must be ≤ 1 (sequential).
	mu.Lock()
	maxIF := maxInFlight
	mu.Unlock()
	assert.LessOrEqual(t, maxIF, 1, "restarts must be sequential: peak concurrent Start calls must be ≤ 1")
}

// countingBackend is a filesmgrTestBackend that counts Start/Stop calls.
type countingBackend struct {
	filesmgrTestBackend
	mu         sync.Mutex
	startCalls int
	stopCalls  int
}

func (b *countingBackend) Start(_ context.Context, _ context.CancelFunc) error {
	b.mu.Lock()
	b.startCalls++
	b.mu.Unlock()
	return nil
}

func (b *countingBackend) Stop(_ context.Context) error {
	b.mu.Lock()
	b.stopCalls++
	b.mu.Unlock()
	return nil
}

// TestSubscribeToFilesmgr_CoalescesAndDeliversReliably fires 10 upgrade events
// for the same file, runs the restartDispatcher, and asserts that exactly one
// restart (Stop+Start) is issued within 1 second.
func TestSubscribeToFilesmgr_CoalescesAndDeliversReliably(t *testing.T) {
	be := &countingBackend{
		filesmgrTestBackend: filesmgrTestBackend{managedBinary: "orb-worker"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &orbAgent{
		logger:         slog.Default(),
		backends:       map[string]backend.Backend{},
		filesManager:   &mockFilesManager{},
		cancelFunction: cancel,
		ctx:            ctx,
	}
	a.backends["worker"] = be

	// Simulate the bridge firing 10 upgrade events for the same backend.
	for i := 0; i < 10; i++ {
		a.pendingRestartsMu.Lock()
		if a.pendingRestarts == nil {
			a.pendingRestarts = make(map[string]struct{})
		}
		a.pendingRestarts["worker"] = struct{}{}
		a.pendingRestartsMu.Unlock()
	}

	go a.restartDispatcher(ctx)

	// Allow up to 1 second for the coalesced restart to complete.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		be.mu.Lock()
		starts := be.startCalls
		be.mu.Unlock()
		if starts >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cancel the dispatcher before asserting so no further restarts occur.
	cancel()
	time.Sleep(20 * time.Millisecond)

	be.mu.Lock()
	defer be.mu.Unlock()
	assert.Equal(t, 1, be.startCalls, "coalescing: 10 upgrade events must produce exactly 1 restart")
	assert.Equal(t, 1, be.stopCalls, "coalescing: 10 upgrade events must produce exactly 1 stop")
}

// TestSubscribeToFilesmgr_TriggersRestartOnInstall verifies that EventInstalled
// (first-time file arrival) also triggers a backend restart — Fix 3.
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

// buildTestTarGz produces a minimal in-memory .tar.gz containing the given files.
func buildTestTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func testSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestRestartBackendWithFilesmgrRollback_FirstInstallFailureFallsBackToBaked
// verifies the end-to-end first-install self-heal path (Fix 4):
//   - A real filesmgr.Manager has an entry installed (simulating a first-install).
//   - The backend's Start fails on the first call (broken binary).
//   - restartBackendWithFilesmgrRollback calls Rollback, which — because there is
//     no Previous — removes the entry from the manager entirely.
//   - The retry Start succeeds (baked binary path).
//   - After the flow the entry is gone from the manager.
func TestRestartBackendWithFilesmgrRollback_FirstInstallFailureFallsBackToBaked(t *testing.T) {
	// Build a minimal tar.gz archive to serve as the "binary".
	archive := buildTestTarGz(t, map[string]string{"orb-worker": "#!/bin/sh\nexit 0\n"})
	sum := testSHA256Hex(archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	// Real FilesManager with temp root.
	root := t.TempDir()
	fm := filesmgr.NewManager(slog.Default(), root)
	require.NoError(t, fm.Start(context.Background()))
	defer func() { _ = fm.Stop(context.Background()) }()

	// Install v1.0.0 (no previous — first install).
	_, err := fm.Ensure(context.Background(), filesmgr.FileSpec{
		Name:    "orb-worker",
		Version: "1.0.0",
		URL:     srv.URL + "/orb-worker.tar.gz",
		SHA256:  sum,
		Extract: true,
	})
	require.NoError(t, err)

	// Confirm the entry is present.
	_, ok := fm.Get("orb-worker")
	require.True(t, ok, "entry must exist before rollback test")

	// Backend: fails on first Start, succeeds on second.
	be := &failOnceThenSucceedBackend{
		filesmgrTestBackend: filesmgrTestBackend{managedBinary: "orb-worker"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &orbAgent{
		logger:         slog.Default(),
		backends:       map[string]backend.Backend{"worker": be},
		filesManager:   fm,
		cancelFunction: cancel,
		ctx:            ctx,
	}

	// Execute the restart+rollback flow.
	a.restartBackendWithFilesmgrRollback(ctx, "worker")

	// Start must have been called twice: first attempt (fails) + retry after rollback.
	be.mu.Lock()
	starts := be.startCalls
	be.mu.Unlock()
	assert.Equal(t, 2, starts, "Start must be called twice: initial failure + retry after rollback")

	// After rollback-to-default, the entry must be gone from the manager.
	_, stillPresent := fm.Get("orb-worker")
	assert.False(t, stillPresent, "filesmgr entry must be removed after rollback-to-default")
}
