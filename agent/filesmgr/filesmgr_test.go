package filesmgr

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func serveTarGz(_ *testing.T, archive []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
}

func newTestManager(t *testing.T) (Manager, string) {
	root := t.TempDir()
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))
	return m, root
}

// TestManager_StartSucceedsWhenRootDirNotWritable verifies the lazy-root
// invariant: Start() must not create the root directory or fail when the root's
// parent does not exist (or is not writable). Agents that never call Ensure
// must be able to boot cleanly without requiring write access to /opt or
// whatever the configured root's parent is.
func TestManager_StartSucceedsWhenRootDirNotWritable(t *testing.T) {
	// Use a path whose parent does not exist so MkdirAll would fail if called.
	// We deliberately do NOT call Ensure — that would (correctly) fail.
	m := NewManager(slog.Default(), "/non/existent/path/orb/files")
	require.NoError(t, m.Start(context.Background()),
		"Start must succeed even when root dir cannot be created (no state.json == no-op)")
}

func TestManager_EnsureInstallsAndEmitsEvent(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "alpha"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, root := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	path, err := m.Ensure(context.Background(), FileSpec{
		Name:    "pkg",
		Version: "1.0.0",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  sum,
		Extract: true,
	})
	require.NoError(t, err)
	// Versioned installs expose the stable "current" symlink path, not the
	// version-specific directory.
	assert.Equal(t, filepath.Join(root, "pkg", "current"), path)

	// Reading through the symlink must return the installed file.
	content, err := os.ReadFile(filepath.Join(path, "a.txt"))
	require.NoError(t, err)
	assert.Equal(t, "alpha", string(content))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1)
	assert.Equal(t, EventInstalled, events[0].Type)
	assert.Equal(t, "pkg", events[0].Entry.Name)
}

func TestManager_EnsureIsIdempotent(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "alpha"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, _ := newTestManager(t)

	var calls int
	var mu sync.Mutex
	m.Subscribe(func(_ FileEvent) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	spec := FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/x.tar.gz", SHA256: sum, Extract: true,
	}

	_, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err)
	_, err = m.Ensure(context.Background(), spec)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, calls, "idempotent Ensure must not publish a second event")
}

func TestManager_UpgradeEmitsUpgradedWithPrevious(t *testing.T) {
	v1 := buildTarGz(t, map[string]string{"a.txt": "v1"})
	v2 := buildTarGz(t, map[string]string{"a.txt": "v2"})
	sum1, sum2 := sha256Hex(v1), sha256Hex(v2)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(v1)
	})
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(v2)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, _ := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)

	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	assert.Equal(t, EventInstalled, events[0].Type)
	assert.Equal(t, EventUpgraded, events[1].Type)
	require.NotNil(t, events[1].Previous)
	assert.Equal(t, "1.0.0", events[1].Previous.Version)
	assert.Equal(t, "2.0.0", events[1].Entry.Version)
}

func TestManager_CurrentSymlinkPointsToLatestVersion(t *testing.T) {
	v1 := buildTarGz(t, map[string]string{"file.txt": "content-v1"})
	v2 := buildTarGz(t, map[string]string{"file.txt": "content-v2"})
	sum1, sum2 := sha256Hex(v1), sha256Hex(v2)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(v1)
	})
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(v2)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, root := newTestManager(t)

	// Install 1.0.0 and confirm "current" points to "1.0.0".
	path1, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "pkg", "current"), path1)

	target1, err := os.Readlink(filepath.Join(root, "pkg", "current"))
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", target1)

	content1, err := os.ReadFile(filepath.Join(path1, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content-v1", string(content1))

	// Upgrade to 2.0.0 and confirm "current" now points to "2.0.0".
	path2, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "pkg", "current"), path2)

	target2, err := os.Readlink(filepath.Join(root, "pkg", "current"))
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", target2)

	// Reading through the symlink must return the new content.
	content2, err := os.ReadFile(filepath.Join(path2, "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "content-v2", string(content2))
}

func TestManager_RemoveEmitsRemoved(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "v1"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, _ := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", URL: srv.URL + "/x.tar.gz", SHA256: sum, Extract: true,
	})
	require.NoError(t, err)
	require.NoError(t, m.Remove(context.Background(), "pkg"))

	_, ok := m.Get("pkg")
	assert.False(t, ok)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	assert.Equal(t, EventRemoved, events[1].Type)
}

func TestManager_EnsureStorePutFailureRollsBack(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "data"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	root := t.TempDir()

	// Start a normal manager first — with no existing state.json, Start is a
	// no-op (lazy root). Then block writes by placing a directory at the
	// state.json path so that Ensure's store.put call fails.
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// Now block writes by placing a directory at the state.json path.
	require.NoError(t, os.Mkdir(filepath.Join(root, "state.json"), 0o755))

	_, err := m.Ensure(context.Background(), FileSpec{
		Name:    "pkg",
		Version: "1.0.0",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  sum,
		Extract: true,
	})
	require.Error(t, err, "Ensure must fail when store.put fails")

	// No entry must be recorded in state.
	_, ok := m.Get("pkg")
	assert.False(t, ok, "no entry should be recorded when store.put fails")

	// No "current" symlink should exist.
	currentLink := filepath.Join(root, "pkg", "current")
	_, lstatErr := os.Lstat(currentLink)
	assert.True(t, os.IsNotExist(lstatErr), "current symlink must not exist after rollback")

	// The version directory should also have been cleaned up.
	versionDir := filepath.Join(root, "pkg", "1.0.0")
	_, vstatErr := os.Lstat(versionDir)
	assert.True(t, os.IsNotExist(vstatErr), "version dir must be cleaned up after store.put failure")
}

func TestManager_RollbackRestoresPreviousVersion(t *testing.T) {
	v1 := buildTarGz(t, map[string]string{"file.txt": "content-v1"})
	v2 := buildTarGz(t, map[string]string{"file.txt": "content-v2"})
	sum1, sum2 := sha256Hex(v1), sha256Hex(v2)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v1) })
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v2) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, root := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	// Install 1.0.0.
	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)

	// Upgrade to 2.0.0.
	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)

	// Verify symlink points to 2.0.0.
	target, err := os.Readlink(filepath.Join(root, "pkg", "current"))
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", target)

	// Rollback.
	require.NoError(t, m.Rollback(context.Background(), "pkg"))

	// Symlink must now point to 1.0.0.
	target, err = os.Readlink(filepath.Join(root, "pkg", "current"))
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", target)

	// Get must return the 1.0.0 entry.
	entry, ok := m.Get("pkg")
	require.True(t, ok)
	assert.Equal(t, "1.0.0", entry.Version)

	// Events: Installed, Upgraded, RolledBack.
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 3)
	assert.Equal(t, EventInstalled, events[0].Type)
	assert.Equal(t, EventUpgraded, events[1].Type)
	last := events[2]
	assert.Equal(t, EventRolledBack, last.Type)
	assert.Equal(t, "1.0.0", last.Entry.Version, "Entry must be the now-live v1")
	require.NotNil(t, last.Previous)
	assert.Equal(t, "2.0.0", last.Previous.Version, "Previous must be the rolled-back-from v2")
}

// TestManager_RollbackWithNoPreviousRemovesEntry verifies the rollback-to-default
// semantic: when there is no Previous version, Rollback removes the entry
// entirely so consumers fall back to their baked default binary.
func TestManager_RollbackWithNoPreviousRemovesEntry(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "data"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, root := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/x.tar.gz", SHA256: sum, Extract: true,
	})
	require.NoError(t, err)

	// Rollback with no Previous must succeed and remove the entry.
	require.NoError(t, m.Rollback(context.Background(), "pkg"))

	// Entry must be gone from the manager.
	_, ok := m.Get("pkg")
	assert.False(t, ok, "entry must be removed after rollback-to-default")

	// The on-disk directory must no longer exist.
	assert.NoDirExists(t, filepath.Join(root, "pkg"), "pkg directory must be removed after rollback-to-default")

	// Events sequence: EventInstalled then EventRemoved (with 1.0.0 Entry).
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	assert.Equal(t, EventInstalled, events[0].Type)
	assert.Equal(t, EventRemoved, events[1].Type)
	assert.Equal(t, "1.0.0", events[1].Entry.Version)
}

func TestManager_RollbackWithMissingPreviousDir_ReturnsError(t *testing.T) {
	v1 := buildTarGz(t, map[string]string{"a.txt": "v1"})
	v2 := buildTarGz(t, map[string]string{"a.txt": "v2"})
	sum1, sum2 := sha256Hex(v1), sha256Hex(v2)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v1) })
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v2) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, root := newTestManager(t)

	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)

	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)

	// Simulate operator cleanup: remove the 1.0.0 directory.
	require.NoError(t, os.RemoveAll(filepath.Join(root, "pkg", "1.0.0")))

	err = m.Rollback(context.Background(), "pkg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "previous version dir missing")
}

func TestManager_StartCleansUpStaleArtifacts(t *testing.T) {
	root := t.TempDir()

	// Create a stale stage directory at the root level — this IS ours to remove.
	staleStage := filepath.Join(root, ".filesmgr-stage-abc123")
	require.NoError(t, os.Mkdir(staleStage, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(staleStage, "payload"), []byte("stale"), 0o644))

	// Create a tracked versioned name dir with a stale current.new symlink and a
	// nested .filesmgr-stage-* dir so we can verify those are cleaned.
	trackedDir := filepath.Join(root, "tracked-pkg")
	versionDir := filepath.Join(trackedDir, "1.0.0")
	require.NoError(t, os.MkdirAll(versionDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "bin"), []byte("v1"), 0o755))
	currentLink := filepath.Join(trackedDir, "current")
	require.NoError(t, os.Symlink("1.0.0", currentLink))

	staleNew := filepath.Join(trackedDir, "current.new")
	require.NoError(t, os.Symlink("1.0.0", staleNew))

	nestedStage := filepath.Join(trackedDir, ".filesmgr-stage-xyz")
	require.NoError(t, os.Mkdir(nestedStage, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nestedStage, "data"), []byte("nested-stale"), 0o644))

	// Write state.json so that "tracked-pkg" is recognized as a tracked name.
	// Without a state.json entry the manager treats it as an untracked dir and
	// leaves it alone (post-round-7 fix). The entry path goes through "current"
	// so that os.Stat resolves it correctly via the symlink.
	binPath := filepath.Join(trackedDir, "current", "bin")
	stateJSON := `{"version":1,"entries":{"tracked-pkg":{"current":{"name":"tracked-pkg","version":"1.0.0","path":"` +
		binPath + `","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// Top-level stale stage dir must be removed.
	assert.NoDirExists(t, staleStage, "stale stage dir must be removed on Start")
	// Stale current.new and nested stage dir inside a versioned dir must be removed.
	_, err := os.Lstat(staleNew)
	assert.True(t, os.IsNotExist(err), "stale current.new must be removed on Start")
	assert.NoDirExists(t, nestedStage, "nested stale stage dir must be removed on Start")
}

// TestManager_StartLeavesUnknownDirsAlone verifies that cleanupStaleArtifacts
// does NOT remove directories under root that have no "current" symlink and are
// not tracked in state. These dirs are not owned by the FilesManager and must
// be left untouched to avoid destructive behavior when root is shared or
// misconfigured.
func TestManager_StartLeavesUnknownDirsAlone(t *testing.T) {
	root := t.TempDir()

	// Create a directory that is completely unrelated to the FilesManager.
	unknownDir := filepath.Join(root, "totally-unrelated")
	require.NoError(t, os.MkdirAll(unknownDir, 0o755))
	unknownFile := filepath.Join(unknownDir, "some-file.txt")
	require.NoError(t, os.WriteFile(unknownFile, []byte("keep me"), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// The unknown directory and its content must survive Start.
	assert.DirExists(t, unknownDir, "unknown dir must not be removed on Start")
	assert.FileExists(t, unknownFile, "file inside unknown dir must not be removed on Start")
}

// TestManager_EnsureRestoresExactStateOnSymlinkFailure verifies that when the
// symlink swap fails during an upgrade (1.0.0 → 2.0.0 → 3.0.0), the store is
// restored to the exact pre-upgrade tracked state (Current=2.0.0, Previous=1.0.0)
// rather than being poisoned to (Current=2.0.0, Previous=3.0.0) by a naïve store.put.
func TestManager_EnsureRestoresExactStateOnSymlinkFailure(t *testing.T) {
	v1 := buildTarGz(t, map[string]string{"file.txt": "v1"})
	v2 := buildTarGz(t, map[string]string{"file.txt": "v2"})
	v3 := buildTarGz(t, map[string]string{"file.txt": "v3"})
	sum1, sum2, sum3 := sha256Hex(v1), sha256Hex(v2), sha256Hex(v3)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v1) })
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v2) })
	mux.HandleFunc("/v3.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v3) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, root := newTestManager(t)

	// Install 1.0.0 then 2.0.0 so Previous=1.0.0 is recorded.
	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)
	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)

	// Block the symlink swap for 3.0.0 by making the <root>/pkg/ directory
	// read-only so os.Symlink() inside swapSymlink cannot create the temp
	// symlink (current.new). Restore write permission on test cleanup.
	pkgDir := filepath.Join(root, "pkg")
	require.NoError(t, os.Chmod(pkgDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(pkgDir, 0o755) })

	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "3.0.0",
		URL: srv.URL + "/v3.tar.gz", SHA256: sum3, Extract: true,
	})
	// Restore write permission before asserting so cleanup of TempDir succeeds.
	_ = os.Chmod(pkgDir, 0o755)
	require.Error(t, err, "Ensure must fail when symlink swap fails")

	// Store must be restored to exactly Current=2.0.0, Previous=1.0.0.
	tracked, ok := m.(*filesmgr).store.getTracked("pkg")
	require.True(t, ok)
	assert.Equal(t, "2.0.0", tracked.Current.Version, "current must be v2 after failed v3 Ensure")
	require.NotNil(t, tracked.Previous, "previous must not be nil")
	assert.Equal(t, "1.0.0", tracked.Previous.Version, "previous must be v1, not poisoned by v3")
}

// TestManager_EnsureChmodsOnModeChange verifies that re-Ensure-ing the same
// file with a different Mode updates the on-disk permissions even when SHA256
// and Version match (idempotent path — applies mode change without re-fetching).
func TestManager_EnsureChmodsOnModeChange(t *testing.T) {
	blob := []byte("executable-content")
	sum := sha256Hex(blob)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	m, root := newTestManager(t)

	spec := FileSpec{
		Name:    "tool",
		Version: "1.0.0",
		URL:     srv.URL + "/tool",
		SHA256:  sum,
		Extract: false,
		Mode:    0o644,
	}
	_, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err)

	filePath := filepath.Join(root, "tool", "current", "tool")
	fi, err := os.Stat(filePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm())

	// Re-Ensure with same SHA256/Version but different Mode.
	spec.Mode = 0o755
	_, err = m.Ensure(context.Background(), spec)
	require.NoError(t, err)

	fi, err = os.Stat(filePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "mode must be updated on idempotent Ensure with new Mode")
}

// TestManager_RollbackRejectsUnversionedEntries verifies that Rollback returns
// an error when either current or previous has an empty Version. Rollback
// creates a symlink target relative to the name dir; an unversioned entry
// would yield a self-referential symlink, so such calls are rejected.
func TestManager_RollbackRejectsUnversionedEntries(t *testing.T) {
	root := t.TempDir()
	// Manually inject an unversioned tracked entry directly into the store so
	// we bypass Ensure's versioned-path logic.
	s := newStore(filepath.Join(root, "state.json"))
	p := filepath.Join(root, "tool")
	require.NoError(t, os.MkdirAll(p, 0o755))
	// Put with no Version (empty string).
	require.NoError(t, s.put(FileEntry{Name: "tool", Version: "", Path: p, SHA256: "abc"}))
	// Inject a fake previous also with no version so the Previous != nil check passes.
	p2 := filepath.Join(root, "tool2")
	require.NoError(t, os.MkdirAll(p2, 0o755))
	require.NoError(t, s.putTracked("tool", trackedEntry{
		Current:  FileEntry{Name: "tool", Version: "", Path: p, SHA256: "abc"},
		Previous: &FileEntry{Name: "tool", Version: "", Path: p2, SHA256: "def"},
	}))

	fm := &filesmgr{
		logger:  slog.Default(),
		root:    root,
		store:   s,
		fetcher: newFetcher(slog.Default()),
		bus:     newEventBusWithLogger(slog.Default()),
	}

	err := fm.Rollback(context.Background(), "tool")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires versioned entries")
}

// TestManager_RollbackRestoresSymlinkIfStateWriteFails verifies that when the
// state write fails after the symlink has been swapped to the previous version,
// Rollback best-effort swaps the symlink back to its pre-rollback target so
// the filesystem stays consistent with the persisted state.
func TestManager_RollbackRestoresSymlinkIfStateWriteFails(t *testing.T) {
	v1 := buildTarGz(t, map[string]string{"file.txt": "v1"})
	v2 := buildTarGz(t, map[string]string{"file.txt": "v2"})
	sum1, sum2 := sha256Hex(v1), sha256Hex(v2)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v1) })
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(v2) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, root := newTestManager(t)

	// Install 1.0.0 then 2.0.0.
	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)
	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)

	// Confirm symlink points to 2.0.0 before rollback.
	linkPath := filepath.Join(root, "pkg", "current")
	target, err := os.Readlink(linkPath)
	require.NoError(t, err)
	require.Equal(t, "2.0.0", target)

	// Block state writes by replacing state.json with a directory.
	statePath := filepath.Join(root, "state.json")
	require.NoError(t, os.Remove(statePath))
	require.NoError(t, os.Mkdir(statePath, 0o755))
	t.Cleanup(func() { _ = os.RemoveAll(statePath) })

	// Rollback must fail (state write fails).
	err = m.Rollback(context.Background(), "pkg")
	require.Error(t, err, "Rollback must fail when state write fails")

	// Best-effort restore: symlink must point back to 2.0.0 (pre-rollback target).
	restoredTarget, readErr := os.Readlink(linkPath)
	require.NoError(t, readErr)
	assert.Equal(t, "2.0.0", restoredTarget, "symlink must be restored to pre-rollback target after state write failure")
}

// TestManager_RemoveRejectsUnsafeNames verifies that Remove returns an error
// for path-traversal names and does not touch the filesystem (Prior #1).
func TestManager_RemoveRejectsUnsafeNames(t *testing.T) {
	m, root := newTestManager(t)

	for _, badName := range []string{"../etc", "/etc", "..", "."} {
		err := m.Remove(context.Background(), badName)
		require.Error(t, err, "Remove(%q) must return error", badName)
	}

	// Filesystem under root must be untouched (only state.json may exist).
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	for _, e := range entries {
		assert.Equal(t, "state.json", e.Name(), "unexpected file created for bad Remove: %s", e.Name())
	}
}

// TestManager_StartCleansUpStateTmpFiles verifies that state-*.json.tmp files
// left by a crashed atomic write are removed on the next Start().
func TestManager_StartCleansUpStateTmpFiles(t *testing.T) {
	root := t.TempDir()

	// Create a tracked entry on disk so Start has pending entries and enters the
	// full reconciliation + cleanupStaleArtifacts path (with the lazy-root change,
	// Start returns early when state.json is missing or empty).
	nameDir := filepath.Join(root, "x")
	require.NoError(t, os.MkdirAll(nameDir, 0o755))
	filePath := filepath.Join(nameDir, "bin")
	require.NoError(t, os.WriteFile(filePath, []byte("v1"), 0o755))
	stateJSON := `{"version":1,"entries":{"x":{"current":{"name":"x","version":"","path":"` +
		filePath + `","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	// Plant a fake state-*.json.tmp file at the root (as if a crash left it).
	tmpFile := filepath.Join(root, "state-abc123.json.tmp")
	require.NoError(t, os.WriteFile(tmpFile, []byte(`{}`), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	_, statErr := os.Stat(tmpFile)
	assert.True(t, os.IsNotExist(statErr), "state-*.json.tmp must be removed on Start")
}

// TestManager_StartPreservesUnversionedExtractedContent verifies that an
// unversioned Extract install (no "current" symlink) is not destroyed by
// cleanupStaleArtifacts. Only stage artifacts inside the name dir are removed;
// the extracted content (files and subdirs) survives Start().
func TestManager_StartPreservesUnversionedExtractedContent(t *testing.T) {
	root := t.TempDir()

	// Set up the on-disk layout for an unversioned Extract install:
	//   <root>/x/file.txt
	//   <root>/x/subdir/
	// No "current" symlink — this is an unversioned placement.
	nameDir := filepath.Join(root, "x")
	require.NoError(t, os.MkdirAll(filepath.Join(nameDir, "subdir"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nameDir, "file.txt"), []byte("content"), 0o644))

	// Populate state.json with an unversioned tracked entry so the manager
	// knows about this name. Path points to the name dir itself (Extract, no version).
	stateJSON := `{"version":1,"entries":{"x":{"current":{"name":"x","version":"","path":"` +
		nameDir + `","sha256":"abc","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	// Plant a stale stage dir inside the name dir — this SHOULD be removed.
	staleStage := filepath.Join(nameDir, ".filesmgr-stage-orphan")
	require.NoError(t, os.Mkdir(staleStage, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(staleStage, "tmp"), []byte("stale"), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// Extracted content must survive.
	assert.FileExists(t, filepath.Join(nameDir, "file.txt"), "file.txt must not be removed on Start")
	assert.DirExists(t, filepath.Join(nameDir, "subdir"), "subdir must not be removed on Start")

	// Stage dir inside name dir must be gone.
	assert.NoDirExists(t, staleStage, "stale stage dir inside unversioned name dir must be removed on Start")
}

// TestManager_EnsureRefetchesOnTamper verifies that if the on-disk file is
// modified after installation, a subsequent Ensure with the same spec detects
// the SHA256 mismatch and re-fetches the original content.
func TestManager_EnsureRefetchesOnTamper(t *testing.T) {
	blob := []byte("original-content-do-not-tamper")
	sum := sha256Hex(blob)

	var serveCount int
	var serveMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		serveMu.Lock()
		serveCount++
		serveMu.Unlock()
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	m, root := newTestManager(t)

	spec := FileSpec{
		Name:    "tool",
		Version: "1.0.0",
		URL:     srv.URL + "/tool",
		SHA256:  sum,
		Extract: false,
	}

	// First install.
	path, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err)

	filePath := filepath.Join(root, "tool", "current", "tool")
	require.FileExists(t, filePath)

	// Record server hits after the first install.
	serveMu.Lock()
	hitsAfterInstall := serveCount
	serveMu.Unlock()
	require.Greater(t, hitsAfterInstall, 0, "server must be hit during the initial install")

	// Tamper: overwrite the file with different content.
	require.NoError(t, os.WriteFile(filePath, []byte("tampered!"), 0o644))

	// Second Ensure with the same spec — must detect mismatch and re-fetch.
	path2, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, path, path2, "path must be stable across re-fetch")

	// The file must have the original content again.
	got, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, blob, got, "file content must be restored after tamper re-fetch")

	// Server must have been hit again after the tamper (re-fetch occurred).
	serveMu.Lock()
	hitsAfterRefetch := serveCount
	serveMu.Unlock()
	assert.Greater(t, hitsAfterRefetch, hitsAfterInstall,
		"server must be hit again after tamper detection (re-fetch must occur)")
}

// TestManager_EnsureRefetchesWhenSingleFilePathBecameDirectory verifies that if
// the on-disk path for a single-file (non-Extract) entry has been replaced by a
// directory (e.g. operator tampering or a mode-transition mistake), Ensure
// detects the mismatch and re-fetches the original content.
func TestManager_EnsureRefetchesWhenSingleFilePathBecameDirectory(t *testing.T) {
	blob := []byte("single-file-content")
	sum := sha256Hex(blob)

	var serveCount int
	var serveMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		serveMu.Lock()
		serveCount++
		serveMu.Unlock()
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	m, root := newTestManager(t)

	spec := FileSpec{
		Name:    "tool",
		Version: "1.0.0",
		URL:     srv.URL + "/tool",
		SHA256:  sum,
		Extract: false,
	}

	// First install.
	path, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err)

	filePath := filepath.Join(root, "tool", "current", "tool")
	require.FileExists(t, filePath)

	serveMu.Lock()
	hitsAfterInstall := serveCount
	serveMu.Unlock()
	require.Greater(t, hitsAfterInstall, 0, "server must be hit during the initial install")

	// Tamper: replace the file with a directory at the same path.
	require.NoError(t, os.Remove(filePath))
	require.NoError(t, os.Mkdir(filePath, 0o755))

	// Second Ensure with the same spec — must detect the directory and re-fetch.
	path2, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, path, path2, "path must be stable across re-fetch")

	// The path must be a regular file again with the original content.
	fi, err := os.Stat(path2)
	require.NoError(t, err)
	assert.False(t, fi.IsDir(), "path must be a regular file after re-fetch, not a directory")

	got, err := os.ReadFile(path2)
	require.NoError(t, err)
	assert.Equal(t, blob, got, "file content must be restored after directory-tamper re-fetch")

	// Server must have been hit again (re-fetch occurred).
	serveMu.Lock()
	hitsAfterRefetch := serveCount
	serveMu.Unlock()
	assert.Greater(t, hitsAfterRefetch, hitsAfterInstall,
		"server must be hit again after directory-tamper detection (re-fetch must occur)")
}

// TestManager_StartLeavesUntrackedNameWithCurrentSymlinkAlone verifies that
// cleanupStaleArtifacts does NOT touch a name directory that is untracked in
// state.json even when it contains a "current" symlink that resembles a
// FilesManager versioned install. Such directories are not owned by the manager
// and must be left entirely untouched to avoid destructive behavior when root
// is shared with other tooling that uses the same symlink convention.
func TestManager_StartLeavesUntrackedNameWithCurrentSymlinkAlone(t *testing.T) {
	root := t.TempDir()

	// Create a directory that looks like a versioned install but is NOT tracked.
	foreignDir := filepath.Join(root, "foreign")
	versionDir1 := filepath.Join(foreignDir, "1.0.0")
	versionDir2 := filepath.Join(foreignDir, "2.0.0")
	require.NoError(t, os.MkdirAll(versionDir1, 0o755))
	require.NoError(t, os.MkdirAll(versionDir2, 0o755))
	// Set up a "current" symlink pointing at 1.0.0, just like the manager would.
	currentLink := filepath.Join(foreignDir, "current")
	require.NoError(t, os.Symlink("1.0.0", currentLink))

	// Start with no state.json — "foreign" is untracked.
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// All three must survive: the current symlink and both version directories.
	_, lstatErr := os.Lstat(currentLink)
	assert.NoError(t, lstatErr, "current symlink inside untracked dir must not be removed on Start")
	assert.DirExists(t, versionDir1, "1.0.0 dir inside untracked name must not be removed on Start")
	assert.DirExists(t, versionDir2, "2.0.0 dir inside untracked name must not be removed on Start")
}

// TestManager_StartRecoversCrashedInstall verifies that Start() detects and
// cleans up the crash window where store.put succeeded (state.json written) but
// the process died before swapSymlink, leaving a version directory on disk that
// is never reachable via the "current" symlink.
//
// Expected behaviour:
//   - The orphan version directory is removed.
//   - The state entry is dropped (path doesn't resolve).
func TestManager_StartRecoversCrashedInstall(t *testing.T) {
	root := t.TempDir()

	nameDir := filepath.Join(root, "x")
	versionDir := filepath.Join(nameDir, "1.0.0")
	// Simulate: fetcher placed the version dir but swapSymlink never ran.
	require.NoError(t, os.MkdirAll(versionDir, 0o755))
	// NOTE: no "current" symlink and no binary inside the version dir (the
	// binary path recorded in state.json also doesn't exist on disk).

	// state.json records the entry as if the install completed (store.put ran).
	// Current.Path uses the "current" symlink path — which doesn't exist yet.
	currentPath := filepath.Join(nameDir, "current", "binary")
	stateJSON := `{"version":1,"entries":{"x":{"current":{"name":"x","version":"1.0.0","path":"` +
		currentPath + `","sha256":"abc","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// The orphan version directory must be gone.
	assert.NoDirExists(t, versionDir, "crashed-install version dir must be removed on Start")

	// The entry must be dropped from state.
	_, ok := m.Get("x")
	assert.False(t, ok, "crashed-install entry must be dropped from state on Start")
}

// TestManager_StartSkipsWriteWhenReconciliationIsNoOp verifies that Start()
// does NOT write to state.json when reconciliation found nothing to change.
// This is required for read-only deployments where the filesystem may be
// mounted read-only after correct state was pre-provisioned: the manager must
// be able to boot without attempting any disk writes.
func TestManager_StartSkipsWriteWhenReconciliationIsNoOp(t *testing.T) {
	root := t.TempDir()
	nameDir := filepath.Join(root, "x")
	versionDir := filepath.Join(nameDir, "1.0.0")
	require.NoError(t, os.MkdirAll(versionDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "binary"), []byte("v1"), 0o755))
	require.NoError(t, os.Symlink("1.0.0", filepath.Join(nameDir, "current")))

	currentBin := filepath.Join(nameDir, "current", "binary")
	stateJSON := `{"version":1,"entries":{"x":{"current":{"name":"x","version":"1.0.0","path":"` +
		currentBin + `","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	statePath := filepath.Join(root, "state.json")
	require.NoError(t, os.WriteFile(statePath, []byte(stateJSON), 0o644))

	// Capture the mtime before Start. If commitReconciled runs, the file is
	// rewritten and mtime advances.
	infoBefore, err := os.Stat(statePath)
	require.NoError(t, err)
	mtimeBefore := infoBefore.ModTime()
	// Wait a moment so any rewrite would produce a distinguishable mtime.
	time.Sleep(20 * time.Millisecond)

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	infoAfter, err := os.Stat(statePath)
	require.NoError(t, err)
	assert.Equal(t, mtimeBefore, infoAfter.ModTime(),
		"state.json must not be rewritten when reconciliation found no changes")

	// Sanity: the entry must still be tracked.
	entry, ok := m.Get("x")
	require.True(t, ok)
	assert.Equal(t, "1.0.0", entry.Version)
}

// TestManager_StartRecoversSymlinkMismatchCrash_DemotesPrevious verifies the
// real-world crash window: store.put recorded the upgrade (Current=v2,
// Previous=v1) but swapSymlink never ran (current still points at v1).
// On recovery, the v2 dir is removed AND state is demoted to (Current=v1,
// Previous=nil) so the manager keeps tracking the actually-live binary.
// Without demotion, filesManager.Get() would return nothing and consumers
// would silently fall back to their baked binary while v1 is still running.
func TestManager_StartRecoversSymlinkMismatchCrash_DemotesPrevious(t *testing.T) {
	root := t.TempDir()
	nameDir := filepath.Join(root, "x")

	// Set up the v1 install (the previously-live, still-live version).
	v1Dir := filepath.Join(nameDir, "1.0.0")
	require.NoError(t, os.MkdirAll(v1Dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v1Dir, "binary"), []byte("v1"), 0o755))

	// The current symlink still points at v1 (the swap step crashed).
	currentLink := filepath.Join(nameDir, "current")
	require.NoError(t, os.Symlink("1.0.0", currentLink))

	// The fetcher placed v2's version dir before the crash.
	v2Dir := filepath.Join(nameDir, "2.0.0")
	require.NoError(t, os.MkdirAll(v2Dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(v2Dir, "binary"), []byte("v2"), 0o755))

	// state.json: Current=v2 (just recorded by store.put), Previous=v1
	// (promoted from the prior Current). Current.Path resolves through the
	// stale symlink so os.Stat would succeed — only the symlink-target check
	// detects the mismatch.
	v1Bin := filepath.Join(v1Dir, "binary")
	currentBin := filepath.Join(nameDir, "current", "binary")
	stateJSON := `{"version":1,"entries":{"x":{"current":{"name":"x","version":"2.0.0","path":"` +
		currentBin + `","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"},` +
		`"previous":{"name":"x","version":"1.0.0","path":"` +
		v1Bin + `","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// The crashed v2 version dir must be removed.
	assert.NoDirExists(t, v2Dir, "crashed v2 version dir must be removed on Start")

	// v1's dir and the stale symlink should be untouched (live install).
	assert.DirExists(t, v1Dir, "live v1 version dir must be preserved")
	target, err := os.Readlink(currentLink)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", target, "current symlink target must be preserved")

	// State must be demoted: Current=v1, Previous=nil. The manager continues
	// tracking the live binary so consumers don't silently downgrade.
	entry, ok := m.Get("x")
	require.True(t, ok, "entry must be retained (demoted) so filesManager.Get returns the live version path")
	assert.Equal(t, "1.0.0", entry.Version, "Current must be demoted to v1")
}

// TestManager_StartRecoversSymlinkMismatchCrash_DropsWhenNoPrevious verifies the
// fallback case: if state has no Previous matching the symlink target (e.g. the
// state file is corrupt or out-of-sync beyond simple crash), the entry is
// dropped. Consumers fall back to baked binary until a fresh Ensure re-records.
func TestManager_StartRecoversSymlinkMismatchCrash_DropsWhenNoPrevious(t *testing.T) {
	root := t.TempDir()
	nameDir := filepath.Join(root, "x")

	v1Dir := filepath.Join(nameDir, "1.0.0")
	require.NoError(t, os.MkdirAll(v1Dir, 0o755))
	currentLink := filepath.Join(nameDir, "current")
	require.NoError(t, os.Symlink("1.0.0", currentLink))

	v2Dir := filepath.Join(nameDir, "2.0.0")
	require.NoError(t, os.MkdirAll(v2Dir, 0o755))

	// State has Current=v2 but NO Previous (unrealistic corruption / partial
	// state). Symlink points at v1, which is untracked.
	currentBin := filepath.Join(nameDir, "current", "binary")
	stateJSON := `{"version":1,"entries":{"x":{"current":{"name":"x","version":"2.0.0","path":"` +
		currentBin + `","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	assert.NoDirExists(t, v2Dir, "crashed v2 dir must be removed")
	_, ok := m.Get("x")
	assert.False(t, ok, "entry must be dropped when Previous doesn't match symlink target")
}

// TestManager_StartPreservesNonTrackedVersionDirs verifies that subdirectories
// inside a tracked name dir which are NOT referenced by any tracked entry are
// preserved on Start. We cannot distinguish a stale-but-harmless old version
// dir from something an operator or companion process placed there, so we err
// on the side of preservation. Crashed-install recovery is handled separately
// via state.json reconciliation in Start (TestManager_StartRecoversCrashedInstall).
func TestManager_StartPreservesNonTrackedVersionDirs(t *testing.T) {
	root := t.TempDir()

	// Manually create the on-disk layout for a tracked entry at v1.0.0.
	nameDir := filepath.Join(root, "mypkg")
	trackedVersionDir := filepath.Join(nameDir, "1.0.0")
	require.NoError(t, os.MkdirAll(trackedVersionDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(trackedVersionDir, "bin"), []byte("v1"), 0o755))

	// Set up the current symlink pointing to the tracked version.
	currentLink := filepath.Join(nameDir, "current")
	require.NoError(t, os.Symlink("1.0.0", currentLink))

	// Plant a non-tracked subdir under the same name dir (could be an old
	// version, operator-placed data, etc.). It must NOT be removed on Start.
	otherDir := filepath.Join(nameDir, "0.9.0")
	require.NoError(t, os.MkdirAll(otherDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(otherDir, "bin"), []byte("old"), 0o755))

	// Write state.json referencing only v1.0.0.
	stateJSON := `{"version":1,"entries":{"mypkg":{"current":{"name":"mypkg","version":"1.0.0","path":"` +
		currentLink + `/bin","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// The non-tracked directory must still exist — only known-artifact patterns
	// (.filesmgr-stage-*, .filesmgr-backup-*, current.new) are touched.
	assert.DirExists(t, otherDir, "non-tracked subdir must be preserved on Start")

	// The tracked version directory must also still exist.
	assert.DirExists(t, trackedVersionDir, "tracked version dir must not be removed on Start")
}

func TestNew_DummyWhenInactive(t *testing.T) {
	for _, active := range []string{"", "local", "unknown"} {
		m := New(slog.Default(), config.FilesManagerConfig{Active: active})
		require.NotNil(t, m)
		_, ok := m.(*dummyFilesManager)
		assert.True(t, ok, "active=%q should yield the dummy files manager", active)
		// Dummy Get always reports not-installed so consumers fall back to baked binaries.
		_, found := m.Get("anything")
		assert.False(t, found)
	}
}

func TestNew_FleetWhenActive(t *testing.T) {
	m := New(slog.Default(), config.FilesManagerConfig{Active: "fleet"})
	ff, ok := m.(*FleetFilesManager)
	require.True(t, ok)
	// Default root applied to the embedded engine.
	eng, ok := ff.Manager.(*filesmgr)
	require.True(t, ok)
	assert.Equal(t, defaultRoot, eng.root)
}

func TestNew_FleetUsesConfiguredRoot(t *testing.T) {
	m := New(slog.Default(), config.FilesManagerConfig{Active: "fleet", Root: "/custom/files"})
	ff, ok := m.(*FleetFilesManager)
	require.True(t, ok)
	eng, ok := ff.Manager.(*filesmgr)
	require.True(t, ok)
	assert.Equal(t, "/custom/files", eng.root)
}

// TestManager_StartCleansUpStaleBackupDirs verifies that .filesmgr-backup-*
// directories left behind by a crashed renameSwap call are removed on the next
// Start(). This covers:
//   - A backup parent dir at the root level (e.g. from a crash during an
//     unversioned Extract swap).
//   - A backup parent dir inside a tracked versioned name directory.
//   - A backup parent dir inside a tracked unversioned (Extract, no version)
//     name directory.
func TestManager_StartCleansUpStaleBackupDirs(t *testing.T) {
	root := t.TempDir()

	// --- Root-level backup dir ---
	// Simulate a crash that left a .filesmgr-backup-* dir directly under root.
	rootBackup := filepath.Join(root, ".filesmgr-backup-rootlevel")
	require.NoError(t, os.MkdirAll(filepath.Join(rootBackup, "dst"), 0o755))

	// --- Versioned name dir with a nested backup dir ---
	// Set up a tracked versioned install (tracked-versioned / 1.0.0).
	versionedNameDir := filepath.Join(root, "tracked-versioned")
	versionDir := filepath.Join(versionedNameDir, "1.0.0")
	require.NoError(t, os.MkdirAll(versionDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "bin"), []byte("v1"), 0o755))
	currentLink := filepath.Join(versionedNameDir, "current")
	require.NoError(t, os.Symlink("1.0.0", currentLink))

	// Plant a stale backup parent inside the versioned name dir.
	nestedBackupVersioned := filepath.Join(versionedNameDir, ".filesmgr-backup-nested")
	require.NoError(t, os.MkdirAll(filepath.Join(nestedBackupVersioned, "dst"), 0o755))

	// --- Unversioned name dir with a nested backup dir ---
	// Set up a tracked unversioned Extract install (tracked-unversioned).
	unversionedNameDir := filepath.Join(root, "tracked-unversioned")
	require.NoError(t, os.MkdirAll(unversionedNameDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(unversionedNameDir, "file.txt"), []byte("content"), 0o644))

	// Plant a stale backup parent inside the unversioned name dir.
	nestedBackupUnversioned := filepath.Join(unversionedNameDir, ".filesmgr-backup-nested2")
	require.NoError(t, os.MkdirAll(filepath.Join(nestedBackupUnversioned, "dst"), 0o755))

	// Write state.json with both entries so the manager recognises them.
	versionedPath := filepath.Join(versionedNameDir, "current", "bin")
	stateJSON := `{"version":1,"entries":{` +
		`"tracked-versioned":{"current":{"name":"tracked-versioned","version":"1.0.0","path":"` + versionedPath + `","sha256":"","source":"","installed_at":"0001-01-01T00:00:00Z"}},` +
		`"tracked-unversioned":{"current":{"name":"tracked-unversioned","version":"","path":"` + unversionedNameDir + `","sha256":"abc","source":"","installed_at":"0001-01-01T00:00:00Z"}}` +
		`}}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "state.json"), []byte(stateJSON), 0o644))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// All three backup dirs must be removed.
	assert.NoDirExists(t, rootBackup,
		"root-level stale backup dir must be removed on Start")
	assert.NoDirExists(t, nestedBackupVersioned,
		"nested stale backup dir inside versioned name dir must be removed on Start")
	assert.NoDirExists(t, nestedBackupUnversioned,
		"nested stale backup dir inside unversioned name dir must be removed on Start")

	// The tracked content must survive.
	assert.DirExists(t, versionDir, "tracked version dir must not be removed on Start")
	assert.FileExists(t, filepath.Join(unversionedNameDir, "file.txt"),
		"unversioned content must not be removed on Start")
}

// TestManager_EnsureRecordsFailureOnChecksumMismatch verifies that a
// failed Ensure (here, a SHA256 that doesn't match the fetched archive) is
// recorded via ListPending instead of being silently dropped, and a
// subsequent successful Ensure for the same name clears it.
func TestManager_EnsureRecordsFailureOnChecksumMismatch(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "alpha"})
	realSum := sha256Hex(archive)
	wrongSum := strings.Repeat("0", len(realSum))
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, _ := newTestManager(t)

	_, err := m.Ensure(context.Background(), FileSpec{
		Name:    "pkg",
		Version: "1.0.0",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  wrongSum,
		Extract: true,
	})
	require.Error(t, err)

	pending := m.ListPending()
	require.Len(t, pending, 1)
	assert.Equal(t, "pkg", pending[0].Name)
	assert.Equal(t, "1.0.0", pending[0].Version)
	assert.Equal(t, FileEntryStateFailed, pending[0].State)
	assert.NotEmpty(t, pending[0].Error)
	assert.False(t, pending[0].Timeout)
	assert.WithinDuration(t, time.Now(), pending[0].UpdatedAt, 5*time.Second)

	// The failed name must not appear in List() (no successful install).
	assert.Empty(t, m.List())

	// A subsequent successful Ensure for the same name clears the failure.
	_, err = m.Ensure(context.Background(), FileSpec{
		Name:    "pkg",
		Version: "1.0.0",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  realSum,
		Extract: true,
	})
	require.NoError(t, err)
	assert.Empty(t, m.ListPending())
}

// TestManager_EnsureRecordsTimeoutFailure verifies a context deadline
// exceeded during Ensure is recorded as a Timeout failure —
// distinguishing the 10-minute install timeout case from other errors, per
// the ticket's requirement to report checksum mismatch, timeout, and
// download errors distinctly enough to be useful.
func TestManager_EnsureRecordsTimeoutFailure(t *testing.T) {
	// A server that never responds within the deadline forces ctx.Err() to be
	// DeadlineExceeded by the time Ensure returns.
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-blocked
	}))
	// Unblock the handler before Close (which waits for in-flight requests to
	// finish) — deferred in this order so close(blocked) runs first (LIFO).
	defer srv.Close()
	defer close(blocked)

	m, _ := newTestManager(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := m.Ensure(ctx, FileSpec{
		Name:    "pkg-timeout",
		Version: "1.0.0",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  strings.Repeat("0", 64),
		Extract: true,
	})
	require.Error(t, err)

	pending := m.ListPending()
	require.Len(t, pending, 1)
	assert.Equal(t, "pkg-timeout", pending[0].Name)
	assert.Equal(t, FileEntryStateFailed, pending[0].State)
	assert.True(t, pending[0].Timeout, "expected a context-deadline failure to be flagged as a timeout")
}

// TestManager_EnsureSerializesFailureBookkeepingAcrossConcurrentCalls covers a
// race flagged in review: Ensure's wrapper calls setPendingFailed/clearPending
// AFTER ensureLocked has already released its internal per-name mutex
// (mutexFor), so relying on that mutex alone leaves a brief unprotected
// window where an older but slower failing call's setPendingFailed could run
// after a newer but faster successful call's clearPending — leaving
// ListPending reporting "failed" even though the most recent attempt
// actually succeeded. The fix adds a second, outer per-name mutex
// (ensureCallMutexFor) that Ensure holds across the whole call, including
// record/clear, so no other Ensure call for the same name can even begin
// until the previous one's record/clear has completed.
//
// Note: black-box channel handshakes can force call B to block until call A
// finishes its fetch (mutexFor already guarantees that much on its own), but
// cannot deterministically land B inside the few-instruction gap between
// ensureLocked's internal unlock and the wrapper's record/clear call that
// was the actual unprotected window — that gap is too narrow to hit
// reliably without instrumenting the code under test. This test instead
// verifies the resulting behavioral guarantee: when call A (fails) and call
// B (succeeds) for the same name genuinely run concurrently, whichever call
// completes last — proven here by explicit channel signals establishing A
// starts and blocks first while B is confirmed still waiting — is the one
// whose outcome is reflected once both have returned. Reverting the
// ensureCallMutexFor fix does not make this specific test fail (the
// existing internal mutex already serializes enough of the operation for
// this particular interleaving), but the outer lock is still required to
// close the general case Codex identified.
func TestManager_EnsureSerializesFailureBookkeepingAcrossConcurrentCalls(t *testing.T) {
	const name = "pkg-race"

	archive := buildTarGz(t, map[string]string{"a.txt": "alpha"})
	sum := sha256Hex(archive)

	aStarted := make(chan struct{})
	var aStartedOnce sync.Once
	aProceed := make(chan struct{})
	aSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// go-getter/http may retry the request; only signal aStarted once so
		// a retry doesn't panic on a double-close.
		aStartedOnce.Do(func() { close(aStarted) })
		<-aProceed
		// Fail the fetch outright (no valid archive body).
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer aSrv.Close()

	bStarted := make(chan struct{})
	bSrv := serveTarGz(t, archive)
	defer bSrv.Close()

	m, _ := newTestManager(t)

	var wg sync.WaitGroup
	var errA, errB error

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errA = m.Ensure(context.Background(), FileSpec{
			Name:    name,
			Version: "1.0.0",
			URL:     aSrv.URL + "/x.tar.gz",
			SHA256:  strings.Repeat("0", 64),
			Extract: true,
		})
	}()

	<-aStarted // A is now inside its fetch, holding Ensure's outer per-name lock.

	wg.Add(1)
	go func() {
		defer wg.Done()
		close(bStarted) // signals only that the goroutine is running, not that B's HTTP handler fired
		_, errB = m.Ensure(context.Background(), FileSpec{
			Name:    name,
			Version: "2.0.0",
			URL:     bSrv.URL + "/x.tar.gz",
			SHA256:  sum,
			Extract: true,
		})
	}()
	<-bStarted // B's goroutine is running and calling Ensure, but should block on the lock A holds.

	// B must still be blocked waiting for A's lock — it cannot have installed
	// yet. This is best-effort timing but generous enough (50ms) to catch a
	// regression where B is not blocked at all.
	time.Sleep(50 * time.Millisecond)
	assert.Empty(t, m.List(), "B must not have been able to proceed while A holds the outer lock")

	close(aProceed) // let A fail and run its setPendingFailed + release the lock.
	wg.Wait()

	require.Error(t, errA)
	require.NoError(t, errB)

	// B ran strictly after A (including A's setPendingFailed) and succeeded, so
	// the final state must show no outstanding failure and the successful
	// install — never a stale "failed" left over from A.
	assert.Empty(t, m.ListPending(), "B's success must have cleared any failure A recorded")
	entries := m.List()
	require.Len(t, entries, 1)
	assert.Equal(t, name, entries[0].Name)
	assert.Equal(t, "2.0.0", entries[0].Version)
}
