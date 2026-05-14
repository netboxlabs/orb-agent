package filesmgr

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	// Install v1 and confirm "current" points to "1.0.0".
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

	// Upgrade to v2 and confirm "current" now points to "2.0.0".
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

	// Start a normal manager so Start() can create the root dir.
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// Now block writes by placing a directory at the state.json path.
	// state.json doesn't exist yet (no puts yet), so we just mkdir it.
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

	// Install v1.
	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)

	// Upgrade to v2.
	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)

	// Verify symlink points to v2.
	target, err := os.Readlink(filepath.Join(root, "pkg", "current"))
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", target)

	// Rollback.
	require.NoError(t, m.Rollback(context.Background(), "pkg"))

	// Symlink must now point to v1.
	target, err = os.Readlink(filepath.Join(root, "pkg", "current"))
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", target)

	// Get must return the v1 entry.
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

func TestManager_RollbackWithNoPrevious_ReturnsError(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "data"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, _ := newTestManager(t)

	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/x.tar.gz", SHA256: sum, Extract: true,
	})
	require.NoError(t, err)

	err = m.Rollback(context.Background(), "pkg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no previous version")
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

	// Simulate operator cleanup: remove the v1 directory.
	require.NoError(t, os.RemoveAll(filepath.Join(root, "pkg", "1.0.0")))

	err = m.Rollback(context.Background(), "pkg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "previous version dir missing")
}

func TestManager_StartCleansUpStaleArtifacts(t *testing.T) {
	root := t.TempDir()

	// Create a stale stage directory at the root level.
	staleStage := filepath.Join(root, ".filesmgr-stage-abc123")
	require.NoError(t, os.Mkdir(staleStage, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(staleStage, "payload"), []byte("stale"), 0o644))

	// Create a stale current.new symlink inside a name directory.
	nameDir := filepath.Join(root, "mypkg")
	require.NoError(t, os.MkdirAll(nameDir, 0o755))
	staleNew := filepath.Join(nameDir, "current.new")
	require.NoError(t, os.Symlink("1.0.0", staleNew))

	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))

	// Both stale artifacts must be gone after Start().
	assert.NoDirExists(t, staleStage, "stale stage dir must be removed on Start")
	_, err := os.Lstat(staleNew)
	assert.True(t, os.IsNotExist(err), "stale current.new must be removed on Start")
}
