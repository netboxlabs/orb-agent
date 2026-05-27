package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/filesmgr"
)

func sha256HexOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestWorkerBackend_ResolvesExecFromFilesManager verifies that resolveExecPath
// returns the FilesManager-managed path when an "orb-worker" entry is a regular
// file, and falls back to the baked d.exec value when no entry exists.
func TestWorkerBackend_ResolvesExecFromFilesManager(t *testing.T) {
	// --- Setup: serve a fake binary as a raw file (not extracted). ---
	// We use a plain binary content so the entry path resolves to a regular file.
	binaryContent := []byte("#!/bin/sh\nexit 0\n")
	sum := sha256HexOf(binaryContent)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(binaryContent)
	}))
	defer srv.Close()

	// --- Case 1: FilesManager has a regular-file entry. resolveExecPath must return its Path. ---
	root := t.TempDir()
	fm := filesmgr.NewManager(slog.Default(), root)
	require.NoError(t, fm.Start(context.Background()))
	defer func() { _ = fm.Stop(context.Background()) }()

	// Use Extract:false so the entry path is the file itself, not a directory.
	installedPath, err := fm.Ensure(context.Background(), filesmgr.FileSpec{
		Name:    "orb-worker",
		Version: "1.0.0",
		URL:     srv.URL + "/orb-worker",
		SHA256:  sum,
		Extract: false,
		Mode:    0o755,
	})
	require.NoError(t, err)
	require.NotEmpty(t, installedPath)

	// Confirm the installed entry's Path matches what Get returns.
	entry, ok := fm.Get("orb-worker")
	require.True(t, ok)
	require.NotEmpty(t, entry.Path)

	// Sanity check: the path must be a regular file, not a directory.
	info, err := os.Stat(entry.Path)
	require.NoError(t, err)
	require.False(t, info.IsDir(), "installed entry path must be a regular file")

	// Construct a workerBackend with filesManager set.
	be := &workerBackend{
		exec:         defaultExec,
		logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
		filesManager: fm,
	}

	resolved := be.resolveExecPath()
	assert.Equal(t, entry.Path, resolved,
		"resolveExecPath must return the FilesManager-managed path when entry is a regular file")
	assert.NotEqual(t, defaultExec, resolved,
		"resolveExecPath must not return the baked default when FilesManager has a regular-file entry")

	// --- Case 2: no FilesManager entry. resolveExecPath must fall back to d.exec. ---
	beNoFM := &workerBackend{
		exec:   defaultExec,
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
	// filesManager is nil — simulates a backend that was never given a manager.
	assert.Equal(t, defaultExec, beNoFM.resolveExecPath(),
		"resolveExecPath must return baked default when filesManager is nil")

	// --- Case 3: FilesManager present but no entry for "orb-worker". ---
	emptyRoot := t.TempDir()
	emptyFM := filesmgr.NewManager(slog.Default(), emptyRoot)
	require.NoError(t, emptyFM.Start(context.Background()))
	defer func() { _ = emptyFM.Stop(context.Background()) }()

	beEmptyFM := &workerBackend{
		exec:         defaultExec,
		logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
		filesManager: emptyFM,
	}
	assert.Equal(t, defaultExec, beEmptyFM.resolveExecPath(),
		"resolveExecPath must return baked default when FilesManager has no entry for orb-worker")
}

// TestWorkerBackend_ManagedBinaryNameIsOrbWorker verifies Fix 2c: the worker
// backend now declares its managed binary as "orb-worker".
func TestWorkerBackend_ManagedBinaryNameIsOrbWorker(t *testing.T) {
	be := &workerBackend{}
	assert.Equal(t, "orb-worker", be.ManagedBinaryName())
}

// TestWorkerBackend_FallsBackWhenManagedPathIsDirectory verifies that
// resolveExecPath falls back to d.exec when FilesManager has an entry whose
// Path is a directory (e.g. Ensure called with Extract:true — entry.Path is
// the "current" symlink pointing to a directory, not a file).
func TestWorkerBackend_FallsBackWhenManagedPathIsDirectory(t *testing.T) {
	// Create a temp dir to serve as the managed path — simulates what happens
	// when FilesManager stores a directory as the entry path.
	dirPath := t.TempDir()

	// Build a stub FilesManager whose Get returns a directory path.
	fm := &stubDirFilesManager{path: dirPath}

	be := &workerBackend{
		exec:         defaultExec,
		logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
		filesManager: fm,
	}

	resolved := be.resolveExecPath()
	assert.Equal(t, defaultExec, resolved,
		"resolveExecPath must fall back to d.exec when the managed path is a directory")
}

// stubDirFilesManager is a minimal filesmgr.Manager that returns a fixed
// entry path (used to inject a directory path for testing resolveExecPath).
type stubDirFilesManager struct {
	path string
}

func (s *stubDirFilesManager) Start(_ context.Context) error { return nil }
func (s *stubDirFilesManager) Stop(_ context.Context) error  { return nil }
func (s *stubDirFilesManager) Ensure(_ context.Context, _ filesmgr.FileSpec) (string, error) {
	return s.path, nil
}

func (s *stubDirFilesManager) Get(name string) (filesmgr.FileEntry, bool) {
	if name == "orb-worker" {
		return filesmgr.FileEntry{Name: name, Path: s.path}, true
	}
	return filesmgr.FileEntry{}, false
}
func (s *stubDirFilesManager) Remove(_ context.Context, _ string) error   { return nil }
func (s *stubDirFilesManager) Rollback(_ context.Context, _ string) error { return nil }
func (s *stubDirFilesManager) Subscribe(_ func(filesmgr.FileEvent)) func() {
	return func() {}
}
