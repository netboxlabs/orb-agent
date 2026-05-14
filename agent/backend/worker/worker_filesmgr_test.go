package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

// buildBinaryTarGz creates a minimal .tar.gz containing a single executable
// shell script at the given filename with the given content.
func buildBinaryTarGz(t *testing.T, filename, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: filename,
		Mode: 0o755,
		Size: int64(len(content)),
	}))
	_, err := tw.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func sha256HexOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestWorkerBackend_ResolvesExecFromFilesManager verifies that resolveExecPath
// returns the FilesManager-managed path when an "orb-worker" entry is installed,
// and falls back to the baked d.exec value when no entry exists.
func TestWorkerBackend_ResolvesExecFromFilesManager(t *testing.T) {
	// --- Setup: build a fake orb-worker archive and serve it. ---
	archive := buildBinaryTarGz(t, "orb-worker", "#!/bin/sh\nexit 0\n")
	sum := sha256HexOf(archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	// --- Case 1: FilesManager has an entry. resolveExecPath must return its Path. ---
	root := t.TempDir()
	fm := filesmgr.NewManager(slog.Default(), root)
	require.NoError(t, fm.Start(context.Background()))
	defer func() { _ = fm.Stop(context.Background()) }()

	installedPath, err := fm.Ensure(context.Background(), filesmgr.FileSpec{
		Name:    "orb-worker",
		Version: "1.0.0",
		URL:     srv.URL + "/orb-worker.tar.gz",
		SHA256:  sum,
		Extract: true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, installedPath)

	// Confirm the installed entry's Path matches what Get returns.
	entry, ok := fm.Get("orb-worker")
	require.True(t, ok)
	require.NotEmpty(t, entry.Path)

	// Construct a workerBackend with filesManager set via Configure.
	be := &workerBackend{
		exec:   defaultExec,
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
	be.filesManager = fm

	resolved := be.resolveExecPath()
	assert.Equal(t, entry.Path, resolved,
		"resolveExecPath must return the FilesManager-managed path when entry exists")
	assert.NotEqual(t, defaultExec, resolved,
		"resolveExecPath must not return the baked default when FilesManager has an entry")

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
