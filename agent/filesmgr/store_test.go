package filesmgr

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_RoundTrip(t *testing.T) {
	root := t.TempDir()
	s := newStore(filepath.Join(root, "state.json"))

	entry := FileEntry{
		Name:        "x",
		Version:     "1.0.0",
		Path:        filepath.Join(root, "x", "1.0.0"),
		SHA256:      "abc",
		Source:      "https://example.com/x.tar.gz",
		InstalledAt: time.Now().UTC().Truncate(time.Second),
	}

	// Pre-create the path so reconciliation keeps it.
	require.NoError(t, os.MkdirAll(entry.Path, 0o755))

	require.NoError(t, s.put(entry))

	s2 := newStore(filepath.Join(root, "state.json"))
	require.NoError(t, s2.load())

	got, ok := s2.get("x")
	require.True(t, ok)
	assert.Equal(t, entry.Name, got.Name)
	assert.Equal(t, entry.Version, got.Version)
	assert.Equal(t, entry.SHA256, got.SHA256)
}

func TestStore_ReconciliationDropsMissingFiles(t *testing.T) {
	root := t.TempDir()
	s := newStore(filepath.Join(root, "state.json"))

	// Record an entry whose path doesn't exist.
	require.NoError(t, s.put(FileEntry{
		Name:        "ghost",
		Path:        filepath.Join(root, "does-not-exist"),
		SHA256:      "abc",
		InstalledAt: time.Now().UTC(),
	}))

	s2 := newStore(filepath.Join(root, "state.json"))
	require.NoError(t, s2.load())

	_, ok := s2.get("ghost")
	assert.False(t, ok, "missing path should drop entry on reconciliation")
}

func TestStore_LoadMissingFileIsOK(t *testing.T) {
	root := t.TempDir()
	s := newStore(filepath.Join(root, "state.json"))
	require.NoError(t, s.load())
	assert.Empty(t, s.all())
}

func TestStore_Delete(t *testing.T) {
	root := t.TempDir()
	s := newStore(filepath.Join(root, "state.json"))

	p := filepath.Join(root, "y")
	require.NoError(t, os.MkdirAll(p, 0o755))
	require.NoError(t, s.put(FileEntry{Name: "y", Path: p, SHA256: "abc"}))

	require.NoError(t, s.delete("y"))
	_, ok := s.get("y")
	assert.False(t, ok)
}
