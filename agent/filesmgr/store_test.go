package filesmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

func TestStore_V1Migration(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")

	// Write a hand-crafted legacy-format state.json.
	p := filepath.Join(root, "x", "1.0.0")
	require.NoError(t, os.MkdirAll(p, 0o755))
	v1JSON := `{
  "version": 1,
  "entries": {
    "x": {
      "name": "x",
      "version": "1.0.0",
      "path": "` + p + `",
      "sha256": "abc",
      "source": "https://example.com/x.tar.gz",
      "installed_at": "2026-01-01T00:00:00Z"
    }
  }
}`
	require.NoError(t, os.WriteFile(statePath, []byte(v1JSON), 0o644))

	s := newStore(statePath)
	require.NoError(t, s.load())

	// Entry must be present.
	got, ok := s.get("x")
	require.True(t, ok)
	assert.Equal(t, "x", got.Name)
	assert.Equal(t, "1.0.0", got.Version)

	// No Previous should exist after migration.
	tracked, ok := s.getTracked("x")
	require.True(t, ok)
	assert.Nil(t, tracked.Previous, "v1 migration must produce no Previous")
}

func TestStore_V2RoundTripWithPrevious(t *testing.T) {
	root := t.TempDir()
	s := newStore(filepath.Join(root, "state.json"))

	// Install 1.0.0.
	p1 := filepath.Join(root, "x", "1.0.0")
	require.NoError(t, os.MkdirAll(p1, 0o755))
	entry1 := FileEntry{Name: "x", Version: "1.0.0", Path: p1, SHA256: "aaa", InstalledAt: time.Now().UTC().Truncate(time.Second)}
	require.NoError(t, s.put(entry1))

	// Install v2 — should record v1 as Previous.
	p2 := filepath.Join(root, "x", "2.0.0")
	require.NoError(t, os.MkdirAll(p2, 0o755))
	entry2 := FileEntry{Name: "x", Version: "2.0.0", Path: p2, SHA256: "bbb", InstalledAt: time.Now().UTC().Truncate(time.Second)}
	require.NoError(t, s.put(entry2))

	// Reload from disk and verify Previous is persisted.
	s2 := newStore(filepath.Join(root, "state.json"))
	require.NoError(t, s2.load())

	tracked, ok := s2.getTracked("x")
	require.True(t, ok)
	assert.Equal(t, "2.0.0", tracked.Current.Version)
	require.NotNil(t, tracked.Previous, "previous must be recorded after second put")
	assert.Equal(t, "1.0.0", tracked.Previous.Version)
}

func TestStore_ConcurrentPutsForDifferentNamesAreSerialized(t *testing.T) {
	root := t.TempDir()
	s := newStore(filepath.Join(root, "state.json"))

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("entry-%d", i)
			p := filepath.Join(root, name)
			require.NoError(t, os.MkdirAll(p, 0o755))
			require.NoError(t, s.put(FileEntry{Name: name, Path: p, SHA256: "abc"}))
		}(i)
	}
	wg.Wait()

	all := s.all()
	assert.Len(t, all, n, "all %d entries must be present after concurrent puts", n)
	for i := range n {
		name := fmt.Sprintf("entry-%d", i)
		_, ok := all[name]
		assert.True(t, ok, "entry %s must be present", name)
	}
}

func TestStore_SameVersionReplacementDoesNotPromotePrevious(t *testing.T) {
	root := t.TempDir()
	s := newStore(filepath.Join(root, "state.json"))

	// Install v1.0.0 with SHA A.
	p1 := filepath.Join(root, "x", "1.0.0")
	require.NoError(t, os.MkdirAll(p1, 0o755))
	entry1 := FileEntry{Name: "x", Version: "1.0.0", Path: p1, SHA256: "sha-a"}
	require.NoError(t, s.put(entry1))

	// Re-install the same version with a different SHA (e.g. re-fetch after corruption).
	entry2 := FileEntry{Name: "x", Version: "1.0.0", Path: p1, SHA256: "sha-b"}
	require.NoError(t, s.put(entry2))

	// Previous must be nil: same version replacement must not promote current to previous.
	tracked, ok := s.getTracked("x")
	require.True(t, ok)
	assert.Nil(t, tracked.Previous, "same-version re-put must not set Previous")
	assert.Equal(t, "sha-b", tracked.Current.SHA256, "current SHA must be updated")
}

func TestStore_WriteFailureDoesNotMutateInMemoryState(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "good")
	require.NoError(t, os.MkdirAll(p, 0o755))

	// Place a directory at the exact state.json path so os.Rename onto it
	// fails with EISDIR, exercising the rollback path in put().
	stateDir := filepath.Join(root, "statedir")
	require.NoError(t, os.MkdirAll(stateDir, 0o755))
	statePath := filepath.Join(stateDir, "state.json")
	require.NoError(t, os.Mkdir(statePath, 0o755))

	s := newStore(statePath)
	// Attempt a put — the disk write must fail because state.json is a directory.
	err := s.put(FileEntry{Name: "x", Path: p, SHA256: "def"})
	require.Error(t, err, "expected put to fail when state.json path is a directory")

	// In-memory state must be unchanged (no "x" entry).
	_, ok := s.get("x")
	assert.False(t, ok, "in-memory state must not be mutated on write failure")
}
