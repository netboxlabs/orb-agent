package filesmgr

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

const stateSchemaVersion = 2

// trackedEntry holds the current installed entry plus the displaced previous
// entry (if any) so that Rollback can restore it.
type trackedEntry struct {
	Current  FileEntry  `json:"current"`
	Previous *FileEntry `json:"previous,omitempty"`
}

type stateFile struct {
	Version int                     `json:"version"`
	Entries map[string]trackedEntry `json:"entries"`
}

// store persists the FilesManager's known entries to a state.json file.
// It is safe for concurrent use.
type store struct {
	path    string
	mu      sync.RWMutex
	writeMu sync.Mutex // serializes all disk writes
	entries map[string]trackedEntry
	logger  *slog.Logger
}

func newStore(path string) *store {
	return &store{
		path:    path,
		entries: make(map[string]trackedEntry),
		logger:  slog.Default(),
	}
}

// load reads state.json (if present) and drops any entries whose Path
// does not exist on disk. A missing state.json file is not an error.
// Older state files using the flat entry format are upgraded in-memory
// to the current tracked format with no Previous pointers.
func (s *store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}

	// Peek at version field first.
	var peek struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return err
	}

	var tracked map[string]trackedEntry

	if peek.Version <= 1 {
		// Legacy flat format: entries is map[string]FileEntry.
		var sf1 struct {
			Version int                  `json:"version"`
			Entries map[string]FileEntry `json:"entries"`
		}
		if err := json.Unmarshal(data, &sf1); err != nil {
			return err
		}
		tracked = make(map[string]trackedEntry, len(sf1.Entries))
		for name, entry := range sf1.Entries {
			tracked[name] = trackedEntry{Current: entry, Previous: nil}
		}
	} else {
		// Current tracked format.
		var sf stateFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return err
		}
		tracked = sf.Entries
	}

	// Reconcile: drop entries whose current path is missing on disk; drop
	// previous pointers whose path is missing (current stays if it exists).
	for name, te := range tracked {
		if _, statErr := os.Stat(te.Current.Path); statErr != nil {
			s.logger.Warn("filesmgr: dropping entry, path missing", "name", name, "path", te.Current.Path)
			delete(tracked, name)
			continue
		}
		if te.Previous != nil {
			if _, statErr := os.Stat(te.Previous.Path); statErr != nil {
				s.logger.Warn("filesmgr: dropping previous entry, path missing", "name", name, "path", te.Previous.Path)
				te.Previous = nil
				tracked[name] = te
			}
		}
	}
	s.entries = tracked
	return nil
}

// loadPending reads state.json and returns the raw entries map without any
// filesystem reconciliation (no stat checks, no drops). A missing state.json
// file returns an empty map. Older v1 flat-format files are upgraded in-memory
// to the tracked format.
//
// This is the first half of the split-load approach for crash recovery: the
// caller (filesmgr.Start) inspects each entry for missing paths, removes any
// orphan version directories created by a crashed install, and then calls
// commitReconciled to persist the validated entries and update in-memory state.
func (s *store) loadPending() (map[string]trackedEntry, error) {
	s.mu.RLock()
	data, err := os.ReadFile(s.path)
	s.mu.RUnlock()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return make(map[string]trackedEntry), nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return make(map[string]trackedEntry), nil
	}

	var peek struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return nil, err
	}

	if peek.Version <= 1 {
		var sf1 struct {
			Version int                  `json:"version"`
			Entries map[string]FileEntry `json:"entries"`
		}
		if err := json.Unmarshal(data, &sf1); err != nil {
			return nil, err
		}
		tracked := make(map[string]trackedEntry, len(sf1.Entries))
		for name, entry := range sf1.Entries {
			tracked[name] = trackedEntry{Current: entry, Previous: nil}
		}
		return tracked, nil
	}

	var sf stateFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, err
	}
	return sf.Entries, nil
}

// commitReconciled replaces the in-memory entries map with the caller-supplied
// reconciled map and persists it to disk. This is the second half of the
// split-load approach: after crash recovery has dropped entries whose paths are
// missing, the caller passes the cleaned-up map here.
// If the disk write fails, the in-memory state is left unchanged.
func (s *store) commitReconciled(entries map[string]trackedEntry) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := s.writeSnapshot(entries); err != nil {
		return err
	}

	s.mu.Lock()
	s.entries = entries
	s.mu.Unlock()
	return nil
}

// put inserts a new current entry. If an existing entry is already tracked,
// the existing Current is recorded as the new Previous (one level of history
// only — older Previous entries are replaced).
// If the disk write fails, the in-memory state is left unchanged.
//
// writeMu is acquired first to serialize the entire snapshot-mutate-write-commit
// sequence. This prevents a lost-update race where two concurrent puts for
// different names both snapshot the same pre-state map and the second commit
// silently drops the first's update.
func (s *store) put(entry FileEntry) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Build the candidate snapshot WITHOUT mutating the live map.
	s.mu.RLock()
	next := make(map[string]trackedEntry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()

	var prevPtr *FileEntry
	if existing, ok := next[entry.Name]; ok {
		// Only carry Previous when the new entry has a different version.
		// Same-version replacements (re-fetch with different SHA, or recovery
		// from missing-on-disk) would land at the same on-disk path as the
		// existing entry, so Previous would be a no-op rollback target.
		if existing.Current.Version != entry.Version {
			prev := existing.Current
			prevPtr = &prev
		}
	}
	next[entry.Name] = trackedEntry{Current: entry, Previous: prevPtr}

	if err := s.writeSnapshot(next); err != nil {
		return err
	}

	// Commit only on success.
	s.mu.Lock()
	s.entries = next
	s.mu.Unlock()
	return nil
}

// putWithoutPrevious overwrites an entry setting Previous to nil.
// Used during Rollback (where the rolled-back-to version has no further back)
// and during error recovery.
func (s *store) putWithoutPrevious(entry FileEntry) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.RLock()
	next := make(map[string]trackedEntry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()

	next[entry.Name] = trackedEntry{Current: entry, Previous: nil}

	if err := s.writeSnapshot(next); err != nil {
		return err
	}

	s.mu.Lock()
	s.entries = next
	s.mu.Unlock()
	return nil
}

// putTracked writes a tracked entry verbatim, bypassing the
// promote-current-to-previous logic of put(). Used by the Ensure rollback-on-
// failure path to restore exact prior state and avoid poisoning Previous.
func (s *store) putTracked(name string, te trackedEntry) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.RLock()
	next := make(map[string]trackedEntry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()

	next[name] = te

	if err := s.writeSnapshot(next); err != nil {
		return err
	}

	s.mu.Lock()
	s.entries = next
	s.mu.Unlock()
	return nil
}

// delete removes an entry by name and atomically writes state.json.
// If the disk write fails, the in-memory state is left unchanged.
func (s *store) delete(name string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Build the candidate snapshot WITHOUT mutating the live map.
	s.mu.RLock()
	next := make(map[string]trackedEntry, len(s.entries))
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()
	delete(next, name)

	if err := s.writeSnapshot(next); err != nil {
		return err
	}

	// Commit only on success.
	s.mu.Lock()
	s.entries = next
	s.mu.Unlock()
	return nil
}

// get returns the current entry for name, if present.
func (s *store) get(name string) (FileEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[name]
	if !ok {
		return FileEntry{}, false
	}
	return e.Current, ok
}

// getTracked returns the full tracked entry including previous.
func (s *store) getTracked(name string) (trackedEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[name]
	return e, ok
}

// all returns a snapshot of all current entries.
func (s *store) all() map[string]FileEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]FileEntry, len(s.entries))
	for k, v := range s.entries {
		out[k] = v.Current
	}
	return out
}

// iterTracked calls fn for every tracked entry in a consistent snapshot.
// Used by cleanupStaleArtifacts to enumerate both current and previous
// version directories so neither is mistakenly removed as an orphan.
func (s *store) iterTracked(fn func(name string, te trackedEntry)) {
	s.mu.RLock()
	snapshot := make(map[string]trackedEntry, len(s.entries))
	for k, v := range s.entries {
		snapshot[k] = v
	}
	s.mu.RUnlock()
	for name, te := range snapshot {
		fn(name, te)
	}
}

// writeSnapshot marshals snapshot to a unique temp file, fsyncs it, renames
// it into the final state.json path, then fsyncs the parent directory so the
// rename is durable. Caller must hold writeMu.
func (s *store) writeSnapshot(snapshot map[string]trackedEntry) error {
	sf := stateFile{Version: stateSchemaVersion, Entries: snapshot}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Use a unique temp name to avoid collisions under concurrent callers
	// (writeMu serializes, but be defensive anyway).
	f, err := os.CreateTemp(dir, "state-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()

	// Clean up temp on any failure path.
	var writeErr error
	defer func() {
		if writeErr != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, writeErr = f.Write(data); writeErr != nil {
		_ = f.Close()
		return writeErr
	}
	if writeErr = f.Sync(); writeErr != nil {
		_ = f.Close()
		return writeErr
	}
	if writeErr = f.Close(); writeErr != nil {
		return writeErr
	}

	if writeErr = os.Rename(tmpName, s.path); writeErr != nil {
		return writeErr
	}

	// fsync the parent directory so the rename (directory entry update) is durable.
	// These errors are non-fatal: the file is written and the rename succeeded;
	// losing the dir fsync only matters on a power-loss between rename and fsync.
	// Use separate variables (openErr, syncErr) so they are clearly distinct from
	// writeErr, which controls the deferred cleanup of the temp file.
	dfd, openErr := os.Open(dir)
	if openErr != nil {
		s.logger.Warn("filesmgr: cannot open dir for fsync", "dir", dir, "error", openErr)
		return nil
	}
	if syncErr := dfd.Sync(); syncErr != nil {
		s.logger.Warn("filesmgr: dir fsync failed", "dir", dir, "error", syncErr)
	}
	_ = dfd.Close()
	return nil
}
