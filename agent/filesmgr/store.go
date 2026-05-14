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
// If the file is version 1 (old format), it is upgraded in-memory to v2
// with no Previous pointers.
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
		// v1 format: entries is map[string]FileEntry.
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
		// v2 format.
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

// put inserts a new current entry. If an existing entry is already tracked,
// the existing Current is recorded as the new Previous (one level of history
// only — older Previous entries are replaced).
// If the disk write fails, the in-memory state is left unchanged.
func (s *store) put(entry FileEntry) error {
	// Build the candidate snapshot WITHOUT mutating the live map.
	s.mu.RLock()
	next := make(map[string]trackedEntry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()

	var prevPtr *FileEntry
	if existing, ok := next[entry.Name]; ok {
		prev := existing.Current
		prevPtr = &prev
	}
	next[entry.Name] = trackedEntry{Current: entry, Previous: prevPtr}

	// Serialize disk writes globally.
	s.writeMu.Lock()
	err := s.writeSnapshot(next)
	s.writeMu.Unlock()
	if err != nil {
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
	s.mu.RLock()
	next := make(map[string]trackedEntry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()

	next[entry.Name] = trackedEntry{Current: entry, Previous: nil}

	s.writeMu.Lock()
	err := s.writeSnapshot(next)
	s.writeMu.Unlock()
	if err != nil {
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
	// Build the candidate snapshot WITHOUT mutating the live map.
	s.mu.RLock()
	next := make(map[string]trackedEntry, len(s.entries))
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()
	delete(next, name)

	// Serialize disk writes globally.
	s.writeMu.Lock()
	err := s.writeSnapshot(next)
	s.writeMu.Unlock()
	if err != nil {
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
	dfd, err := os.Open(dir)
	if err != nil {
		// Non-fatal: the file is written, the rename succeeded; losing the dir
		// fsync only matters on a power-loss between rename and fsync.
		s.logger.Warn("filesmgr: cannot open dir for fsync", "dir", dir, "error", err)
		return nil
	}
	if err := dfd.Sync(); err != nil {
		s.logger.Warn("filesmgr: dir fsync failed", "dir", dir, "error", err)
	}
	_ = dfd.Close()
	return nil
}
