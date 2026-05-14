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

const stateSchemaVersion = 1

type stateFile struct {
	Version int                  `json:"version"`
	Entries map[string]FileEntry `json:"entries"`
}

// store persists the FilesManager's known entries to a state.json file.
// It is safe for concurrent use.
type store struct {
	path    string
	mu      sync.RWMutex
	writeMu sync.Mutex // serializes all disk writes
	entries map[string]FileEntry
	logger  *slog.Logger
}

func newStore(path string) *store {
	return &store{
		path:    path,
		entries: make(map[string]FileEntry),
		logger:  slog.Default(),
	}
}

// load reads state.json (if present) and drops any entries whose Path
// does not exist on disk. A missing state.json file is not an error.
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

	var sf stateFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return err
	}

	for name, entry := range sf.Entries {
		if _, statErr := os.Stat(entry.Path); statErr != nil {
			s.logger.Warn("filesmgr: dropping entry, path missing", "name", name, "path", entry.Path)
			continue
		}
		s.entries[name] = entry
	}
	return nil
}

// put inserts or replaces an entry and atomically writes state.json.
// If the disk write fails, the in-memory state is left unchanged.
func (s *store) put(entry FileEntry) error {
	// Build the candidate snapshot WITHOUT mutating the live map.
	s.mu.RLock()
	next := make(map[string]FileEntry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	s.mu.RUnlock()
	next[entry.Name] = entry

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

// delete removes an entry by name and atomically writes state.json.
// If the disk write fails, the in-memory state is left unchanged.
func (s *store) delete(name string) error {
	// Build the candidate snapshot WITHOUT mutating the live map.
	s.mu.RLock()
	next := make(map[string]FileEntry, len(s.entries))
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

// get returns the entry for name, if present.
func (s *store) get(name string) (FileEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[name]
	return e, ok
}

// all returns a snapshot of all entries.
func (s *store) all() map[string]FileEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]FileEntry, len(s.entries))
	for k, v := range s.entries {
		out[k] = v
	}
	return out
}

// writeSnapshot marshals snapshot to a unique temp file, fsyncs it, renames
// it into the final state.json path, then fsyncs the parent directory so the
// rename is durable. Caller must hold writeMu.
func (s *store) writeSnapshot(snapshot map[string]FileEntry) error {
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
