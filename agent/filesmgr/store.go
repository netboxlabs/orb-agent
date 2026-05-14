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
func (s *store) put(entry FileEntry) error {
	s.mu.Lock()
	s.entries[entry.Name] = entry
	snapshot := make(map[string]FileEntry, len(s.entries))
	for k, v := range s.entries {
		snapshot[k] = v
	}
	s.mu.Unlock()
	return s.write(snapshot)
}

// delete removes an entry by name and atomically writes state.json.
func (s *store) delete(name string) error {
	s.mu.Lock()
	delete(s.entries, name)
	snapshot := make(map[string]FileEntry, len(s.entries))
	for k, v := range s.entries {
		snapshot[k] = v
	}
	s.mu.Unlock()
	return s.write(snapshot)
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

func (s *store) write(snapshot map[string]FileEntry) error {
	sf := stateFile{Version: stateSchemaVersion, Entries: snapshot}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
