package filesmgr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// swapSymlink atomically replaces linkPath so it points to target.
// It creates a temporary symlink next to linkPath, then renames it into
// place — rename(2) is atomic for symlinks on POSIX file-systems.
func swapSymlink(target, linkPath string) error {
	tmp := linkPath + ".new"
	// Remove stale temp symlink if a previous run crashed.
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	return nil
}

// filesmgr is the default Manager implementation.
type filesmgr struct {
	logger *slog.Logger
	root   string

	store   *store
	fetcher *fetcher
	bus     *eventBus

	// perNameMu serializes Ensure calls for the same logical name.
	perNameMu sync.Map // name -> *sync.Mutex

	// filesmgrUnsubscribe is set by the agent after subscribing; it is not
	// used internally here but Stop() calls bus.close() directly.
}

// NewManager constructs a default Manager rooted at the given directory.
// All files are placed under <root>/<name>/<version>/. The state.json
// file lives at <root>/state.json.
func NewManager(logger *slog.Logger, root string) Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &filesmgr{
		logger:  logger.With("subsystem", "filesmgr"),
		root:    root,
		store:   newStore(filepath.Join(root, "state.json")),
		fetcher: newFetcher(),
		bus:     newEventBusWithLogger(logger),
	}
}

// Start creates the root directory, loads persisted state, and removes any
// stale temp directories or partial symlinks left by a previous crash.
func (m *filesmgr) Start(_ context.Context) error {
	if err := os.MkdirAll(m.root, 0o755); err != nil {
		return err
	}
	if err := m.store.load(); err != nil {
		return err
	}
	m.cleanupStaleArtifacts()
	return nil
}

// cleanupStaleArtifacts removes temp stage directories (.filesmgr-stage-*)
// left at the root level and any current.new symlinks inside name directories.
func (m *filesmgr) cleanupStaleArtifacts() {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		m.logger.Warn("filesmgr: cannot read root for cleanup", "root", m.root, "error", err)
		return
	}
	for _, e := range entries {
		fullPath := filepath.Join(m.root, e.Name())
		// Remove top-level stale temp stage dirs.
		if strings.HasPrefix(e.Name(), ".filesmgr-stage-") {
			m.logger.Info("filesmgr: removing stale stage dir", "path", fullPath)
			if err := os.RemoveAll(fullPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove stale stage dir", "path", fullPath, "error", err)
			}
			continue
		}
		// Inside each name directory, remove any stale current.new symlinks.
		if e.IsDir() {
			staleNew := filepath.Join(fullPath, "current.new")
			if fi, err := os.Lstat(staleNew); err == nil {
				m.logger.Info("filesmgr: removing stale current.new", "path", staleNew)
				if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
					if err := os.Remove(staleNew); err != nil {
						m.logger.Warn("filesmgr: failed to remove stale current.new", "path", staleNew, "error", err)
					}
				}
			}
		}
	}
}

// Stop closes the event bus so that any lingering subscribers no longer
// receive events after the manager has stopped.
func (m *filesmgr) Stop(_ context.Context) error {
	m.bus.close()
	return nil
}

func (m *filesmgr) Get(name string) (FileEntry, bool) {
	return m.store.get(name)
}

func (m *filesmgr) Subscribe(handler func(FileEvent)) (unsubscribe func()) {
	return m.bus.subscribe(handler)
}

// Ensure makes sure the file described by spec is present on disk and matches
// the declared SHA256. Correct operation order (atomicity guarantee):
//  1. Fetch into fresh version directory.
//  2. Attempt store.put; if it fails, clean up the version dir.
//  3. Swap the "current" symlink; if it fails, roll back store.put.
func (m *filesmgr) Ensure(ctx context.Context, spec FileSpec) (string, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}

	mu := m.mutexFor(spec.Name)
	mu.Lock()
	defer mu.Unlock()

	existing, hasExisting := m.store.get(spec.Name)
	if hasExisting && existing.SHA256 == spec.SHA256 && existing.Version == spec.Version {
		if _, err := os.Stat(existing.Path); err == nil {
			return existing.Path, nil
		}
		// path missing on disk; fall through to re-fetch.
	}

	// versionedDir is where the fetcher places the version directory.
	versionedDir := m.placementPath(spec)

	// Step 1: fetch into the version directory.
	if err := m.fetcher.fetch(ctx, spec, versionedDir); err != nil {
		return "", err
	}

	// Determine the consumer-visible entry path.
	// For versioned installs, the entry path uses the "current" symlink.
	// For single-file (non-extract), the path includes the filename derived
	// from the URL so callers can locate the binary directly.
	var entryPath string
	if spec.Version != "" {
		linkPath := filepath.Join(m.root, spec.Name, "current")
		if spec.Extract {
			// entry path: <root>/<name>/current (symlink to version dir)
			entryPath = linkPath
		} else {
			// entry path: <root>/<name>/current/<filename>
			filename := filepath.Base(versionedDir) // versionedDir = <root>/<name>/<version>
			// We need the actual filename from the URL.
			fn, err := filenameFromURL(spec.URL)
			if err != nil {
				_ = os.RemoveAll(versionedDir)
				return "", err
			}
			_ = filename // unused; use fn from URL
			entryPath = filepath.Join(linkPath, fn)
		}
	} else {
		// No versioning: versionedDir IS the placement. For single-file,
		// the actual file sits inside versionedDir.
		if spec.Extract {
			entryPath = versionedDir
		} else {
			fn, err := filenameFromURL(spec.URL)
			if err != nil {
				_ = os.RemoveAll(versionedDir)
				return "", err
			}
			entryPath = filepath.Join(versionedDir, fn)
		}
	}

	entry := FileEntry{
		Name:        spec.Name,
		Version:     spec.Version,
		Path:        entryPath,
		SHA256:      spec.SHA256,
		Source:      spec.URL,
		InstalledAt: time.Now().UTC(),
	}

	// Step 2: persist state BEFORE making the symlink visible to consumers.
	if err := m.store.put(entry); err != nil {
		// Roll back: remove the version dir we just fetched.
		_ = os.RemoveAll(versionedDir)
		return "", err
	}

	// Step 3: swap "current" symlink (only for versioned placements).
	if spec.Version != "" {
		linkPath := filepath.Join(m.root, spec.Name, "current")
		if err := swapSymlink(spec.Version, linkPath); err != nil {
			// Roll back: restore or delete state entry, remove version dir.
			if hasExisting {
				_ = m.store.put(existing)
			} else {
				_ = m.store.delete(spec.Name)
			}
			_ = os.RemoveAll(versionedDir)
			return "", fmt.Errorf("swap current symlink: %w", err)
		}
	}

	if hasExisting {
		prev := existing
		m.bus.publish(FileEvent{Type: EventUpgraded, Entry: entry, Previous: &prev})
	} else {
		m.bus.publish(FileEvent{Type: EventInstalled, Entry: entry})
	}
	return entryPath, nil
}

func (m *filesmgr) Remove(_ context.Context, name string) error {
	mu := m.mutexFor(name)
	mu.Lock()
	defer mu.Unlock()

	entry, ok := m.store.get(name)
	if !ok {
		return nil
	}

	// When the entry uses a "current" symlink, remove the symlink first so
	// callers cannot read through it after this call returns.
	currentLink := filepath.Join(m.root, name, "current")
	if fi, err := os.Lstat(currentLink); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if removeErr := os.Remove(currentLink); removeErr != nil {
			return fmt.Errorf("remove current symlink %s: %w", currentLink, removeErr)
		}
	}

	// Remove the entire name directory (covers all version sub-dirs).
	nameDir := filepath.Join(m.root, name)
	if err := os.RemoveAll(nameDir); err != nil {
		return fmt.Errorf("remove %s: %w", nameDir, err)
	}

	if err := m.store.delete(name); err != nil {
		return err
	}
	m.bus.publish(FileEvent{Type: EventRemoved, Entry: entry})
	return nil
}

func (m *filesmgr) mutexFor(name string) *sync.Mutex {
	v, _ := m.perNameMu.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex) //nolint:forcetypeassert
}

func (m *filesmgr) placementPath(spec FileSpec) string {
	if spec.Version != "" {
		return filepath.Join(m.root, spec.Name, spec.Version)
	}
	return filepath.Join(m.root, spec.Name)
}
