package filesmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
}

// NewManager constructs a default Manager rooted at the given directory.
// All files are placed under <root>/<name>/<version>/. The state.json
// file lives at <root>/state.json.
func NewManager(logger *slog.Logger, root string) Manager {
	if logger == nil {
		logger = slog.Default()
	}
	l := logger.With("subsystem", "filesmgr")
	return &filesmgr{
		logger:  l,
		root:    root,
		store:   newStore(filepath.Join(root, "state.json")),
		fetcher: newFetcher(l),
		bus:     newEventBusWithLogger(logger),
	}
}

// ensureRoot creates the root directory if it does not already exist.
// It is called lazily at first use (Ensure, Remove, Rollback, or startup
// crash recovery) rather than unconditionally in Start, so that agents
// that never call Ensure do not require write access to the root's parent
// (e.g. /opt on a non-root deployment where the default root is
// /opt/orb/files).
func (m *filesmgr) ensureRoot() error {
	return os.MkdirAll(m.root, 0o755)
}

// Start loads persisted state, performs crash recovery for partially-installed
// entries, and removes any stale temp directories or partial symlinks left by
// a previous crash. The root directory is only created when there are entries
// to reconcile (i.e. state.json exists and is non-empty).
//
// Startup sequence:
//  1. loadPending: read state.json into memory without any filesystem checks.
//     A missing state.json returns an empty map (no error).
//  2. If there are no pending entries, return immediately — no directory
//     creation needed (lazy root).
//  3. ensureRoot: create the root directory now that we know we need it.
//  4. Crash recovery: for each entry whose Current.Path doesn't exist on disk,
//     remove the implied version directory (created by the fetcher but never
//     activated by swapSymlink) and drop the entry from state.
//  5. commitReconciled: persist the post-recovery entries and update in-memory
//     state in a single atomic write.
//  6. cleanupStaleArtifacts: remove stage dirs, current.new links, and orphan
//     version dirs inside tracked name directories.
func (m *filesmgr) Start(_ context.Context) error {
	// Don't MkdirAll here unconditionally — it would fail on non-root
	// deployments when the default /opt/orb/files isn't writable, breaking
	// agents that never use FilesManager. The directory is created lazily on
	// first use (Ensure / crash-recovery commit).

	// Phase 1: read state.json without filesystem reconciliation.
	// loadPending returns an empty map (nil error) when state.json is missing.
	pending, err := m.store.loadPending()
	if err != nil {
		return err
	}

	// No pending entries means this agent has never used FilesManager (or its
	// state was cleared). Skip root creation and all reconciliation.
	if len(pending) == 0 {
		return nil
	}

	// We have entries to reconcile — the root directory must exist.
	if err := m.ensureRoot(); err != nil {
		return err
	}

	// Phase 2: crash recovery — detect entries whose Current.Path is missing
	// (process died after store.put but before swapSymlink) and clean up the
	// orphaned version directory the fetcher already placed on disk.
	reconciled := make(map[string]trackedEntry, len(pending))
	for name, te := range pending {
		if _, statErr := os.Stat(te.Current.Path); statErr != nil {
			// The recorded path doesn't exist. If there is a version directory
			// on disk it is an orphan from a crashed install — remove it.
			if te.Current.Version != "" {
				versionDir := filepath.Join(m.root, name, te.Current.Version)
				if _, vdirErr := os.Stat(versionDir); vdirErr == nil {
					if rmErr := os.RemoveAll(versionDir); rmErr != nil {
						m.logger.Warn("filesmgr: failed to remove crashed-install version dir",
							"name", name, "dir", versionDir, "error", rmErr)
					} else {
						m.logger.Info("filesmgr: removed crashed-install version dir",
							"name", name, "dir", versionDir)
					}
				}
			}
			// Drop the entry; do not add to reconciled.
			m.logger.Warn("filesmgr: dropping entry, path missing (crash recovery)",
				"name", name, "path", te.Current.Path)
			continue
		}
		// Path exists. Also validate Previous if present.
		if te.Previous != nil {
			if _, prevErr := os.Stat(te.Previous.Path); prevErr != nil {
				m.logger.Warn("filesmgr: dropping previous entry, path missing",
					"name", name, "path", te.Previous.Path)
				te.Previous = nil
			}
		}
		reconciled[name] = te
	}

	// Phase 3: persist the post-recovery entries and update in-memory state.
	if err := m.store.commitReconciled(reconciled); err != nil {
		return err
	}

	m.cleanupStaleArtifacts()
	return nil
}

// cleanupStaleArtifacts removes:
//  1. Top-level temp stage directories (.filesmgr-stage-*).
//  2. Top-level backup parent directories (.filesmgr-backup-*) left by a
//     crashed renameSwap call.
//  3. Top-level state temp files (state-*.json.tmp) left by a crashed write.
//  4. Stale current.new symlinks, nested .filesmgr-stage-* dirs, and nested
//     .filesmgr-backup-* dirs inside each name directory.
//  5. Orphan version subdirectories inside name directories that are not
//     referenced by any tracked entry (neither current nor previous).
//     These are left when the process crashed between store.put and
//     swapSymlink — the version dir exists on disk but state.json was never
//     updated to reflect the symlink target.
//
// For unversioned Extract installs (no "current" symlink, but a tracked entry
// exists), the extracted content under <root>/<name>/ is the install itself —
// only stage/backup artifacts inside it are cleaned; the content is left untouched.
//
// Only directories that the manager recognizes as its own (via tracked state or
// known marker artifacts like .filesmgr-stage-*, .filesmgr-backup-*, current.new)
// are subject to cleanup. Unknown dirs are left untouched.
func (m *filesmgr) cleanupStaleArtifacts() {
	// Build the set of live version directories from the loaded store so we
	// don't delete versions that are still tracked (current or previous).
	liveDirs := make(map[string]bool)
	m.store.iterTracked(func(_ string, te trackedEntry) {
		if d := versionDirFromEntry(m.root, te.Current); d != "" && te.Current.Version != "" {
			liveDirs[d] = true
		}
		if te.Previous != nil {
			if d := versionDirFromEntry(m.root, *te.Previous); d != "" && te.Previous.Version != "" {
				liveDirs[d] = true
			}
		}
	})

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
		// Remove top-level stale backup parent dirs left by a crashed renameSwap.
		if strings.HasPrefix(e.Name(), ".filesmgr-backup-") {
			m.logger.Info("filesmgr: removing stale backup dir", "path", fullPath)
			if err := os.RemoveAll(fullPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove stale backup dir", "path", fullPath, "error", err)
			}
			continue
		}
		// Remove top-level state temp files left by a crashed atomic write.
		if strings.HasPrefix(e.Name(), "state-") && strings.HasSuffix(e.Name(), ".json.tmp") {
			m.logger.Info("filesmgr: removing stale state temp file", "path", fullPath)
			if err := os.Remove(fullPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove stale state temp file", "path", fullPath, "error", err)
			}
			continue
		}
		// Inside each name directory: decide cleanup strategy based on whether
		// a "current" symlink exists (versioned install vs. unversioned install
		// vs. abandoned name dir).
		if !e.IsDir() {
			continue
		}
		currentPath := filepath.Join(fullPath, "current")
		_, currentErr := os.Lstat(currentPath)
		_, tracked := m.store.get(e.Name())

		switch {
		case !tracked:
			// Untracked name: leave alone regardless of any FilesManager-like
			// markers it might contain (including a "current" symlink). Cleanup
			// is the manager's domain only for names it owns.
		case currentErr == nil:
			// Tracked versioned install: clean stale current.new, nested stage
			// dirs, and orphan version subdirs.
			m.cleanVersionedOrphans(fullPath, liveDirs)
		default:
			// Tracked unversioned install: the name dir IS the install content.
			// Only clean stage artifacts and current.new — leave the rest.
			m.cleanStageArtifactsOnly(fullPath)
		}
	}
}

// cleanVersionedOrphans cleans inside a versioned name directory:
//   - removes stale current.new symlinks / files
//   - removes nested .filesmgr-stage-* directories
//   - removes orphan version subdirectories not in liveDirs
func (m *filesmgr) cleanVersionedOrphans(nameDir string, liveDirs map[string]bool) {
	staleNew := filepath.Join(nameDir, "current.new")
	if fi, err := os.Lstat(staleNew); err == nil {
		m.logger.Info("filesmgr: removing stale current.new", "path", staleNew)
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			if err := os.Remove(staleNew); err != nil {
				m.logger.Warn("filesmgr: failed to remove stale current.new", "path", staleNew, "error", err)
			}
		}
	}
	inner, _ := os.ReadDir(nameDir)
	for _, ie := range inner {
		innerPath := filepath.Join(nameDir, ie.Name())
		if strings.HasPrefix(ie.Name(), ".filesmgr-stage-") {
			m.logger.Info("filesmgr: removing nested stale stage dir", "path", innerPath)
			if err := os.RemoveAll(innerPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove nested stale stage dir", "path", innerPath, "error", err)
			}
			continue
		}
		if strings.HasPrefix(ie.Name(), ".filesmgr-backup-") {
			m.logger.Info("filesmgr: removing nested stale backup dir", "path", innerPath)
			if err := os.RemoveAll(innerPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove nested stale backup dir", "path", innerPath, "error", err)
			}
			continue
		}
		// Skip non-directory entries and reserved names inside name dirs.
		if !ie.IsDir() || ie.Name() == "current" {
			continue
		}
		// Any subdirectory that is not a tracked version dir is an orphan.
		if !liveDirs[innerPath] {
			m.logger.Info("filesmgr: removing orphan version dir", "path", innerPath)
			if err := os.RemoveAll(innerPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove orphan version dir", "path", innerPath, "error", err)
			}
		}
	}
}

// cleanStageArtifactsOnly cleans only stage artifacts and stale current.new
// inside an unversioned name directory. The directory's own content (extracted
// files, subdirs) is preserved — it IS the install.
func (m *filesmgr) cleanStageArtifactsOnly(nameDir string) {
	staleNew := filepath.Join(nameDir, "current.new")
	if fi, err := os.Lstat(staleNew); err == nil {
		m.logger.Info("filesmgr: removing stale current.new (unversioned)", "path", staleNew)
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			if err := os.Remove(staleNew); err != nil {
				m.logger.Warn("filesmgr: failed to remove stale current.new (unversioned)", "path", staleNew, "error", err)
			}
		}
	}
	inner, _ := os.ReadDir(nameDir)
	for _, ie := range inner {
		if strings.HasPrefix(ie.Name(), ".filesmgr-stage-") {
			innerPath := filepath.Join(nameDir, ie.Name())
			m.logger.Info("filesmgr: removing nested stale stage dir (unversioned)", "path", innerPath)
			if err := os.RemoveAll(innerPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove nested stale stage dir (unversioned)", "path", innerPath, "error", err)
			}
			continue
		}
		if strings.HasPrefix(ie.Name(), ".filesmgr-backup-") {
			innerPath := filepath.Join(nameDir, ie.Name())
			m.logger.Info("filesmgr: removing nested stale backup dir (unversioned)", "path", innerPath)
			if err := os.RemoveAll(innerPath); err != nil {
				m.logger.Warn("filesmgr: failed to remove nested stale backup dir (unversioned)", "path", innerPath, "error", err)
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
	if err := m.ensureRoot(); err != nil {
		return "", fmt.Errorf("filesmgr: create root: %w", err)
	}

	mu := m.mutexFor(spec.Name)
	mu.Lock()

	// Capture the full pre-mutation tracked entry so we can restore it exactly
	// if the symlink swap fails later — verbatim restoration avoids poisoning
	// Previous with the failed version.
	preTracked, hadExisting := m.store.getTracked(spec.Name)
	existing := preTracked.Current
	if hadExisting && existing.SHA256 == spec.SHA256 && existing.Version == spec.Version {
		if info, err := os.Stat(existing.Path); err == nil {
			if !info.IsDir() {
				// Verify the on-disk SHA256 still matches the recorded one before
				// doing any work. Tampered or corrupted files fall through to
				// re-fetch (which also re-chmods), so chmoding first would be
				// wasted work on the re-fetch path.
				// Only re-verify regular files; for Extract bundles (directories)
				// the recorded SHA256 is of the archive — we don't keep the
				// archive on disk, so we cannot cheaply re-verify. Trust the
				// versioned directory's contents.
				if actual, hashErr := sha256File(existing.Path); hashErr == nil && actual == spec.SHA256 {
					// Content matches; now optionally chmod if mode differs.
					if !spec.Extract && spec.Mode != 0 {
						if info.Mode().Perm() != spec.Mode.Perm() {
							if err := os.Chmod(existing.Path, spec.Mode); err != nil {
								mu.Unlock()
								return "", fmt.Errorf("chmod %s: %w", existing.Path, err)
							}
						}
					}
					mu.Unlock()
					return existing.Path, nil
				}
				// SHA mismatch or hash error: fall through to re-fetch.
			} else if spec.Extract {
				// Extracted bundle: cannot cheaply re-verify; trust on-disk state.
				mu.Unlock()
				return existing.Path, nil
			}
			// spec.Extract == false but path is a directory: on-disk state has
			// diverged from what was recorded (e.g. operator tampering or a
			// mode-transition mistake). Fall through to re-fetch.
		}
		// path missing on disk or SHA mismatch; fall through to re-fetch.
	}

	// versionedDir is where the fetcher places the version directory.
	versionedDir := m.placementPath(spec)

	// Step 1: fetch into the version directory.
	if err := m.fetcher.fetch(ctx, spec, versionedDir); err != nil {
		mu.Unlock()
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
			fn, err := filenameFromURL(spec.URL)
			if err != nil {
				_ = os.RemoveAll(versionedDir)
				mu.Unlock()
				return "", err
			}
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
				mu.Unlock()
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
		mu.Unlock()
		return "", err
	}

	// Step 3: swap "current" symlink (only for versioned placements).
	if spec.Version != "" {
		linkPath := filepath.Join(m.root, spec.Name, "current")
		if err := swapSymlink(spec.Version, linkPath); err != nil {
			// Roll back: restore exact prior state to avoid poisoning Previous.
			// putTracked writes the trackedEntry verbatim — no promote logic.
			// Both rollback paths are non-recoverable here (we're already in the
			// swap-failed error path); log failures so operators can notice and
			// reconcile manually — the next agent restart will recover via the
			// crash-recovery path in Start().
			if hadExisting {
				if rollbackErr := m.store.putTracked(spec.Name, preTracked); rollbackErr != nil {
					m.logger.Error("filesmgr: failed to restore pre-state after symlink swap failure",
						"name", spec.Name, "error", rollbackErr)
				}
			} else {
				if rollbackErr := m.store.delete(spec.Name); rollbackErr != nil {
					m.logger.Error("filesmgr: failed to delete entry after symlink swap failure",
						"name", spec.Name, "error", rollbackErr)
				}
			}
			_ = os.RemoveAll(versionedDir)
			mu.Unlock()
			return "", fmt.Errorf("swap current symlink: %w", err)
		}
	}

	// Build the event before unlocking; publish after to avoid blocking other
	// goroutines waiting on this name's mutex while a slow subscriber runs.
	var ev FileEvent
	if hadExisting {
		prev := existing
		ev = FileEvent{Type: EventUpgraded, Entry: entry, Previous: &prev}
	} else {
		ev = FileEvent{Type: EventInstalled, Entry: entry}
	}
	mu.Unlock()
	m.bus.publish(ev)
	return entryPath, nil
}

func (m *filesmgr) Remove(_ context.Context, name string) error {
	if err := isSafePathSegment(name, "name"); err != nil {
		return err
	}
	if err := m.ensureRoot(); err != nil {
		return fmt.Errorf("filesmgr: create root: %w", err)
	}
	mu := m.mutexFor(name)
	mu.Lock()

	entry, ok := m.store.get(name)
	if !ok {
		mu.Unlock()
		return nil
	}

	ev, err := m.removeLocked(name, entry)
	mu.Unlock()
	if err != nil {
		return err
	}

	// Note: we intentionally do NOT delete the per-name mutex on Remove.
	// Doing so would race with concurrent callers who already obtained the
	// old mutex via mutexFor() but haven't acquired it yet — they would
	// proceed with the now-orphaned mutex while a later caller would get a
	// fresh mutex via LoadOrStore, breaking the serialization invariant for
	// the same logical name. The mutex map grows monotonically with the set
	// of logical names ever Ensure'd, which is bounded in practice (small
	// set of backend binaries and plugin names).

	m.bus.publish(ev)
	return nil
}

// removeLocked performs the disk and state mutations for a Remove operation and
// returns the event to publish. It does NOT publish the event itself; callers
// must publish after releasing the per-name mutex to avoid blocking other
// goroutines on a slow subscriber. Caller must hold the per-name mutex.
func (m *filesmgr) removeLocked(name string, current FileEntry) (FileEvent, error) {
	// Remove the entire name directory (covers all version sub-dirs and the
	// current symlink). os.RemoveAll is safe even if parts are missing.
	nameDir := filepath.Join(m.root, name)
	if err := os.RemoveAll(nameDir); err != nil {
		return FileEvent{}, fmt.Errorf("filesmgr: remove %s: %w", nameDir, err)
	}
	if err := m.store.delete(name); err != nil {
		return FileEvent{}, fmt.Errorf("filesmgr: delete state %s: %w", name, err)
	}
	return FileEvent{Type: EventRemoved, Entry: current}, nil
}

func (m *filesmgr) Rollback(_ context.Context, name string) error {
	if err := isSafePathSegment(name, "name"); err != nil {
		return err
	}
	if err := m.ensureRoot(); err != nil {
		return fmt.Errorf("filesmgr: create root: %w", err)
	}
	mu := m.mutexFor(name)
	mu.Lock()

	tracked, ok := m.store.getTracked(name)
	if !ok {
		mu.Unlock()
		return fmt.Errorf("filesmgr: %s not tracked, nothing to roll back", name)
	}
	if tracked.Previous == nil {
		// No previous version recorded. Roll back to "default" meaning no
		// managed entry — consumers fall back to their baked binary.
		// This is the first-install-failure recovery path.
		ev, err := m.removeLocked(name, tracked.Current)
		mu.Unlock()
		if err != nil {
			return err
		}
		// Note: we intentionally do NOT delete the per-name mutex here.
		// See the same comment in Remove for the full rationale: deleting
		// the mutex after releasing it races with concurrent callers who
		// already hold a reference to the old mutex but haven't locked it
		// yet, breaking the serialization invariant.
		m.bus.publish(ev)
		return nil
	}
	// Rollback creates a symlink target relative to the name dir; an
	// unversioned entry would yield a self-referential symlink, so reject.
	if tracked.Current.Version == "" || tracked.Previous.Version == "" {
		mu.Unlock()
		return fmt.Errorf("filesmgr: rollback requires versioned entries (current=%q, previous=%q)",
			tracked.Current.Version, tracked.Previous.Version)
	}
	prev := *tracked.Previous

	// The previous version's directory must still exist on disk.
	versionDir := versionDirFromEntry(m.root, prev)
	if _, err := os.Stat(versionDir); err != nil {
		mu.Unlock()
		return fmt.Errorf("filesmgr: previous version dir missing: %w", err)
	}

	// Atomic symlink swap back to the previous version's directory basename.
	versionBase := filepath.Base(versionDir)
	linkPath := filepath.Join(m.root, name, "current")

	// Read the current symlink target before we swap, so we can restore it
	// if the state write fails after the swap.
	oldTarget, _ := os.Readlink(linkPath) // empty string if missing/not-symlink

	if err := swapSymlink(versionBase, linkPath); err != nil {
		mu.Unlock()
		return fmt.Errorf("filesmgr: swap symlink: %w", err)
	}

	// Update store: previous becomes current, previous is cleared.
	if err := m.store.putWithoutPrevious(prev); err != nil {
		// The symlink already points to the old version but state is still the
		// new version. Best-effort: swap back so filesystem matches state.
		if oldTarget != "" {
			_ = swapSymlink(oldTarget, linkPath)
		}
		mu.Unlock()
		return fmt.Errorf("filesmgr: persist rollback: %w", err)
	}

	// Build the event before unlocking; publish after to avoid holding the
	// per-name mutex while a slow subscriber runs.
	rolledBackFrom := tracked.Current
	ev := FileEvent{
		Type:     EventRolledBack,
		Entry:    prev,
		Previous: &rolledBackFrom,
	}
	mu.Unlock()
	m.bus.publish(ev)
	return nil
}

// versionDirFromEntry returns the on-disk version directory for an entry.
// Convention: entries are always placed under <root>/<name>/<version>.
func versionDirFromEntry(root string, entry FileEntry) string {
	return filepath.Join(root, entry.Name, entry.Version)
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

// sha256File computes the SHA-256 hex digest of the file at path by streaming
// it through a hash. Returns lowercase hex on success.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
