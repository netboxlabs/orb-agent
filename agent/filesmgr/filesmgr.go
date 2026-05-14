package filesmgr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

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
	return &filesmgr{
		logger:  logger.With("subsystem", "filesmgr"),
		root:    root,
		store:   newStore(filepath.Join(root, "state.json")),
		fetcher: newFetcher(),
		bus:     newEventBusWithLogger(logger),
	}
}

func (m *filesmgr) Start(_ context.Context) error {
	if err := os.MkdirAll(m.root, 0o755); err != nil {
		return err
	}
	return m.store.load()
}

func (m *filesmgr) Stop(_ context.Context) error {
	return nil
}

func (m *filesmgr) Get(name string) (FileEntry, bool) {
	return m.store.get(name)
}

func (m *filesmgr) Subscribe(handler func(FileEvent)) (unsubscribe func()) {
	return m.bus.subscribe(handler)
}

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

	dst := m.placementPath(spec)
	if err := m.fetcher.fetch(ctx, spec, dst); err != nil {
		return "", err
	}

	entry := FileEntry{
		Name:        spec.Name,
		Version:     spec.Version,
		Path:        dst,
		SHA256:      spec.SHA256,
		Source:      spec.URL,
		InstalledAt: time.Now().UTC(),
	}
	if err := m.store.put(entry); err != nil {
		return "", err
	}

	if hasExisting {
		prev := existing
		m.bus.publish(FileEvent{Type: EventUpgraded, Entry: entry, Previous: &prev})
	} else {
		m.bus.publish(FileEvent{Type: EventInstalled, Entry: entry})
	}
	return dst, nil
}

func (m *filesmgr) Remove(_ context.Context, name string) error {
	mu := m.mutexFor(name)
	mu.Lock()
	defer mu.Unlock()

	entry, ok := m.store.get(name)
	if !ok {
		return nil
	}
	if err := os.RemoveAll(entry.Path); err != nil {
		return fmt.Errorf("remove %s: %w", entry.Path, err)
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
	if spec.TargetPath != "" {
		return spec.TargetPath
	}
	if spec.Version != "" {
		return filepath.Join(m.root, spec.Name, spec.Version)
	}
	return filepath.Join(m.root, spec.Name)
}
