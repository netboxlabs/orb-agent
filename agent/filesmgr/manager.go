package filesmgr

import "context"

// Manager downloads, verifies, and tracks files on disk at runtime.
// Implementations must be safe for concurrent use.
type Manager interface {
	// Start prepares the manager. Loads state.json if present and
	// reconciles in-memory state against the filesystem.
	Start(ctx context.Context) error

	// Stop shuts down the manager cleanly.
	Stop(ctx context.Context) error

	// Ensure makes sure the file described by spec is present on disk and
	// matches the declared sha256. If the file is already present and
	// matches the spec, returns the existing path with no fetch or event.
	// If absent or different, fetches via go-getter, verifies, and places
	// atomically. Synchronous; callers wrap in a goroutine for async use.
	Ensure(ctx context.Context, spec FileSpec) (path string, err error)

	// Get returns the current entry for a logical name, if installed.
	Get(name string) (FileEntry, bool)

	// Remove deletes a tracked file and its on-disk version directory.
	// Idempotent.
	Remove(ctx context.Context, name string) error

	// Subscribe registers a handler invoked on every FileEvent. The
	// returned function removes the subscription. Handlers run synchronously
	// from the goroutine that mutated state; handlers must not block.
	Subscribe(handler func(FileEvent)) (unsubscribe func())
}
