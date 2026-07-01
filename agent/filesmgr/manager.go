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
	//
	// NOTE: the per-name mutex is held for the entire fetch + state-update +
	// symlink-swap sequence, including network I/O. Concurrent operations on
	// the same logical name (another Ensure, Remove, or Rollback) block for the
	// duration of an in-flight fetch. For the current v1 consumer set (a small
	// number of backend binaries) this serialization is acceptable; high-churn
	// callers should expect Ensure to be slow under contention. Future
	// refactor could stage the fetch outside the lock and acquire it only for
	// the commit phase.
	//
	// TAMPER-DETECTION ASYMMETRY: on the idempotent fast path (spec already
	// installed and matching), Ensure re-hashes the on-disk file for single-
	// file specs (Extract == false) and falls through to re-fetch on mismatch.
	// For extracted bundles (Extract == true) the on-disk tree is trusted as
	// long as the version directory exists — the recorded SHA256 is of the
	// archive (which we don't keep on disk), so re-hashing the extracted tree
	// can't cheaply prove integrity against the spec. Operators modifying
	// files inside an extracted bundle will not trigger a re-fetch; either
	// remove the entry to force a fresh fetch, or use single-file delivery
	// for assets that must be tamper-checked on every Ensure.
	Ensure(ctx context.Context, spec FileSpec) (path string, err error)

	// Get returns the current entry for a logical name, if installed.
	Get(name string) (FileEntry, bool)

	// List returns a snapshot of all currently installed entries. The slice is
	// a fresh copy; mutating it does not affect manager state, and order is
	// unspecified. Results are keyed by FileEntry.Name.
	List() []FileEntry

	// Remove deletes a tracked file and its on-disk version directory.
	// Idempotent.
	Remove(ctx context.Context, name string) error

	// Rollback restores the previous version of a tracked file. It atomically
	// swaps the `current` symlink back to the previous version's location and
	// updates state.json so the previous entry becomes current (and previous
	// is cleared). Emits EventRolledBack on success.
	//
	// Returns an error if name has no previous version recorded (e.g., it's
	// a first install) or if the previous version's directory no longer
	// exists on disk.
	//
	// SPECIAL CASE — first-install rollback: if there is no Previous version
	// recorded, Rollback removes the entry entirely (the agent's "rollback to
	// default" semantic, so consumers fall back to their baked binary). This
	// emits EventRemoved.
	//
	// Manual callers should be aware that EventRemoved is ignored by the
	// agent's file-event-to-restart bridge (to avoid restart loops in the
	// auto-rollback flow which already handles restart synchronously). If you
	// are calling Rollback from outside the auto-rollback flow and the affected
	// name corresponds to a ManagedBinary backend, you are responsible for
	// triggering that backend's restart yourself.
	Rollback(ctx context.Context, name string) error

	// Subscribe registers a handler invoked on every FileEvent. The
	// returned function removes the subscription. Handlers run synchronously
	// from the goroutine that mutated state; handlers must not block.
	Subscribe(handler func(FileEvent)) (unsubscribe func())
}
