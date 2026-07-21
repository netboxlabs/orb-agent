// Package filesmgr provides a subsystem for downloading, verifying, and
// tracking files on disk at runtime. Files include backend binaries and
// runtime-installable plugin bundles.
package filesmgr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileSpec describes a file the manager should ensure is present on disk.
type FileSpec struct {
	// Name is a logical key, unique within the manager.
	// Examples: "custom_worker_backend", "orb-worker".
	Name string

	// Version is optional. If set, the file is placed under <root>/<name>/<version>/.
	Version string

	// URL is any URL go-getter accepts (HTTP, S3, git, ...).
	URL string

	// SHA256 of the fetched archive or single-file payload. Required. Lowercase hex.
	SHA256 string

	// Extract indicates whether URL points to an archive that should be
	// extracted (true) or a single file that should be placed as-is (false).
	Extract bool

	// TargetPath optionally overrides the default placement path.
	// Not yet supported; Validate() rejects any non-empty value.
	TargetPath string

	// Mode optionally sets the file permission bits for single-file downloads
	// (Extract == false). Zero means default (0o644 — readable data file).
	// Callers that need an executable should set 0o755 explicitly.
	// Ignored when Extract == true (archive extractor preserves per-entry modes).
	Mode os.FileMode
}

// isSafePathSegment returns an error if s is not a safe single-path segment.
// A safe segment: non-empty, not absolute, contains no path separators, does
// not equal ".." or ".", and is unchanged by filepath.Clean.
func isSafePathSegment(s, field string) error {
	if s == "" {
		return errors.New(field + " must not be empty")
	}
	if filepath.IsAbs(s) {
		return errors.New(field + " must not be an absolute path")
	}
	if strings.ContainsAny(s, "/\\") {
		return errors.New(field + " must not contain path separators")
	}
	if s == ".." || s == "." {
		return errors.New(field + " must not be '.' or '..'")
	}
	if filepath.Clean(s) != s {
		return errors.New(field + " is not a clean single path segment")
	}
	return nil
}

// reservedNamePrefix is the prefix FilesManager uses internally for its own
// on-disk artifacts (.filesmgr-stage-*, .filesmgr-backup-*, etc.). Names AND
// versions with this prefix are rejected so that legitimate tracked entries
// can never collide with stage/backup cleanup logic — a versioned install
// landing at <root>/<name>/.filesmgr-stage-foo would be deleted by
// cleanVersionedOrphans on the next Start.
const reservedNamePrefix = ".filesmgr-"

// Validate returns an error if required fields are missing or unsafe.
func (s FileSpec) Validate() error {
	if strings.HasPrefix(s.Name, reservedNamePrefix) {
		return errors.New("name must not use the reserved \"" + reservedNamePrefix + "\" prefix")
	}
	if err := isSafePathSegment(s.Name, "name"); err != nil {
		return err
	}
	if s.URL == "" {
		return errors.New("url is required")
	}
	if s.SHA256 == "" {
		return errors.New("sha256 is required")
	}
	if s.Version != "" {
		if strings.HasPrefix(s.Version, reservedNamePrefix) {
			return errors.New("version must not use the reserved \"" + reservedNamePrefix + "\" prefix")
		}
		if err := isSafePathSegment(s.Version, "version"); err != nil {
			return err
		}
	}
	if s.TargetPath != "" {
		return errors.New("TargetPath not supported in v1")
	}
	return nil
}

// FileEntryState values describe where a name is in its install lifecycle,
// mirroring the State+Error pattern policies.PolicyData already uses
// (State + BackendErr). FileEntry itself only ever carries
// FileEntryStateInstalled implicitly for entries returned by Manager.List
// (the persisted, successfully-installed set) — State/Error/UpdatedAt below
// are populated only on the transient entries Manager.ListPending returns.
const (
	// FileEntryStateInstalling marks a name whose Ensure call is currently
	// in flight (set at the start of Ensure, before fetch/verify begins).
	FileEntryStateInstalling = "installing"
	// FileEntryStateInstalled marks a name with a successful, persisted
	// install. Entries from Manager.List are always in this state, though
	// FileEntry.State is left unset on them (see doc above) — this constant
	// exists for callers that want to compare against ListPending entries
	// uniformly.
	FileEntryStateInstalled = "installed"
	// FileEntryStateFailed marks a name whose most recent Ensure attempt
	// failed (checksum mismatch, install timeout, or download/extract
	// error).
	FileEntryStateFailed = "failed"
)

// FileEntry is the recorded state for one logical name.
//
// Manager.List returns only successfully-installed entries persisted to
// state.json; on those, State/Error/UpdatedAt are always zero and only
// Name/Version/Path/SHA256/Source/InstalledAt are meaningful.
//
// Manager.ListPending returns a second, in-memory-only view of names whose
// most recent Ensure call is either still in flight (State ==
// FileEntryStateInstalling) or failed (State == FileEntryStateFailed, Error
// populated). This is intentionally NOT persisted to state.json: neither an
// in-flight nor a failed attempt has an on-disk artifact worth surviving a
// restart, and every restart/reconnect already triggers a fresh install
// attempt anyway (see FleetFilesManager.SendBundleListRequest). A name is
// cleared from the pending view as soon as a subsequent Ensure call for it
// succeeds.
type FileEntry struct {
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	Path        string    `json:"path"`
	SHA256      string    `json:"sha256"`
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`

	// State, Error, Timeout, and UpdatedAt below are populated only on
	// entries returned by Manager.ListPending (installing/failed); they are
	// always zero on entries returned by Manager.List.
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
	// Timeout is true when a failed attempt's context deadline was exceeded
	// (the 10-minute install timeout), as opposed to a checksum mismatch or
	// download/extract error.
	Timeout   bool      `json:"timeout,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// FileEventType is the kind of state transition.
type FileEventType int

const (
	// EventInstalled fires the first time a logical name is recorded.
	EventInstalled FileEventType = iota
	// EventUpgraded fires when a known name is re-ensured with a different
	// version or sha256.
	EventUpgraded
	// EventRemoved fires when a name is explicitly removed.
	EventRemoved
	// EventRolledBack fires after a successful Rollback. Entry is the now-live
	// (previous) entry; Previous is the entry that was rolled back FROM (the
	// one that was active until Rollback was called).
	EventRolledBack
)

// FileEvent is delivered to subscribers on state changes.
type FileEvent struct {
	Type     FileEventType
	Entry    FileEntry
	Previous *FileEntry
}
