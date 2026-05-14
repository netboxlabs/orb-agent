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

// Validate returns an error if required fields are missing or unsafe.
func (s FileSpec) Validate() error {
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
		if err := isSafePathSegment(s.Version, "version"); err != nil {
			return err
		}
	}
	if s.TargetPath != "" {
		return errors.New("TargetPath not supported in v1")
	}
	return nil
}

// FileEntry is the recorded state for one logical name.
type FileEntry struct {
	Name        string    `json:"name"`
	Version     string    `json:"version,omitempty"`
	Path        string    `json:"path"`
	SHA256      string    `json:"sha256"`
	Source      string    `json:"source"`
	InstalledAt time.Time `json:"installed_at"`
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
