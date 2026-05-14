// Package filesmgr provides a subsystem for downloading, verifying, and
// tracking files on disk at runtime. Files include backend binaries and
// runtime-installable plugin bundles.
package filesmgr

import (
	"errors"
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
	// When empty, the manager derives a path under its root.
	TargetPath string
}

// Validate returns an error if required fields are missing.
func (s FileSpec) Validate() error {
	if s.Name == "" {
		return errors.New("name is required")
	}
	if s.URL == "" {
		return errors.New("url is required")
	}
	if s.SHA256 == "" {
		return errors.New("sha256 is required")
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
)

// FileEvent is delivered to subscribers on state changes.
type FileEvent struct {
	Type     FileEventType
	Entry    FileEntry
	Previous *FileEntry
}
