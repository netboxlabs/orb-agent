package filesmgr

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-getter"
)

// fetcher downloads, verifies, and atomically places a file (or extracted
// directory) at a destination path.
type fetcher struct {
	logger *slog.Logger
}

func newFetcher(logger *slog.Logger) *fetcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &fetcher{logger: logger}
}

// allowedSchemes is the set of URL schemes that FilesManager accepts.
// file://, git://, s3://, gcs:// etc. are blocked to prevent SSRF and
// local-file escapes from untrusted fleet-supplied URLs.
var allowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// httpGetters is the explicit getter map used when constructing go-getter
// clients. Defense-in-depth: even if the scheme check above is bypassed,
// go-getter will not find a registered getter for unlisted schemes.
var httpGetters = map[string]getter.Getter{
	"http":  new(getter.HttpGetter),
	"https": new(getter.HttpGetter),
}

// knownArchiveSuffixes lists the archive extensions go-getter recognizes from a
// URL path, longest-first so multi-part suffixes (e.g. "tar.gz") are matched
// before their single-part tails (e.g. "gz"). Keep this in sync with the
// github.com/hashicorp/go-getter version in go.mod.
var knownArchiveSuffixes = []string{
	"tar.bz2", "tar.gz", "tar.xz",
	"tbz2", "tgz", "txz",
	"tar", "zip",
}

// hasKnownArchiveSuffix reports whether urlPath ends in an archive extension
// go-getter can detect on its own (so we should not override its choice).
func hasKnownArchiveSuffix(urlPath string) bool {
	lower := strings.ToLower(urlPath)
	for _, s := range knownArchiveSuffixes {
		if strings.HasSuffix(lower, "."+s) {
			return true
		}
	}
	return false
}

// filenameFromURL extracts the last non-empty path segment from rawURL,
// stripping any query string. Returns an error if no usable filename can
// be derived.
func filenameFromURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	// Strip query string and use only the URL path portion.
	base := path.Base(u.Path)
	// Reject any base that isn't a safe single-segment filename: empty,
	// "/", ".", "..", or anything containing path separators. Without
	// this, a URL like https://example.com/a/.. would yield a base of
	// ".." which, when joined with the staging/destination path, escapes
	// the managed root — a path-traversal write primitive driven by
	// untrusted URL input.
	if err := isSafePathSegment(base, "filename"); err != nil {
		return "", fmt.Errorf("cannot derive safe filename from URL %q: %w", rawURL, err)
	}
	return base, nil
}

// renameSwap atomically replaces dst with src using a swap-via-backup pattern.
// If dst does not exist, it falls back to a simple os.Rename(src, dst).
// If dst exists, the sequence is:
//  1. Create a unique backup parent directory via os.MkdirTemp (atomic; no
//     Remove-then-Rename race because the parent dir is the reservation).
//  2. Rename dst → <backupParent>/dst (atomic on POSIX; same-fs).
//  3. Rename src → dst (atomic on POSIX).
//  4. RemoveAll the backup parent (best-effort; failures are logged).
//
// Using a backup parent directory (rather than renaming dst directly to a
// unique path) eliminates the TOCTOU window that existed when MkdirTemp was
// followed by os.Remove: between Remove and Rename another process could
// create a file at the same path, causing the rename to fail. By keeping the
// MkdirTemp-created directory and moving dst into it as a child, the rename
// target is a path inside a directory that only we own — no race possible.
//
// If step 3 fails, renameSwap attempts to restore the original by renaming
// <backupParent>/dst back to dst. Works for both files and directories;
// avoids the ENOTEMPTY/EEXIST error that os.Rename returns when overwriting a
// non-empty directory on Linux.
func (f *fetcher) renameSwap(src, dst string) error {
	if _, err := os.Lstat(dst); os.IsNotExist(err) {
		// Simple case: dst does not exist yet.
		return os.Rename(src, dst)
	}

	// dst exists — use backup-parent-swap pattern to avoid TOCTOU.
	// MkdirTemp creates a uniquely-named empty directory inside filepath.Dir(dst)
	// on the same filesystem, ensuring the subsequent rename is same-fs atomic.
	// We never remove this directory before using it — dst is moved inside it as
	// a child, so the backup path is always under a directory that only we own.
	backupParent, err := os.MkdirTemp(filepath.Dir(dst), ".filesmgr-backup-*")
	if err != nil {
		return fmt.Errorf("create backup parent: %w", err)
	}
	backupChild := filepath.Join(backupParent, "dst")

	// Move existing dst into the backup parent.
	if err := os.Rename(dst, backupChild); err != nil {
		_ = os.RemoveAll(backupParent)
		return fmt.Errorf("backup existing dst: %w", err)
	}

	// Move new content into place.
	if err := os.Rename(src, dst); err != nil {
		// Best-effort restore: put the original back.
		_ = os.Rename(backupChild, dst)
		_ = os.RemoveAll(backupParent)
		return fmt.Errorf("place new content: %w", err)
	}

	// Clean up the backup parent (and the saved dst inside it).
	// Best-effort: log on failure but don't fail the call.
	if rmErr := os.RemoveAll(backupParent); rmErr != nil {
		f.logger.Warn("filesmgr: failed to remove backup parent after successful swap",
			"path", backupParent, "error", rmErr)
	}
	return nil
}

// fetch downloads spec.URL into dst. If spec.Extract is true, dst is a
// directory containing the extracted archive contents; otherwise dst is a
// directory and the file is placed at dst/<filename>. The download is
// verified against spec.SHA256. Placement is atomic: download is staged in
// a sibling temp path and renamed into place on success. On failure, the
// staging path is removed and dst is left untouched.
//
// For Extract==false the file is placed at <dst>/<filename> and made
// executable (0o755). <dst> itself is the version directory.
func (f *fetcher) fetch(ctx context.Context, spec FileSpec, dst string) error {
	if err := spec.Validate(); err != nil {
		return err
	}

	// Parse and validate the URL scheme before doing anything on disk.
	u, err := url.Parse(spec.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if !allowedSchemes[scheme] {
		return fmt.Errorf("URL scheme %q is not allowed; only http and https are permitted", scheme)
	}

	// Stage in a sibling temp path so the rename is atomic on the same fs.
	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".filesmgr-stage-*")
	if err != nil {
		return err
	}

	// Always clean the stage on exit. If we successfully rename it into
	// place we replace `tmp` with "" so cleanup is a no-op.
	defer func() {
		if tmp != "" {
			_ = os.RemoveAll(tmp)
		}
	}()

	// Build the go-getter URL with the checksum query so go-getter verifies it.
	q := u.Query()
	q.Set("checksum", "sha256:"+spec.SHA256)
	// When extracting, ensure go-getter knows the archive format. It infers the
	// decompressor from the source URL's path suffix (or an explicit ?archive=),
	// decided BEFORE following any redirect. A control-plane URL (e.g.
	// /bundles/<name>/<version>) is extension-less and 302-redirects to the real
	// object, so go-getter never sees the archive suffix; without a hint it
	// treats the request as a plain directory download and rejects the checksum
	// ("checksum cannot be specified for directory download").
	//
	// Only supply a default when the format is otherwise undetermined: if the
	// caller already passed ?archive= or the URL path carries a recognized
	// archive suffix (.zip, .tar.xz, ...), respect that so non-tar.gz archives
	// keep working. The default (tar.gz) covers the extension-less bundle case.

	urlPathForSuffixCheck := u.Path
	if idx := strings.Index(urlPathForSuffixCheck, "//"); idx >= 0 {
		urlPathForSuffixCheck = urlPathForSuffixCheck[:idx]
	}
	if spec.Extract && q.Get("archive") == "" && !hasKnownArchiveSuffix(urlPathForSuffixCheck) {
		q.Set("archive", "tar.gz")
	}
	u.RawQuery = q.Encode()

	var stagePath string
	var mode getter.ClientMode

	if spec.Extract {
		mode = getter.ClientModeDir
		stagePath = filepath.Join(tmp, "extracted")
	} else {
		// Single-file mode: stage the file by its URL-derived filename.
		filename, err := filenameFromURL(spec.URL)
		if err != nil {
			return err
		}
		mode = getter.ClientModeFile
		stagePath = filepath.Join(tmp, filename)
	}

	client := &getter.Client{
		Ctx:     ctx,
		Src:     u.String(),
		Dst:     stagePath,
		Mode:    mode,
		Getters: httpGetters,
		// DisableSymlinks blocks tar entries that are symbolic links from being
		// honored during extraction. Without this a crafted archive can include
		// a symlink entry pointing outside the extraction target (e.g. "/etc")
		// and subsequent regular-file entries that write through it, escaping
		// the staging directory. Since FileSpec.URL can come from runtime
		// (untrusted) configuration, this is a real filesystem-escape vector
		// rather than a theoretical hardening concern.
		DisableSymlinks: true,
	}
	if err := client.Get(); err != nil {
		return fmt.Errorf("fetch %s: %w", spec.Name, err)
	}

	if spec.Extract {
		// Atomic rename of the extracted directory into dst.
		// If dst already exists (re-ensure with different content), use a
		// swap-via-backup pattern: move the existing dst out of the way first,
		// rename the new content in, then remove the backup. This handles the
		// case where dst is an existing directory (os.Rename(dir→dir) fails on
		// Linux) and provides a restore path if the second rename fails.
		if err := f.renameSwap(stagePath, dst); err != nil {
			return fmt.Errorf("place %s: %w", dst, err)
		}
	} else {
		// For single-file mode: create the version directory, then move the
		// staged file into it. The version directory (dst) must not exist yet.
		filename := filepath.Base(stagePath)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return fmt.Errorf("create version dir %s: %w", dst, err)
		}
		// Apply file permissions to the staged file BEFORE renaming into place
		// so that if chmod fails the file never lands at its final location with
		// wrong permissions (chmod-before-rename for atomicity).
		mode := spec.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := os.Chmod(stagePath, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", stagePath, err)
		}
		finalPath := filepath.Join(dst, filename)
		if err := f.renameSwap(stagePath, finalPath); err != nil {
			return fmt.Errorf("place %s: %w", finalPath, err)
		}
	}

	// Leave `tmp` set so the deferred RemoveAll(tmp) runs and removes the
	// now-empty staging parent directory. (The stagePath was renamed OUT
	// of tmp into dst; the parent dir itself still exists and would leak
	// as a `.filesmgr-stage-*` directory per successful Ensure otherwise.)
	return nil
}
