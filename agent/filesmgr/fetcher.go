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
	if base == "" || base == "/" || base == "." {
		return "", fmt.Errorf("cannot derive filename from URL %q", rawURL)
	}
	return base, nil
}

// renameSwap atomically replaces dst with src using a swap-via-backup pattern.
// If dst does not exist, it falls back to a simple os.Rename(src, dst).
// If dst exists, the sequence is:
//  1. Get a unique backup path in the same directory as dst (same filesystem).
//  2. Rename dst → backup (atomic on POSIX; same-fs).
//  3. Rename src → dst (atomic on POSIX).
//  4. Remove the backup (best-effort; failures are logged via f.logger).
//
// If step 3 fails, renameSwap attempts to restore the original by renaming
// backup → dst. Works for both files and directories; avoids the
// ENOTEMPTY/EEXIST error that os.Rename returns when overwriting a non-empty
// directory on Linux.
func (f *fetcher) renameSwap(src, dst string) error {
	if _, err := os.Lstat(dst); os.IsNotExist(err) {
		// Simple case: dst does not exist yet.
		return os.Rename(src, dst)
	}

	// dst exists — use backup-swap pattern.
	// MkdirTemp creates an empty directory; remove it immediately so we have
	// a unique path name we can use as the backup rename target.
	backup, err := os.MkdirTemp(filepath.Dir(dst), ".filesmgr-backup-*")
	if err != nil {
		return fmt.Errorf("create backup path: %w", err)
	}
	// Remove the empty dir so rename can take that name.
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("clear backup placeholder: %w", err)
	}

	// Move existing dst out of the way.
	if err := os.Rename(dst, backup); err != nil {
		return fmt.Errorf("backup existing dst: %w", err)
	}

	// Move new content into place.
	if err := os.Rename(src, dst); err != nil {
		// Best-effort restore: put the original back.
		_ = os.Rename(backup, dst)
		return fmt.Errorf("place new content: %w", err)
	}

	// Clean up the backup. Best-effort: log on failure but don't fail the call.
	if rmErr := os.RemoveAll(backup); rmErr != nil {
		f.logger.Warn("filesmgr: failed to remove backup after successful swap",
			"backup", backup, "error", rmErr)
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
		if err := os.Rename(stagePath, finalPath); err != nil {
			return fmt.Errorf("place %s: %w", finalPath, err)
		}
	}

	tmp = "" // cancel cleanup
	return nil
}
