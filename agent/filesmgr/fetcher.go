package filesmgr

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-getter"
)

// fetcher downloads, verifies, and atomically places a file (or extracted
// directory) at a destination path.
type fetcher struct{}

func newFetcher() *fetcher {
	return &fetcher{}
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
		if err := os.Rename(stagePath, dst); err != nil {
			return fmt.Errorf("place %s: %w", dst, err)
		}
	} else {
		// For single-file mode: create the version directory, then move the
		// staged file into it. The version directory (dst) must not exist yet.
		filename := filepath.Base(stagePath)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return fmt.Errorf("create version dir %s: %w", dst, err)
		}
		finalPath := filepath.Join(dst, filename)
		if err := os.Rename(stagePath, finalPath); err != nil {
			return fmt.Errorf("place %s: %w", finalPath, err)
		}
		// Apply file permissions. Default to 0o644 (data file); callers set
		// 0o755 explicitly for executables via FileSpec.Mode.
		mode := spec.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := os.Chmod(finalPath, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", finalPath, err)
		}
	}

	tmp = "" // cancel cleanup
	return nil
}
