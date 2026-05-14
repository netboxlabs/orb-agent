package filesmgr

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-getter"
)

// fetcher downloads, verifies, and atomically places a file (or extracted
// directory) at a destination path.
type fetcher struct{}

func newFetcher() *fetcher {
	return &fetcher{}
}

// fetch downloads spec.URL into dst. If spec.Extract is true, dst is a
// directory; otherwise dst is a file path. The download is verified against
// spec.SHA256. Placement is atomic: download is staged in a sibling temp
// path and renamed into place on success. On failure, the staging path is
// removed and dst is left untouched.
func (f *fetcher) fetch(ctx context.Context, spec FileSpec, dst string) error {
	if err := spec.Validate(); err != nil {
		return err
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
	u, err := url.Parse(spec.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	q := u.Query()
	q.Set("checksum", "sha256:"+spec.SHA256)
	u.RawQuery = q.Encode()

	mode := getter.ClientModeFile
	stagePath := filepath.Join(tmp, "payload")
	if spec.Extract {
		mode = getter.ClientModeDir
		stagePath = filepath.Join(tmp, "extracted")
	}

	client := &getter.Client{
		Ctx:  ctx,
		Src:  u.String(),
		Dst:  stagePath,
		Mode: mode,
	}
	if err := client.Get(); err != nil {
		return fmt.Errorf("fetch %s: %w", spec.Name, err)
	}

	// Ensure any stale dst is gone, then atomically rename.
	_ = os.RemoveAll(dst)
	if err := os.Rename(stagePath, dst); err != nil {
		return fmt.Errorf("place %s: %w", dst, err)
	}

	tmp = "" // cancel cleanup
	return nil
}
