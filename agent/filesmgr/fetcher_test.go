package filesmgr

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTarGz produces an in-memory .tar.gz containing files named in `entries`
// with the provided content.
func buildTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestFetcher_FetchAndExtractArchive(t *testing.T) {
	archive := buildTarGz(t, map[string]string{
		"hello.txt": "hi",
	})
	sum := sha256Hex(archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "extracted")

	f := newFetcher(nil)
	err := f.fetch(context.Background(), FileSpec{
		Name:    "x",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  sum,
		Extract: true,
	}, dst)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(dst, "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hi", string(got))
}

func TestFetcher_SHA256Mismatch(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "extracted")

	f := newFetcher(nil)
	err := f.fetch(context.Background(), FileSpec{
		Name:    "x",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  "deadbeef",
		Extract: true,
	}, dst)
	require.Error(t, err)
	assert.NoDirExists(t, dst, "destination should be clean on failure")
}

func TestFetcher_RejectsFileScheme(t *testing.T) {
	f := newFetcher(nil)
	err := f.fetch(context.Background(), FileSpec{
		Name:   "x",
		URL:    "file:///etc/passwd",
		SHA256: "abc",
	}, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file", "error should mention the rejected scheme")
	assert.Contains(t, err.Error(), "not allowed")
}

func TestFilenameFromURL_RejectsTraversal(t *testing.T) {
	traversalURLs := []string{
		"https://example.com/a/..",      // path.Base yields ".."
		"https://example.com/..",        // path.Base yields ".."
		"https://example.com/a/../b/..", // path.Base yields ".."
	}
	for _, u := range traversalURLs {
		_, err := filenameFromURL(u)
		require.Error(t, err, "URL %q must be rejected", u)
		assert.Contains(t, err.Error(), "cannot derive safe filename",
			"URL %q error must mention safe-filename rejection", u)
	}
}

func TestFetcher_PlacesSingleFile(t *testing.T) {
	// Serve a small blob (non-archive); no Mode set → default 0o644.
	blob := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03}
	sum := sha256Hex(blob)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "1.0.0")

	f := newFetcher(nil)
	err := f.fetch(context.Background(), FileSpec{
		Name:    "orb-worker",
		URL:     srv.URL + "/orb-worker",
		SHA256:  sum,
		Extract: false,
		// Mode intentionally omitted → should default to 0o644.
	}, dst)
	require.NoError(t, err)

	// File must land at <dst>/orb-worker (the URL's last segment).
	placedPath := filepath.Join(dst, "orb-worker")
	require.FileExists(t, placedPath)

	got, err := os.ReadFile(placedPath)
	require.NoError(t, err)
	assert.Equal(t, blob, got)

	// Default mode must be 0o644 (data file, not executable).
	fi, err := os.Stat(placedPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "single-file default mode must be 0o644")
}

func TestFetcher_PlacesSingleFile_ExecutableMode(t *testing.T) {
	// Same fetch but with Mode: 0o755 → file must be executable.
	blob := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	sum := sha256Hex(blob)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "1.0.0")

	f := newFetcher(nil)
	err := f.fetch(context.Background(), FileSpec{
		Name:    "orb-worker",
		URL:     srv.URL + "/orb-worker",
		SHA256:  sum,
		Extract: false,
		Mode:    0o755,
	}, dst)
	require.NoError(t, err)

	placedPath := filepath.Join(dst, "orb-worker")
	require.FileExists(t, placedPath)

	fi, err := os.Stat(placedPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "Mode: 0o755 must produce an executable file")
}

// TestFetcher_ReEnsureExtractedReplacesExistingDst verifies that fetching an
// Extract=true spec into a dst that already exists as a directory succeeds —
// the renameSwap helper replaces the existing content atomically.
func TestFetcher_ReEnsureExtractedReplacesExistingDst(t *testing.T) {
	// First archive: contains v1.txt.
	archive1 := buildTarGz(t, map[string]string{"v1.txt": "first"})
	sum1 := sha256Hex(archive1)

	// Second archive: contains v2.txt (different content, different SHA).
	archive2 := buildTarGz(t, map[string]string{"v2.txt": "second"})
	sum2 := sha256Hex(archive2)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive1)
	})
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive2)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "pkg")

	f := newFetcher(nil)

	// First fetch — dst does not yet exist.
	err := f.fetch(context.Background(), FileSpec{
		Name:    "pkg",
		URL:     srv.URL + "/v1.tar.gz",
		SHA256:  sum1,
		Extract: true,
	}, dst)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(dst, "v1.txt"), "v1.txt must be present after first fetch")

	// Place a marker file inside the extracted dir to confirm it is replaced.
	markerPath := filepath.Join(dst, "marker.txt")
	require.NoError(t, os.WriteFile(markerPath, []byte("marker"), 0o644))

	// Second fetch — dst already exists as a directory.
	err = f.fetch(context.Background(), FileSpec{
		Name:    "pkg",
		URL:     srv.URL + "/v2.tar.gz",
		SHA256:  sum2,
		Extract: true,
	}, dst)
	require.NoError(t, err, "re-fetch into existing dst must succeed")

	// New archive's content must be present.
	assert.FileExists(t, filepath.Join(dst, "v2.txt"), "v2.txt must be present after second fetch")

	// Old content (v1.txt) and the marker must be gone — dst was replaced.
	assert.NoFileExists(t, filepath.Join(dst, "v1.txt"), "v1.txt must be gone after replacement")
	assert.NoFileExists(t, markerPath, "marker must be gone after dst replacement")
}

// TestFetcher_FollowsRedirectAndExtracts verifies that when the bundle URL is
// an extension-less control-plane path that 302-redirects to the actual archive
// (e.g. a presigned storage URL), the fetcher still extracts the archive and
// verifies its checksum. go-getter selects its decompressor from the SOURCE URL
// path (or an explicit ?archive= hint) BEFORE the request, so it never sees the
// redirect target's .tar.gz suffix — the fetcher must supply the archive hint
// from FileSpec.Extract.
func TestFetcher_FollowsRedirectAndExtracts(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
	sum := sha256Hex(archive)

	mux := http.NewServeMux()
	// Extension-less path, like the control-plane bundle endpoint.
	mux.HandleFunc("/bundles/test-bundle/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/blob", http.StatusFound)
	})
	mux.HandleFunc("/blob", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "v1")
	f := newFetcher(nil)
	err := f.fetch(context.Background(), FileSpec{
		Name:    "test-bundle",
		URL:     srv.URL + "/bundles/test-bundle/1.0.0",
		SHA256:  sum,
		Extract: true,
	}, dst)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(dst, "hello.txt"))
	require.NoError(t, err)
	require.Equal(t, "hi", string(got))
}

func TestHasKnownArchiveSuffix(t *testing.T) {
	cases := map[string]bool{
		"/path/to/bundle.tar.gz":     true,
		"/path/to/bundle.tgz":        true,
		"/path/to/bundle.zip":        true,
		"/path/to/bundle.tar.xz":     true,
		"/path/to/bundle.tar":        true,
		"/path/to/bundle.gz":         true,
		"/BUNDLE.TAR.GZ":             true,  // case-insensitive
		"/bundles/test-bundle/1.0.0": false, // extension-less control-plane path
		"/bundles/name/2.12.0":       false,
		"/download":                  false,
		"":                           false,
	}
	for path, want := range cases {
		if got := hasKnownArchiveSuffix(path); got != want {
			t.Errorf("hasKnownArchiveSuffix(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestFetcher_ZipURLNotForcedToTarGz guards the Codex review concern: a URL that
// already names a non-tar.gz archive must keep its format. We assert the guard
// logic (hasKnownArchiveSuffix) recognizes .zip so fetch() will NOT inject
// ?archive=tar.gz over it; go-getter's own .zip decompressor then handles it.
func TestFetcher_ZipURLNotForcedToTarGz(t *testing.T) {
	if !hasKnownArchiveSuffix("/some/object.zip") {
		t.Fatal(".zip must be recognized so the tar.gz default is not forced over it")
	}
	if hasKnownArchiveSuffix("/bundles/x/1.0.0") {
		t.Fatal("extension-less path must NOT be treated as a known archive (default applies)")
	}
}
