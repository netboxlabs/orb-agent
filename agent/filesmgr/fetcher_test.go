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

	f := newFetcher()
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

	f := newFetcher()
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
	f := newFetcher()
	err := f.fetch(context.Background(), FileSpec{
		Name:   "x",
		URL:    "file:///etc/passwd",
		SHA256: "abc",
	}, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file", "error should mention the rejected scheme")
	assert.Contains(t, err.Error(), "not allowed")
}

func TestFetcher_PlacesSingleFile(t *testing.T) {
	// Serve a small binary blob (non-archive).
	blob := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03}
	sum := sha256Hex(blob)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "1.0.0")

	f := newFetcher()
	err := f.fetch(context.Background(), FileSpec{
		Name:    "orb-worker",
		URL:     srv.URL + "/orb-worker",
		SHA256:  sum,
		Extract: false,
	}, dst)
	require.NoError(t, err)

	// File must land at <dst>/orb-worker (the URL's last segment).
	placedPath := filepath.Join(dst, "orb-worker")
	require.FileExists(t, placedPath)

	got, err := os.ReadFile(placedPath)
	require.NoError(t, err)
	assert.Equal(t, blob, got)

	// Must be executable (0o755).
	fi, err := os.Stat(placedPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "single-file binary must be 0o755")
}
