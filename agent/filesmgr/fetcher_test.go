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
