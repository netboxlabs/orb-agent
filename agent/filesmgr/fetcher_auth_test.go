package filesmgr

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildAuthTarGz returns a gzipped tar containing a single file, plus its sha256.
func buildAuthTarGz(t *testing.T) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := []byte("bundle-payload")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "plugin.txt",
		Mode: 0o644,
		Size: int64(len(content)),
	}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

// TestFetcher_SendsBearerToControlPlane_NotToRedirectTarget verifies that when a
// token source is configured, the fetcher sends Authorization: Bearer to the
// control-plane URL, and that the header is NOT forwarded to the redirect target
// (mirroring the stdlib's cross-host stripping that protects the S3 presigned URL).
func TestFetcher_SendsBearerToControlPlane_NotToRedirectTarget(t *testing.T) {
	archive, archiveSHA := buildAuthTarGz(t)

	// "S3" origin: serves the bytes, and records whether it ever saw an
	// Authorization header (it must not). Bind explicitly on tcp4 127.0.0.1 so
	// the cross-host redirect below is deterministic regardless of the host's
	// IPv4/IPv6 preference.
	var sawAuthAtTarget atomic.Bool
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuthAtTarget.Store(true)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	target.Listener = ln
	target.Start()
	defer target.Close()
	targetPort := target.Listener.Addr().(*net.TCPAddr).Port

	// "Control plane": requires the bearer, then 302-redirects to target.
	var sawAuthAtControlPlane atomic.Bool
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			sawAuthAtControlPlane.Store(true)
		} else {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Redirect to a DIFFERENT host so the test exercises the same cross-host
		// Authorization-stripping the Go stdlib applies in prod. The target binds
		// tcp4 127.0.0.1; redirecting to localhost:<port> reaches the same listener
		// but the stdlib treats the differing host as cross-host and strips the header.
		crossHostURL := fmt.Sprintf("http://localhost:%d", targetPort)
		http.Redirect(w, r, crossHostURL, http.StatusFound)
	}))
	defer control.Close()

	dst := filepath.Join(t.TempDir(), "v1")
	f := newFetcher(slog.Default())
	f.tokenSource = func(_ context.Context) (string, error) { return "test-token", nil }

	spec := FileSpec{
		Name:    "nbl_test",
		Version: "1.0.0",
		URL:     control.URL,
		SHA256:  archiveSHA,
		Extract: true,
	}
	require.NoError(t, f.fetch(context.Background(), spec, dst))

	require.True(t, sawAuthAtControlPlane.Load(), "control plane never received the bearer token")
	require.False(t, sawAuthAtTarget.Load(), "bearer token leaked to the redirect (S3) target")

	// Sanity: the extracted file landed.
	_, statErr := os.Stat(filepath.Join(dst, "plugin.txt"))
	require.NoError(t, statErr)
}

// TestFetcher_NoTokenSource_SendsNoAuth verifies the default path is unchanged:
// with no token source, no Authorization header is sent (presigned-URL behavior).
func TestFetcher_NoTokenSource_SendsNoAuth(t *testing.T) {
	archive, archiveSHA := buildAuthTarGz(t)

	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "v1")
	f := newFetcher(slog.Default()) // tokenSource nil

	spec := FileSpec{
		Name:    "nbl_test",
		Version: "1.0.0",
		URL:     srv.URL,
		SHA256:  archiveSHA,
		Extract: true,
	}
	require.NoError(t, f.fetch(context.Background(), spec, dst))
	require.False(t, sawAuth.Load(), "unexpected Authorization header on no-token path")
}

// TestFetcher_PresignedURL_NoBearerEvenWithTokenSource verifies the bearer is
// NOT attached to a direct presigned/capability URL even when a token source is
// configured — only the extension-less control-plane URL is authenticated. This
// guards against leaking the agent token to object storage and against
// invalidating SigV4-signed requests.
func TestFetcher_PresignedURL_NoBearerEvenWithTokenSource(t *testing.T) {
	archive, archiveSHA := buildAuthTarGz(t)

	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "v1")
	f := newFetcher(slog.Default())
	f.tokenSource = func(_ context.Context) (string, error) { return "test-token", nil }

	// Presigned-style: path ends in .tar.gz and carries a SigV4 signature param.
	spec := FileSpec{
		Name:    "nbl_test",
		Version: "1.0.0",
		URL:     srv.URL + "/nbl_test/1.0.0/bundle.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef",
		SHA256:  archiveSHA,
		Extract: true,
	}
	require.NoError(t, f.fetch(context.Background(), spec, dst))
	require.False(t, sawAuth.Load(), "bearer must not be sent to a presigned URL")
}
