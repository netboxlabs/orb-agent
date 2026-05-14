package filesmgr

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveTarGz(_ *testing.T, archive []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	}))
}

func newTestManager(t *testing.T) (Manager, string) {
	root := t.TempDir()
	m := NewManager(slog.Default(), root)
	require.NoError(t, m.Start(context.Background()))
	return m, root
}

func TestManager_EnsureInstallsAndEmitsEvent(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "alpha"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, root := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	path, err := m.Ensure(context.Background(), FileSpec{
		Name:    "pkg",
		Version: "1.0.0",
		URL:     srv.URL + "/x.tar.gz",
		SHA256:  sum,
		Extract: true,
	})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "pkg", "1.0.0"), path)

	content, err := os.ReadFile(filepath.Join(path, "a.txt"))
	require.NoError(t, err)
	assert.Equal(t, "alpha", string(content))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1)
	assert.Equal(t, EventInstalled, events[0].Type)
	assert.Equal(t, "pkg", events[0].Entry.Name)
}

func TestManager_EnsureIsIdempotent(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "alpha"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, _ := newTestManager(t)

	var calls int
	var mu sync.Mutex
	m.Subscribe(func(_ FileEvent) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	spec := FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/x.tar.gz", SHA256: sum, Extract: true,
	}

	_, err := m.Ensure(context.Background(), spec)
	require.NoError(t, err)
	_, err = m.Ensure(context.Background(), spec)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, calls, "idempotent Ensure must not publish a second event")
}

func TestManager_UpgradeEmitsUpgradedWithPrevious(t *testing.T) {
	v1 := buildTarGz(t, map[string]string{"a.txt": "v1"})
	v2 := buildTarGz(t, map[string]string{"a.txt": "v2"})
	sum1, sum2 := sha256Hex(v1), sha256Hex(v2)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(v1)
	})
	mux.HandleFunc("/v2.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(v2)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m, _ := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "1.0.0",
		URL: srv.URL + "/v1.tar.gz", SHA256: sum1, Extract: true,
	})
	require.NoError(t, err)

	_, err = m.Ensure(context.Background(), FileSpec{
		Name: "pkg", Version: "2.0.0",
		URL: srv.URL + "/v2.tar.gz", SHA256: sum2, Extract: true,
	})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	assert.Equal(t, EventInstalled, events[0].Type)
	assert.Equal(t, EventUpgraded, events[1].Type)
	require.NotNil(t, events[1].Previous)
	assert.Equal(t, "1.0.0", events[1].Previous.Version)
	assert.Equal(t, "2.0.0", events[1].Entry.Version)
}

func TestManager_RemoveEmitsRemoved(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"a.txt": "v1"})
	sum := sha256Hex(archive)
	srv := serveTarGz(t, archive)
	defer srv.Close()

	m, _ := newTestManager(t)

	var events []FileEvent
	var mu sync.Mutex
	m.Subscribe(func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	_, err := m.Ensure(context.Background(), FileSpec{
		Name: "pkg", URL: srv.URL + "/x.tar.gz", SHA256: sum, Extract: true,
	})
	require.NoError(t, err)
	require.NoError(t, m.Remove(context.Background(), "pkg"))

	_, ok := m.Get("pkg")
	assert.False(t, ok)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 2)
	assert.Equal(t, EventRemoved, events[1].Type)
}
