package filesmgr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sleepRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (s *sleepRecorder) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delays = append(s.delays, d)
	return nil
}

func (s *sleepRecorder) recorded() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.delays...)
}

func newRetryTestFetcher() (*fetcher, *sleepRecorder) {
	rec := &sleepRecorder{}
	f := newFetcher(nil)
	f.retry = retryPolicy{
		maxAttempts: 4,
		baseDelay:   time.Millisecond,
		maxDelay:    4 * time.Millisecond,
		sleep:       rec.sleep,
	}
	return f, rec
}

// flakyBundleServer answers the first len(failures) GET requests with the given
// statuses (and an optional Retry-After), then serves payload. It returns the
// number of GET requests seen. go-getter probes with HEAD first; answering 405
// makes it fall back to a plain GET, and HEAD is not counted.
func flakyBundleServer(t *testing.T, payload []byte, failures []int, retryAfter string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		n := int(gets.Add(1))
		if n <= len(failures) {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(failures[n-1])
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv, &gets
}

func bundleSpec(srv *httptest.Server, sum string) FileSpec {
	// Extension-less path, like the control-plane bundle endpoint.
	return FileSpec{Name: "x", URL: srv.URL + "/bundles/x/1.0.0", SHA256: sum, Extract: true}
}

func repeatStatus(code, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = code
	}
	return out
}

func TestFetcher_RetriesTransientStatus(t *testing.T) {
	for _, code := range []int{
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
			srv, gets := flakyBundleServer(t, archive, []int{code}, "")
			f, sleeps := newRetryTestFetcher()
			dst := filepath.Join(t.TempDir(), "out")

			require.NoError(t, f.fetch(context.Background(), bundleSpec(srv, sha256Hex(archive)), dst))

			assert.EqualValues(t, 2, gets.Load())
			got := sleeps.recorded()
			require.Len(t, got, 1)
			assert.GreaterOrEqual(t, got[0], time.Millisecond/2)
			assert.LessOrEqual(t, got[0], time.Millisecond)

			content, err := os.ReadFile(filepath.Join(dst, "hello.txt"))
			require.NoError(t, err)
			assert.Equal(t, "hi", string(content))
		})
	}
}

func TestFetcher_HonorsRetryAfter(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
	srv, gets := flakyBundleServer(t, archive, repeatStatus(http.StatusServiceUnavailable, 2), "2")
	f, sleeps := newRetryTestFetcher()

	require.NoError(t, f.fetch(context.Background(), bundleSpec(srv, sha256Hex(archive)), filepath.Join(t.TempDir(), "out")))

	assert.EqualValues(t, 3, gets.Load())
	assert.Equal(t, []time.Duration{2 * time.Second, 2 * time.Second}, sleeps.recorded())
}

func TestFetcher_CapsRetryAfter(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
	srv, _ := flakyBundleServer(t, archive, []int{http.StatusTooManyRequests}, "3600")
	f, sleeps := newRetryTestFetcher()

	require.NoError(t, f.fetch(context.Background(), bundleSpec(srv, sha256Hex(archive)), filepath.Join(t.TempDir(), "out")))

	assert.Equal(t, []time.Duration{maxRetryAfter}, sleeps.recorded())
}

func TestFetcher_GivesUpAfterMaxAttempts(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
	srv, gets := flakyBundleServer(t, archive, repeatStatus(http.StatusServiceUnavailable, 10), "")
	f, sleeps := newRetryTestFetcher()
	f.retry.maxAttempts = 3
	dst := filepath.Join(t.TempDir(), "out")

	err := f.fetch(context.Background(), bundleSpec(srv, sha256Hex(archive)), dst)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad response code: 503")
	var se *httpStatusError
	require.True(t, errors.As(err, &se))
	assert.Equal(t, http.StatusServiceUnavailable, se.StatusCode)
	assert.EqualValues(t, 3, gets.Load())
	assert.Len(t, sleeps.recorded(), 2)
	assert.NoDirExists(t, dst, "destination must stay clean when every attempt fails")
}

func TestFetcher_DoesNotRetryOtherStatuses(t *testing.T) {
	for _, code := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
			srv, gets := flakyBundleServer(t, archive, repeatStatus(code, 5), "")
			f, sleeps := newRetryTestFetcher()

			err := f.fetch(context.Background(), bundleSpec(srv, sha256Hex(archive)), filepath.Join(t.TempDir(), "out"))

			require.Error(t, err)
			var se *httpStatusError
			require.True(t, errors.As(err, &se), "the status must be recoverable by callers")
			assert.Equal(t, code, se.StatusCode)
			assert.EqualValues(t, 1, gets.Load())
			assert.Empty(t, sleeps.recorded())
		})
	}
}

func TestFetcher_ChecksumMismatchIsNotRetried(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
	srv, gets := flakyBundleServer(t, archive, nil, "")
	f, sleeps := newRetryTestFetcher()

	err := f.fetch(context.Background(), bundleSpec(srv, "deadbeef"), filepath.Join(t.TempDir(), "out"))

	require.Error(t, err)
	var se *httpStatusError
	assert.False(t, errors.As(err, &se), "a checksum failure is not an HTTP status failure")
	assert.EqualValues(t, 1, gets.Load())
	assert.Empty(t, sleeps.recorded())
}

func TestFetcher_RetryAbortedWhenContextEnds(t *testing.T) {
	archive := buildTarGz(t, map[string]string{"hello.txt": "hi"})
	srv, gets := flakyBundleServer(t, archive, repeatStatus(http.StatusServiceUnavailable, 5), "")
	f, _ := newRetryTestFetcher()
	f.retry.sleep = func(context.Context, time.Duration) error { return context.Canceled }

	err := f.fetch(context.Background(), bundleSpec(srv, sha256Hex(archive)), filepath.Join(t.TempDir(), "out"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "retry aborted")
	var se *httpStatusError
	assert.True(t, errors.As(err, &se))
	assert.EqualValues(t, 1, gets.Load())
}

func TestFetcher_RetriesSingleFileDownload(t *testing.T) {
	blob := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	srv, gets := flakyBundleServer(t, blob, []int{http.StatusBadGateway}, "")
	f, _ := newRetryTestFetcher()
	dst := filepath.Join(t.TempDir(), "1.0.0")

	require.NoError(t, f.fetch(context.Background(), FileSpec{
		Name:   "orb-worker",
		URL:    srv.URL + "/orb-worker",
		SHA256: sha256Hex(blob),
	}, dst))

	got, err := os.ReadFile(filepath.Join(dst, "orb-worker"))
	require.NoError(t, err)
	assert.Equal(t, blob, got)
	assert.EqualValues(t, 2, gets.Load())
}

func TestRetryPolicy_Delay(t *testing.T) {
	p := retryPolicy{baseDelay: 2 * time.Second, maxDelay: 30 * time.Second}.withDefaults()

	within := func(attempt int, lo, hi time.Duration) {
		t.Helper()
		for i := 0; i < 200; i++ {
			d := p.delay(attempt, 0)
			require.GreaterOrEqual(t, d, lo)
			require.LessOrEqual(t, d, hi)
		}
	}
	within(1, time.Second, 2*time.Second)
	within(2, 2*time.Second, 4*time.Second)
	within(3, 4*time.Second, 8*time.Second)
	within(10, 15*time.Second, 30*time.Second)

	assert.Equal(t, 5*time.Second, p.delay(1, 5*time.Second))
	assert.Equal(t, maxRetryAfter, p.delay(1, 10*time.Minute))
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":            0,
		"garbage":     0,
		"0":           0,
		"-5":          0,
		"7":           7 * time.Second,
		" 7 ":         7 * time.Second,
		"99999999999": time.Hour,
		now.Add(30 * time.Second).Format(http.TimeFormat): 30 * time.Second,
		now.Add(-time.Minute).Format(http.TimeFormat):     0,
	}
	for in, want := range cases {
		assert.Equal(t, want, parseRetryAfter(in, now), "Retry-After %q", in)
	}
}

// The status comes from the transport, not from go-getter's error text, so a
// go-getter upgrade that rewords its error cannot break status detection.
func TestStatusRecorder_WrapUsesRecordedStatusNotErrorText(t *testing.T) {
	rec := newStatusRecorder()

	rec.mu.Lock()
	rec.status, rec.retryAfter = http.StatusForbidden, ""
	rec.mu.Unlock()
	err := rec.wrap(errors.New("some unrelated wording"))
	var se *httpStatusError
	require.True(t, errors.As(err, &se))
	assert.Equal(t, http.StatusForbidden, se.StatusCode)
	assert.Equal(t, "some unrelated wording", err.Error(), "message is passed through unchanged")

	rec.mu.Lock()
	rec.status = http.StatusOK
	rec.mu.Unlock()
	plain := errors.New("checksum did not match")
	assert.Same(t, plain, rec.wrap(plain), "a failure after a 2xx is not a status failure")
}
