package filesmgr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-getter"
)

const (
	defaultRetryMaxAttempts = 4
	defaultRetryBaseDelay   = 2 * time.Second
	defaultRetryMaxDelay    = 30 * time.Second

	// maxRetryAfter caps a server-provided Retry-After so an overloaded or
	// misbehaving server cannot park a download for the whole install budget.
	maxRetryAfter = 60 * time.Second
)

// retryPolicy controls how transient download failures are retried. Zero
// fields use the defaults.
type retryPolicy struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	// sleep waits for d or until ctx is done. Replaceable in tests.
	sleep func(ctx context.Context, d time.Duration) error
}

func defaultRetryPolicy() retryPolicy {
	return retryPolicy{
		maxAttempts: defaultRetryMaxAttempts,
		baseDelay:   defaultRetryBaseDelay,
		maxDelay:    defaultRetryMaxDelay,
		sleep:       sleepContext,
	}
}

func (p retryPolicy) withDefaults() retryPolicy {
	d := defaultRetryPolicy()
	if p.maxAttempts <= 0 {
		p.maxAttempts = d.maxAttempts
	}
	if p.baseDelay <= 0 {
		p.baseDelay = d.baseDelay
	}
	if p.maxDelay <= 0 {
		p.maxDelay = d.maxDelay
	}
	if p.sleep == nil {
		p.sleep = d.sleep
	}
	return p
}

// delay returns how long to wait before the next attempt. A server-provided
// Retry-After wins (capped); otherwise exponential backoff with jitter so many
// agents retrying against one overloaded server do not stay in lockstep.
func (p retryPolicy) delay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, maxRetryAfter)
	}
	d := p.baseDelay << (attempt - 1)
	if d <= 0 || d > p.maxDelay {
		d = p.maxDelay
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryableStatus reports whether an HTTP status is worth retrying: the
// server is asking us to slow down or is temporarily unavailable.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// httpStatusError is a download failure caused by a non-2xx response. Its
// message is go-getter's, unchanged; the type lets callers act on the status.
type httpStatusError struct {
	StatusCode int
	RetryAfter time.Duration
	err        error
}

func (e *httpStatusError) Error() string { return e.err.Error() }
func (e *httpStatusError) Unwrap() error { return e.err }

// parseRetryAfter parses a Retry-After header (delta-seconds or HTTP date).
// Unparseable, empty or non-positive values return 0.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(min(secs, 3600)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// statusRecorder is a RoundTripper that remembers the most recent response's
// status and Retry-After, because go-getter only reports "bad response code: N"
// as a string.
type statusRecorder struct {
	base http.RoundTripper

	mu         sync.Mutex
	status     int
	retryAfter string
}

func newStatusRecorder() *statusRecorder {
	var tr *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = dt.Clone()
	} else {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	// Match go-getter's default client, which does not keep connections alive.
	tr.DisableKeepAlives = true
	tr.MaxIdleConnsPerHost = -1
	return &statusRecorder{base: tr}
}

func (r *statusRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.status, r.retryAfter = 0, ""
		return nil, err
	}
	r.status, r.retryAfter = resp.StatusCode, resp.Header.Get("Retry-After")
	return resp, nil
}

// wrap turns err into an *httpStatusError when it was caused by the last
// response having a non-2xx status. Anything else (transport errors, checksum
// mismatches, extraction errors) is returned unchanged.
func (r *statusRecorder) wrap(err error) error {
	r.mu.Lock()
	status, retryAfter := r.status, r.retryAfter
	r.mu.Unlock()

	if status < http.StatusBadRequest || !strings.Contains(err.Error(), "bad response code: "+strconv.Itoa(status)) {
		return err
	}
	return &httpStatusError{
		StatusCode: status,
		RetryAfter: parseRetryAfter(retryAfter, time.Now()),
		err:        err,
	}
}

// newHTTPGetters is the explicit getter map used when constructing go-getter
// clients. Defense-in-depth: even if the scheme check in fetch is bypassed,
// go-getter will not find a registered getter for unlisted schemes.
func newHTTPGetters(client *http.Client) map[string]getter.Getter {
	return map[string]getter.Getter{
		"http":  &getter.HttpGetter{Client: client},
		"https": &getter.HttpGetter{Client: client},
	}
}

// download runs one go-getter download into stagePath, retrying transient
// server failures (429 and 5xx) with backoff. Other failures are returned
// immediately. The source URL is never logged: it can carry a signature.
func (f *fetcher) download(ctx context.Context, name, src, stagePath string, mode getter.ClientMode) error {
	logger := f.logger
	if logger == nil {
		logger = slog.Default()
	}
	policy := f.retry.withDefaults()

	for attempt := 1; ; attempt++ {
		err := f.downloadOnce(ctx, src, stagePath, mode)
		if err == nil {
			return nil
		}

		var se *httpStatusError
		if !errors.As(err, &se) || !retryableStatus(se.StatusCode) || attempt >= policy.maxAttempts {
			return err
		}

		delay := policy.delay(attempt, se.RetryAfter)
		logger.Warn("filesmgr: bundle download failed with a transient error; retrying",
			"name", name,
			"status", se.StatusCode,
			"attempt", attempt,
			"max_attempts", policy.maxAttempts,
			"retry_in", delay.String())

		// Start the next attempt from a clean stage so a partial file is
		// never resumed or extracted over.
		_ = os.RemoveAll(stagePath)
		if sleepErr := policy.sleep(ctx, delay); sleepErr != nil {
			return fmt.Errorf("%w (retry aborted: %v)", err, sleepErr)
		}
	}
}

func (f *fetcher) downloadOnce(ctx context.Context, src, stagePath string, mode getter.ClientMode) error {
	rec := newStatusRecorder()
	client := &getter.Client{
		Ctx:     ctx,
		Src:     src,
		Dst:     stagePath,
		Mode:    mode,
		Getters: newHTTPGetters(&http.Client{Transport: rec}),
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
		return rec.wrap(err)
	}
	return nil
}
