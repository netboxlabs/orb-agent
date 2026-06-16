package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-discovery/gnmi-discovery/metrics"
	"github.com/netboxlabs/orb-discovery/gnmi-discovery/policy"
	"github.com/stretchr/testify/require"
)

// initTestMetrics initialises the OTel meter to a live (but no-export) provider
// so that metricsMiddleware exercises its non-nil instrument branches. The OTLP
// endpoint doesn't need to be reachable — the gRPC exporter dials lazily.
// Cleanup shuts down the MeterProvider (with a short deadline so the test suite
// doesn't stall) before resetting the meter, preventing goroutine leaks from the
// PeriodicReader.
func initTestMetrics(t *testing.T) {
	t.Helper()
	// Use an ephemeral local address that nothing is actually listening on.
	// otlpmetricgrpc.New does NOT dial during construction.
	if err := metrics.SetupMetricsExport(
		context.Background(),
		slog.Default(),
		"127.0.0.1:19317", // nothing listening — lazy gRPC dial
		60,
	); err != nil {
		t.Skipf("could not init test metrics (OTel exporter setup failed): %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_ = metrics.Shutdown(ctx)
		cancel()
		metrics.ResetMeter()
	})
}

// newTestManager creates a policy.Manager backed by a FakeDialer for unit tests.
// A t.Cleanup is registered to stop all running policy runners so no background
// goroutines leak after the test.
func newTestManager(t *testing.T) *policy.Manager {
	t.Helper()
	var client diode.Client
	m, err := policy.NewManager(
		context.Background(),
		slog.Default(),
		client,
		&gnmi.FakeDialer{Session: &gnmi.FakeSession{}},
		"",
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Stop() })
	return m
}

// validPolicyYAML returns a minimal valid policy YAML document with the given
// policy name and host.
func validPolicyYAML(name, host string) []byte {
	return []byte(fmt.Sprintf(`
policies:
  %s:
    config: {}
    scope:
      targets:
        - host: %s
`, name, host))
}

// --- existing tests (preserved) ---

func TestStatusRoute(t *testing.T) {
	logger := slog.Default()
	var client diode.Client
	mgr, err := policy.NewManager(context.Background(), logger, client,
		&gnmi.FakeDialer{Session: &gnmi.FakeSession{}}, "")
	require.NoError(t, err)
	s := NewServer("127.0.0.1", 0, logger, mgr, "test")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

// TestStatusConcurrent fires many concurrent GET /api/v1/status requests to
// verify there is no data race on s.stat (caught by -race).
func TestStatusConcurrent(t *testing.T) {
	logger := slog.Default()
	var client diode.Client
	mgr, err := policy.NewManager(context.Background(), logger, client,
		&gnmi.FakeDialer{Session: &gnmi.FakeSession{}}, "")
	require.NoError(t, err)
	s := NewServer("127.0.0.1", 0, logger, mgr, "test")

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, req)
			// Each goroutine must receive a valid 200 response.
			if w.Code != http.StatusOK {
				t.Errorf("expected 200, got %d", w.Code)
			}
		}()
	}
	wg.Wait()
}

// --- getCapabilities ---

func TestGetCapabilities(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var caps Capabilities
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &caps))
	require.NotEmpty(t, caps.Capabilities)
}

// TestGetCapabilitiesWithMetrics exercises the non-nil metricsMiddleware branches
// (GetAPIRequests.Add and GetAPIResponseLatency.Record) by sending a request
// after initialising the OTel meter.
func TestGetCapabilitiesWithMetrics(t *testing.T) {
	initTestMetrics(t)
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

// --- createPolicy ---

func TestCreatePolicyBadContentType(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	body := bytes.NewBufferString(`policies: {}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "Content-Type")
}

func TestCreatePolicyMissingContentType(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies",
		bytes.NewBufferString(`policies: {}`))
	// No Content-Type header set → mediaType will be ""
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreatePolicyBadYAML(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	body := bytes.NewBufferString(`: : : invalid yaml :::`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", body)
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreatePolicyNoPolicies(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	body := bytes.NewBufferString("policies: {}\n")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", body)
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "no policies")
}

func TestCreatePolicySuccess(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	body := validPolicyYAML("alpha", "10.0.0.1")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "alpha")
}

func TestCreatePolicyWithCharsetSuffix(t *testing.T) {
	// mime.ParseMediaType should strip parameters like "; charset=utf-8".
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	body := validPolicyYAML("beta", "10.0.0.2")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/x-yaml; charset=utf-8")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
}

func TestCreatePolicyConflict(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")

	// First POST — must succeed.
	post := func() *httptest.ResponseRecorder {
		body := validPolicyYAML("gamma", "10.0.0.3")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/x-yaml")
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		return w
	}
	w1 := post()
	require.Equal(t, http.StatusCreated, w1.Code)

	// Second POST with the same policy name → 409 Conflict.
	w2 := post()
	require.Equal(t, http.StatusConflict, w2.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "already exists")
}

func TestCreatePolicyStartError(t *testing.T) {
	// StartPolicy returns an error when a target pins an unknown profile.
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	body := []byte(`
policies:
  badprofile:
    config: {}
    scope:
      targets:
        - host: 10.0.0.4
          profile: nonexistent-profile
`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "nonexistent-profile")
}

func TestCreatePolicyBodyTooLarge(t *testing.T) {
	// Send a body larger than 1 MiB to exercise the MaxBytesReader error branch,
	// which must surface as 413 Request Entity Too Large (not a generic 400).
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	// Build a body slightly over 1 MiB.
	bigBody := strings.NewReader(strings.Repeat("x", 1<<20+1))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bigBody)
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// --- deletePolicy ---

func TestDeletePolicyNotFound(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/nonexistent", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "not found")
}

func TestDeletePolicySuccess(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")

	// Create the policy first.
	body := validPolicyYAML("to-delete", "10.0.0.5")
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(body))
	createReq.Header.Set("Content-Type", "application/x-yaml")
	cw := httptest.NewRecorder()
	s.Router().ServeHTTP(cw, createReq)
	require.Equal(t, http.StatusCreated, cw.Code)

	// Now delete it.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/to-delete", nil)
	dw := httptest.NewRecorder()
	s.Router().ServeHTTP(dw, delReq)

	require.Equal(t, http.StatusOK, dw.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(dw.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "to-delete")
}

// --- Start / Stop ---

// TestStartStop starts the HTTP server on an ephemeral port, verifies it
// serves requests, then calls Stop and confirms a clean shutdown.
func TestStartStop(t *testing.T) {
	mgr := newTestManager(t)
	// Pick a free port by letting the OS assign one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	freePort := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close()) // release so the server can bind it

	s := NewServer("127.0.0.1", freePort, slog.Default(), mgr, "v0")
	errCh := s.Start()

	// Poll until the server is ready (or fail after 2 s).
	addr := fmt.Sprintf("http://127.0.0.1:%d/api/v1/status", freePort)
	var lastErr error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, httpErr := http.Get(addr) //nolint:noctx
		if httpErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				lastErr = nil
				break
			}
		}
		lastErr = httpErr
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, lastErr, "server did not become ready in time")

	// Stop the server and confirm the error channel closes cleanly.
	s.Stop()
	select {
	case err, open := <-errCh:
		if open {
			require.NoError(t, err, "unexpected error from Start()")
		}
		// channel closed → clean shutdown ✓
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() did not close the error channel within 3 s")
	}
}

// TestStopIdempotent verifies that Stop() can be called even when the server
// was never Start()ed (exercises the graceful-shutdown path on an unlistened
// httpServer).
func TestStopIdempotent(t *testing.T) {
	mgr := newTestManager(t)
	s := NewServer("127.0.0.1", 0, slog.Default(), mgr, "v0")
	// Stop without Start — Shutdown on an unstarted http.Server returns nil.
	require.NotPanics(t, s.Stop)
}

// TestStartReturnsChannel verifies that Start() returns a non-nil channel and
// does not block the caller.
func TestStartReturnsChannel(t *testing.T) {
	mgr := newTestManager(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	s := NewServer("127.0.0.1", port, slog.Default(), mgr, "v0")
	errCh := s.Start()
	require.NotNil(t, errCh)
	s.Stop()
	// Stop triggers graceful shutdown; the serve goroutine sends its final
	// error and closes errCh. Drain to completion so we don't leak it.
	for err := range errCh {
		_ = err
	}
}

// --- metricsMiddleware coverage ---

// TestMetricsMiddlewareNonNilInstruments exercises the metricsMiddleware with a
// live (but unexported) OTel meter so the apiMetric != nil branches are taken.
// This is done in a separate sub-test that resets the global metrics state
// afterward via t.Cleanup, keeping other tests unaffected.
func TestMetricsMiddlewareNonNilInstruments(t *testing.T) {
	initTestMetrics(t)

	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")

	// Exercise multiple endpoints to hit both the counter and histogram branches
	// with varying HTTP methods and status codes.
	cases := []struct {
		method, path string
		body         io.Reader
		contentType  string
		wantStatus   int
	}{
		{http.MethodGet, "/api/v1/status", nil, "", http.StatusOK},
		{http.MethodGet, "/api/v1/capabilities", nil, "", http.StatusOK},
		{http.MethodDelete, "/api/v1/policies/missing", nil, "", http.StatusNotFound},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, tc.body)
		if tc.contentType != "" {
			req.Header.Set("Content-Type", tc.contentType)
		}
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		require.Equal(t, tc.wantStatus, w.Code)
	}
}

// TestCreateAndDeleteMultiplePolicies verifies that multiple policies can be
// created and individually deleted in sequence.
func TestCreateAndDeleteMultiplePolicies(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")

	names := []string{"p1", "p2", "p3"}
	hosts := []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"}
	for i, name := range names {
		body := validPolicyYAML(name, hosts[i])
		req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/x-yaml")
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code, "creating policy %s", name)
	}

	for _, name := range names {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/"+name, nil)
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "deleting policy %s", name)
	}
}

// TestCreatePolicyInvalidMode verifies that a policy with an invalid mode is
// rejected with 400 by ParsePolicies validation.
func TestCreatePolicyInvalidMode(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")
	body := []byte(`
policies:
  badmode:
    config:
      mode: streaming
    scope:
      targets:
        - host: 10.0.0.9
`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "mode")
}

// TestCreatePolicyConflictBatchResponse verifies that when a batch includes a
// policy that already exists the server returns 409 Conflict and that after the
// failed batch the pre-existing policy is still listed as running (no state
// leak). The rollback branch (stop already-started policies on conflict) may or
// may not execute depending on Go's non-deterministic map iteration — this test
// only asserts the observable contract: conflict is reported and persistent state
// is consistent.
func TestCreatePolicyConflictBatchResponse(t *testing.T) {
	mgr := newTestManager(t)
	s := NewServer("127.0.0.1", 0, slog.Default(), mgr, "v0")

	// Pre-create "pre-existing" so the batch will hit a conflict on it.
	preBody := validPolicyYAML("pre-existing", "10.2.0.99")
	preReq := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(preBody))
	preReq.Header.Set("Content-Type", "application/x-yaml")
	preW := httptest.NewRecorder()
	s.Router().ServeHTTP(preW, preReq)
	require.Equal(t, http.StatusCreated, preW.Code)

	// Submit a batch that includes "pre-existing" (conflict) and a fresh policy.
	// The order of iteration is non-deterministic; the batch will be rejected
	// with 409 regardless of which policy is encountered first because one of
	// them always conflicts.
	batchBody := []byte(`
policies:
  fresh-policy:
    config: {}
    scope:
      targets:
        - host: 10.2.0.1
  pre-existing:
    config: {}
    scope:
      targets:
        - host: 10.2.0.99
`)
	batchReq := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(batchBody))
	batchReq.Header.Set("Content-Type", "application/x-yaml")
	batchW := httptest.NewRecorder()
	s.Router().ServeHTTP(batchW, batchReq)

	// The batch must be rejected with 409 Conflict because "pre-existing" is in it.
	require.Equal(t, http.StatusConflict, batchW.Code,
		"batch containing an existing policy name must return 409")

	// After the failed batch the pre-existing policy must still be running.
	require.True(t, mgr.HasPolicy("pre-existing"),
		"pre-existing policy must still be running after failed batch")

	// The fresh-policy must NOT be permanently installed (it was either rolled
	// back or never started, depending on iteration order).
	require.False(t, mgr.HasPolicy("fresh-policy"),
		"fresh-policy must not persist after a rolled-back or rejected batch")
}

// TestCreatePolicyStartErrorWithRollback sends a two-policy batch where the
// first policy starts successfully and the second fails (unknown pinned profile).
// This exercises the StartPolicy-error rollback loop that calls StopPolicy on
// the already-started policies.
func TestCreatePolicyStartErrorWithRollback(t *testing.T) {
	s := NewServer("127.0.0.1", 0, slog.Default(), newTestManager(t), "v0")

	// Use a YAML batch where one policy is valid and one pins an unknown profile.
	// Go map iteration order is non-deterministic, so use names that are likely
	// to be iterated in the order "good-policy" first, then "bad-profile-policy".
	// Since we cannot guarantee order, we accept any 4xx response.
	batchBody := []byte(`
policies:
  aaa-good-policy:
    config: {}
    scope:
      targets:
        - host: 10.3.0.1
  zzz-bad-profile:
    config: {}
    scope:
      targets:
        - host: 10.3.0.2
          profile: nonexistent-profile-xyz
`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewBuffer(batchBody))
	req.Header.Set("Content-Type", "application/x-yaml")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)

	// Either aaa-good-policy started first (rollback executed) → 400,
	// or zzz-bad-profile was processed first (no rollback needed) → 400.
	// Both paths give 400.
	require.Equal(t, http.StatusBadRequest, w.Code)
	var resp Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Detail, "nonexistent-profile-xyz")
}

// TestStartErrorOnUsedPort verifies that Start() sends a non-nil error on the
// returned channel when the port is already in use, exercising the
// non-ErrServerClosed error path. A closed channel (no error) is a failure.
func TestStartErrorOnUsedPort(t *testing.T) {
	// Bind a port and hold it open so the server cannot listen on it.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = blocker.Close() }()
	usedPort := blocker.Addr().(*net.TCPAddr).Port

	mgr := newTestManager(t)
	s := NewServer("127.0.0.1", usedPort, slog.Default(), mgr, "v0")
	errCh := s.Start()

	select {
	case startErr, open := <-errCh:
		if !open {
			t.Fatal("Start() closed the error channel without sending an error — expected a bind-failure error")
		}
		require.Error(t, startErr, "Start() must send a non-nil error when the port is already in use")
	case <-time.After(3 * time.Second):
		t.Fatal("Start() did not produce an error within 3 s")
	}
}
