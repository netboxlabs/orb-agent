package discovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/discovery"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// errConfigureExtra is a sentinel returned by the ConfigureExtra hook in tests.
var errConfigureExtra = errors.New("configure-extra boom")

// testBackend is a synthetic embedder mirroring how the real diode backends will
// embed DiscoveryBase: it wires the three func-field hooks to its own methods.
type testBackend struct {
	discovery.Base
	configureExtraErr   error
	configureExtraCalls int
	logLines            []string
}

func newTestBackend(logger *slog.Logger) *testBackend {
	b := &testBackend{}
	b.Logger = logger
	b.APIProtocol = "http"
	b.Exec = "discovery-test-exec"
	b.NameHyphen = "discovery-test"
	b.NameUnderscore = "discovery_test"
	b.APIPort = "9999" // embedder default, overridden only when config["port"] is present

	b.BuildArgs = b.buildArgs
	b.LogLine = b.logLineAdapter
	b.ConfigureExtra = b.configureExtra
	return b
}

func (b *testBackend) buildArgs() []string {
	args := []string{
		"--diode-app-name-prefix", b.DiodeAppNamePrefix,
		"--host", b.APIHost,
		"--port", b.APIPort,
	}
	if b.DiodeDryRun {
		args = append([]string{"--dry-run", "--dry-run-output-dir", b.DiodeDryRunOutputDir}, args...)
	} else {
		opts := []string{"--diode-target", b.DiodeTarget}
		if !b.DiodeTargetFromOtel {
			opts = append(opts, "--diode-client-id", b.DiodeClientID, "--diode-client-secret", b.DiodeClientSecret)
		}
		args = append(opts, args...)
	}
	if b.DiodeLogLevel != "" {
		args = append(args, "--log-level", b.DiodeLogLevel)
	}
	if b.DiodeOtelEndpoint != "" {
		args = append(args, "--otel-endpoint", b.DiodeOtelEndpoint)
	}
	return args
}

func (b *testBackend) logLineAdapter(line string, _ bool) {
	b.logLines = append(b.logLines, line)
}

func (b *testBackend) configureExtra(_ map[string]any) error {
	b.configureExtraCalls++
	return b.configureExtraErr
}

// captureHandler is a slog.Handler that records every record's message and attrs.
type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

type capturedRecord struct {
	msg   string
	attrs map[string]string
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) hasAttr(key, value string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if v, ok := r.attrs[key]; ok && v == value {
			return true
		}
	}
	return false
}

// recordingServer returns an httptest server that records every request path and
// answers the discovery REST endpoints.
func recordingServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var (
		mu    sync.Mutex
		paths []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/status":
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(backend.StatusResponse{
				Version: "9.8.7",
				Policies: []backend.PolicyStatus{
					{Name: "p1", Status: "running"},
				},
			}))
		case r.URL.Path == "/api/v1/capabilities":
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"capability": true}))
		case strings.HasPrefix(r.URL.Path, "/api/v1/policies"):
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"status": "success"}))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, &paths
}

func runningBackend(t *testing.T, logger *slog.Logger, server *httptest.Server) *testBackend {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	b := newTestBackend(logger)
	b.APIHost = serverURL.Hostname()
	b.APIPort = serverURL.Port()

	// A running mock so CommonRequest's GetRunningStatus reports Running.
	mockCmd := &mocks.MockCmd{}
	mockCmd.On("Status").Return(backend.CmdStatus{PID: 4321, Complete: false, Exit: -1})
	b.Proc = mockCmd
	return b
}

func TestDiscoveryBaseConfigure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := newTestBackend(logger)

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "collector:4317"
	commons.Diode.Target = "default-target"
	commons.Diode.ClientID = "default-client"
	commons.Diode.ClientSecret = "default-secret"
	commons.Diode.AgentName = "default-agent"
	commons.Diode.DryRunOutputDir = "/tmp/default"

	require.NoError(t, b.Configure(map[string]any{
		"host":          "example.com",
		"port":          8080,
		"target":        "cfg-target",
		"client_id":     "cfg-client",
		"client_secret": "cfg-secret",
		"agent_name":    "cfg-agent",
		"log_level":     "debug",
	}, commons))

	assert.Equal(t, "example.com", b.APIHost)
	assert.Equal(t, "8080", b.APIPort, "numeric port must be stringified")
	assert.Equal(t, "cfg-target", b.DiodeTarget)
	assert.Equal(t, "cfg-client", b.DiodeClientID)
	assert.Equal(t, "cfg-secret", b.DiodeClientSecret)
	assert.Equal(t, "cfg-agent", b.DiodeAppNamePrefix)
	assert.Equal(t, "debug", b.DiodeLogLevel)
	assert.Equal(t, "collector:4317", b.DiodeOtelEndpoint)
	assert.False(t, b.DiodeTargetFromOtel, "explicit target must not be flagged as from-otel")
	assert.Equal(t, 1, b.configureExtraCalls, "ConfigureExtra must run during Configure")

	// PolicyRepo is exported so each embedder's Configure can store the repo.
	repo, err := policies.NewMemRepo()
	require.NoError(t, err)
	b.PolicyRepo = repo
	assert.NotNil(t, b.PolicyRepo)
}

func TestDiscoveryBaseConfigureFallsBackToCommons(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := newTestBackend(logger)

	commons := config.BackendCommons{}
	commons.Diode.Target = "commons-target"
	commons.Diode.ClientID = "commons-client"
	commons.Diode.DryRun = true
	commons.Diode.DryRunOutputDir = "/tmp/commons"

	require.NoError(t, b.Configure(map[string]any{}, commons))

	assert.Equal(t, "localhost", b.APIHost, "missing host falls back to default")
	assert.Equal(t, "9999", b.APIPort, "missing port keeps the embedder default")
	assert.Equal(t, "commons-target", b.DiodeTarget)
	assert.Equal(t, "commons-client", b.DiodeClientID)
	assert.True(t, b.DiodeDryRun)
	assert.Equal(t, "/tmp/commons", b.DiodeDryRunOutputDir)
}

func TestDiscoveryBaseConfigureOtelTargetFromOtel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := newTestBackend(logger)

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "otel:4317"

	require.NoError(t, b.Configure(map[string]any{}, commons))

	assert.Equal(t, "otel:4317", b.DiodeOtelEndpoint)
	assert.Equal(t, "otel:4317", b.DiodeTarget, "empty target adopts the OTLP endpoint")
	assert.True(t, b.DiodeTargetFromOtel, "target adopted from OTLP must be flagged")
}

func TestDiscoveryBaseConfigureExtraErrorAbortsBeforeOtelLog(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)
	b := newTestBackend(logger)
	b.configureExtraErr = errConfigureExtra

	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "otel:4317"

	err := b.Configure(map[string]any{}, commons)
	require.ErrorIs(t, err, errConfigureExtra)
	assert.Equal(t, 1, b.configureExtraCalls)
	assert.False(t, capture.hasAttr("endpoint", "otel:4317"),
		"ConfigureExtra error must abort before the OTLP-endpoint log")
}

func TestDiscoveryBaseRESTMethods(t *testing.T) {
	server, paths := recordingServer(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := runningBackend(t, logger, server)

	version, err := b.Version()
	require.NoError(t, err)
	assert.Equal(t, "9.8.7", version)

	caps, err := b.GetCapabilities()
	require.NoError(t, err)
	assert.Equal(t, true, caps["capability"])

	status, err := b.GetPolicyStatus()
	require.NoError(t, err)
	require.Len(t, status, 1)
	assert.Equal(t, "p1", status[0].Name)

	require.NoError(t, b.ApplyPolicy(policies.PolicyData{
		ID: "id1", Name: "policy-one", Data: map[string]any{"k": "v"},
	}, false))

	assert.Contains(t, *paths, "/api/v1/status")
	assert.Contains(t, *paths, "/api/v1/capabilities")
	assert.Contains(t, *paths, "/api/v1/policies")
}

func TestDiscoveryBaseRemovePolicyPathEscapes(t *testing.T) {
	server, paths := recordingServer(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := runningBackend(t, logger, server)

	require.NoError(t, b.RemovePolicy(policies.PolicyData{ID: "id1", Name: "a/b"}))

	assert.Contains(t, *paths, "/api/v1/policies/a%2Fb",
		"a slash in the policy name must be path-escaped in the request URL")
	assert.NotContains(t, *paths, "/api/v1/policies/a/b",
		"the raw, unescaped name must not reach the server as a path")
}

func TestDiscoveryBaseRemovePolicyUsesPreviousName(t *testing.T) {
	server, paths := recordingServer(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := runningBackend(t, logger, server)

	require.NoError(t, b.RemovePolicy(policies.PolicyData{
		ID:                 "id1",
		Name:               "new name",
		PreviousPolicyData: &policies.PolicyData{Name: "old/name"},
	}))

	assert.Contains(t, *paths, "/api/v1/policies/old%2Fname",
		"a renamed policy must be removed under its previous (escaped) name")
}

// TestDiscoveryBaseNameFormHyphen asserts the hyphen form is the CommonRequest
// backend id: with no running process, CommonRequest emits its skip-warn carrying
// the hyphen name as the "backend" attr.
func TestDiscoveryBaseNameFormHyphen(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)
	b := newTestBackend(logger)
	b.Proc = nil // not running => CommonRequest logs the skip-warn

	_, _ = b.Version()
	assert.True(t, capture.hasAttr("backend", "discovery-test"),
		"CommonRequest must receive the hyphen name form as its backend id")
}

// TestDiscoveryBaseNameFormUnderscore asserts the underscore form is the
// StopProcess backend tag. Start (via backend.StartProcess) publishes proc +
// statusChan to the base, so Stop's StopProcess call drains the mock's status
// channel and logs with the underscore name.
func TestDiscoveryBaseNameFormUnderscore(t *testing.T) {
	server, _ := recordingServer(t)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	createExecutable(t, "discovery-test-exec")

	capture := &captureHandler{}
	logger := slog.New(capture)
	b := newTestBackend(logger)
	b.APIHost = serverURL.Hostname()
	b.APIPort = serverURL.Port()

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)
	overrideNewCmdOptions(t, mockCmd, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, b.Start(ctx, cancel))
	require.NoError(t, b.Stop(ctx))
	assert.True(t, capture.hasAttr("backend", "discovery_test"),
		"StopProcess must receive the underscore name form as its backend tag")
}

func TestDiscoveryBaseStart(t *testing.T) {
	server, _ := recordingServer(t)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	createExecutable(t, "discovery-test-exec")

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := newTestBackend(logger)
	b.APIHost = serverURL.Hostname()
	b.APIPort = serverURL.Port()
	b.DiodeTarget = "t"
	b.DiodeClientID = "c"
	b.DiodeClientSecret = "s"
	b.DiodeAppNamePrefix = "a"

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)
	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, name string, args []string) {
		assert.Equal(t, "discovery-test-exec", name)
		assert.Contains(t, args, "--host")
		assert.Contains(t, args, serverURL.Hostname())
		assert.Contains(t, args, "--diode-target")
		assert.Contains(t, args, "t")
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, b.Start(ctx, cancel))
	assert.False(t, b.GetStartTime().IsZero(), "Start must set the start time")
	assert.Same(t, ctx, b.Ctx, "Start must publish the context to DiscoveryBase.Ctx")

	status, _, err := b.GetRunningStatus()
	require.NoError(t, err)
	assert.Equal(t, backend.Running, status)

	require.NoError(t, b.Stop(ctx))

	mockCmd.AssertExpectations(t)
}

func createExecutable(t *testing.T, name string) {
	t.Helper()
	tempDir := t.TempDir()
	binaryPath := path.Join(tempDir, name)
	file, err := os.Create(binaryPath)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	require.NoError(t, os.Chmod(binaryPath, 0o755))
	t.Setenv("PATH", tempDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func overrideNewCmdOptions(t *testing.T, cmd backend.Commander, assertFn func(options backend.CmdOptions, name string, args []string)) {
	t.Helper()
	original := backend.NewCmdOptions
	backend.NewCmdOptions = func(options backend.CmdOptions, name string, args ...string) backend.Commander {
		if assertFn != nil {
			assertFn(options, name, args)
		}
		return cmd
	}
	t.Cleanup(func() { backend.NewCmdOptions = original })
}
