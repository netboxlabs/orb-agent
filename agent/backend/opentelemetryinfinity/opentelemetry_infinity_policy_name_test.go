package opentelemetryinfinity_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/backend/opentelemetryinfinity"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// TestOpenTelemetryRemovePolicyEscapesTheName pins that the policy name
// reaches the backend as one intact path segment. See the worker backend's
// test of the same name for why each character below breaks.
func TestOpenTelemetryRemovePolicyEscapesTheName(t *testing.T) {
	var mu sync.Mutex
	var deletes []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/status" {
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(StatusResponse{Version: "1.3.4"}))
			return
		}
		// Model the receiving framework rather than accepting every path.
		// ASGI decodes percent-escapes before routing, so a "%2F" arrives as
		// a separator, and Starlette's redirect_slashes then 307s a trailing
		// slash to the route without it. A handler that accepted everything
		// would report a slash name as delivered when it had in fact been
		// redirected onto a different policy.
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.Redirect(w, r, strings.TrimSuffix(r.URL.Path, "/"), http.StatusTemporaryRedirect)
			return
		}
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletes = append(deletes, r.URL.EscapedPath())
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"status": "success"}))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)

	originalNewCmdOptions := backend.NewCmdOptions
	defer func() { backend.NewCmdOptions = originalNewCmdOptions }()
	backend.NewCmdOptions = func(_ backend.CmdOptions, _ string, _ ...string) backend.Commander {
		return mockCmd
	}

	require.True(t, opentelemetryinfinity.Register())
	be := backend.GetBackend("opentelemetry_infinity")

	require.NoError(t, be.Configure(slog.New(slog.NewTextHandler(os.Stdout, nil)), repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, config.BackendCommons{}, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, be.Start(ctx, cancel))

	for _, c := range policyNameEscapingCases {
		require.NoError(t, be.RemovePolicy(policies.PolicyData{ID: "id-1", Name: c.name}),
			"removing %q must not fail", c.name)
	}

	// A slash cannot be kept inside one path segment, so the name is refused
	// before a request is built. Escaping it would send "%2F", which the
	// framework decodes back into a separator and redirects, deleting the
	// policy without the slash and reporting success.
	mu.Lock()
	sent := len(deletes)
	mu.Unlock()
	require.Error(t, be.RemovePolicy(policies.PolicyData{ID: "id-1", Name: "nightly/"}),
		"a name carrying a slash must fail rather than address another policy")

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, deletes, sent, "the refused name must not reach the backend at all")
	require.Len(t, deletes, len(policyNameEscapingCases))
	for i, c := range policyNameEscapingCases {
		assert.Equal(t, c.wantPath, deletes[i], "policy name %q", c.name)
	}
}

// policyNameEscapingCases is duplicated per backend on purpose: each one
// builds its own URL, so a shared table would let a backend that stopped
// escaping pass on another's coverage.
var policyNameEscapingCases = []struct {
	name     string
	wantPath string
}{
	// Names that already worked, byte-identical after the change.
	{"dummy-policy-name", "/api/v1/policies/dummy-policy-name"},
	{"core metrics", "/api/v1/policies/core%20metrics"},
	{"My Office Network #2", "/api/v1/policies/My%20Office%20Network%20%232"},
	{"reports?live", "/api/v1/policies/reports%3Flive"},
	{"100%", "/api/v1/policies/100%25"},
}
