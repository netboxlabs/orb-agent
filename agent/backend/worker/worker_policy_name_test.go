package worker_test

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
	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

// TestWorkerRemovePolicyEscapesTheName pins that the policy name reaches
// the backend as one intact path segment.
//
// Policy names are operator-written and forwarded verbatim, so a name such
// as "My Office Network #2" is a legitimate thing to write. Unescaped, the
// client reads the "#" as a fragment and never sends the rest, so the
// request lands on a truncated name and deletes an unrelated policy or
// nothing at all, reporting success either way.
//
// Asserting on EscapedPath rather than Path is the point of the test: Path
// is already decoded, so it cannot tell an escaped name from a truncated
// one.
func TestWorkerRemovePolicyEscapesTheName(t *testing.T) {
	var mu sync.Mutex
	var deletes []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/status" {
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"version": "1.0.0"}))
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

	createExecutable(t, "orb-worker")

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)
	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, _ string, _ []string) {})

	require.True(t, worker.Register())
	be := backend.GetBackend("worker")

	require.NoError(t, be.Configure(slog.New(slog.NewTextHandler(os.Stdout, nil)), repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, config.BackendCommons{}, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, be.Start(ctx, cancel))

	for _, c := range policyNameEscapingCases {
		require.NoError(t, be.RemovePolicy(policies.PolicyData{ID: "id-1", Name: c.name}),
			"removing %q must not fail; before escaping, %%  did not even parse as a URL", c.name)
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
	// Names that already worked. These must be byte-identical after the
	// change, or the escaping is double-encoding.
	{"dummy-policy-name", "/api/v1/policies/dummy-policy-name"},
	{"core metrics", "/api/v1/policies/core%20metrics"},
	// "#" is read as a fragment and never leaves the client.
	{"My Office Network #2", "/api/v1/policies/My%20Office%20Network%20%232"},
	// "?" is read as a query, same outcome.
	{"reports?live", "/api/v1/policies/reports%3Flive"},
	// "%" is worse: the URL does not parse at all, so the request is
	// never made.
	{"100%", "/api/v1/policies/100%25"},
}
