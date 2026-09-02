package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/server"
)

// testProfilesRoot is the directory the policies below name their override
// inside. A policy-supplied profiles_dir is confined to a root the operator
// sets, so a server built without one accepts no override at all.
func testProfilesRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	return root
}

func newTestServer(t *testing.T) *server.Server {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	manager := policy.NewManager(ctx, logger, policy.Options{ProfilesRoot: testProfilesRoot(t)})
	return server.NewServer("localhost", 8078, logger, manager, "1.0.0")
}

func TestGetPolicies_Empty(t *testing.T) {
	srv := newTestServer(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	srv.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `[]`, w.Body.String())
}

func TestGetPolicies_WithPolicy(t *testing.T) {
	srv := newTestServer(t)

	// A policy-supplied profiles_dir is confined to the server's profiles root,
	// so the bundled tree this test overlays is named inside it.
	profilesDir := filepath.Join(testProfilesRoot(t), "profiles", "snmp-profiles")

	body := fmt.Appendf(nil, `
policies:
  my-policy:
    config:
      metrics_interval: 60
      profiles_dir: %s
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
      targets:
        - host: 192.168.1.1
`, profilesDir)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	srv.Router().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"my-policy"`)
	assert.Contains(t, w.Body.String(), `"running"`)

	srv.Stop()
}

// The agent polls /status on a timer while the API is otherwise in use, so two
// handlers run at once. Computing the uptime on the shared status struct while
// copying that struct into the response is a data race, which this test trips
// under -race.
func TestGetStatus_ConcurrentRequests(t *testing.T) {
	srv := newTestServer(t)

	const requests = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/v1/status", nil)
			srv.Router().ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)

			var got map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, "1.0.0", got["version"])
			assert.NotNil(t, got["up_time_seconds"])
		}()
	}
	close(start)
	wg.Wait()
}

// A policy with no targets starts no jobs, so accepting one leaves the operator
// with a policy the API reports as running and that collects nothing.
func TestCreatePolicy_RejectsPolicyWithNoTargets(t *testing.T) {
	srv := newTestServer(t)

	body := []byte(`
policies:
  my-policy:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
`)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "no targets")

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	srv.Router().ServeHTTP(w, req)
	assert.JSONEq(t, `[]`, w.Body.String())
}

// The documented policy body limit. Hard-coded rather than read from the
// package so a change to the constant has to be a deliberate contract change.
const policyBodyLimit = 1 << 20

// padPolicyTo grows a policy document to exactly n bytes with YAML comment
// lines, which the parser ignores.
func padPolicyTo(t *testing.T, body []byte, n int) []byte {
	t.Helper()
	require.Less(t, len(body), n, "policy is already at or over the target size")

	pad := make([]byte, 0, n-len(body))
	for len(pad) < n-len(body) {
		pad = append(pad, '#')
	}
	// The final byte closes the trailing comment line.
	pad[len(pad)-1] = '\n'
	return append(body, pad...)
}

func validPolicy(t *testing.T) []byte {
	t.Helper()
	profilesDir := filepath.Join(testProfilesRoot(t), "profiles", "snmp-profiles")
	return fmt.Appendf(nil, `
policies:
  my-policy:
    config:
      metrics_interval: 60
      profiles_dir: %s
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
      targets:
        - host: 192.168.1.1
`, profilesDir)
}

func postPolicy(t *testing.T, srv *server.Server, contentType string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	require.NoError(t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	srv.Router().ServeHTTP(w, req)
	return w
}

// io.ReadAll buffers the whole body before parsing, so an unbounded body lets a
// single request exhaust the process, and the listener has no authentication in
// front of it.
func TestCreatePolicy_RejectsBodyOverTheLimit(t *testing.T) {
	srv := newTestServer(t)

	w := postPolicy(t, srv, "application/x-yaml", padPolicyTo(t, validPolicy(t), policyBodyLimit+1))

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "1048576")

	// The oversized policy must not have started.
	w = httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	require.NoError(t, err)
	srv.Router().ServeHTTP(w, req)
	assert.JSONEq(t, `[]`, w.Body.String())
}

// The bound is off by one if it rejects a body of exactly the documented size.
func TestCreatePolicy_AcceptsBodyAtTheLimit(t *testing.T) {
	srv := newTestServer(t)
	t.Cleanup(srv.Stop)

	body := padPolicyTo(t, validPolicy(t), policyBodyLimit)
	require.Len(t, body, policyBodyLimit)

	w := postPolicy(t, srv, "application/x-yaml", body)

	require.Equal(t, http.StatusCreated, w.Code)
}

// An endless chunked body never reaches io.ReadAll's end, so the read has to be
// stopped by the bound rather than by the sender.
func TestCreatePolicy_StopsReadingAnEndlessBody(t *testing.T) {
	srv := newTestServer(t)

	// Far more than the bound, so an unbounded read buffers all of it.
	endless := io.LimitReader(zeroes{}, 8*policyBodyLimit)

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/api/v1/policies", endless)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// zeroes is an endless source of comment bytes.
type zeroes struct{}

func (zeroes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '#'
	}
	return len(p), nil
}

// Clients and middleware routinely append a charset parameter, and HTTP media
// types are case-insensitive, so comparing the header as a whole string turns
// valid submissions away before parsing.
func TestCreatePolicy_ContentType(t *testing.T) {
	const invalid = "invalid Content-Type. Only 'application/x-yaml' is supported"

	// Reaches the parser and is rejected there, so the message tells the gate's
	// verdict apart from the parser's.
	noTargets := []byte(`
policies:
  my-policy:
    config:
      metrics_interval: 60
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
`)

	for _, tc := range []struct {
		name        string
		contentType string
		accepted    bool
	}{
		{"bare", "application/x-yaml", true},
		{"charset parameter", "application/x-yaml; charset=utf-8", true},
		{"parameter without a space", "application/x-yaml;charset=UTF-8", true},
		{"upper case media type", "APPLICATION/X-YAML", true},
		{"mixed case with a parameter", "Application/X-Yaml; Charset=utf-8", true},
		{"absent", "", false},
		{"unrelated type", "application/json", false},
		{"yaml under another name", "text/yaml", false},
		// mime.ParseMediaType tolerates a bare trailing semicolon, and the media
		// type is unambiguous, so it is not re-rejected here.
		{"trailing semicolon", "application/x-yaml;", true},
		{"malformed parameter", "application/x-yaml; charset", false},
		{"unterminated quoted parameter", `application/x-yaml; charset="utf-8`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)

			w := postPolicy(t, srv, tc.contentType, noTargets)

			require.Equal(t, http.StatusBadRequest, w.Code)
			if tc.accepted {
				assert.NotContains(t, w.Body.String(), invalid)
				assert.Contains(t, w.Body.String(), "no targets")
			} else {
				assert.Contains(t, w.Body.String(), invalid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A policy name has to be one DELETE /policies/:policy can address
// ---------------------------------------------------------------------------

// namedPolicyBody builds a policy under name. The name is marshalled rather
// than interpolated, so a name carrying a quote or a control character is still
// a well-formed document and the test measures routing rather than YAML.
func namedPolicyBody(t *testing.T, name, profilesDir string) []byte {
	t.Helper()
	body, err := yaml.Marshal(map[string]any{
		"policies": map[string]any{
			name: map[string]any{
				"config": map[string]any{"metrics_interval": 60, "profiles_dir": profilesDir},
				"scope": map[string]any{
					"authentication": map[string]any{"protocol_version": "SNMPv2c", "community": "public"},
					"targets":        []any{map[string]any{"host": "192.0.2.1"}},
				},
			},
		},
	})
	require.NoError(t, err)
	return body
}

// The names policy.ValidatePolicyName accepts have to be names the router can
// deliver back, or the rule is a second opinion the router never asked for.
// Each one is created and then deleted through the real engine, the way the
// agent does it, with the path escaped by the same call the agent's backends
// use.
func TestDeletePolicy_EveryAcceptedNameIsAddressable(t *testing.T) {
	profilesDir := filepath.Join(testProfilesRoot(t), "profiles", "snmp-profiles")
	names := []string{
		"snmp_metrics_1",
		"policy-a",
		"a b",
		"café",
		"a.b",
		"...",
		"a%2Fb",
		"a?b",
		"a#b",
		"a:b",
		"a&b",
		"a+b",
		"a=b",
		" padded ",
	}
	srv := newTestServer(t)
	defer srv.Stop()

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, policy.ValidatePolicyName(name), "the rule rejects a name this test calls addressable")

			w := postPolicy(t, srv, "application/x-yaml", namedPolicyBody(t, name, profilesDir))
			require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

			w = httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodDelete, "/api/v1/policies/"+url.PathEscape(name), nil)
			require.NoError(t, err)
			srv.Router().ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			// Decoded rather than matched against the raw body, which escapes
			// the characters some of these names are here to carry.
			var deleted struct {
				Detail string `json:"detail"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &deleted))
			assert.Contains(t, deleted.Detail, name, "the delete answered for another name")

			w = httptest.NewRecorder()
			req, err = http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
			require.NoError(t, err)
			srv.Router().ServeHTTP(w, req)
			assert.JSONEq(t, `[]`, w.Body.String(), "the delete reached some other policy")
		})
	}
}

// The other half of the same claim: a name the rule refuses is a name the
// router cannot deliver back, so accepting it would leave a policy that runs
// until the backend is restarted. Each case names what the router does with it.
func TestCreatePolicy_RejectsANameNoRouteCanAddress(t *testing.T) {
	profilesDir := filepath.Join(testProfilesRoot(t), "profiles", "snmp-profiles")
	for _, tc := range []struct {
		label string
		name  string
	}{
		{"empty", ""},
		{"whitespace only", " "},
		{"leading slash", "/a"},
		{"embedded slash", "a/b"},
		{"trailing slash", "a/"},
		{"dot", "."},
		{"dot dot", ".."},
	} {
		t.Run(tc.label, func(t *testing.T) {
			require.Error(t, policy.ValidatePolicyName(tc.name), "the rule accepts a name this test calls unaddressable")

			srv := newTestServer(t)
			defer srv.Stop()

			w := postPolicy(t, srv, "application/x-yaml", namedPolicyBody(t, tc.name, profilesDir))
			require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), "policy name")
		})
	}
}

// What the router does with each refused name, recorded rather than assumed.
// A slash misses the route or, with a trailing one, redirects onto the
// neighbouring name. A dot segment reaches the handler as it stands, and is
// refused because it does not survive the path normalisation a client applies
// before the request is sent.
func TestDeletePolicy_RefusedNamesDoNotAddressTheirPolicy(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Stop()

	for _, tc := range []struct {
		label string
		name  string
		code  int
	}{
		{"empty misses the route", "", http.StatusNotFound},
		{"leading slash misses the route", "/a", http.StatusNotFound},
		{"embedded slash misses the route", "a/b", http.StatusNotFound},
		{"trailing slash redirects onto another name", "a/", http.StatusTemporaryRedirect},
	} {
		t.Run(tc.label, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodDelete, "/api/v1/policies/"+url.PathEscape(tc.name), nil)
			require.NoError(t, err)
			srv.Router().ServeHTTP(w, req)

			assert.Equal(t, tc.code, w.Code)
			// The handler answers in JSON, so its absence is what says the
			// request never reached it.
			assert.NotContains(t, w.Body.String(), "policy not found")
		})
	}

	// The redirect a trailing slash earns points at the name without it, so
	// accepting "a/" would hand its delete to a policy called "a".
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodDelete, "/api/v1/policies/"+url.PathEscape("a/"), nil)
	require.NoError(t, err)
	srv.Router().ServeHTTP(w, req)
	assert.Equal(t, "/api/v1/policies/a", w.Header().Get("Location"))

	// A dot segment does reach the handler, so routing alone does not refuse
	// it. What refuses it is that a client assembling the path resolves it
	// away: JoinPath is the stdlib call for that, and ".." leaves the
	// collection entirely.
	base, err := url.Parse("http://127.0.0.1:8078/api/v1/policies")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8078/api/v1", base.JoinPath(url.PathEscape("..")).String())
	assert.Equal(t, "http://127.0.0.1:8078/api/v1/policies", base.JoinPath(url.PathEscape(".")).String())
}

// ---------------------------------------------------------------------------
// A batch POST that fails partway undoes what it started
// ---------------------------------------------------------------------------

// One entry failing leaves the whole request refused, so the entries already
// started have to be stopped again. Whichever order the two are visited in,
// nothing may be left running: the profiles_dir outside the server's root is
// refused by the start rather than by the parser, so the failure lands after a
// policy may already be running.
func TestCreatePolicy_RollsBackWhatItStarted(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Stop()

	profilesDir := filepath.Join(testProfilesRoot(t), "profiles", "snmp-profiles")
	body := fmt.Appendf(nil, `
policies:
  keep:
    config:
      metrics_interval: 60
      profiles_dir: %s
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
      targets:
        - host: 192.0.2.1
  reject:
    config:
      metrics_interval: 60
      profiles_dir: /etc
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: public
      targets:
        - host: 192.0.2.2
`, profilesDir)

	w := postPolicy(t, srv, "application/x-yaml", body)
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "must be inside")

	w = httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	require.NoError(t, err)
	srv.Router().ServeHTTP(w, req)
	assert.JSONEq(t, `[]`, w.Body.String(), "a refused request left a policy running")
}
