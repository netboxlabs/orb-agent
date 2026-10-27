package pktvisor_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
)

type fakeTap struct {
	inputType string
	config    map[string]any
	tags      map[string]any
}

type fakePolicy struct {
	tap  string
	body map[string]any
}

// fakePktvisor serves the parts of pktvisor's admin API the backend uses, with
// its status codes and error bodies. All state sits behind mu; tests change it
// through with.
type fakePktvisor struct {
	server *httptest.Server

	mu       sync.Mutex
	taps     map[string]fakeTap
	policies map[string]fakePolicy

	refusePolicies  bool
	failTapList     bool
	failPolicyList  bool
	stallPolicyPost bool

	// requests logs "METHOD path STATUS" for every request.
	requests []string

	release     chan struct{}
	releaseOnce sync.Once
}

func newFakePktvisor(t *testing.T) *fakePktvisor {
	t.Helper()
	f := &fakePktvisor{
		taps:     map[string]fakeTap{},
		policies: map[string]fakePolicy{},
		release:  make(chan struct{}),
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	// Cleanups run last in first out: this one runs before Close, so Close
	// never waits on a stalled handler.
	t.Cleanup(func() { f.releaseOnce.Do(func() { close(f.release) }) })
	return f
}

// with runs fn holding the state lock.
func (f *fakePktvisor) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// addTap puts a tap in the fake; a nil config or tags is reported as null.
func (f *fakePktvisor) addTap(name, inputType string, cfg, tags map[string]any) {
	f.with(func() { f.taps[name] = fakeTap{inputType: inputType, config: cfg, tags: tags} })
}

// addPolicy puts a policy in the fake, attached to tap.
func (f *fakePktvisor) addPolicy(name, tap string) {
	f.with(func() { f.policies[name] = fakePolicy{tap: tap} })
}

// log returns a copy of the request log.
func (f *fakePktvisor) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// clearLog empties the request log.
func (f *fakePktvisor) clearLog() {
	f.with(func() { f.requests = nil })
}

func (f *fakePktvisor) hasTap(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.taps[name]
	return ok
}

// tapDeletes returns the logged tap DELETE entries.
func tapDeletes(log []string) []string {
	var out []string
	for _, e := range log {
		if strings.HasPrefix(e, "DELETE /api/v1/taps/") {
			out = append(out, e)
		}
	}
	return out
}

// reply writes a JSON answer and logs it. The caller holds mu.
func (f *fakePktvisor) reply(w http.ResponseWriter, r *http.Request, status int, v any) {
	f.requests = append(f.requests, fmt.Sprintf("%s %s %d", r.Method, r.URL.Path, status))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakePktvisor) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	f.reply(w, r, status, map[string]string{"error": msg})
}

func (f *fakePktvisor) serve(w http.ResponseWriter, r *http.Request) {
	// Read the body first: net/http notices a client disconnect only once the
	// body has reached EOF.
	body, _ := io.ReadAll(r.Body)

	const tapsPath = "/api/v1/taps"
	const policiesPath = "/api/v1/policies"
	path := r.URL.Path

	switch {
	case path == "/api/v1/metrics/app" && r.Method == http.MethodGet:
		var info pktvisor.AppInfo
		info.App.Version = "1.2.3"
		f.with(func() { f.reply(w, r, http.StatusOK, info) })
	case path == tapsPath && r.Method == http.MethodGet:
		f.with(func() { f.listTaps(w, r) })
	case path == tapsPath && r.Method == http.MethodPost:
		f.with(func() { f.createTaps(w, r, body) })
	case strings.HasPrefix(path, tapsPath+"/") && r.Method == http.MethodGet:
		f.with(func() { f.getTap(w, r, strings.TrimPrefix(path, tapsPath+"/")) })
	case strings.HasPrefix(path, tapsPath+"/") && r.Method == http.MethodDelete:
		f.with(func() { f.deleteTap(w, r, strings.TrimPrefix(path, tapsPath+"/")) })
	case path == policiesPath && r.Method == http.MethodGet:
		f.with(func() { f.listPolicies(w, r) })
	case path == policiesPath && r.Method == http.MethodPost:
		f.createPolicies(w, r, body)
	case strings.HasPrefix(path, policiesPath+"/") && r.Method == http.MethodDelete:
		f.with(func() { f.deletePolicy(w, r, strings.TrimPrefix(path, policiesPath+"/")) })
	default:
		f.with(func() { f.fail(w, r, http.StatusNotFound, "not found") })
	}
}

func tapJSON(t fakeTap) map[string]any {
	return map[string]any{"input_type": t.inputType, "config": t.config, "tags": t.tags}
}

func (f *fakePktvisor) listTaps(w http.ResponseWriter, r *http.Request) {
	if f.failTapList {
		f.fail(w, r, http.StatusInternalServerError, "tap list failed")
		return
	}
	if len(f.taps) == 0 {
		f.reply(w, r, http.StatusOK, nil)
		return
	}
	out := map[string]any{}
	for name, t := range f.taps {
		out[name] = tapJSON(t)
	}
	f.reply(w, r, http.StatusOK, out)
}

func (f *fakePktvisor) getTap(w http.ResponseWriter, r *http.Request, name string) {
	t, ok := f.taps[name]
	if !ok {
		f.fail(w, r, http.StatusNotFound, "tap does not exists")
		return
	}
	f.reply(w, r, http.StatusOK, map[string]any{name: tapJSON(t)})
}

// createTaps takes the body shape the backend posts: visor.taps, a map of tap
// name to its input_type, config and tags.
func (f *fakePktvisor) createTaps(w http.ResponseWriter, r *http.Request, body []byte) {
	var doc struct {
		Visor struct {
			Taps map[string]struct {
				InputType string         `yaml:"input_type"`
				Config    map[string]any `yaml:"config"`
				Tags      map[string]any `yaml:"tags"`
			} `yaml:"taps"`
		} `yaml:"visor"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		f.fail(w, r, http.StatusBadRequest, "invalid tap document")
		return
	}
	for name := range doc.Visor.Taps {
		if _, exists := f.taps[name]; exists {
			f.fail(w, r, http.StatusConflict, fmt.Sprintf("module name '%s' already exists", name))
			return
		}
	}
	for name, t := range doc.Visor.Taps {
		f.taps[name] = fakeTap{inputType: t.InputType, config: t.Config, tags: t.Tags}
	}
	f.reply(w, r, http.StatusCreated, doc.Visor.Taps)
}

func (f *fakePktvisor) deleteTap(w http.ResponseWriter, r *http.Request, name string) {
	if _, ok := f.taps[name]; !ok {
		f.fail(w, r, http.StatusNotFound, "tap does not exists")
		return
	}
	delete(f.taps, name)
	f.reply(w, r, http.StatusOK, map[string]string{"status": "success"})
}

func (f *fakePktvisor) listPolicies(w http.ResponseWriter, r *http.Request) {
	if f.failPolicyList {
		f.fail(w, r, http.StatusInternalServerError, "policy list failed")
		return
	}
	out := map[string]any{}
	for name, p := range f.policies {
		entry := map[string]any{}
		if p.tap != "" {
			entry["taps"] = map[string]any{p.tap: map[string]any{}}
			if t, ok := f.taps[p.tap]; ok {
				out[t.inputType+"-resources"] = map[string]any{}
			}
		}
		out[name] = entry
	}
	f.reply(w, r, http.StatusOK, out)
}

func (f *fakePktvisor) deletePolicy(w http.ResponseWriter, r *http.Request, name string) {
	name, err := url.PathUnescape(name)
	if err != nil {
		f.fail(w, r, http.StatusBadRequest, "bad policy name")
		return
	}
	if _, ok := f.policies[name]; !ok {
		f.fail(w, r, http.StatusNotFound, "policy does not exists")
		return
	}
	delete(f.policies, name)
	f.reply(w, r, http.StatusOK, map[string]string{"status": "success"})
}

// createPolicies takes the body shape the backend posts: visor.policies, a map
// of policy name to its body.
func (f *fakePktvisor) createPolicies(w http.ResponseWriter, r *http.Request, body []byte) {
	var doc struct {
		Visor struct {
			Policies map[string]map[string]any `yaml:"policies"`
		} `yaml:"visor"`
	}
	f.mu.Lock()
	if f.refusePolicies {
		f.fail(w, r, http.StatusInternalServerError, "policy refused")
		f.mu.Unlock()
		return
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		f.fail(w, r, http.StatusBadRequest, "invalid policy document")
		f.mu.Unlock()
		return
	}

	pending := map[string]fakePolicy{}
	for name, pol := range doc.Visor.Policies {
		input, _ := pol["input"].(map[string]any)
		tap, _ := input["tap"].(string)
		_, hasSelector := input["tap_selector"]
		if tap == "" && !hasSelector {
			f.fail(w, r, http.StatusInternalServerError, "missing key 'input.tap' or key 'input.tap_selector'")
			f.mu.Unlock()
			return
		}
		if tap != "" {
			t, ok := f.taps[tap]
			if !ok {
				f.fail(w, r, http.StatusInternalServerError, fmt.Sprintf("tap '%s' does not exist", tap))
				f.mu.Unlock()
				return
			}
			if it, _ := input["input_type"].(string); it != "" && it != t.inputType {
				f.fail(w, r, http.StatusInternalServerError,
					fmt.Sprintf("input_type '%s' does not match tap '%s' of type '%s'", it, tap, t.inputType))
				f.mu.Unlock()
				return
			}
		}
		pending[name] = fakePolicy{tap: tap, body: pol}
	}

	if f.stallPolicyPost {
		f.requests = append(f.requests, "POST /api/v1/policies stalled")
		f.mu.Unlock()
		// Wait without the lock, for the client to give up or for shutdown.
		select {
		case <-r.Context().Done():
		case <-f.release:
		}
		return
	}

	for name, pol := range pending {
		f.policies[name] = pol
	}
	f.reply(w, r, http.StatusCreated, map[string]string{"status": "created"})
	f.mu.Unlock()
}

// startAgainst configures and starts a pktvisor backend whose admin API is the
// fake. It logs to a discard handler: a text handler's lock would order log
// writes across goroutines and hide data races.
func startAgainst(t *testing.T, f *fakePktvisor) backend.Backend {
	t.Helper()

	serverURL, err := url.Parse(f.server.URL)
	require.NoError(t, err)

	createExecutable(t, "pktvisord")

	repo, err := policies.NewMemRepo()
	require.NoError(t, err)

	mockCmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(mockCmd, 12345)
	overrideNewCmdOptions(t, mockCmd, func(_ backend.CmdOptions, _ string, _ []string) {})

	require.True(t, pktvisor.Register())
	be := backend.GetBackend("pktvisor")

	commons := config.BackendCommons{}
	commons.Otlp.HTTP = f.server.URL

	require.NoError(t, be.Configure(slog.New(slog.DiscardHandler), repo, map[string]any{
		"host": serverURL.Hostname(),
		"port": serverURL.Port(),
	}, commons, nil))

	baseCtx := context.WithValue(context.Background(), config.ContextKey("agent_id"), "test-agent")
	ctx, cancel := context.WithCancel(baseCtx)
	t.Cleanup(cancel)
	require.NoError(t, be.Start(ctx, cancel))

	// The start's own readiness probe is not what tests look at.
	f.clearLog()
	return be
}
