package secretsmgr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestDopplerStart_EmptyTokenFails(t *testing.T) {
	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{},
	}
	err := d.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "token is required")
}

func TestDopplerStart_DefaultsAPIHostAndTimeout(t *testing.T) {
	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{Token: "dp.st.faketoken"},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://api.doppler.com", d.apiHost)
	require.NotNil(t, d.httpClient)
	require.Equal(t, defaultDopplerTimeout, d.httpClient.Timeout)
}

func TestDopplerStart_CustomTimeout(t *testing.T) {
	timeoutSec := 5
	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{Token: "dp.st.faketoken", Timeout: &timeoutSec},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, 5*time.Second, d.httpClient.Timeout)
}

func TestDopplerStart_TrimsTrailingSlashFromAPIHost(t *testing.T) {
	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{Token: "dp.st.faketoken", APIHost: "https://api.doppler.com/"},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://api.doppler.com", d.apiHost)
}

func TestDopplerStart_TokenFromEnv(t *testing.T) {
	t.Setenv("DOPPLER_TOKEN_TEST_TASK2", "dp.st.fromenv")
	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{Token: "${DOPPLER_TOKEN_TEST_TASK2}"},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "dp.st.fromenv", d.config.Token)
}

func TestDopplerStart_UnsetEnvTokenFails(t *testing.T) {
	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{Token: "${ORB_UNSET_VAR_TASK2}"},
	}
	err := d.Start(context.Background())
	require.Error(t, err)
}

// fakeDopplerServer emulates the /v3/configs/config/secret endpoint.
type fakeDopplerServer struct {
	*httptest.Server
	mu      sync.Mutex
	secrets map[string]string // key = "<project>|<config>|<name>", value = computed value
	missing map[string]bool   // key = same; explicitly absent → 404
	calls   atomic.Int32
	lastReq atomic.Value // url.Values of the last request
}

func newFakeDopplerServer() *fakeDopplerServer {
	f := &fakeDopplerServer{
		secrets: make(map[string]string),
		missing: make(map[string]bool),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/configs/config/secret", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer dp.st.faketoken" {
			http.Error(w, `{"messages":["unauthorized"]}`, http.StatusUnauthorized)
			return
		}
		q := r.URL.Query()
		f.lastReq.Store(q)
		key := q.Get("project") + "|" + q.Get("config") + "|" + q.Get("name")

		f.mu.Lock()
		defer f.mu.Unlock()
		if f.missing[key] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"messages":["Secret not found"]}`))
			return
		}
		val, ok := f.secrets[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"messages":["Secret not found"]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": q.Get("name"),
			"value": map[string]any{
				"raw":      val,
				"computed": val,
			},
		})
	})
	f.Server = httptest.NewServer(mux)
	return f
}

func (f *fakeDopplerServer) set(project, cfg, name, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[project+"|"+cfg+"|"+name] = value
}

func (f *fakeDopplerServer) delete(project, cfg, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, project+"|"+cfg+"|"+name)
	f.missing[project+"|"+cfg+"|"+name] = true
}

func newDopplerManagerForTest(t *testing.T, fake *fakeDopplerServer, cfg config.DopplerManager) *dopplerManager {
	t.Helper()
	cfg.Token = "dp.st.faketoken"
	cfg.APIHost = fake.URL
	d := &dopplerManager{preLogger: newTestLogger(), config: cfg}
	require.NoError(t, d.Start(context.Background()))
	return d
}

func TestDopplerFetch_FullyQualifiedBody(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "s3cret")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{})
	val, err := d.fetch("orb/prd/API_KEY")
	require.NoError(t, err)
	require.Equal(t, "s3cret", val)

	q := fake.lastReq.Load().(url.Values)
	require.Equal(t, "orb", q.Get("project"))
	require.Equal(t, "prd", q.Get("config"))
	require.Equal(t, "API_KEY", q.Get("name"))
}

func TestDopplerFetch_ShortBodyUsesDefaults(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "s3cret")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})
	val, err := d.fetch("API_KEY")
	require.NoError(t, err)
	require.Equal(t, "s3cret", val)
}

func TestDopplerFetch_ShortBodyWithoutDefaultsFails(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{})
	_, err := d.fetch("API_KEY")
	require.Error(t, err)
	require.Contains(t, err.Error(), "project")
}

func TestDopplerFetch_GrammarErrors(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	for _, body := range []string{"orb/prd", "orb/prd/API_KEY/extra", ""} {
		_, err := d.fetch(body)
		require.Errorf(t, err, "body %q should have failed", body)
	}
}

func TestDopplerFetch_NotFound(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	_, err := d.fetch("MISSING")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestDopplerFetch_Unauthorized(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()

	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{Token: "wrong", APIHost: fake.URL, Project: "orb", Config: "prd"},
	}
	require.NoError(t, d.Start(context.Background()))

	_, err := d.fetch("API_KEY")
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
	require.Contains(t, err.Error(), "unauthorized", "error should surface Doppler's messages field")
}

// TestDopplerSolvePolicySecrets_PropagatesAuthErrorWithMessage verifies that an
// auth failure encountered while resolving a policy placeholder surfaces both
// the HTTP status and Doppler's `messages` payload after passing through the
// shared processMap/processValue resolver pipeline.
func TestDopplerSolvePolicySecrets_PropagatesAuthErrorWithMessage(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "s3cret")

	d := &dopplerManager{
		preLogger: newTestLogger(),
		config:    config.DopplerManager{Token: "wrong", APIHost: fake.URL, Project: "orb", Config: "prd"},
	}
	require.NoError(t, d.Start(context.Background()))

	payload := config.PolicyPayload{
		ID: "policy-1",
		Data: map[string]any{
			"auth": map[string]any{"token": "${doppler://API_KEY}"},
		},
	}
	_, err := d.SolvePolicySecrets(payload)
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
	require.Contains(t, err.Error(), "unauthorized", "messages envelope must survive resolver wrapping")
}

func TestDopplerFetch_EmptyComputedValueFails(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})
	_, err := d.fetch("API_KEY")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestDopplerResolveBody_CacheHitAvoidsSecondHTTP(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "v1")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	v1, err := d.resolveBody("API_KEY", "policy-a")
	require.NoError(t, err)
	require.Equal(t, "v1", v1)

	v2, err := d.resolveBody("API_KEY", "policy-b")
	require.NoError(t, err)
	require.Equal(t, "v1", v2)

	require.EqualValues(t, 1, fake.calls.Load(), "second resolve should hit cache")

	d.mu.Lock()
	defer d.mu.Unlock()
	require.True(t, d.usedVars["API_KEY"].policyIDs["policy-a"])
	require.True(t, d.usedVars["API_KEY"].policyIDs["policy-b"])
}

func TestDopplerSolvePolicySecrets_ReplacesPlaceholders(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "s3cret")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	payload := config.PolicyPayload{
		ID: "policy-1",
		Data: map[string]any{
			"endpoint": "https://example.com",
			"auth": map[string]any{
				"token": "${doppler://API_KEY}",
			},
		},
	}
	out, err := d.SolvePolicySecrets(payload)
	require.NoError(t, err)

	data := out.Data.(map[string]any)
	auth := data["auth"].(map[string]any)
	require.Equal(t, "s3cret", auth["token"])
}

func TestDopplerSolveConfigSecrets_ReplacesInBackendsAndClearsTracking(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "BACKEND_TOKEN", "be-tok")
	fake.set("orb", "prd", "FLEET_SECRET", "fleet-tok")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	backends := map[string]any{
		"otel": map[string]any{
			"token": "${doppler://BACKEND_TOKEN}",
		},
	}
	cm := config.ManagerConfig{
		Active: "fleet",
		Sources: config.Sources{
			Fleet: config.FleetManager{
				ClientSecret: "${doppler://FLEET_SECRET}",
			},
		},
	}

	outBackends, outCM, err := d.SolveConfigSecrets(backends, cm)
	require.NoError(t, err)

	otel := outBackends["otel"].(map[string]any)
	require.Equal(t, "be-tok", otel["token"])
	require.Equal(t, "fleet-tok", outCM.Sources.Fleet.ClientSecret)

	d.mu.Lock()
	defer d.mu.Unlock()
	require.Empty(t, d.usedVars, "config-time refs must not be tracked for re-apply")
}

func TestDopplerPollSecrets_DetectsChange(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "v1")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	gotCalls := make(chan map[string]bool, 1)
	d.RegisterUpdatePoliciesCallback(func(m map[string]bool) {
		gotCalls <- m
	})

	_, err := d.resolveBody("API_KEY", "policy-1")
	require.NoError(t, err)

	// Server-side rotation.
	fake.set("orb", "prd", "API_KEY", "v2")

	d.pollSecrets()
	select {
	case m := <-gotCalls:
		require.Equal(t, map[string]bool{"policy-1": true}, m)
	case <-time.After(time.Second):
		t.Fatal("expected callback not invoked")
	}

	d.mu.Lock()
	require.Equal(t, "v2", d.usedVars["API_KEY"].Value)
	d.mu.Unlock()
}

func TestDopplerPollSecrets_NoChangeNoCallback(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "v1")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	called := atomic.Bool{}
	d.RegisterUpdatePoliciesCallback(func(map[string]bool) {
		called.Store(true)
	})

	_, err := d.resolveBody("API_KEY", "policy-1")
	require.NoError(t, err)

	d.pollSecrets()
	require.False(t, called.Load(), "no change → no callback")
}

func TestDopplerPollSecrets_FailureEvictsAndReportsFalse(t *testing.T) {
	fake := newFakeDopplerServer()
	defer fake.Close()
	fake.set("orb", "prd", "API_KEY", "v1")

	d := newDopplerManagerForTest(t, fake, config.DopplerManager{Project: "orb", Config: "prd"})

	gotCalls := make(chan map[string]bool, 1)
	d.RegisterUpdatePoliciesCallback(func(m map[string]bool) {
		gotCalls <- m
	})

	_, err := d.resolveBody("API_KEY", "policy-1")
	require.NoError(t, err)

	fake.delete("orb", "prd", "API_KEY")

	d.pollSecrets()
	select {
	case m := <-gotCalls:
		require.Equal(t, map[string]bool{"policy-1": false}, m)
	case <-time.After(time.Second):
		t.Fatal("expected failure callback not invoked")
	}

	d.mu.Lock()
	_, present := d.usedVars["API_KEY"]
	d.mu.Unlock()
	require.False(t, present, "failed entry must be evicted from cache")
}

func TestNewManager_ReturnsDopplerManagerWhenActive(t *testing.T) {
	logger := newTestLogger()
	m := New(logger, config.ManagerSecrets{
		Active: "doppler",
		Sources: config.SecretsSources{
			Doppler: config.DopplerManager{Token: "dp.st.anything"},
		},
	})
	_, ok := m.(*dopplerManager)
	require.True(t, ok, "New() with active=doppler must return *dopplerManager, got %T", m)
}
