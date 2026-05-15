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

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestDopplerStart_EmptyTokenFails(t *testing.T) {
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{},
	}
	err := d.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "token is required")
}

func TestDopplerStart_DefaultsAPIHostAndTimeout(t *testing.T) {
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{Token: "dp.st.faketoken"},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://api.doppler.com", d.apiHost)
	require.NotNil(t, d.httpClient)
}

func TestDopplerStart_TokenFromEnv(t *testing.T) {
	t.Setenv("DOPPLER_TOKEN_TEST_TASK2", "dp.st.fromenv")
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{Token: "${DOPPLER_TOKEN_TEST_TASK2}"},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "dp.st.fromenv", d.config.Token)
}

func TestDopplerStart_UnsetEnvTokenFails(t *testing.T) {
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{Token: "${ORB_UNSET_VAR_TASK2}"},
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

func newDopplerManagerForTest(t *testing.T, fake *fakeDopplerServer, cfg config.DopplerManager) *dopplerManager {
	t.Helper()
	cfg.Token = "dp.st.faketoken"
	cfg.APIHost = fake.URL
	d := &dopplerManager{logger: newTestLogger(), config: cfg}
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
		logger: newTestLogger(),
		config: config.DopplerManager{Token: "wrong", APIHost: fake.URL, Project: "orb", Config: "prd"},
	}
	require.NoError(t, d.Start(context.Background()))

	_, err := d.fetch("API_KEY")
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
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
