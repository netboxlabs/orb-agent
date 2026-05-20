package secretsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestCyberArkStart_RequiresURL(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "url is required")
}

func TestCyberArkStart_RequiresAppID(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "app_id is required")
}

func TestCyberArkStart_TrimsTrailingSlashFromURL(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com/", AppID: "orb"},
	}
	require.NoError(t, c.Start(context.Background()))
	require.Equal(t, "https://ccp.example.com", c.baseURL.String())
}

func TestCyberArkStart_AcceptsURLWithPathPrefix(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com/cyberark", AppID: "orb"},
	}
	require.NoError(t, c.Start(context.Background()))
	require.Equal(t, "/cyberark", c.baseURL.Path, "path prefix must be preserved")
}

func TestCyberArkStart_RejectsURLWithQueryOrFragment(t *testing.T) {
	for _, bad := range []string{
		"https://ccp.example.com?x=y",
		"https://ccp.example.com#anchor",
		"https://ccp.example.com/cyberark?a=1",
	} {
		t.Run(bad, func(t *testing.T) {
			c := &cyberarkManager{
				preLogger: newTestLogger(),
				config:    config.CyberArkManager{URL: bad, AppID: "orb"},
			}
			err := c.Start(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), "query string or fragment")
		})
	}
}

func TestCyberArkStart_RejectsURLWithoutHost(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://", AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "must include a host")
}

func TestCyberArkStart_RejectsURLAlreadyAtCCPEndpoint(t *testing.T) {
	// Operators copying examples from upstream CyberArk integrations
	// sometimes paste the full endpoint URL. Catch it at startup; otherwise
	// fetch builds /AIMWebService/api/Accounts/AIMWebService/api/Accounts
	// and 404s consistently at runtime.
	for _, bad := range []string{
		"https://ccp.example.com/AIMWebService/api/Accounts",
		"https://ccp.example.com/AIMWebService/api/Accounts/",
		"https://ccp.example.com/some/prefix/AIMWebService/api/Accounts",
	} {
		t.Run(bad, func(t *testing.T) {
			c := &cyberarkManager{
				preLogger: newTestLogger(),
				config:    config.CyberArkManager{URL: bad, AppID: "orb"},
			}
			err := c.Start(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), "already includes the CCP endpoint path")
		})
	}
}

func TestCyberArkStart_RejectsCABundleWithOnlyPrivateKey(t *testing.T) {
	// A PEM file that has a recognisable PEM block but no certificate must
	// be rejected at startup rather than producing an empty trust pool that
	// fails opaquely at TLS handshake time. Generate the key at runtime via
	// the same helper the mTLS test uses, so there's no literal-looking
	// private-key material in the source tree to trip secret scanners.
	_, keyPEM := generateTestCertPair(t, "ca-bundle-key-only-fixture")

	dir := t.TempDir()
	keyOnly := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyOnly, keyPEM, 0o600))

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: keyOnly},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no parseable certificates")
}

func TestCyberArkStart_RejectsUnparseableURL(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "ht tp://bad url", AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not parse")
}

func TestCyberArkStart_RejectsNonHTTPScheme(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "ftp://ccp.example.com", AppID: "orb"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "http or https")
}

func TestCyberArkStart_DefaultTimeout(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb"},
	}
	require.NoError(t, c.Start(context.Background()))
	require.NotNil(t, c.httpClient)
	require.Equal(t, defaultCyberArkTimeout, c.httpClient.Timeout)
}

func TestCyberArkStart_CustomTimeout(t *testing.T) {
	timeoutSec := 5
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", Timeout: &timeoutSec},
	}
	require.NoError(t, c.Start(context.Background()))
	require.Equal(t, 5*defaultCyberArkTimeoutUnit, c.httpClient.Timeout)
}

func TestCyberArkStart_RequiresBothCertAndKey(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", ClientCert: "/tmp/cert.pem"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_key")

	c = &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", ClientKey: "/tmp/key.pem"},
	}
	err = c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_cert")
}

func TestCyberArkStart_RejectsMissingCABundle(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: "/nonexistent/ca.pem"},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca_bundle")
}

func TestCyberArkStart_RejectsCABundleWithNoPEMBlocks(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "not-a-pem.txt")
	require.NoError(t, os.WriteFile(bad, []byte("this is not pem"), 0o600))

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: bad},
	}
	err := c.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "ca_bundle")
}

func TestCyberArkStart_AcceptsCABundle(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte(testSelfSignedCAPEM), 0o600))

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", CABundle: caPath},
	}
	require.NoError(t, c.Start(context.Background()))
	require.NotNil(t, c.httpClient.Transport)

	tr := c.httpClient.Transport.(*http.Transport)
	require.NotNil(t, tr.TLSClientConfig)
	require.NotNil(t, tr.TLSClientConfig.RootCAs)
}

func TestCyberArkStart_SkipTLSVerifyFlowsThroughToTransport(t *testing.T) {
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config:    config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb", SkipTLSVerify: true},
	}
	require.NoError(t, c.Start(context.Background()))
	tr := c.httpClient.Transport.(*http.Transport)
	require.True(t, tr.TLSClientConfig.InsecureSkipVerify)
}

func cyberarkManagerWith(appID string) *cyberarkManager {
	return &cyberarkManager{config: config.CyberArkManager{AppID: appID}}
}

func TestCyberArkParseBody_ShortForm(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "orb-agent", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "Content", ref.field)
}

func TestCyberArkParseBody_ShortFormWithField(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("Lab/DB-Account/UserName")
	require.NoError(t, err)
	require.Equal(t, "orb-agent", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "UserName", ref.field)
}

func TestCyberArkParseBody_Qualified(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("OtherApp//Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "OtherApp", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "Content", ref.field)
}

func TestCyberArkParseBody_QualifiedWithField(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	ref, err := c.parseBody("OtherApp//Lab/DB-Account/UserName")
	require.NoError(t, err)
	require.Equal(t, "OtherApp", ref.appID)
	require.Equal(t, "Lab", ref.safe)
	require.Equal(t, "DB-Account", ref.object)
	require.Equal(t, "UserName", ref.field)
}

func TestCyberArkParseBody_GrammarErrors(t *testing.T) {
	c := cyberarkManagerWith("orb-agent")
	for _, body := range []string{
		"",                                     // empty
		"Lab",                                  // 1 segment short — no object
		"Lab/DB-Account/UserName/Extra",        // 4 segments short — too long
		"OtherApp//Lab",                        // qualified short — no object
		"OtherApp//Lab/DB-Account/Field/Extra", // qualified too long
		"//Lab/DB-Account",                     // empty AppID before //
		"/Lab/DB-Account",                      // leading slash
		"Lab/",                                 // trailing slash
		"Lab//Object",                          // // with nothing after AppID makes no sense
	} {
		_, err := c.parseBody(body)
		require.Errorf(t, err, "body %q should have been rejected", body)
	}
}

func TestCyberArkParseBody_ShortFormRequiresConfiguredAppID(t *testing.T) {
	c := cyberarkManagerWith("")
	_, err := c.parseBody("Lab/DB-Account")
	require.Error(t, err)
	require.Contains(t, err.Error(), "app_id")
}

// fakeCCP emulates the GET /AIMWebService/api/Accounts endpoint.
type fakeCCP struct {
	*httptest.Server
	mu       sync.Mutex
	accounts map[string]map[string]any // key = "<AppID>|<Safe>|<Object>"
	missing  map[string]bool
	calls    atomic.Int32
	lastReq  atomic.Value // url.Values
}

func newFakeCCP() *fakeCCP {
	f := &fakeCCP{accounts: map[string]map[string]any{}, missing: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/AIMWebService/api/Accounts", func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		q := r.URL.Query()
		f.lastReq.Store(q)
		key := q.Get("AppID") + "|" + q.Get("Safe") + "|" + q.Get("Object")

		f.mu.Lock()
		defer f.mu.Unlock()
		if f.missing[key] {
			http.Error(w, `{"ErrorCode":"APPAP004E","ErrorMsg":"Object not found"}`, http.StatusNotFound)
			return
		}
		acc, ok := f.accounts[key]
		if !ok {
			http.Error(w, `{"ErrorCode":"APPAP004E","ErrorMsg":"Object not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(acc)
	})
	f.Server = httptest.NewServer(mux)
	return f
}

func (f *fakeCCP) set(appID, safe, object string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[appID+"|"+safe+"|"+object] = fields
}

func (f *fakeCCP) delete(appID, safe, object string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.accounts, appID+"|"+safe+"|"+object)
	f.missing[appID+"|"+safe+"|"+object] = true
}

func newCyberarkManagerForTest(t *testing.T, fake *fakeCCP, cfg config.CyberArkManager) *cyberarkManager {
	t.Helper()
	if cfg.AppID == "" {
		cfg.AppID = "orb-agent"
	}
	cfg.URL = fake.URL
	c := &cyberarkManager{preLogger: newTestLogger(), config: cfg}
	require.NoError(t, c.Start(context.Background()))
	return c
}

func TestCyberArkFetch_ShortForm_ReturnsContent(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "DB-Account", map[string]any{
		"Content":  "s3cret",
		"UserName": "dbuser",
	})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	val, err := c.fetch("Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "s3cret", val)

	q := fake.lastReq.Load().(url.Values)
	require.Equal(t, "orb-agent", q.Get("AppID"))
	require.Equal(t, "Lab", q.Get("Safe"))
	require.Equal(t, "DB-Account", q.Get("Object"))
}

func TestCyberArkFetch_FieldSelector_ReturnsUserName(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "DB-Account", map[string]any{
		"Content":  "s3cret",
		"UserName": "dbuser",
	})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	val, err := c.fetch("Lab/DB-Account/UserName")
	require.NoError(t, err)
	require.Equal(t, "dbuser", val)
}

func TestCyberArkFetch_QualifiedAppID_OverridesYAML(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("OtherApp", "Lab", "DB-Account", map[string]any{"Content": "ot-secret"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	val, err := c.fetch("OtherApp//Lab/DB-Account")
	require.NoError(t, err)
	require.Equal(t, "ot-secret", val)

	q := fake.lastReq.Load().(url.Values)
	require.Equal(t, "OtherApp", q.Get("AppID"))
}

func TestCyberArkFetch_ReasonIsForwarded(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "x"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{Reason: "policy resolution"})
	_, err := c.fetch("Lab/Acc")
	require.NoError(t, err)

	q := fake.lastReq.Load().(url.Values)
	require.Equal(t, "policy resolution", q.Get("Reason"))
}

func TestCyberArkFetch_NotFound(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Missing")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
	require.Contains(t, err.Error(), "Object not found", "underlying CCP error message must surface")
}

func TestCyberArkFetch_FieldMissingFromResponse(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "x"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Acc/Database")
	require.Error(t, err)
	require.Contains(t, err.Error(), `field "Database"`)
}

func TestCyberArkFetch_FieldEmptyInResponse(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": ""})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Acc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty")
}

func TestCyberArkFetch_Unauthorized(t *testing.T) {
	fake := &fakeCCP{accounts: map[string]map[string]any{}, missing: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/AIMWebService/api/Accounts", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"ErrorCode":"AUTH","ErrorMsg":"App not authorized"}`, http.StatusUnauthorized)
	})
	fake.Server = httptest.NewServer(mux)
	defer fake.Close()

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	_, err := c.fetch("Lab/Acc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
	require.Contains(t, err.Error(), "App not authorized")
}

// testSelfSignedCAPEM is a syntactically-valid X.509 self-signed CA PEM block
// used purely to drive the CA-bundle parsing happy path. It is NOT used for
// any real TLS handshake.
const testSelfSignedCAPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
`

func TestCyberArkResolveBody_CacheHitAvoidsSecondHTTP(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v1"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})

	v1, err := c.resolveBody("Lab/Acc", "policy-a")
	require.NoError(t, err)
	require.Equal(t, "v1", v1)

	v2, err := c.resolveBody("Lab/Acc", "policy-b")
	require.NoError(t, err)
	require.Equal(t, "v1", v2)

	require.EqualValues(t, 1, fake.calls.Load(), "second resolve should hit cache")
}

func TestCyberArkSolvePolicySecrets_ReplacesPlaceholder(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "s3cret"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	payload := config.PolicyPayload{
		ID: "policy-1",
		Data: map[string]any{
			"auth": map[string]any{"password": "${cyberark://Lab/Acc}"},
		},
	}
	out, err := c.SolvePolicySecrets(payload)
	require.NoError(t, err)
	auth := out.Data.(map[string]any)["auth"].(map[string]any)
	require.Equal(t, "s3cret", auth["password"])
}

func TestCyberArkPollSecrets_DetectsChange(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v1"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	got := make(chan map[string]bool, 4)
	c.RegisterUpdatePoliciesCallback(func(m map[string]bool) { got <- m })

	_, err := c.resolveBody("Lab/Acc", "policy-1")
	require.NoError(t, err)

	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v2"})

	c.pollSecrets()
	select {
	case m := <-got:
		require.Equal(t, map[string]bool{"policy-1": true}, m)
	case <-time.After(time.Second):
		t.Fatal("expected change callback not invoked")
	}
}

func TestCyberArkPollSecrets_FailureEvictsAndReportsFalse(t *testing.T) {
	fake := newFakeCCP()
	defer fake.Close()
	fake.set("orb-agent", "Lab", "Acc", map[string]any{"Content": "v1"})

	c := newCyberarkManagerForTest(t, fake, config.CyberArkManager{})
	got := make(chan map[string]bool, 4)
	c.RegisterUpdatePoliciesCallback(func(m map[string]bool) { got <- m })

	_, err := c.resolveBody("Lab/Acc", "policy-1")
	require.NoError(t, err)

	fake.delete("orb-agent", "Lab", "Acc")

	c.pollSecrets()
	select {
	case m := <-got:
		require.Equal(t, map[string]bool{"policy-1": false}, m)
	case <-time.After(time.Second):
		t.Fatal("expected failure callback not invoked")
	}

	c.mu.Lock()
	_, present := c.usedVars["Lab/Acc"]
	c.mu.Unlock()
	require.False(t, present, "failed entry must be evicted")
}

func TestNewManager_ReturnsCyberArkManagerWhenActive(t *testing.T) {
	logger := newTestLogger()
	m := New(logger, config.ManagerSecrets{
		Active: "cyberark",
		Sources: config.SecretsSources{
			CyberArk: config.CyberArkManager{URL: "https://ccp.example.com", AppID: "orb"},
		},
	})
	_, ok := m.(*cyberarkManager)
	require.True(t, ok, "New() with active=cyberark must return *cyberarkManager, got %T", m)
}

// generateTestCertPair produces a self-signed EC cert/key PEM pair valid for
// 127.0.0.1 and "localhost" with the given CommonName. Used to drive the
// mTLS round-trip test; not used in production paths.
func generateTestCertPair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestCyberArk_mTLS_HandshakeRoundTrip(t *testing.T) {
	// Generate a CA-ish cert that doubles as a server cert AND is accepted
	// as a client cert. Same key material is used for both sides of the
	// handshake; this is fine for the test's purposes (it proves Go's
	// http.Client presents the cert we asked for).
	serverCertPEM, serverKeyPEM := generateTestCertPair(t, "server.localhost")
	clientCertPEM, clientKeyPEM := generateTestCertPair(t, "orb-agent-client")

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, serverCertPEM, 0o600))
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certFile, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, clientKeyPEM, 0o600))

	// Server requires client cert.
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)
	clientCA := x509.NewCertPool()
	clientCA.AppendCertsFromPEM(clientCertPEM)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Content":"mtls-ok"}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// With a configured client cert + CA bundle, the handshake should succeed.
	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config: config.CyberArkManager{
			URL:        srv.URL,
			AppID:      "orb-agent",
			CABundle:   caFile,
			ClientCert: certFile,
			ClientKey:  keyFile,
		},
	}
	require.NoError(t, c.Start(context.Background()))

	val, err := c.fetch("Lab/Acc")
	require.NoError(t, err)
	require.Equal(t, "mtls-ok", val)

	// Without the client cert/key, the handshake must fail.
	c2 := &cyberarkManager{
		preLogger: newTestLogger(),
		config: config.CyberArkManager{
			URL:      srv.URL,
			AppID:    "orb-agent",
			CABundle: caFile,
		},
	}
	require.NoError(t, c2.Start(context.Background()))
	_, err = c2.fetch("Lab/Acc")
	require.Error(t, err, "fetch without client cert must fail")
}

func TestCyberArk_SkipTLSVerify_AcceptsSelfSignedServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Content":"skip-tls-ok"}`))
	}))
	defer srv.Close()

	c := &cyberarkManager{
		preLogger: newTestLogger(),
		config: config.CyberArkManager{
			URL:           srv.URL,
			AppID:         "orb-agent",
			SkipTLSVerify: true,
		},
	}
	require.NoError(t, c.Start(context.Background()))

	val, err := c.fetch("Lab/Acc")
	require.NoError(t, err)
	require.Equal(t, "skip-tls-ok", val)
}
